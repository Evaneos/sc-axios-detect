#!/usr/bin/env python3
"""Scan local filesystem for compromised axios versions and related IOCs.

Usage: python3 detect-axios.py [root_path]
  root_path: directory to scan (default: entire filesystem)

Zero external dependencies — stdlib only.
"""

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

# --- IOCs ---

COMPROMISED_VERSIONS = {"1.14.1", "0.30.4"}
MALICIOUS_DEP = "plain-crypto-js"
RELATED_PKGS = ["@shadanai/openclaw", "@qqbrowser/openclaw-qbot"]
C2_DOMAIN = "sfrclak.com"
C2_IP = "142.11.206.73"
C2_PORT = 8000

RAT_PATHS = {
    "Darwin": ["/Library/Caches/com.apple.act.mond"],
    "Linux": ["/tmp/ld.py"],
    "Windows": [os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "wt.exe")],
}

DROPPER_NAMES = {"6202033.vbs", "6202033.ps1", "ld.py"}

RAT_USER_AGENT_PATTERN = re.compile(
    r"msie 8\.0.*windows nt 5\.1.*trident/4\.0", re.IGNORECASE
)

# Directories that cannot contain node_modules or JS lockfiles, per OS.
PRUNE_DIRS_LINUX = {"/etc", "/boot", "/lost+found", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
                    "/proc", "/sys", "/dev", "/run"}
PRUNE_DIRS_DARWIN = {"/etc", "/boot", "/lost+found", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
                     "/System", "/Library/Apple"}
# Windows: C:\Windows contains OS binaries, C:\Recovery is system recovery.
# Resolved at runtime from %SYSTEMROOT% to handle non-standard install paths.
PRUNE_DIRS_WINDOWS: set[str] = set()  # populated in Scanner.__init__

LOCKFILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
}

# --- Severity model ---

SEVERITY_ORDER = ["CLEAN", "LATENT", "INSTALLED", "CONFIRMED"]


class Scanner:
    def __init__(self, root: str):
        self.root = root
        self.severity = "CLEAN"
        self.findings: list[dict] = []
        self.os_type = platform.system()  # "Linux", "Darwin", "Windows"

        # Build OS-specific prune set
        if self.os_type == "Windows":
            windir = os.environ.get("SYSTEMROOT", r"C:\Windows")
            recovery = os.path.join(os.environ.get("SYSTEMDRIVE", "C:") + os.sep, "Recovery")
            PRUNE_DIRS_WINDOWS.update({os.path.normcase(windir), os.path.normcase(recovery)})
            self._prune_dirs = PRUNE_DIRS_WINDOWS
        elif self.os_type == "Darwin":
            self._prune_dirs = PRUNE_DIRS_DARWIN
        else:
            self._prune_dirs = PRUNE_DIRS_LINUX

    def escalate(self, level: str):
        if SEVERITY_ORDER.index(level) > SEVERITY_ORDER.index(self.severity):
            self.severity = level

    def record(self, category: str, finding_type: str, detail: str, path: str = ""):
        entry = {"category": category, "type": finding_type, "detail": detail}
        if path:
            entry["path"] = path
        self.findings.append(entry)

    def alert(self, msg: str):
        print(f"\033[0;31m[ALERT]\033[0m {msg}")

    def warn(self, msg: str):
        print(f"\033[1;33m[WARN]\033[0m {msg}")

    def ok(self, msg: str):
        print(f"\033[0;32m[OK]\033[0m {msg}")

    def header(self, msg: str):
        print(f"\033[1m{msg}\033[0m")

    # --- Filesystem walking ---

    def _should_prune(self, dirpath: str) -> bool:
        """Skip system dirs that cannot contain node_modules."""
        normalized = os.path.normcase(dirpath)
        if normalized in self._prune_dirs:
            return True
        # On Windows, also prune anything under the Windows dir
        # (normcase check above catches the root, this catches subdirs
        # reached via junction/symlink from outside)
        if self.os_type == "Windows":
            windir = os.path.normcase(os.environ.get("SYSTEMROOT", r"C:\Windows"))
            if normalized.startswith(windir + os.sep):
                return True
        if os.path.basename(dirpath) == ".git":
            return True
        return False

    def walk(self):
        """Walk the filesystem, pruning as we go."""
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            # Prune in-place to prevent descending
            dirnames[:] = [
                d for d in dirnames
                if not self._should_prune(os.path.join(dirpath, d))
            ]
            yield dirpath, dirnames, filenames

    # --- Step 1: Scan node_modules/axios ---

    def scan_axios_packages(self):
        self.header("[1/6] Scanning installed axios packages in node_modules...")
        for dirpath, _dirnames, filenames in self.walk():
            # Match */node_modules/axios/package.json but not nested node_modules
            if not dirpath.endswith(os.sep + os.path.join("node_modules", "axios")):
                continue
            # Skip nested: ...node_modules/X/node_modules/axios
            parts = dirpath.replace("\\", "/").split("/")
            nm_count = parts.count("node_modules")
            if nm_count > 1:
                continue

            pkg_json = os.path.join(dirpath, "package.json")
            if not os.path.isfile(pkg_json):
                continue

            try:
                with open(pkg_json, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            version = data.get("version", "")
            if version in COMPROMISED_VERSIONS:
                self.alert(f"Compromised axios@{version} installed at: {pkg_json}")
                self.record("node_modules", "compromised_axios", f"axios@{version}", pkg_json)
                self.escalate("LATENT")

            # Check if plain-crypto-js is listed as a dependency
            for dep_field in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = data.get(dep_field, {})
                if MALICIOUS_DEP in deps:
                    self.alert(f"Malicious dependency '{MALICIOUS_DEP}' found in: {pkg_json}")
                    self.record("node_modules", "malicious_dependency", MALICIOUS_DEP, pkg_json)
                    self.escalate("LATENT")

    # --- Step 2: Scan lockfiles ---

    def scan_lockfiles(self):
        self.header("[2/6] Scanning lockfiles...")
        for dirpath, _dirnames, filenames in self.walk():
            # Skip lockfiles inside node_modules
            if "node_modules" in dirpath.replace("\\", "/").split("/"):
                continue
            for fname in filenames:
                if fname in LOCKFILE_NAMES:
                    self._check_lockfile(os.path.join(dirpath, fname), fname)

    def _check_lockfile(self, filepath: str, basename: str):
        try:
            # bun.lockb is binary
            mode = "rb" if basename == "bun.lockb" else "r"
            with open(filepath, mode, **({"encoding": "utf-8", "errors": "replace"} if mode == "r" else {})) as f:
                content = f.read()
        except OSError:
            return

        found_axios = False
        found_dep = False

        if basename == "package-lock.json":
            found_axios, found_dep = self._check_package_lock(filepath, content)
        elif basename == "yarn.lock":
            found_axios, found_dep = self._check_yarn_lock(content)
        elif basename == "pnpm-lock.yaml":
            found_axios, found_dep = self._check_pnpm_lock(content)
        elif basename in ("bun.lock", "bun.lockb"):
            found_axios, found_dep = self._check_bun_lock(content, binary=basename == "bun.lockb")

        if found_axios:
            self.alert(f"Compromised axios version in lockfile: {filepath}")
            self.record("lockfile", "compromised_axios", "axios", filepath)
            self.escalate("LATENT")
        if found_dep:
            self.alert(f"'{MALICIOUS_DEP}' in lockfile: {filepath}")
            self.record("lockfile", "malicious_dependency", MALICIOUS_DEP, filepath)
            self.escalate("LATENT")

    def _check_package_lock(self, filepath: str, content: str) -> tuple:
        if "axios" not in content:
            return False, False
        found_axios = False
        found_dep = False
        try:
            lock = json.loads(content)
            pkgs = lock.get("packages", lock.get("dependencies", {}))
            for key, val in pkgs.items():
                if "axios" in key and isinstance(val, dict) and val.get("version") in COMPROMISED_VERSIONS:
                    found_axios = True
                if MALICIOUS_DEP in key:
                    found_dep = True
        except (json.JSONDecodeError, AttributeError):
            pass
        return found_axios, found_dep

    def _check_yarn_lock(self, content: str) -> tuple:
        found_axios = False
        found_dep = False
        if re.search(r'^"?axios@', content, re.MULTILINE):
            for m in re.finditer(r'^"?axios@[^\n]*\n(?:[^\n]*\n){0,5}', content, re.MULTILINE):
                block = m.group()
                for v in COMPROMISED_VERSIONS:
                    if re.search(rf'version:?\s+"?{re.escape(v)}"?', block):
                        found_axios = True
        if MALICIOUS_DEP in content:
            found_dep = True
        return found_axios, found_dep

    def _check_pnpm_lock(self, content: str) -> tuple:
        found_axios = False
        found_dep = False
        for v in COMPROMISED_VERSIONS:
            if re.search(rf"""['"]/axios/{re.escape(v)}['"]|axios:\s+{re.escape(v)}""", content):
                found_axios = True
        if MALICIOUS_DEP in content:
            found_dep = True
        return found_axios, found_dep

    def _check_bun_lock(self, content, binary: bool = False) -> tuple:
        found_axios = False
        found_dep = False
        if binary:
            # Binary: match the npm tarball URL to tie package name to version
            # avoids false positives from unrelated packages (e.g. tslib@1.14.1)
            for v in COMPROMISED_VERSIONS:
                if f"axios/-/axios-{v}.tgz".encode() in content:
                    found_axios = True
            if MALICIOUS_DEP.encode() in content:
                found_dep = True
        else:
            for v in COMPROMISED_VERSIONS:
                if re.search(rf'"axios"[^}}]*"{re.escape(v)}"', content):
                    found_axios = True
            if MALICIOUS_DEP in content:
                found_dep = True
        return found_axios, found_dep

    # --- Step 3: Malicious packages in node_modules ---

    def scan_malicious_packages(self):
        self.header("[3/6] Scanning for malicious packages in node_modules...")
        targets = [MALICIOUS_DEP] + RELATED_PKGS
        for dirpath, _dirnames, filenames in self.walk():
            for target in targets:
                # Handle scoped packages: @scope/name -> node_modules/@scope/name
                expected_suffix = os.path.join("node_modules", *target.split("/"))
                if dirpath.replace("\\", "/").endswith(expected_suffix.replace("\\", "/")):
                    pkg_json = os.path.join(dirpath, "package.json")
                    if os.path.isfile(pkg_json):
                        label = "malicious_package" if target == MALICIOUS_DEP else "related_campaign_package"
                        self.alert(f"{'Malicious' if target == MALICIOUS_DEP else 'Related campaign'} package installed: {pkg_json}")
                        self.record("installed", label, target, pkg_json)
                        self.escalate("INSTALLED")

    # --- Step 4: RAT payload files ---

    def scan_rat_payloads(self):
        self.header("[4/6] Scanning for RAT payload files...")
        rat_paths = RAT_PATHS.get(self.os_type, [])

        # WSL: also check Windows paths
        if self.os_type == "Linux" and os.path.isdir("/mnt/c/ProgramData"):
            rat_paths = rat_paths + ["/mnt/c/ProgramData/wt.exe"]

        for rat_path in rat_paths:
            if os.path.isfile(rat_path):
                self.alert(f"RAT payload found: {rat_path}")
                self.record("artifact", "rat_payload", f"{self.os_type} RAT", rat_path)
                self.artifact_found = True

                # macOS: check code signing
                if self.os_type == "Darwin" and shutil.which("codesign"):
                    ret = subprocess.run(
                        ["codesign", "-v", rat_path],
                        capture_output=True, timeout=10
                    )
                    if ret.returncode != 0:
                        self.alert("  File is NOT signed by Apple (expected for RAT)")

        # Check temp dirs for known dropper filenames
        temp_dirs = self._get_temp_dirs()
        for tmp_dir in temp_dirs:
            if not os.path.isdir(tmp_dir):
                continue
            for root, _dirs, files in os.walk(tmp_dir):
                # Limit depth to 2
                depth = root[len(tmp_dir):].count(os.sep)
                if depth > 2:
                    continue
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if fname in DROPPER_NAMES:
                        self.alert(f"Dropper artifact found: {fpath}")
                        self.record("artifact", "dropper_file", fname, fpath)
                        self.artifact_found = True

    def _get_temp_dirs(self) -> list:
        dirs = []
        if self.os_type == "Windows":
            for var in ("TEMP", "TMP"):
                d = os.environ.get(var)
                if d:
                    dirs.append(d)
        else:
            dirs.extend(["/tmp", "/var/tmp"])
            tmpdir = os.environ.get("TMPDIR")
            if tmpdir:
                dirs.append(tmpdir)
        return list(set(dirs))

    # --- Step 5: Network / process / log artifacts ---

    def scan_network_and_processes(self):
        self.header("[5/6] Scanning for C2 network traces and suspicious processes...")
        self._check_processes()
        self._check_connections()
        self._check_logs()

    def _run_cmd(self, cmd: list, timeout: int = 15) -> str | None:
        """Run a command, return stdout or None on failure."""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout if r.returncode == 0 else None
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

    def _check_processes(self):
        if self.os_type == "Windows":
            out = self._run_cmd(["tasklist", "/FO", "CSV", "/NH"])
            if out and "wt.exe" in out.lower():
                self.warn("Process 'wt.exe' is running (may be Windows Terminal or the RAT -- verify manually)")
            return

        if not shutil.which("pgrep"):
            return

        patterns = {
            "com.apple.act.mond": "com.apple.act.mond",
            "/tmp/ld.py": "/tmp/ld.py",
        }
        for pattern, label in patterns.items():
            out = self._run_cmd(["pgrep", "-f", pattern])
            if out and out.strip():
                self.alert(f"Running process matches RAT: {label}")
                self.record("process", "rat_process", label, "")
                self.artifact_found = True

    def _check_connections(self):
        if self.os_type == "Windows":
            out = self._run_cmd(["netstat", "-n"])
            if out and (C2_IP in out or f":{C2_PORT}" in out):
                self.alert(f"Active connection to C2 {C2_IP}:{C2_PORT} detected (netstat)")
                self.record("network", "c2_connection", f"{C2_IP}:{C2_PORT}", "")
                self.artifact_found = True
            return

        # Linux/macOS: try ss first, then lsof
        if shutil.which("ss"):
            out = self._run_cmd(["ss", "-tnp"])
            if out and (C2_IP in out or f":{C2_PORT}" in out):
                self.alert(f"Active connection to C2 {C2_IP}:{C2_PORT} detected (ss)")
                self.record("network", "c2_connection", f"{C2_IP}:{C2_PORT}", "")
                self.artifact_found = True
        elif shutil.which("lsof"):
            out = self._run_cmd(["lsof", f"-i@{C2_IP}"])
            if out and out.strip():
                self.alert(f"Active connection to C2 IP {C2_IP} detected (lsof)")
                self.record("network", "c2_connection", C2_IP, "")
                self.artifact_found = True

    def _check_logs(self):
        if self.os_type == "Darwin" and shutil.which("log"):
            print("  Checking macOS unified log for C2 traces (this may take a moment)...")
            out = self._run_cmd(
                ["log", "show", "--predicate", "processImagePath contains 'mDNSResponder'", "--last", "48h"],
                timeout=30,
            )
            if out and (C2_DOMAIN in out or C2_IP in out):
                self.alert(f"C2 indicator found in macOS DNS logs ({C2_DOMAIN} or {C2_IP})")
                self.record("network", "c2_dns_log", C2_DOMAIN, "macOS unified log")
                self.artifact_found = True

        elif self.os_type == "Linux":
            for logfile in ("/var/log/syslog", "/var/log/messages", "/var/log/kern.log"):
                if os.path.isfile(logfile) and os.access(logfile, os.R_OK):
                    try:
                        with open(logfile, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        if C2_DOMAIN in content or C2_IP in content:
                            self.alert(f"C2 indicator found in {logfile}")
                            self.record("network", "c2_log_trace", C2_DOMAIN, logfile)
                            self.artifact_found = True
                    except OSError:
                        pass

            if shutil.which("journalctl"):
                out = self._run_cmd(["journalctl", "--since", "48 hours ago", "--no-pager", "-q"], timeout=30)
                if out and (C2_DOMAIN in out or C2_IP in out):
                    self.alert("C2 indicator found in journald logs")
                    self.record("network", "c2_log_trace", C2_DOMAIN, "journald")
                    self.artifact_found = True

        elif self.os_type == "Windows":
            # Check Windows Event Log via PowerShell
            if shutil.which("powershell"):
                out = self._run_cmd([
                    "powershell", "-NoProfile", "-Command",
                    f"Get-WinEvent -LogName Microsoft-Windows-DNS-Client/Operational -MaxEvents 1000 2>$null | "
                    f"Where-Object {{ $_.Message -match '{C2_DOMAIN}' -or $_.Message -match '{C2_IP}' }} | "
                    f"Select-Object -First 1 | Format-List"
                ], timeout=30)
                if out and out.strip():
                    self.alert(f"C2 indicator found in Windows DNS event log")
                    self.record("network", "c2_log_trace", C2_DOMAIN, "Windows Event Log")
                    self.artifact_found = True

        # Check proxy/access logs (Linux/macOS)
        if self.os_type != "Windows":
            for access_log in (
                "/var/log/squid/access.log",
                "/var/log/nginx/access.log",
                "/var/log/apache2/access.log",
                "/var/log/httpd/access_log",
            ):
                if os.path.isfile(access_log) and os.access(access_log, os.R_OK):
                    try:
                        with open(access_log, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        if RAT_USER_AGENT_PATTERN.search(content):
                            self.alert(f"RAT User-Agent signature found in {access_log}")
                            self.record("network", "rat_user_agent", "IE8 fake UA", access_log)
                            self.artifact_found = True
                    except OSError:
                        pass

    # --- Step 6: npm cache ---

    def scan_npm_cache(self):
        self.header("[6/6] Scanning npm cache for compromised packages...")
        cache_dir = self._find_npm_cache()
        if not cache_dir:
            self.warn("npm cache directory not found -- skipping cache check")
            return

        cacache = os.path.join(cache_dir, "_cacache")
        if not os.path.isdir(cacache):
            return

        targets = [MALICIOUS_DEP] + RELATED_PKGS
        # Walk the cacache content-v2 entries
        for root, _dirs, files in os.walk(cacache):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        # Read first 64KB -- enough for metadata entries
                        chunk = f.read(65536)
                except OSError:
                    continue
                for target in targets:
                    if target.encode() in chunk:
                        label = "malicious_package" if target == MALICIOUS_DEP else "related_campaign_package"
                        self.alert(f"'{target}' found in npm cache: {fpath}")
                        self.record("npm_cache", label, target, cacache)
                        self.escalate("INSTALLED")
                        # Don't check same file again for this target
                        break

    def _find_npm_cache(self) -> str | None:
        if shutil.which("npm"):
            out = self._run_cmd(["npm", "config", "get", "cache"])
            if out and out.strip():
                d = out.strip()
                if os.path.isdir(d):
                    return d

        # Fallback to default locations
        home = Path.home()
        if self.os_type == "Windows":
            candidates = [home / "AppData" / "Local" / "npm-cache", home / ".npm"]
        else:
            candidates = [home / ".npm"]

        for c in candidates:
            if c.is_dir():
                return str(c)
        return None

    # --- Run ---

    def run(self) -> int:
        self.artifact_found = False

        print(f"\033[1m=== Axios Supply Chain Scanner (local) ===\033[0m")
        print(f"Scanning: {self.root}")
        print(f"Looking for: axios@{'/'.join(COMPROMISED_VERSIONS)} / {MALICIOUS_DEP}")
        print(f"Also checking: related campaign packages, RAT payloads, C2 traces, npm cache")
        print()

        self.scan_axios_packages()
        self.scan_lockfiles()
        self.scan_malicious_packages()
        self.scan_rat_payloads()
        self.scan_network_and_processes()
        self.scan_npm_cache()

        if self.artifact_found:
            self.escalate("CONFIRMED")

        # --- Summary ---
        print()
        self.header("=== Scan Complete ===")
        count = len(self.findings)
        print(f"Findings: {count} indicator(s) | Severity: \033[1m{self.severity}\033[0m")
        print()

        if self.severity == "CLEAN":
            self.ok("No compromised axios versions or malicious dependencies detected.")
            print()
            print("  \033[1mBest practice:\033[0m pin exact dependency versions in package.json to prevent")
            print("  supply chain attacks from silently upgrading to compromised versions.")
            return 0

        # Write JSON report
        hostname = socket.gethostname().split(".")[0]
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        json_file = f"axios-scan-{hostname}-{timestamp}.json"

        report = {
            "scan_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hostname": hostname,
            "os": self.os_type,
            "scan_root": self.root,
            "severity": self.severity,
            "finding_count": count,
            "findings": self.findings,
        }

        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        # Severity banner
        if self.severity == "LATENT":
            print("\033[1;33m\033[1m" + "=" * 62 + "\033[0m")
            print("\033[1;33m\033[1m SEVERITY: LATENT -- Compromised version in lockfile, not yet installed\033[0m")
            print("\033[1;33m\033[1m" + "=" * 62 + "\033[0m")
            print()
            print("  \033[1mTL;DR:\033[0m The compromised axios version is referenced in your lockfile but has")
            print("  not been installed yet. Clean the lockfile and pin axios to a safe version")
            print("  before running any install command.")

        elif self.severity == "INSTALLED":
            print("\033[0;31m\033[1m" + "=" * 62 + "\033[0m")
            print("\033[0;31m\033[1m SEVERITY: INSTALLED -- Malicious package was installed (infection probable)\033[0m")
            print("\033[0;31m\033[1m" + "=" * 62 + "\033[0m")
            print()
            print("  \033[1mTL;DR:\033[0m The malicious package plain-crypto-js was found in node_modules.")
            print("  The postinstall dropper has likely executed. Treat this as an active infection.")
            print("  \033[0;31mRotate ALL secrets immediately and alert your security team.\033[0m")

        elif self.severity == "CONFIRMED":
            print("\033[0;31m\033[1m" + "=" * 62 + "\033[0m")
            print("\033[0;31m\033[1m SEVERITY: CONFIRMED -- Malware execution artifacts detected\033[0m")
            print("\033[0;31m\033[1m" + "=" * 62 + "\033[0m")
            print()
            print("  \033[1mTL;DR:\033[0m The RAT payload was deployed on this machine. This system is")
            print("  compromised. \033[0;31mRotate ALL secrets NOW and alert your security team immediately.\033[0m")

        print()
        print(f"  \033[1mScan results saved to:\033[0m {os.path.abspath(json_file)}")
        print("  Send this file to your security team for triage.")
        return 1


def default_root() -> str:
    if platform.system() == "Windows":
        return os.environ.get("SYSTEMDRIVE", "C:\\") + "\\"
    return "/"


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else default_root()

    if not os.path.isdir(root):
        print(f"Error: '{root}' is not a directory.", file=sys.stderr)
        sys.exit(2)

    scanner = Scanner(root)
    sys.exit(scanner.run())


if __name__ == "__main__":
    main()
