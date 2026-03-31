#!/usr/bin/env bash
# detect-axios.sh — Scan local filesystem for compromised axios versions
#
# Usage: ./detect-axios.sh [root_path]
#   root_path: directory to scan (default: /)
#
# Detects:
#   - axios@1.14.1 and axios@0.30.4 in lockfiles and installed node_modules
#   - plain-crypto-js dependency (the malicious package)
#   - OS-level execution artifacts (temp dirs, C2 domain traces)

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

COMPROMISED_VERSION="1.14.1"
COMPROMISED_VERSION_0X="0.30.4"
MALICIOUS_DEP="plain-crypto-js"
C2_DOMAIN="sfrclak.com"

ROOT="${1:-/}"
FOUND=0
SEVERITY="CLEAN"  # CLEAN → LATENT → INSTALLED → CONFIRMED

escalate_severity() {
  local new="$1"
  case "$SEVERITY" in
    CLEAN)     SEVERITY="$new" ;;
    LATENT)    [[ "$new" != "LATENT" ]] && SEVERITY="$new" ;;
    INSTALLED) [[ "$new" == "CONFIRMED" ]] && SEVERITY="$new" ;;
  esac
}

log_alert() {
  echo -e "${RED}[ALERT]${RESET} $1"
  FOUND=$((FOUND + 1))
}

log_warn() {
  echo -e "${YELLOW}[WARN]${RESET} $1"
}

log_info() {
  echo -e "${GREEN}[OK]${RESET} $1"
}

echo -e "${BOLD}=== Axios Supply Chain Scanner (local) ===${RESET}"
echo "Scanning: ${ROOT}"
echo "Looking for: axios@${COMPROMISED_VERSION} / axios@${COMPROMISED_VERSION_0X} / ${MALICIOUS_DEP}"
echo ""

# --- 1. Scan installed node_modules/axios/package.json ---
echo -e "${BOLD}[1/4] Scanning installed axios packages in node_modules...${RESET}"

while IFS= read -r pkg_json; do
  version=$(grep -o '"version"\s*:\s*"[^"]*"' "$pkg_json" 2>/dev/null | head -1 | grep -o '[0-9][^"]*' || true)
  if [[ "$version" == "$COMPROMISED_VERSION" || "$version" == "$COMPROMISED_VERSION_0X" ]]; then
    log_alert "Compromised axios@${version} installed at: ${pkg_json}"
    # LATENT, not INSTALLED: the presence of axios itself doesn't mean plain-crypto-js
    # was installed and its postinstall executed. Step 3 checks for that specifically.
    escalate_severity "LATENT"
  fi

  # Check if plain-crypto-js is a dependency
  if grep -q "$MALICIOUS_DEP" "$pkg_json" 2>/dev/null; then
    log_alert "Malicious dependency '${MALICIOUS_DEP}' found in: ${pkg_json}"
    escalate_severity "LATENT"
  fi
done < <(find "$ROOT" \
  \( -fstype proc -o -fstype sysfs -o -fstype devtmpfs -o -fstype devpts \
     -o -fstype tmpfs -o -fstype cgroup -o -fstype cgroup2 \
     -o -fstype fuse -o -fstype fuse.gvfsd-fuse \
     -o -fstype nfs -o -fstype nfs4 -o -fstype cifs \) -prune \
  -o -path '*/node_modules/axios/package.json' \
     -not -path '*/node_modules/*/node_modules/axios/package.json' \
     -print \
  2>/dev/null || true)

# --- 2. Scan lockfiles ---
echo -e "${BOLD}[2/4] Scanning lockfiles...${RESET}"

scan_lockfile() {
  local file="$1"
  local basename
  basename=$(basename "$file")
  local hit=0

  case "$basename" in
    package-lock.json)
      # JSON format: use Python for precise parsing
      if grep -q "axios" "$file" 2>/dev/null; then
        # Exit codes: 0=clean, 1=axios only, 2=malicious dep only, 3=both
        if python3 -c "
import json, sys
file_path, versions, malicious_dep = sys.argv[1], sys.argv[2].split(','), sys.argv[3]
rc = 0
try:
    with open(file_path) as f:
        lock = json.load(f)
    pkgs = lock.get('packages', lock.get('dependencies', {}))
    for key, val in pkgs.items():
        if 'axios' in key and val.get('version') in versions:
            rc |= 1
        if malicious_dep in key:
            rc |= 2
except Exception:
    pass
sys.exit(rc)
" "$file" "${COMPROMISED_VERSION},${COMPROMISED_VERSION_0X}" "$MALICIOUS_DEP" 2>/dev/null; then
          : # clean
        else
          local rc=$?
          if (( rc & 1 )); then
            log_alert "Compromised axios version in lockfile: ${file}"
            hit=1
          fi
          if (( rc & 2 )); then
            log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
            hit=1
          fi
        fi
      fi
      ;;

    yarn.lock)
      if grep -qE "^\"?axios@" "$file" 2>/dev/null; then
        if grep -A5 "^\"*axios@" "$file" 2>/dev/null | grep -qE "version:?\s+\"?(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})\"?"; then
          log_alert "Compromised axios version in lockfile: ${file}"
          hit=1
        fi
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;

    pnpm-lock.yaml)
      # pnpm format: '/axios/1.14.1' or 'axios: 1.14.1'
      if grep -qE "['\"]/axios/(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})['\"]|axios:\s+(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})" "$file" 2>/dev/null; then
        log_alert "Compromised axios version in lockfile: ${file}"
        hit=1
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;

    bun.lock)
      # bun.lock is JSONC — use JSON-aware pattern
      if grep -qE "\"axios\"[^}]*\"(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})\"" "$file" 2>/dev/null; then
        log_alert "Compromised axios version in lockfile: ${file}"
        hit=1
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;

    bun.lockb)
      # bun.lockb is binary — strings are stored separately, not as JSON
      # Check that both "axios" and the compromised version appear in the file
      if grep -qa "axios" "$file" 2>/dev/null && \
         grep -qaE "(${COMPROMISED_VERSION}|${COMPROMISED_VERSION_0X})" "$file" 2>/dev/null; then
        log_alert "Compromised axios version in lockfile: ${file}"
        hit=1
      fi
      if grep -qa "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;
  esac

  if [[ $hit -eq 1 ]]; then
    escalate_severity "LATENT"
  fi

  return $hit
}

while IFS= read -r lockfile; do
  scan_lockfile "$lockfile" || true
done < <(find "$ROOT" \
  \( -fstype proc -o -fstype sysfs -o -fstype devtmpfs -o -fstype devpts \
     -o -fstype tmpfs -o -fstype cgroup -o -fstype cgroup2 \
     -o -fstype fuse -o -fstype fuse.gvfsd-fuse \
     -o -fstype nfs -o -fstype nfs4 -o -fstype cifs \) -prune \
  -o \( -name 'package-lock.json' \
        -o -name 'yarn.lock' \
        -o -name 'pnpm-lock.yaml' \
        -o -name 'bun.lock' \
        -o -name 'bun.lockb' \) \
     -not -path '*/node_modules/*' \
     -print \
  2>/dev/null || true)

# --- 3. Check for malicious package installation ---
echo -e "${BOLD}[3/4] Scanning for '${MALICIOUS_DEP}' installed in node_modules...${RESET}"

while IFS= read -r mal_pkg; do
  log_alert "Malicious package installed: ${mal_pkg}"
  escalate_severity "INSTALLED"
done < <(find "$ROOT" \
  \( -fstype proc -o -fstype sysfs -o -fstype devtmpfs -o -fstype devpts \
     -o -fstype tmpfs -o -fstype cgroup -o -fstype cgroup2 \
     -o -fstype fuse -o -fstype fuse.gvfsd-fuse \
     -o -fstype nfs -o -fstype nfs4 -o -fstype cifs \) -prune \
  -o -path "*node_modules/${MALICIOUS_DEP}/package.json" -print \
  2>/dev/null || true)

# --- 4. Scan for execution artifacts ---
echo -e "${BOLD}[4/4] Scanning for malware execution artifacts...${RESET}"

ARTIFACT_FOUND=false

# Directories to check for dropper artifacts
TEMP_DIRS=("/tmp" "/var/tmp")
[[ -n "${TMPDIR:-}" ]] && TEMP_DIRS+=("$TMPDIR")

# On macOS, also check per-user temp
if [[ "$(uname)" == "Darwin" ]]; then
  user_tmp=$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null || true)
  [[ -n "$user_tmp" ]] && TEMP_DIRS+=("$user_tmp")
fi

# Check temp directories for recently created suspicious files (last 48h)
for tmp_dir in "${TEMP_DIRS[@]}"; do
  [[ -d "$tmp_dir" ]] || continue
  while IFS= read -r suspicious_file; do
    log_alert "Suspicious recent file in temp directory: ${suspicious_file}"
    ARTIFACT_FOUND=true
  done < <(find "$tmp_dir" -maxdepth 2 -type f \
    \( -name "*.sh" -o -name "*.bat" -o -name "*.cmd" -o -name "*.ps1" -o -perm /111 \) \
    -mtime -2 \
    2>/dev/null | grep -iE "crypto|axios|plain|payload|dropper" || true)
done

# Check for C2 domain in DNS cache / logs
if command -v log &>/dev/null && [[ "$(uname)" == "Darwin" ]]; then
  echo "  Checking macOS DNS logs (this may take a moment)..."
  if timeout 30 log show --predicate "processImagePath contains 'mDNSResponder'" --last 48h 2>/dev/null \
    | grep -q "${C2_DOMAIN}" 2>/dev/null; then
    log_alert "C2 domain '${C2_DOMAIN}' found in DNS logs"
    ARTIFACT_FOUND=true
  fi
elif [[ -f /var/log/syslog ]]; then
  if grep -q "${C2_DOMAIN}" /var/log/syslog 2>/dev/null; then
    log_alert "C2 domain '${C2_DOMAIN}' found in syslog"
    ARTIFACT_FOUND=true
  fi
fi

# Check for active/recent network connections to C2
if command -v lsof &>/dev/null; then
  if lsof -i :8000 2>/dev/null | grep -q "${C2_DOMAIN}" 2>/dev/null; then
    log_alert "Active connection to C2 server ${C2_DOMAIN}:8000 detected"
    ARTIFACT_FOUND=true
  fi
fi

if [[ "$ARTIFACT_FOUND" == true ]]; then
  escalate_severity "CONFIRMED"
fi

# --- Summary & Guidance ---
echo ""
echo -e "${BOLD}=== Scan Complete ===${RESET}"
echo -e "Findings: ${FOUND} indicator(s) | Severity: ${BOLD}${SEVERITY}${RESET}"
echo ""

case "$SEVERITY" in
  CLEAN)
    log_info "No compromised axios versions or malicious dependencies detected."
    echo ""
    echo -e " ${BOLD}Best practice:${RESET} pin exact dependency versions in package.json to prevent"
    echo "  supply chain attacks from silently upgrading to compromised versions."
    exit 0
    ;;

  LATENT)
    echo -e "${YELLOW}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${YELLOW}${BOLD} SEVERITY: LATENT — Compromised version in lockfile, not yet installed${RESET}"
    echo -e "${YELLOW}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e " ${BOLD}TL;DR:${RESET} The compromised axios version is referenced in your lockfile but has"
    echo "  not been installed yet. Clean the lockfile and pin axios to a safe version"
    echo "  before running any install command."
    echo ""
    echo -e " ${BOLD}Step-by-step remediation:${RESET}"
    echo ""
    echo "  1. Pin axios to a safe version in package.json (1.14.0 for 1.x, 0.30.3 for 0.x)"
    echo "     → This prevents the compromised version from being resolved on next install."
    echo ""
    echo "  2. Delete the compromised lockfile"
    echo "     → The lockfile pins the malicious version; it must be regenerated clean."
    echo ""
    echo "  3. Delete node_modules/ directory"
    echo "     → Ensures no cached resolution of the compromised dependency tree."
    echo ""
    echo "  4. Run a fresh install (npm install / bun install / yarn / pnpm install)"
    echo "     → Regenerates a clean lockfile with the safe version."
    echo ""
    echo "  5. Verify: search the new lockfile for \"plain-crypto-js\""
    echo "     → It should NOT appear. If it does, the version pin did not take effect."
    echo ""
    echo "  6. Commit the cleaned lockfile."
    echo ""
    echo -e " ${BOLD}Best practice:${RESET} pin exact dependency versions in package.json to prevent"
    echo "  future supply chain attacks from silently upgrading to compromised versions."
    exit 1
    ;;

  INSTALLED)
    echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${RED}${BOLD} SEVERITY: INSTALLED — Malicious package was installed (infection probable)${RESET}"
    echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e " ${BOLD}TL;DR:${RESET} The malicious package plain-crypto-js was found in node_modules."
    echo "  The postinstall dropper has likely executed. Treat this as an active infection."
    echo -e "  ${RED}Rotate ALL secrets immediately and alert your security team.${RESET}"
    echo ""
    echo -e " ${YELLOW}⚠ WARNING:${RESET} The malware deletes its own artifacts after execution."
    echo "  Absence of OS-level traces does NOT mean the system is clean."
    echo ""
    echo -e " ${BOLD}Step-by-step remediation:${RESET}"
    echo ""
    echo "  1. DO NOT delete node_modules yet"
    echo "     → Preserve evidence for forensic analysis if needed."
    echo ""
    echo "  2. Manually inspect temp directories for dropper artifacts:"
    echo "     - macOS/Linux: /tmp, \$TMPDIR, /var/tmp"
    echo "     - Windows: C:\\ProgramData"
    echo "     → Look for recently created executables or scripts you don't recognize."
    echo ""
    echo "  3. Check for network connections to the C2 server:"
    echo "     - Search logs/connections for: ${C2_DOMAIN} or port 8000"
    echo "     → Confirms whether the RAT payload was able to phone home."
    echo ""
    echo "  4. Rotate ALL secrets and credentials accessible from this environment:"
    echo "     - .env files, CI/CD tokens, API keys, SSH keys, cloud credentials"
    echo "     → The RAT had potential access to everything on this machine."
    echo ""
    echo "  5. Alert your security team and the rest of the organization."
    echo "     → Other machines/environments may also be affected."
    echo ""
    echo "  6. Clean the lockfile:"
    echo "     - Pin axios to a safe version (1.14.0 / 0.30.3)"
    echo "     - Delete lockfile and node_modules/, reinstall, verify no plain-crypto-js"
    echo ""
    echo "  7. Consider the machine compromised until proven otherwise."
    echo "     → Audit access logs for services this machine connected to."
    echo ""
    echo -e " ${BOLD}Best practice:${RESET} pin exact dependency versions in package.json to prevent"
    echo "  future supply chain attacks from silently upgrading to compromised versions."
    exit 1
    ;;

  CONFIRMED)
    echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${RED}${BOLD} SEVERITY: CONFIRMED — Malware execution artifacts detected${RESET}"
    echo -e "${RED}${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e " ${BOLD}TL;DR:${RESET} The RAT payload was deployed on this machine. This system is"
    echo -e "  compromised. ${RED}Rotate ALL secrets NOW and alert your security team immediately.${RESET}"
    echo ""
    echo -e " ${BOLD}Step-by-step remediation:${RESET}"
    echo ""
    echo "  1. Disconnect the machine from the network if possible."
    echo "     → Prevents further data exfiltration via the C2 channel."
    echo ""
    echo "  2. DO NOT delete node_modules or artifacts yet."
    echo "     → Preserve all evidence for forensic analysis."
    echo ""
    echo "  3. Rotate ALL secrets and credentials — not just on this machine:"
    echo "     - .env files, CI/CD tokens, API keys, SSH keys, GPG keys, cloud credentials"
    echo "     - Any service this machine had access to (AWS, GCP, GitHub, etc.)"
    echo "     → The RAT had full access to the local environment."
    echo ""
    echo "  4. Alert your security team and the rest of the organization IMMEDIATELY."
    echo "     → This is a confirmed breach, not a potential one."
    echo ""
    echo "  5. Audit recent activity:"
    echo "     - Review git commits made from this machine (the attacker may have had"
    echo "       access to SSH/GPG keys)"
    echo "     - Check access logs of cloud services, CI/CD platforms, internal tools"
    echo "     → Determine the blast radius of the compromise."
    echo ""
    echo "  6. Evaluate a full machine wipe and rebuild."
    echo "     → The safest remediation for a confirmed RAT infection."
    echo ""
    echo "  7. After rebuild: clean the lockfile:"
    echo "     - Pin axios to a safe version (1.14.0 / 0.30.3)"
    echo "     - Delete lockfile and node_modules/, reinstall, verify no plain-crypto-js"
    echo ""
    echo -e " ${BOLD}Best practice:${RESET} pin exact dependency versions in package.json to prevent"
    echo "  future supply chain attacks from silently upgrading to compromised versions."
    exit 1
    ;;
esac
