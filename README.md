# axios-detect

Detection scripts for the [axios supply chain attack](https://socket.dev/blog/axios-npm-package-compromised) targeting `axios@1.14.1` and `axios@0.30.4` which pull in `plain-crypto-js@4.2.1`, a confirmed malicious package.

**Pre-built binaries** (no Python or dependencies needed):

Download from the [latest release](https://github.com/Evaneos/sc-axios-detect/releases/latest), then run:

```bash
# Linux
chmod +x detect-axios-linux-amd64
./detect-axios-linux-amd64

# macOS (Apple Silicon)
chmod +x detect-axios-darwin-arm64
./detect-axios-darwin-arm64

# macOS (Intel)
chmod +x detect-axios-darwin-amd64
./detect-axios-darwin-amd64

# Windows
detect-axios-windows-amd64.exe
```

**From source**:

```bash
# Linux / macOS
./locally/detect-axios.sh # No Python 3

# Any platform (Linux, macOS, Windows)
python3 locally/detect-axios.py # Requires Python 3, no other dependencies
```

This scans your entire machine. No arguments needed.

## What it detects

- `axios@1.14.1` and `axios@0.30.4` referenced in any lockfile or installed in `node_modules`
- `plain-crypto-js` dependency (the malicious dropper package)
- Related campaign packages (`@shadanai/openclaw`, `@qqbrowser/openclaw-qbot`)
- RAT payload files at known paths (persist after the malware's self-cleanup)
- Running RAT processes and active C2 connections (`sfrclak.com` / `142.11.206.73`)
- C2 traces in system logs, DNS cache, and proxy logs
- Malicious tarballs in the npm cache

Supported lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`

## Scripts

### Local filesystem scan (bash)

Scans a directory tree for installed `node_modules`, lockfiles, and OS-level execution artifacts.

Requires: `find`, `grep` (mandatory); `python3`, `pgrep`, `ss`/`lsof`, `journalctl`, `npm` (optional -- the script checks for these at startup and skips checks that need missing tools).

```bash
# Scan a specific project directory
./locally/detect-axios.sh ~/projects/my-app

# Scan the entire disk
./locally/detect-axios.sh /
```

### Local filesystem scan (Python -- cross-platform)

Same detection as the bash version, but runs on Linux, macOS, and Windows. Zero external dependencies -- Python 3 standard library only.

```bash
# Scan the entire machine (default)
python3 locally/detect-axios.py

# Scan a specific directory
python3 locally/detect-axios.py ~/projects/my-app

# Windows
python locally\detect-axios.py
python locally\detect-axios.py C:\Users\me\projects
```

If any compromise indicators are found, the script writes a JSON report to the current directory with a unique filename (e.g. `axios-scan-myhostname-20260331-120000.json`). No JSON file is produced if the scan is clean.

#### Severity levels

| Level | Meaning |
|-------|---------|
| **CLEAN** | No indicators found |
| **LATENT** | Compromised version in lockfile, not yet installed |
| **INSTALLED** | Malicious package found in `node_modules` or npm cache -- infection probable |
| **CONFIRMED** | RAT payload, C2 connection, or execution artifacts detected |

### GitHub organization scan

Scans all repositories in a GitHub organization (or user account) via the API. Searches recursively through the full file tree -- lockfiles in subdirectories are found too.

Requires: [GitHub CLI](https://cli.github.com/) (`gh`) authenticated.

```bash
# Scan an org (default branch, 10 parallel workers)
./repositories/detect-axios-org.sh my-org

# Scan all branches, 20 parallel workers
./repositories/detect-axios-org.sh my-org --branch all --parallel 20

# Include archived repos and forks (excluded by default)
./repositories/detect-axios-org.sh my-org --include-archived --include-forks
```

## Exit codes

- `0` -- no compromise detected
- `1` -- at least one indicator found
- `2` -- missing required dependencies (local scanner only)

## JSON report format

When compromise indicators are found, the local scanner writes a JSON file:

```json
{
  "scan_date": "2026-03-31T09:37:40Z",
  "hostname": "myhostname",
  "os": "Linux",
  "scan_root": "/home/user/projects",
  "severity": "LATENT",
  "finding_count": 2,
  "findings": [
    {
      "category": "lockfile",
      "type": "compromised_axios",
      "detail": "axios",
      "path": "/home/user/projects/package-lock.json"
    },
    {
      "category": "lockfile",
      "type": "malicious_dependency",
      "detail": "plain-crypto-js",
      "path": "/home/user/projects/package-lock.json"
    }
  ]
}
```

Send this file to your security team for triage.
