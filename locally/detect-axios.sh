#!/usr/bin/env bash
# detect-axios.sh — Scan local filesystem for compromised axios versions
#
# Usage: ./detect-axios.sh [root_path]
#   root_path: directory to scan (default: /)
#
# Detects:
#   - axios@1.14.1 in lockfiles and installed node_modules
#   - plain-crypto-js dependency (the malicious package)

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

COMPROMISED_VERSION="1.14.1"
MALICIOUS_DEP="plain-crypto-js"

ROOT="${1:-/}"
FOUND=0

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
echo "Looking for: axios@${COMPROMISED_VERSION} / ${MALICIOUS_DEP}"
echo ""

# --- 1. Scan installed node_modules/axios/package.json ---
echo -e "${BOLD}[1/3] Scanning installed axios packages in node_modules...${RESET}"

while IFS= read -r pkg_json; do
  version=$(grep -o '"version"\s*:\s*"[^"]*"' "$pkg_json" 2>/dev/null | head -1 | grep -o '[0-9][^"]*' || true)
  if [[ "$version" == "$COMPROMISED_VERSION" ]]; then
    log_alert "Compromised axios@${version} installed at: ${pkg_json}"
  fi

  # Check if plain-crypto-js is a dependency
  if grep -q "$MALICIOUS_DEP" "$pkg_json" 2>/dev/null; then
    log_alert "Malicious dependency '${MALICIOUS_DEP}' found in: ${pkg_json}"
  fi
done < <(find "$ROOT" \
  -path '*/node_modules/axios/package.json' \
  -not -path '*/node_modules/*/node_modules/axios/package.json' \
  2>/dev/null || true)

# --- 2. Scan lockfiles ---
echo -e "${BOLD}[2/3] Scanning lockfiles...${RESET}"

scan_lockfile() {
  local file="$1"
  local basename
  basename=$(basename "$file")
  local hit=0

  case "$basename" in
    package-lock.json)
      # JSON format: use Python for precise parsing
      if grep -q "axios" "$file" 2>/dev/null; then
        if python3 -c "
import json, sys
file_path, target_version, malicious_dep = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(file_path) as f:
        lock = json.load(f)
    pkgs = lock.get('packages', lock.get('dependencies', {}))
    for key, val in pkgs.items():
        if 'axios' in key and val.get('version') == target_version:
            sys.exit(1)
        if malicious_dep in key:
            sys.exit(2)
except Exception:
    pass
sys.exit(0)
" "$file" "$COMPROMISED_VERSION" "$MALICIOUS_DEP" 2>/dev/null; then
          : # clean
        else
          local rc=$?
          if [[ $rc -eq 1 ]]; then
            log_alert "axios@${COMPROMISED_VERSION} in lockfile: ${file}"
            hit=1
          elif [[ $rc -eq 2 ]]; then
            log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
            hit=1
          fi
        fi
      fi
      ;;

    yarn.lock)
      # Yarn classic & berry format
      if grep -qE "axios@.*:" "$file" 2>/dev/null; then
        if grep -A2 "axios@" "$file" 2>/dev/null | grep -q "version \"${COMPROMISED_VERSION}\""; then
          log_alert "axios@${COMPROMISED_VERSION} in lockfile: ${file}"
          hit=1
        fi
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;

    pnpm-lock.yaml)
      if grep -qE "axios.*${COMPROMISED_VERSION}" "$file" 2>/dev/null; then
        log_alert "axios@${COMPROMISED_VERSION} in lockfile: ${file}"
        hit=1
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;

    bun.lock|bun.lockb)
      # bun.lock is JSONC, bun.lockb is binary — grep both
      if grep -qaE "axios.*${COMPROMISED_VERSION}" "$file" 2>/dev/null; then
        log_alert "axios@${COMPROMISED_VERSION} in lockfile: ${file}"
        hit=1
      fi
      if grep -qa "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;
  esac

  return $hit
}

while IFS= read -r lockfile; do
  scan_lockfile "$lockfile" || true
done < <(find "$ROOT" \
  \( -name 'package-lock.json' \
     -o -name 'yarn.lock' \
     -o -name 'pnpm-lock.yaml' \
     -o -name 'bun.lock' \
     -o -name 'bun.lockb' \) \
  -not -path '*/node_modules/*' \
  2>/dev/null || true)

# --- 3. Quick check for the malicious package installed anywhere ---
echo -e "${BOLD}[3/3] Scanning for '${MALICIOUS_DEP}' installed anywhere...${RESET}"

while IFS= read -r mal_pkg; do
  log_alert "Malicious package installed: ${mal_pkg}"
done < <(find "$ROOT" \
  -path "*node_modules/${MALICIOUS_DEP}/package.json" \
  2>/dev/null || true)

# --- Summary ---
echo ""
echo -e "${BOLD}=== Scan Complete ===${RESET}"
if [[ $FOUND -gt 0 ]]; then
  echo -e "${RED}${BOLD}Found ${FOUND} potential compromise indicator(s).${RESET}"
  echo -e "${RED}Action required: pin axios to a safe version and run a clean install.${RESET}"
  exit 1
else
  log_info "No compromised axios versions or malicious dependencies detected."
  exit 0
fi
