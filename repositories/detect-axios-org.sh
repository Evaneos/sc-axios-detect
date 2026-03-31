#!/usr/bin/env bash
# detect-axios-org.sh — Scan all repos in a GitHub org for compromised axios in lockfiles
#
# Usage: ./detect-axios-org.sh <org> [--branch <default|all>] [--parallel <n>]
#
# Requires: gh CLI (authenticated)
#
# Scans package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock in every repo
# of the given GitHub organization, looking for axios@1.14.1 or plain-crypto-js.

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

COMPROMISED_VERSION="1.14.1"
MALICIOUS_DEP="plain-crypto-js"
LOCKFILES=("package-lock.json" "yarn.lock" "pnpm-lock.yaml" "bun.lock" "bun.lockb")

PARALLEL=10
BRANCH_MODE="default"  # "default" = default branch only, "all" = all branches
ORG=""

# --- Parse args ---
usage() {
  echo "Usage: $0 <github-org> [--branch default|all] [--parallel <n>]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch) BRANCH_MODE="$2"; shift 2 ;;
    --parallel) PARALLEL="$2"; shift 2 ;;
    --help|-h) usage ;;
    -*) echo "Unknown option: $1"; usage ;;
    *) ORG="$1"; shift ;;
  esac
done

[[ -z "$ORG" ]] && usage

# --- Verify gh CLI ---
if ! command -v gh &>/dev/null; then
  echo -e "${RED}Error: 'gh' CLI is required. Install from https://cli.github.com${RESET}"
  exit 1
fi

if ! gh auth status &>/dev/null; then
  echo -e "${RED}Error: 'gh' is not authenticated. Run 'gh auth login' first.${RESET}"
  exit 1
fi

TMPDIR=$(mktemp -d)
RESULTS_FILE="${TMPDIR}/results.log"
PROGRESS_FILE="${TMPDIR}/progress.log"
touch "$RESULTS_FILE" "$PROGRESS_FILE"

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

echo -e "${BOLD}=== Axios Supply Chain Scanner (GitHub Org) ===${RESET}"
echo "Organization: ${ORG}"
echo "Parallelism:  ${PARALLEL}"
echo "Branch mode:  ${BRANCH_MODE}"
echo "Looking for:  axios@${COMPROMISED_VERSION} / ${MALICIOUS_DEP}"
echo ""

# --- List all repos ---
echo -e "${BOLD}Fetching repository list...${RESET}"

# Try org endpoint first, fall back to user endpoint
REPOS=$(gh api --paginate "/orgs/${ORG}/repos" --jq '.[].full_name' 2>/dev/null) || \
  REPOS=$(gh api --paginate "/users/${ORG}/repos" --jq '.[].full_name' 2>/dev/null) || \
  true

# Filter out any empty lines
REPOS=$(echo "$REPOS" | sed '/^$/d')

if [[ -z "$REPOS" ]]; then
  echo -e "${RED}No repositories found for '${ORG}'. Check the org/user name and your permissions.${RESET}"
  exit 1
fi

REPO_COUNT=$(echo "$REPOS" | wc -l | tr -d ' ')
echo -e "Found ${BOLD}${REPO_COUNT}${RESET} repositories."
echo ""

# --- Scan function for a single repo ---
scan_repo() {
  local repo="$1"
  local repo_short="${repo#*/}"
  local branches=()

  if [[ "$BRANCH_MODE" == "all" ]]; then
    while IFS= read -r b; do
      [[ -n "$b" ]] && branches+=("$b")
    done < <(gh api --paginate "/repos/${repo}/branches" --jq '.[].name' 2>/dev/null || true)
  else
    local default_branch
    default_branch=$(gh api "/repos/${repo}" --jq '.default_branch' 2>/dev/null || echo "main")
    branches=("$default_branch")
  fi

  local scanned_lockfiles=()
  local has_any_lockfile=false

  for branch in "${branches[@]}"; do
    # Use Git Trees API to recursively find all lockfiles and their SHAs
    local tree_data
    tree_data=$(gh api "/repos/${repo}/git/trees/${branch}?recursive=1" \
      --jq '.tree[] | select(.path | test("(package-lock\\.json|yarn\\.lock|pnpm-lock\\.yaml|bun\\.lock|bun\\.lockb)$")) | "\(.sha)\t\(.path)"' \
      2>/dev/null || true)

    if [[ -z "$tree_data" ]]; then
      continue
    fi

    local blob_sha lockfile_path
    while IFS=$'\t' read -r blob_sha lockfile_path; do
      [[ -z "$lockfile_path" ]] && continue

      # Download via Contents API (handles auth for private repos)
      local decoded
      decoded=$(gh api "/repos/${repo}/contents/${lockfile_path}?ref=${branch}" \
        --jq '.content // empty' 2>/dev/null | base64 -d 2>/dev/null || true)

      # Fallback: for large files (>1MB), content is null — use the cached Blob SHA
      if [[ -z "$decoded" && -n "$blob_sha" ]]; then
        decoded=$(gh api "/repos/${repo}/git/blobs/${blob_sha}" \
          --jq '.content // empty' 2>/dev/null | base64 -d 2>/dev/null || true)
      fi

      if [[ -z "$decoded" ]]; then
        scanned_lockfiles+=("${lockfile_path}@${branch}: download failed")
        has_any_lockfile=true
        continue
      fi

      has_any_lockfile=true
      local file_status="clean"

      local lockfile_basename
      lockfile_basename=$(basename "$lockfile_path")

      local found_axios=false found_dep=false

      case "$lockfile_basename" in
        package-lock.json)
          if echo "$decoded" | grep -qE "\"axios\"[^}]*\"${COMPROMISED_VERSION}\""; then
            found_axios=true
          fi
          ;;
        yarn.lock)
          if echo "$decoded" | grep -A3 '^"*axios@' | grep -q "version \"${COMPROMISED_VERSION}\""; then
            found_axios=true
          fi
          ;;
        pnpm-lock.yaml)
          if echo "$decoded" | grep -qE "['\"]/axios/${COMPROMISED_VERSION}['\"]|axios:\s+${COMPROMISED_VERSION}"; then
            found_axios=true
          fi
          ;;
        bun.lock|bun.lockb)
          if echo "$decoded" | grep -qaE "\"axios\"[^}]*\"${COMPROMISED_VERSION}\""; then
            found_axios=true
          fi
          ;;
      esac

      # Malicious dep check — simple substring match is fine, the package name is unique enough
      if echo "$decoded" | grep -q "${MALICIOUS_DEP}"; then
        found_dep=true
      fi

      if [[ "$found_axios" == true ]]; then
        echo -e "${RED}[ALERT]${RESET} axios@${COMPROMISED_VERSION} in ${BOLD}${repo}${RESET} @ ${branch} — ${lockfile_path}" | tee -a "$RESULTS_FILE"
        file_status="COMPROMISED"
      fi

      if [[ "$found_dep" == true ]]; then
        echo -e "${RED}[ALERT]${RESET} ${MALICIOUS_DEP} in ${BOLD}${repo}${RESET} @ ${branch} — ${lockfile_path}" | tee -a "$RESULTS_FILE"
        file_status="COMPROMISED"
      fi

      # Report what we found
      if [[ "$file_status" == "clean" ]]; then
        if echo "$decoded" | grep -q "axios"; then
          scanned_lockfiles+=("${lockfile_path}: axios OK")
        else
          scanned_lockfiles+=("${lockfile_path}: no axios")
        fi
      else
        scanned_lockfiles+=("${lockfile_path}: ${file_status}")
      fi
    done <<< "$tree_data"
  done

  echo "${repo}" >> "$PROGRESS_FILE"
  local done_count
  done_count=$(wc -l < "$PROGRESS_FILE" | tr -d ' ')

  # Build detail line
  local detail=""
  if [[ "$has_any_lockfile" == false ]]; then
    detail="${DIM}no lockfiles${RESET}"
  else
    detail=$(IFS=', '; echo "${scanned_lockfiles[*]}")
  fi

  echo -e "[${done_count}/${REPO_COUNT}] ${BOLD}${repo_short}${RESET} — ${detail}" >&2
}

export -f scan_repo
export RED YELLOW GREEN BOLD DIM RESET
export COMPROMISED_VERSION MALICIOUS_DEP BRANCH_MODE REPO_COUNT
export RESULTS_FILE PROGRESS_FILE
export LOCKFILES_STR="${LOCKFILES[*]}"

# Re-export LOCKFILES inside the function (bash can't export arrays)
# Wrap scan_repo to reconstruct the array
scan_repo_wrapper() {
  IFS=' ' read -ra LOCKFILES <<< "$LOCKFILES_STR"
  export LOCKFILES
  scan_repo "$1"
}
export -f scan_repo_wrapper

# --- Run in parallel ---
echo -e "${BOLD}Scanning repositories (${PARALLEL} parallel workers)...${RESET}"
echo ""

echo "$REPOS" | xargs -P "$PARALLEL" -I {} bash -c 'scan_repo_wrapper "$@"' _ {}

# --- Summary ---
echo ""
echo -e "${BOLD}=== Scan Complete ===${RESET}"

ALERT_COUNT=$(wc -l < "$RESULTS_FILE" | tr -d ' ')
if [[ $ALERT_COUNT -gt 0 ]]; then
  echo -e "${RED}${BOLD}Found ${ALERT_COUNT} alert(s) across the organization.${RESET}"
  echo ""
  echo -e "${BOLD}Details:${RESET}"
  cat "$RESULTS_FILE"
  exit 1
else
  echo -e "${GREEN}[OK]${RESET} No compromised axios versions or malicious dependencies detected in ${ORG}."
  exit 0
fi
