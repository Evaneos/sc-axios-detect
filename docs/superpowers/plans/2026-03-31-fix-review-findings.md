# Fix Review Findings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all bugs and reliability issues identified in the code review of the two axios detection scripts.

**Architecture:** Two independent shell scripts — no shared code to extract. Each task targets one script and one logical concern. Tasks are ordered by priority (high → low) and grouped by script.

**Tech Stack:** Bash, Python 3 (inline), GitHub CLI (`gh`)

---

## File Structure

- Modify: `locally/detect-axios.sh` — local filesystem scanner
- Modify: `repositories/detect-axios-org.sh` — GitHub org scanner

No new files needed. All changes are fixes/improvements to existing scripts.

---

## Task 1: Fix boolean logic bug in package-lock.json pre-filter (local script — HIGH)

**Files:**
- Modify: `locally/detect-axios.sh:72-102`

The `||`/`&&` chain evaluates as `(A || B) && C` due to bash left-to-right precedence. If `A` is true but `C` is false, the Python check is skipped — causing false negatives. The pre-filter grep is redundant since the Python block does the real verification. Replace the complex boolean with a simple presence check.

- [ ] **Step 1: Simplify the pre-filter grep**

Replace lines 72-102 in `locally/detect-axios.sh` with:

```bash
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
```

This fixes two issues at once:
- **Bug #1:** Replaces the broken `||`/`&&` chain with a simple `grep -q "axios"` pre-filter.
- **Bug #2:** Passes variables as `sys.argv` instead of interpolating them into Python source, eliminating injection risk from filenames with special characters.

- [ ] **Step 2: Test manually with a sample package-lock.json**

Create a temp test file and run:

```bash
mkdir -p /tmp/axios-test
cat > /tmp/axios-test/package-lock.json << 'TESTEOF'
{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/axios": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"
    }
  }
}
TESTEOF

./locally/detect-axios.sh /tmp/axios-test
# Expected: [ALERT] axios@1.14.1 in lockfile: /tmp/axios-test/package-lock.json
echo "Exit code: $?"
# Expected: 1

rm -rf /tmp/axios-test
```

- [ ] **Step 3: Test with a clean package-lock.json (no false positive)**

```bash
mkdir -p /tmp/axios-test
cat > /tmp/axios-test/package-lock.json << 'TESTEOF'
{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/axios": {
      "version": "1.7.9",
      "resolved": "https://registry.npmjs.org/axios/-/axios-1.7.9.tgz"
    }
  }
}
TESTEOF

./locally/detect-axios.sh /tmp/axios-test
# Expected: [OK] No compromised axios versions or malicious dependencies detected.
echo "Exit code: $?"
# Expected: 0

rm -rf /tmp/axios-test
```

- [ ] **Step 4: Commit**

```bash
git add locally/detect-axios.sh
git commit -m "fix(local): fix boolean logic bug in package-lock pre-filter and use sys.argv for Python"
```

---

## Task 2: Tighten detection regex in org script (org script — HIGH)

**Files:**
- Modify: `repositories/detect-axios-org.sh:152`

The regex `axios.*${COMPROMISED_VERSION}` matches `axios-mock-adapter@1.14.1` or any line where `axios` and `1.14.1` appear separated by arbitrary text. This produces false positives at org scale.

- [ ] **Step 1: Replace the loose regex with tighter patterns**

Replace lines 151-159 in `repositories/detect-axios-org.sh` with:

```bash
      local lockfile_basename
      lockfile_basename=$(basename "$lockfile_path")

      local found_axios=false found_dep=false

      case "$lockfile_basename" in
        package-lock.json)
          # JSON: "axios" as key with version value nearby
          if echo "$decoded" | grep -qE '"axios"[^}]*"1\.14\.1"'; then
            found_axios=true
          fi
          ;;
        yarn.lock)
          # yarn: "axios@..." header followed by version line
          if echo "$decoded" | grep -A3 '^"*axios@' | grep -q "version \"${COMPROMISED_VERSION}\""; then
            found_axios=true
          fi
          ;;
        pnpm-lock.yaml)
          # pnpm: /axios/1.14.1 or axios: 1.14.1
          if echo "$decoded" | grep -qE "['\"]/axios/${COMPROMISED_VERSION}['\"]|axios:\s+${COMPROMISED_VERSION}"; then
            found_axios=true
          fi
          ;;
        bun.lock|bun.lockb)
          # bun (JSONC/binary): look for axios with version
          if echo "$decoded" | grep -qaE "\"axios\"[^}]*\"${COMPROMISED_VERSION}\""; then
            found_axios=true
          fi
          ;;
      esac

      # Malicious dep check — simple substring match is fine here, the package name is unique enough
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
```

This makes the detection format-aware, like the local script already is.

- [ ] **Step 2: Commit**

```bash
git add repositories/detect-axios-org.sh
git commit -m "fix(org): use format-specific regex per lockfile type to reduce false positives"
```

---

## Task 3: Cache Git Trees response and avoid double API call (org script — HIGH)

**Files:**
- Modify: `repositories/detect-axios-org.sh:112-139`

Currently, when a file is >1MB and the Contents API returns no content, the script calls the Trees API a second time to get the blob SHA. The SHA was already available in the first Trees call. Caching it eliminates one API call per large lockfile.

- [ ] **Step 1: Capture path and SHA together from the Trees API**

Replace lines 112-139 with:

```bash
    # Use Git Trees API to recursively find all lockfiles and their SHAs
    local tree_data
    tree_data=$(gh api "/repos/${repo}/git/trees/${branch}?recursive=1" \
      --jq '.tree[] | select(.path | test("(package-lock\\.json|yarn\\.lock|pnpm-lock\\.yaml|bun\\.lock|bun\\.lockb)$")) | "\(.sha)\t\(.path)"' \
      2>/dev/null || true)

    if [[ -z "$tree_data" ]]; then
      continue
    fi

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
```

The rest of the loop body stays the same. The `done` line changes to:

```bash
    done <<< "$tree_data"
```

- [ ] **Step 2: Commit**

```bash
git add repositories/detect-axios-org.sh
git commit -m "perf(org): cache tree SHA to avoid duplicate API call for large files"
```

---

## Task 4: Add rate limit awareness (org script — HIGH)

**Files:**
- Modify: `repositories/detect-axios-org.sh` — add rate limit check before scan and warning in output

- [ ] **Step 1: Add rate limit check after auth verification**

Insert after line 55 (after the `gh auth status` check):

```bash
# --- Check API rate limit ---
RATE_REMAINING=$(gh api /rate_limit --jq '.resources.core.remaining' 2>/dev/null || echo "unknown")
RATE_LIMIT=$(gh api /rate_limit --jq '.resources.core.limit' 2>/dev/null || echo "unknown")

if [[ "$RATE_REMAINING" != "unknown" && "$RATE_REMAINING" -lt 500 ]]; then
  echo -e "${YELLOW}[WARN]${RESET} GitHub API rate limit is low: ${RATE_REMAINING}/${RATE_LIMIT} remaining."
  echo -e "${YELLOW}[WARN]${RESET} Large orgs may exhaust the limit. Consider using a PAT with higher limits."
  echo ""
fi
```

- [ ] **Step 2: Add simple retry with backoff in scan_repo**

Add a helper function before `scan_repo()`:

```bash
# Retry a gh api call with exponential backoff on rate limit (HTTP 403/429)
gh_api_retry() {
  local max_retries=3
  local delay=5
  local attempt=0
  local result

  while [[ $attempt -lt $max_retries ]]; do
    if result=$(gh api "$@" 2>&1); then
      echo "$result"
      return 0
    fi

    if echo "$result" | grep -qE "rate limit|API rate|403|429"; then
      attempt=$((attempt + 1))
      echo -e "${YELLOW}[WARN]${RESET} Rate limited, retrying in ${delay}s (attempt ${attempt}/${max_retries})..." >&2
      sleep "$delay"
      delay=$((delay * 2))
    else
      echo "$result"
      return 1
    fi
  done

  echo "$result"
  return 1
}
```

Then update the key API calls inside `scan_repo()` to use `gh_api_retry` instead of `gh api` for the Trees and Contents calls. Specifically, replace:
- `gh api "/repos/${repo}/git/trees/..."` → `gh_api_retry "/repos/${repo}/git/trees/..." `
- `gh api "/repos/${repo}/contents/..."` → `gh_api_retry "/repos/${repo}/contents/..."`
- `gh api "/repos/${repo}/git/blobs/..."` → `gh_api_retry "/repos/${repo}/git/blobs/..."`

Don't forget to add `gh_api_retry` to the `export -f` line:

```bash
export -f scan_repo gh_api_retry
```

- [ ] **Step 3: Commit**

```bash
git add repositories/detect-axios-org.sh
git commit -m "feat(org): add rate limit check and retry with backoff on API throttling"
```

---

## Task 5: Filter archived and forked repos (org script — MEDIUM)

**Files:**
- Modify: `repositories/detect-axios-org.sh:76-77`

Scanning archived repos wastes API calls (no CI risk). Forks duplicate content from upstream.

- [ ] **Step 1: Add jq filter to exclude archived and forked repos**

Replace lines 76-78:

```bash
REPOS=$(gh api --paginate "/orgs/${ORG}/repos" \
  --jq '.[] | select(.archived == false and .fork == false) | .full_name' 2>/dev/null) || \
  REPOS=$(gh api --paginate "/users/${ORG}/repos" \
  --jq '.[] | select(.archived == false and .fork == false) | .full_name' 2>/dev/null) || \
  true
```

- [ ] **Step 2: Add `--include-archived` and `--include-forks` flags**

Add to the arg parser (after the `--parallel` case):

```bash
    --include-archived) INCLUDE_ARCHIVED=true; shift ;;
    --include-forks) INCLUDE_FORKS=true; shift ;;
```

Add defaults near the top (after `BRANCH_MODE="default"`):

```bash
INCLUDE_ARCHIVED=false
INCLUDE_FORKS=false
```

Build the jq filter dynamically:

```bash
JQ_FILTER='.[]'
if [[ "$INCLUDE_ARCHIVED" == false ]]; then
  JQ_FILTER="${JQ_FILTER} | select(.archived == false)"
fi
if [[ "$INCLUDE_FORKS" == false ]]; then
  JQ_FILTER="${JQ_FILTER} | select(.fork == false)"
fi
JQ_FILTER="${JQ_FILTER} | .full_name"

REPOS=$(gh api --paginate "/orgs/${ORG}/repos" --jq "$JQ_FILTER" 2>/dev/null) || \
  REPOS=$(gh api --paginate "/users/${ORG}/repos" --jq "$JQ_FILTER" 2>/dev/null) || \
  true
```

- [ ] **Step 3: Update usage message**

```bash
usage() {
  echo "Usage: $0 <github-org> [--branch default|all] [--parallel <n>] [--include-archived] [--include-forks]"
  exit 1
}
```

- [ ] **Step 4: Export the new vars for subshells**

```bash
export INCLUDE_ARCHIVED INCLUDE_FORKS
```

- [ ] **Step 5: Commit**

```bash
git add repositories/detect-axios-org.sh
git commit -m "feat(org): skip archived and forked repos by default, add opt-in flags"
```

---

## Task 6: Improve yarn.lock detection robustness (local script — MEDIUM)

**Files:**
- Modify: `locally/detect-axios.sh:105-117`

`grep -A2` is fragile — yarn berry and edge cases may have the version line further down.

- [ ] **Step 1: Increase context and anchor the pattern**

Replace lines 105-117:

```bash
    yarn.lock)
      # Yarn classic: "axios@^x.y.z:" followed by "  version "x.y.z"" within 5 lines
      # Yarn berry: "axios@npm:x.y.z:" with "  version: x.y.z" within 5 lines
      if grep -qE "^\"?axios@" "$file" 2>/dev/null; then
        if grep -A5 "^\"*axios@" "$file" 2>/dev/null | grep -qE "version:?\s+\"?${COMPROMISED_VERSION}\"?"; then
          log_alert "axios@${COMPROMISED_VERSION} in lockfile: ${file}"
          hit=1
        fi
      fi
      if grep -q "$MALICIOUS_DEP" "$file" 2>/dev/null; then
        log_alert "'${MALICIOUS_DEP}' in lockfile: ${file}"
        hit=1
      fi
      ;;
```

Changes:
- `-A2` → `-A5` for more context
- Anchored `^` to match only dependency headers (not random mentions)
- Pattern handles both `version "x.y.z"` (classic) and `version: x.y.z` (berry)

- [ ] **Step 2: Commit**

```bash
git add locally/detect-axios.sh
git commit -m "fix(local): improve yarn.lock detection for berry format and edge cases"
```

---

## Task 7: Remove dead code — unused LOCKFILES export (org script — LOW)

**Files:**
- Modify: `repositories/detect-axios-org.sh:195-204`

The `LOCKFILES` array is exported and reconstructed in `scan_repo_wrapper`, but `scan_repo()` never uses it. After Task 3, lockfile filtering is done in the jq query on the Trees API response.

- [ ] **Step 1: Remove the dead code**

Remove lines 195 and the `scan_repo_wrapper` function. Replace with a direct call.

Remove:
```bash
export LOCKFILES_STR="${LOCKFILES[*]}"

# Re-export LOCKFILES inside the function (bash can't export arrays)
# Wrap scan_repo to reconstruct the array
scan_repo_wrapper() {
  IFS=' ' read -ra LOCKFILES <<< "$LOCKFILES_STR"
  export LOCKFILES
  scan_repo "$1"
}
export -f scan_repo_wrapper
```

Replace line 210:
```bash
echo "$REPOS" | xargs -P "$PARALLEL" -I {} bash -c 'scan_repo "$@"' _ {}
```

Also remove the `LOCKFILES` array declaration at line 22 if nothing else references it. Keep it only if it's used as documentation or in comments.

- [ ] **Step 2: Verify no other references to LOCKFILES**

```bash
grep -n "LOCKFILES" repositories/detect-axios-org.sh
# Expected: only the array declaration (line 22), which can remain as documentation or be removed
```

- [ ] **Step 3: Commit**

```bash
git add repositories/detect-axios-org.sh
git commit -m "chore(org): remove unused LOCKFILES export and wrapper function"
```

---

## Task 8: Write decoded content to temp file instead of shell variable (org script — MEDIUM)

**Files:**
- Modify: `repositories/detect-axios-org.sh` — inside `scan_repo()`, write decoded content to a temp file

For large `package-lock.json` files (5-20MB is common), holding the full content in a bash variable and piping via `echo` is memory-intensive, especially with 10 parallel workers.

- [ ] **Step 1: Use a temp file for decoded content**

Inside `scan_repo()`, after the `decoded=` assignment and fallback block, replace the pattern of `echo "$decoded" | grep` with file-based operations.

Replace the decoded variable usage with:

```bash
      local tmpfile="${TMPDIR}/decoded_$$_${RANDOM}"

      # Download via Contents API
      gh api "/repos/${repo}/contents/${lockfile_path}?ref=${branch}" \
        --jq '.content // empty' 2>/dev/null | base64 -d > "$tmpfile" 2>/dev/null || true

      # Fallback for large files
      if [[ ! -s "$tmpfile" && -n "$blob_sha" ]]; then
        gh api "/repos/${repo}/git/blobs/${blob_sha}" \
          --jq '.content // empty' 2>/dev/null | base64 -d > "$tmpfile" 2>/dev/null || true
      fi

      if [[ ! -s "$tmpfile" ]]; then
        scanned_lockfiles+=("${lockfile_path}@${branch}: download failed")
        has_any_lockfile=true
        rm -f "$tmpfile"
        continue
      fi

      has_any_lockfile=true
      local file_status="clean"
```

Then replace all `echo "$decoded" | grep` with `grep ... "$tmpfile"`:

```bash
      # (example for the tightened regex from Task 2)
      if grep -qE '"axios"[^}]*"1\.14\.1"' "$tmpfile" 2>/dev/null; then
        found_axios=true
      fi

      if grep -q "${MALICIOUS_DEP}" "$tmpfile" 2>/dev/null; then
        found_dep=true
      fi
```

And for the "does it contain axios at all" check:

```bash
      if [[ "$file_status" == "clean" ]]; then
        if grep -q "axios" "$tmpfile" 2>/dev/null; then
          scanned_lockfiles+=("${lockfile_path}: axios OK")
        else
          scanned_lockfiles+=("${lockfile_path}: no axios")
        fi
      fi

      rm -f "$tmpfile"
```

- [ ] **Step 2: Commit**

```bash
git add repositories/detect-axios-org.sh
git commit -m "perf(org): write decoded lockfile to temp file instead of shell variable"
```

---

## Summary of tasks by priority

| Task | Script | Priority | Description |
|------|--------|----------|-------------|
| 1 | local | HIGH | Fix boolean logic bug + Python injection |
| 2 | org | HIGH | Format-specific regex to reduce false positives |
| 3 | org | HIGH | Cache tree SHA, avoid double API call |
| 4 | org | HIGH | Rate limit check + retry with backoff |
| 5 | org | MEDIUM | Filter archived/forked repos |
| 6 | local | MEDIUM | Improve yarn.lock detection |
| 7 | org | LOW | Remove dead LOCKFILES code |
| 8 | org | MEDIUM | Use temp files for large lockfile content |

**Note:** Tasks 2, 3, 7, and 8 all modify `scan_repo()` in the org script. They should be applied in order (2 → 3 → 8 → 7) to avoid merge conflicts. Task 4 adds code before `scan_repo()` so it's independent. Tasks 1 and 6 modify the local script and are fully independent.
