# axios-detect

Detection scripts for the [axios supply chain attack](https://socket.dev/blog/axios-npm-package-compromised) targeting `axios@1.14.1` and `axios@0.30.4` which pull in `plain-crypto-js@4.2.1`, a confirmed malicious package.

## What it detects

- `axios@1.14.1` and `axios@0.30.4` referenced in any lockfile
- `plain-crypto-js` dependency (the malicious dropper)
- OS-level execution artifacts (local scanner only)

Supported lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`

## Scripts

### Local filesystem scan

Scans a directory tree for installed `node_modules` and lockfiles.

```bash
# Scan a specific directory
./locally/detect-axios.sh ~/projects

# Scan the entire disk
./locally/detect-axios.sh /
```

### GitHub organization scan

Scans all repositories in a GitHub organization (or user account) via the API. Searches recursively through the full file tree — lockfiles in subdirectories are found too.

Requires: [GitHub CLI](https://cli.github.com/) (`gh`) authenticated.

```bash
# Scan an org (default branch, 10 parallel workers)
./repositories/detect-axios-org.sh my-org

# Scan all branches, 20 parallel workers
./repositories/detect-axios-org.sh my-org --branch all --parallel 20
```

## Exit codes

- `0` — no compromise detected
- `1` — at least one indicator found
