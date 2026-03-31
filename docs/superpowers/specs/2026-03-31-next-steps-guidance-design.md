# Next-Steps Guidance for axios-detect Scripts

**Date:** 2026-03-31
**Status:** Draft

## Context

Both detection scripts currently output minimal information when compromised versions are found ("Found N indicators. Action required: pin axios."). Users need actionable, step-by-step remediation guidance tailored to what was detected and which script they ran.

## Design

### Local Script (`locally/detect-axios.sh`)

#### Severity Levels

The script determines a severity level based on what it found during the scan. The highest level wins.

| Level | Condition | Meaning |
|-------|-----------|---------|
| **LATENT** | Lockfile references `axios@1.14.1` or `axios@0.30.4`, but `node_modules/plain-crypto-js/` not found | Compromised version in lockfile, not yet installed. Next `install` will activate it. |
| **INSTALLED** | `node_modules/plain-crypto-js/` is present, no OS-level artifacts found | The postinstall script has likely executed. Absence of artifacts does NOT mean absence of infection — the malware self-deletes after execution. |
| **CONFIRMED** | OS-level artifacts or C2 traces detected | Infection confirmed. The RAT payload was deployed. |

#### Artifact Detection (new step, replaces current step 3)

The current step 3 ("Scanning for plain-crypto-js installed anywhere") is expanded to also search for OS-level artifacts left by the dropper:

**Automatic checks:**
- `node_modules/plain-crypto-js/` presence (existing)
- Files in temp directories: `$TMPDIR`, `/tmp`, `/var/tmp` matching known dropper patterns
- On macOS/Linux: search for recently created suspicious executables in temp dirs
- On Windows (if running under WSL/Git Bash): check `ProgramData` directories
- Network traces: grep system logs or connection records for the C2 domain `sfrclak.com` (port 8000)

**Implementation:** This becomes step 3 "Scanning for malware installation" and step 4 "Scanning for execution artifacts". The step count goes from 3 to 4.

#### Guidance Output by Level

Each level outputs two blocks:

1. **TL;DR** — 2-3 lines, imperative, immediate actions
2. **Step-by-step** — numbered, with a "why" explanation for each step

##### LATENT

```
══════════════════════════════════════════════════════════════
 SEVERITY: LATENT — Compromised version in lockfile, not yet installed
══════════════════════════════════════════════════════════════

 TL;DR: The compromised axios version is referenced in your lockfile but has
 not been installed yet. Clean the lockfile and pin axios to a safe version
 before running any install command.

 Step-by-step remediation:

  1. Pin axios to a safe version in package.json (1.14.0 for 1.x, 0.30.3 for 0.x)
     → This prevents the compromised version from being resolved on next install.

  2. Delete the compromised lockfile
     → The lockfile pins the malicious version; it must be regenerated clean.

  3. Delete node_modules/ directory
     → Ensures no cached resolution of the compromised dependency tree.

  4. Run a fresh install (npm install / bun install / yarn / pnpm install)
     → Regenerates a clean lockfile with the safe version.

  5. Verify: search the new lockfile for "plain-crypto-js"
     → It should NOT appear. If it does, the version pin did not take effect.

  6. Commit the cleaned lockfile.

 Best practice: pin exact dependency versions in package.json to prevent
 future supply chain attacks from silently upgrading to compromised versions.
```

##### INSTALLED

```
══════════════════════════════════════════════════════════════
 SEVERITY: INSTALLED — Malicious package was installed (infection probable)
══════════════════════════════════════════════════════════════

 TL;DR: The malicious package plain-crypto-js was found in node_modules.
 The postinstall dropper has likely executed. Treat this as an active infection.
 Rotate ALL secrets immediately and alert your security team.

 ⚠ WARNING: The malware deletes its own artifacts after execution.
 Absence of OS-level traces does NOT mean the system is clean.

 Step-by-step remediation:

  1. DO NOT delete node_modules yet
     → Preserve evidence for forensic analysis if needed.

  2. Manually inspect temp directories for dropper artifacts:
     - macOS/Linux: /tmp, $TMPDIR, /var/tmp
     - Windows: C:\ProgramData
     → Look for recently created executables or scripts you don't recognize.

  3. Check for network connections to the C2 server:
     - Search logs/connections for: sfrclak.com or port 8000
     → Confirms whether the RAT payload was able to phone home.

  4. Rotate ALL secrets and credentials accessible from this environment:
     - .env files, CI/CD tokens, API keys, SSH keys, cloud credentials
     → The RAT had potential access to everything on this machine.

  5. Alert your security team and the rest of the organization.
     → Other machines/environments may also be affected.

  6. Clean the lockfile (same steps as LATENT level above).

  7. Consider the machine compromised until proven otherwise.
     → Audit access logs for services this machine connected to.

 Best practice: pin exact dependency versions in package.json to prevent
 future supply chain attacks from silently upgrading to compromised versions.
```

##### CONFIRMED

```
══════════════════════════════════════════════════════════════
 SEVERITY: CONFIRMED — Malware execution artifacts detected
══════════════════════════════════════════════════════════════

 TL;DR: The RAT payload was deployed on this machine. This system is
 compromised. Rotate ALL secrets NOW and alert your security team immediately.

 Step-by-step remediation:

  1. Disconnect the machine from the network if possible.
     → Prevents further data exfiltration via the C2 channel.

  2. DO NOT delete node_modules or artifacts yet.
     → Preserve all evidence for forensic analysis.

  3. Rotate ALL secrets and credentials — not just on this machine:
     - .env files, CI/CD tokens, API keys, SSH keys, GPG keys, cloud credentials
     - Any service this machine had access to (AWS, GCP, GitHub, etc.)
     → The RAT had full access to the local environment.

  4. Alert your security team and the rest of the organization IMMEDIATELY.
     → This is a confirmed breach, not a potential one.

  5. Audit recent activity:
     - Review git commits made from this machine (the attacker may have had
       access to SSH/GPG keys)
     - Check access logs of cloud services, CI/CD platforms, internal tools
     → Determine the blast radius of the compromise.

  6. Evaluate a full machine wipe and rebuild.
     → The safest remediation for a confirmed RAT infection.

  7. After rebuild: clean the lockfile (same steps as LATENT level above).

 Best practice: pin exact dependency versions in package.json to prevent
 future supply chain attacks from silently upgrading to compromised versions.
```

#### Clean Scan Output

When no compromise is detected, the existing message is kept with an added best-practice note:

```
[OK] No compromised axios versions or malicious dependencies detected.

 Best practice: pin exact dependency versions in package.json to prevent
 supply chain attacks from silently upgrading to compromised versions.
```

### GitHub Script (`repositories/detect-axios-org.sh`)

The GitHub script has no filesystem access, so no artifact detection is possible. Guidance focuses on code remediation and directing users to verify local environments.

#### When Alerts Are Found

After the details listing, display:

```
══════════════════════════════════════════════════════════════
 NEXT STEPS
══════════════════════════════════════════════════════════════

 TL;DR: Compromised lockfile(s) detected. Remediate the code and verify
 all environments where these repositories were cloned or deployed.

 Code remediation (for each affected repo):

  1. Pin axios to a safe version in package.json (1.14.0 for 1.x, 0.30.3 for 0.x)
  2. Delete the compromised lockfile and node_modules/
  3. Run a fresh install to regenerate a clean lockfile
  4. Verify "plain-crypto-js" does NOT appear in the new lockfile
  5. Commit and push the fix

 Environment verification:

  6. Run the local scanner on every dev machine that cloned the affected repo(s):
     ./locally/detect-axios.sh /path/to/repo

  7. Check CI/CD: if a pipeline ran "install" with the compromised lockfile,
     the runner may have been infected. Review CI logs and rotate CI secrets.

  8. Check staging/production: if a deployment occurred with this version,
     those environments need investigation. Rotate deployed secrets.

  9. If the local scanner reports INSTALLED or CONFIRMED severity:
     rotate ALL secrets accessible from the affected environments and
     alert your security team.

 The malicious versions have been removed from npm, but any lockfile still
 referencing them will reinstall the compromised version.

 Best practice: pin exact dependency versions in package.json to prevent
 future supply chain attacks from silently upgrading to compromised versions.
```

#### Clean Scan Output

```
[OK] No compromised axios versions or malicious dependencies detected in <org>.

 Best practice: pin exact dependency versions in package.json to prevent
 supply chain attacks from silently upgrading to compromised versions.
```

## Implementation Notes

### Local Script Changes

1. Track severity state with variables: `SEVERITY="CLEAN"`, escalate to `LATENT`, `INSTALLED`, `CONFIRMED` as findings are made
2. Split current step 3 into two steps:
   - Step 3: "Scanning for malware installation" — `node_modules/plain-crypto-js/` presence (sets INSTALLED)
   - Step 4: "Scanning for execution artifacts" — temp dir artifacts, C2 traces (sets CONFIRMED)
3. Replace the current summary block with the severity-aware guidance output
4. Artifact scanning patterns (to be refined based on StepSecurity analysis):
   - Temp dirs: files created in the last 48h matching suspicious patterns
   - C2 domain: `sfrclak.com` in network logs, `/var/log/`, DNS cache
   - Platform-specific payload paths documented by StepSecurity

### GitHub Script Changes

1. Replace the current alert summary block with the guidance block
2. Add the best-practice note to the clean output
3. No structural changes to the scan logic itself
