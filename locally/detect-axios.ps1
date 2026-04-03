#Requires -Version 5.1
<#
.SYNOPSIS
    Scan local filesystem for compromised axios versions (supply chain attack).

.DESCRIPTION
    Detects:
      - axios@1.14.1 and axios@0.30.4 in lockfiles and installed node_modules
      - plain-crypto-js dependency (the malicious dropper package)
      - Related campaign packages (@shadanai/openclaw, @qqbrowser/openclaw-qbot)
      - RAT payload files at known paths (persist after dropper self-cleanup)
      - Running RAT processes and active C2 connections (domain + IP)
      - Malicious tarballs in npm cache

    With -Json, outputs a JSON report to stdout and display to stderr.

.PARAMETER Root
    Directory to scan (default: C:\)

.PARAMETER Fleet
    Emit JSON report to stdout (for automation/MDM).
#>
param(
    [string]$Root = "C:\",
    [switch]$Json
)

$ErrorActionPreference = "SilentlyContinue"

# --- IOCs ---
$COMPROMISED_VERSIONS = @("1.14.1", "0.30.4")
$MALICIOUS_DEP = "plain-crypto-js"
$RELATED_PKGS = @("@shadanai/openclaw", "@qqbrowser/openclaw-qbot")
$C2_DOMAIN = "sfrclak.com"
$C2_IP = "142.11.206.73"
$C2_PORT = 8000
$RAT_PATH_WINDOWS = "C:\ProgramData\wt.exe"
$DROPPER_NAMES = @("6202033.vbs", "6202033.ps1", "ld.py")

# --- State ---
$script:Found = 0
$script:Severity = "CLEAN"
$script:Findings = [System.Collections.ArrayList]::new()
$script:ArtifactFound = $false

# --- Helpers ---
function Write-Display {
    param([string]$Message)
    if (-not $Json) {
        Write-Host $Message
    } else {
        [Console]::Error.WriteLine($Message)
    }
}

function Write-Alert {
    param([string]$Message)
    Write-Display "[ALERT] $Message"
    $script:Found++
}

function Write-Warn {
    param([string]$Message)
    Write-Display "[WARN] $Message"
}

function Write-Ok {
    param([string]$Message)
    Write-Display "[OK] $Message"
}

function Add-Finding {
    param([string]$Category, [string]$Type, [string]$Detail, [string]$Path = "")
    $entry = [ordered]@{
        category = $Category
        type     = $Type
        detail   = $Detail
    }
    if ($Path) { $entry.path = $Path }
    [void]$script:Findings.Add($entry)
}

function Set-Severity {
    param([string]$New)
    switch ($script:Severity) {
        "CLEAN"     { $script:Severity = $New }
        "LATENT"    { if ($New -ne "LATENT") { $script:Severity = $New } }
        "INSTALLED" { if ($New -eq "CONFIRMED") { $script:Severity = $New } }
    }
}

# --- Lockfile names ---
$LOCKFILE_NAMES = @("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")

# --- Skip directories that cannot contain node_modules ---
$PRUNE_DIRS = @(
    (Join-Path $env:SystemRoot ""),
    "C:\Recovery",
    "C:\$Recycle.Bin"
)

function Should-Skip {
    param([string]$Dir)
    foreach ($p in $PRUNE_DIRS) {
        if ($Dir -like "$p*") { return $true }
    }
    return $false
}

Write-Display "=== Axios Supply Chain Scanner (local) ==="
Write-Display "Scanning: $Root"
Write-Display "Looking for: axios@$($COMPROMISED_VERSIONS -join ' / axios@') / $MALICIOUS_DEP"
Write-Display "Also checking: related campaign packages, RAT payloads, C2 traces, npm cache"
Write-Display ""

# --- 1. Scan installed node_modules/axios/package.json ---
Write-Display "[1/6] Scanning installed axios packages in node_modules..."

Get-ChildItem -Path $Root -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -match 'node_modules[\\/]axios[\\/]package\.json$' -and
        $_.FullName -notmatch 'node_modules[\\/].*[\\/]node_modules[\\/]axios' -and
        -not (Should-Skip $_.DirectoryName)
    } |
    ForEach-Object {
        try {
            $pkg = Get-Content $_.FullName -Raw | ConvertFrom-Json
            if ($pkg.version -in $COMPROMISED_VERSIONS) {
                Write-Alert "Compromised axios@$($pkg.version) installed at: $($_.FullName)"
                Add-Finding "node_modules" "compromised_axios" "axios@$($pkg.version)" $_.FullName
                Set-Severity "LATENT"
            }
            $raw = Get-Content $_.FullName -Raw
            if ($raw -match [regex]::Escape($MALICIOUS_DEP)) {
                Write-Alert "Malicious dependency '$MALICIOUS_DEP' found in: $($_.FullName)"
                Add-Finding "node_modules" "malicious_dependency" $MALICIOUS_DEP $_.FullName
                Set-Severity "LATENT"
            }
        } catch {}
    }

# --- 2. Scan lockfiles ---
Write-Display "[2/6] Scanning lockfiles..."

function Test-Lockfile {
    param([System.IO.FileInfo]$File)

    $path = $File.FullName
    $name = $File.Name

    # Skip lockfiles inside node_modules
    if ($path -match 'node_modules') { return }

    switch ($name) {
        "package-lock.json" {
            $raw = Get-Content $path -Raw -ErrorAction SilentlyContinue
            if (-not $raw -or $raw -notmatch "axios") { return }
            try {
                $lock = $raw | ConvertFrom-Json
                $pkgs = if ($lock.packages) { $lock.packages } elseif ($lock.dependencies) { $lock.dependencies } else { @{} }
                foreach ($key in $pkgs.PSObject.Properties.Name) {
                    if ($key -match "axios") {
                        $ver = $pkgs.$key.version
                        if ($ver -in $COMPROMISED_VERSIONS) {
                            Write-Alert "Compromised axios version in lockfile: $path"
                            Add-Finding "lockfile" "compromised_axios" "axios" $path
                            Set-Severity "LATENT"
                        }
                    }
                    if ($key -match [regex]::Escape($MALICIOUS_DEP)) {
                        Write-Alert "'$MALICIOUS_DEP' in lockfile: $path"
                        Add-Finding "lockfile" "malicious_dependency" $MALICIOUS_DEP $path
                        Set-Severity "LATENT"
                    }
                }
            } catch {}
        }
        "yarn.lock" {
            $raw = Get-Content $path -Raw -ErrorAction SilentlyContinue
            if (-not $raw) { return }
            foreach ($v in $COMPROMISED_VERSIONS) {
                if ($raw -match "(?m)^""?axios@.*\n(.*\n){0,5}.*version:?\s+""?$([regex]::Escape($v))") {
                    Write-Alert "Compromised axios version in lockfile: $path"
                    Add-Finding "lockfile" "compromised_axios" "axios" $path
                    Set-Severity "LATENT"
                }
            }
            if ($raw -match [regex]::Escape($MALICIOUS_DEP)) {
                Write-Alert "'$MALICIOUS_DEP' in lockfile: $path"
                Add-Finding "lockfile" "malicious_dependency" $MALICIOUS_DEP $path
                Set-Severity "LATENT"
            }
        }
        "pnpm-lock.yaml" {
            $raw = Get-Content $path -Raw -ErrorAction SilentlyContinue
            if (-not $raw) { return }
            foreach ($v in $COMPROMISED_VERSIONS) {
                $escaped = [regex]::Escape($v)
                if ($raw -match "['""/]axios/$escaped['""]|axios:\s+$escaped") {
                    Write-Alert "Compromised axios version in lockfile: $path"
                    Add-Finding "lockfile" "compromised_axios" "axios" $path
                    Set-Severity "LATENT"
                }
            }
            if ($raw -match [regex]::Escape($MALICIOUS_DEP)) {
                Write-Alert "'$MALICIOUS_DEP' in lockfile: $path"
                Add-Finding "lockfile" "malicious_dependency" $MALICIOUS_DEP $path
                Set-Severity "LATENT"
            }
        }
        "bun.lock" {
            $raw = Get-Content $path -Raw -ErrorAction SilentlyContinue
            if (-not $raw) { return }
            foreach ($v in $COMPROMISED_VERSIONS) {
                $escaped = [regex]::Escape($v)
                if ($raw -match """axios""[^}]*""$escaped""") {
                    Write-Alert "Compromised axios version in lockfile: $path"
                    Add-Finding "lockfile" "compromised_axios" "axios" $path
                    Set-Severity "LATENT"
                }
            }
            if ($raw -match [regex]::Escape($MALICIOUS_DEP)) {
                Write-Alert "'$MALICIOUS_DEP' in lockfile: $path"
                Add-Finding "lockfile" "malicious_dependency" $MALICIOUS_DEP $path
                Set-Severity "LATENT"
            }
        }
        "bun.lockb" {
            # Binary: match npm tarball URL pattern to avoid false positives
            $bytes = [System.IO.File]::ReadAllBytes($path)
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            foreach ($v in $COMPROMISED_VERSIONS) {
                if ($text -match "axios/-/axios-$([regex]::Escape($v))\.tgz") {
                    Write-Alert "Compromised axios version in lockfile: $path"
                    Add-Finding "lockfile" "compromised_axios" "axios" $path
                    Set-Severity "LATENT"
                }
            }
            if ($text -match [regex]::Escape($MALICIOUS_DEP)) {
                Write-Alert "'$MALICIOUS_DEP' in lockfile: $path"
                Add-Finding "lockfile" "malicious_dependency" $MALICIOUS_DEP $path
                Set-Severity "LATENT"
            }
        }
    }
}

Get-ChildItem -Path $Root -Recurse -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -in $LOCKFILE_NAMES -and
        -not (Should-Skip $_.DirectoryName) -and
        $_.FullName -notmatch 'node_modules'
    } |
    ForEach-Object { Test-Lockfile $_ }

# --- 3. Check for malicious package installation ---
Write-Display "[3/6] Scanning for malicious packages in node_modules..."

Get-ChildItem -Path $Root -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -match "node_modules[\\/]$([regex]::Escape($MALICIOUS_DEP))[\\/]package\.json$" -and
        -not (Should-Skip $_.DirectoryName)
    } |
    ForEach-Object {
        Write-Alert "Malicious package installed: $($_.FullName)"
        Add-Finding "installed" "malicious_package" $MALICIOUS_DEP $_.FullName
        Set-Severity "INSTALLED"
    }

# Related campaign packages
foreach ($pkg in $RELATED_PKGS) {
    Get-ChildItem -Path $Root -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -match "node_modules[\\/]$([regex]::Escape($pkg))[\\/]package\.json$" -and
            -not (Should-Skip $_.DirectoryName)
        } |
        ForEach-Object {
            Write-Alert "Related campaign package installed: $($_.FullName)"
            Add-Finding "installed" "related_campaign_package" $pkg $_.FullName
            Set-Severity "INSTALLED"
        }
}

# --- 4. Scan for RAT payload files ---
Write-Display "[4/6] Scanning for RAT payload files..."

# 4a. Known Windows RAT path
if (Test-Path $RAT_PATH_WINDOWS) {
    Write-Alert "RAT payload found: $RAT_PATH_WINDOWS"
    Add-Finding "artifact" "rat_payload" "Windows RAT binary" $RAT_PATH_WINDOWS
    $script:ArtifactFound = $true

    # Check if it's signed
    $sig = Get-AuthenticodeSignature $RAT_PATH_WINDOWS -ErrorAction SilentlyContinue
    if (-not $sig -or $sig.Status -ne "Valid") {
        Write-Alert "  File is NOT validly signed (expected for RAT)"
    }
}

# 4b. Check temp directories for dropper files
$tempDirs = @($env:TEMP, $env:TMP, "C:\Windows\Temp") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

foreach ($tmpDir in $tempDirs) {
    foreach ($dropperName in $DROPPER_NAMES) {
        Get-ChildItem -Path $tmpDir -Filter $dropperName -Recurse -Depth 2 -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Alert "Dropper artifact found: $($_.FullName)"
                Add-Finding "artifact" "dropper_file" $dropperName $_.FullName
                $script:ArtifactFound = $true
            }
    }

    # Check for suspicious recent files
    Get-ChildItem -Path $tmpDir -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LastWriteTime -gt (Get-Date).AddDays(-2) -and
            $_.Extension -in @(".sh", ".bat", ".cmd", ".ps1", ".vbs") -and
            $_.Name -match "crypto|axios|plain|payload|dropper"
        } |
        ForEach-Object {
            Write-Alert "Suspicious recent file in temp directory: $($_.FullName)"
            Add-Finding "artifact" "suspicious_temp_file" "pattern match" $_.FullName
            $script:ArtifactFound = $true
        }
}

# --- 5. Scan for network/process/log artifacts ---
Write-Display "[5/6] Scanning for C2 network traces and suspicious processes..."

# 5a. Check for running RAT processes
Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -and ($_.Path -match "wt\.exe" -and $_.Path -match "ProgramData")
} | ForEach-Object {
    Write-Alert "Running process matches RAT: $($_.Path)"
    Add-Finding "process" "rat_process" $_.Path ""
    $script:ArtifactFound = $true
}

# 5b. Check active network connections to C2
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object {
        $_.RemoteAddress -eq $C2_IP -or $_.RemotePort -eq $C2_PORT
    }
if ($connections) {
    Write-Alert "Active connection to C2 IP $C2_IP or port $C2_PORT detected"
    Add-Finding "network" "c2_connection" "${C2_IP}:${C2_PORT}" ""
    $script:ArtifactFound = $true
}

# 5c. Check DNS client cache for C2 domain
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object { $_.Entry -match [regex]::Escape($C2_DOMAIN) -or $_.Data -eq $C2_IP }
if ($dnsCache) {
    Write-Alert "C2 indicator found in DNS cache ($C2_DOMAIN or $C2_IP)"
    Add-Finding "network" "c2_dns_cache" $C2_DOMAIN "DNS client cache"
    $script:ArtifactFound = $true
}

# 5d. Check Windows Event Log for C2 indicators (DNS)
try {
    $dnsEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-DNS-Client/Operational'
        StartTime = (Get-Date).AddHours(-48)
    } -MaxEvents 5000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match [regex]::Escape($C2_DOMAIN) -or $_.Message -match [regex]::Escape($C2_IP) }
    if ($dnsEvents) {
        Write-Alert "C2 indicator found in Windows DNS event log"
        Add-Finding "network" "c2_log_trace" $C2_DOMAIN "Windows DNS event log"
        $script:ArtifactFound = $true
    }
} catch {}

# --- 6. Check npm cache ---
Write-Display "[6/6] Scanning npm cache for compromised packages..."

$npmCache = ""
try {
    $npmCache = & npm config get cache 2>$null
} catch {}
if (-not $npmCache) {
    $npmCache = Join-Path $env:APPDATA "npm-cache"
}

if (Test-Path $npmCache) {
    $cacacheDir = Join-Path $npmCache "_cacache"
    if (Test-Path $cacacheDir) {
        $cacheHit = Get-ChildItem -Path $cacacheDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($MALICIOUS_DEP)
            } |
            Select-Object -First 1
        if ($cacheHit) {
            Write-Alert "Malicious package '$MALICIOUS_DEP' found in npm cache: $npmCache"
            Add-Finding "npm_cache" "malicious_package" $MALICIOUS_DEP $cacacheDir
            Write-Warn "  Run 'npm cache clean --force' after investigation"
            Set-Severity "INSTALLED"
        }

        foreach ($pkg in $RELATED_PKGS) {
            $relHit = Get-ChildItem -Path $cacacheDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($pkg)
                } |
                Select-Object -First 1
            if ($relHit) {
                Write-Alert "Related campaign package '$pkg' found in npm cache"
                Add-Finding "npm_cache" "related_campaign_package" $pkg $cacacheDir
                Set-Severity "INSTALLED"
            }
        }
    }
} else {
    Write-Warn "npm cache directory not found at $npmCache - skipping cache check"
}

if ($script:ArtifactFound) {
    Set-Severity "CONFIRMED"
}

# --- JSON report ---
$report = [ordered]@{
    scan_date     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    hostname      = $env:COMPUTERNAME
    os            = "Windows"
    scan_root     = $Root
    severity      = $script:Severity
    finding_count = $script:Found
    findings      = $script:Findings.ToArray()
}

$json = $report | ConvertTo-Json -Depth 5

if ($Json) {
    # Fleet mode: always emit JSON to stdout
    Write-Output $json
} elseif ($script:Severity -ne "CLEAN") {
    $jsonFile = "axios-scan-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $json | Set-Content $jsonFile -Encoding UTF8
}

# --- Summary ---
Write-Display ""
Write-Display "=== Scan Complete ==="
Write-Display "Findings: $($script:Found) indicator(s) | Severity: $($script:Severity)"
Write-Display ""

switch ($script:Severity) {
    "CLEAN" {
        Write-Ok "No compromised axios versions or malicious dependencies detected."
        Write-Display ""
        Write-Display " Best practice: pin exact dependency versions in package.json to prevent"
        Write-Display "  supply chain attacks from silently upgrading to compromised versions."
        exit 0
    }
    "LATENT" {
        Write-Display "================================================================"
        Write-Display " SEVERITY: LATENT - Compromised version in lockfile, not yet installed"
        Write-Display "================================================================"
        Write-Display ""
        Write-Display " TL;DR: The compromised axios version is referenced in your lockfile but has"
        Write-Display "  not been installed yet. Clean the lockfile and pin axios to a safe version"
        Write-Display "  before running any install command."
    }
    "INSTALLED" {
        Write-Display "================================================================"
        Write-Display " SEVERITY: INSTALLED - Malicious package was installed (infection probable)"
        Write-Display "================================================================"
        Write-Display ""
        Write-Display " TL;DR: The malicious package plain-crypto-js was found in node_modules."
        Write-Display "  The postinstall dropper has likely executed. Treat this as an active infection."
        Write-Display "  Rotate ALL secrets immediately and alert your security team."
    }
    "CONFIRMED" {
        Write-Display "================================================================"
        Write-Display " SEVERITY: CONFIRMED - Malware execution artifacts detected"
        Write-Display "================================================================"
        Write-Display ""
        Write-Display " TL;DR: The RAT payload was deployed on this machine. This system is"
        Write-Display "  compromised. Rotate ALL secrets NOW and alert your security team immediately."
    }
}

if ($jsonFile) {
    Write-Display ""
    Write-Display " Scan results saved to: $(Get-Location)\$jsonFile"
    Write-Display "  Send this file to your security team for triage."
    exit 1
}
