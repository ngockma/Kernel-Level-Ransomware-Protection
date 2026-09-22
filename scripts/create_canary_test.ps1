$ErrorActionPreference = "Stop"

$CanaryNames = @(
    "001_canary_invoice.docx",
    "001_canary_salary.xlsx",
    "001_canary_contract.pdf",
    "001_canary_passwords.txt",
    "001_canary_backup.zip"
)

function ConvertTo-NormalizedKey {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        return ([System.IO.Path]::GetFullPath($Path).TrimEnd('\') ).ToLowerInvariant()
    } catch {
        return $Path.TrimEnd('\').ToLowerInvariant()
    }
}

function Test-IsWindowsPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $windows = [System.Environment]::GetFolderPath("Windows")
    $pathKey = ConvertTo-NormalizedKey -Path $Path
    $windowsKey = ConvertTo-NormalizedKey -Path $windows

    return $pathKey -eq $windowsKey -or $pathKey.StartsWith($windowsKey + "\")
}

function Test-DirectoryWritable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ref]$Reason
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        $Reason.Value = "path does not exist"
        return $false
    }

    if (Test-IsWindowsPath -Path $Path) {
        $Reason.Value = "inside Windows directory"
        return $false
    }

    $probeDir = Join-Path $Path (".guardian_probe_" + [guid]::NewGuid().ToString("N"))
    $probeFile = Join-Path $probeDir "probe.tmp"

    try {
        New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
        Set-Content -LiteralPath $probeFile -Value "guardian" -Encoding ASCII
        return $true
    } catch {
        $Reason.Value = "not writable: " + $_.Exception.Message
        return $false
    } finally {
        if (Test-Path -LiteralPath $probeDir) {
            Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-GuardianTargetDirectories {
    $candidates = New-Object System.Collections.Generic.List[string]

    $candidates.Add("C:\")
    $candidates.Add("C:\Users\")

    if ($env:USERPROFILE) {
        $candidates.Add($env:USERPROFILE)
        $candidates.Add((Join-Path $env:USERPROFILE "Desktop"))
        $candidates.Add((Join-Path $env:USERPROFILE "Documents"))
        $candidates.Add((Join-Path $env:USERPROFILE "Downloads"))
        $candidates.Add((Join-Path $env:USERPROFILE "Pictures"))
        $candidates.Add((Join-Path $env:USERPROFILE "Videos"))
        $candidates.Add((Join-Path $env:USERPROFILE "Music"))
        $candidates.Add((Join-Path $env:USERPROFILE "Favorites"))
        $candidates.Add((Join-Path $env:USERPROFILE "History"))
    }

    if ($env:ProgramData) {
        $candidates.Add($env:ProgramData)
    }

    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        if ($_.Root -and (Test-Path -LiteralPath $_.Root)) {
            $candidates.Add($_.Root)
        }
    }

    $seen = @{}
    $targets = New-Object System.Collections.Generic.List[object]

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $key = ConvertTo-NormalizedKey -Path $candidate
        if ($seen.ContainsKey($key)) {
            continue
        }

        $seen[$key] = $true
        $reason = ""

        if (Test-DirectoryWritable -Path $candidate -Reason ([ref]$reason)) {
            $targets.Add([pscustomobject]@{
                Path = [System.IO.Path]::GetFullPath($candidate)
                Writable = $true
                Reason = ""
            })
        } else {
            Write-Host "[WARN] Skipping target $candidate : $reason"
            $targets.Add([pscustomobject]@{
                Path = $candidate
                Writable = $false
                Reason = $reason
            })
        }
    }

    return $targets
}

function New-CanaryBytes {
    param(
        [Parameter(Mandatory = $true)][string]$BaseTarget,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $bytes = New-Object byte[] 4096
    $header = [Text.Encoding]::ASCII.GetBytes("GUARDIAN_DETECTION_CANARY_V1`nBASE=$BaseTarget`nPATH=$Path`n")
    [Array]::Copy($header, $bytes, [Math]::Min($header.Length, $bytes.Length))

    for ($i = $header.Length; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [byte](($i * 37) -band 0xff)
    }

    return ,$bytes
}

$targets = @(Get-GuardianTargetDirectories)
$entries = New-Object System.Collections.Generic.List[object]
$skipped = New-Object System.Collections.Generic.List[object]

foreach ($target in $targets) {
    if (-not $target.Writable) {
        $skipped.Add([pscustomobject]@{
            base_target = $target.Path
            reason = $target.Reason
        })
        continue
    }

    $canaryDir = Join-Path $target.Path "0_Canary"

    try {
        New-Item -ItemType Directory -Path $canaryDir -Force | Out-Null
    } catch {
        $skipped.Add([pscustomobject]@{
            base_target = $target.Path
            reason = "cannot create 0_Canary: " + $_.Exception.Message
        })
        continue
    }

    foreach ($name in $CanaryNames) {
        $path = Join-Path $canaryDir $name

        try {
            [IO.File]::WriteAllBytes($path, (New-CanaryBytes -BaseTarget $target.Path -Path $path))
            $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            $entries.Add([pscustomobject]@{
                type = "detection_canary"
                base_target = $target.Path
                path = $path
                size = (Get-Item -LiteralPath $path).Length
                sha256 = $hash
            })
            Write-Host "[OK] Detection canary created: $path"
        } catch {
            $skipped.Add([pscustomobject]@{
                base_target = $target.Path
                reason = "cannot create canary $name : " + $_.Exception.Message
            })
        }
    }
}

$manifest = [pscustomobject]@{
    type = "detection_canary_manifest"
    target_count = $targets.Count
    created_count = $entries.Count
    skipped_count = $skipped.Count
    skipped = $skipped
    entries = $entries
}

$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "guardian_canary_manifest.json" -Encoding UTF8

Write-Host "[SUMMARY] targets=$($targets.Count) created=$($entries.Count) skipped=$($skipped.Count)"
$skipped | ForEach-Object {
    Write-Host "[SKIPPED] $($_.base_target) Reason=$($_.reason)"
}

if ($entries.Count -eq 0) {
    exit 1
}
