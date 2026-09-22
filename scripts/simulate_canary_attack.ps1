$ErrorActionPreference = "Stop"

function Get-GuardianCanaryPaths {
    $paths = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath "guardian_canary_manifest.json") {
        try {
            $manifest = Get-Content -LiteralPath "guardian_canary_manifest.json" -Raw | ConvertFrom-Json
            foreach ($entry in @($manifest.entries)) {
                if ($entry.path) {
                    $paths.Add([string]$entry.path)
                }
            }
        } catch {
            Write-Host "[WARN] Cannot parse guardian_canary_manifest.json: $($_.Exception.Message)"
        }
    }

    if ($env:USERPROFILE) {
        $paths.Add((Join-Path $env:USERPROFILE "Desktop\0_Canary\001_canary_invoice.docx"))
        $paths.Add((Join-Path $env:USERPROFILE "Documents\0_Canary\001_canary_invoice.docx"))
        $paths.Add((Join-Path $env:USERPROFILE "Downloads\0_Canary\001_canary_invoice.docx"))
        $paths.Add((Join-Path $env:USERPROFILE "Pictures\0_Canary\001_canary_invoice.docx"))
        $paths.Add((Join-Path $env:USERPROFILE "Videos\0_Canary\001_canary_invoice.docx"))
        $paths.Add((Join-Path $env:USERPROFILE "Music\0_Canary\001_canary_invoice.docx"))
        $paths.Add((Join-Path $env:USERPROFILE "0_Canary\001_canary_invoice.docx"))
    }

    $paths.Add("C:\0_Canary\001_canary_invoice.docx")
    return $paths
}

function ConvertTo-SingleQuotedPowerShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + ($Value -replace "'", "''") + "'"
}

function Invoke-GuardianChildScript {
    param([Parameter(Mandatory = $true)][string]$Script)

    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($Script)
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = (Get-Command powershell.exe -ErrorAction Stop).Source
    $startInfo.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded"
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo

    try {
        if (-not $process.Start()) {
            throw "Cannot start child PowerShell process"
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()

        $output = $stdoutTask.Result + $stderrTask.Result
        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = $output
    }
}

function Test-GlobalCanaryPrefixAllowed {
    if (-not $env:APPDATA) {
        Write-Host "[WARN] APPDATA is unavailable; Recent-folder regression test skipped"
        return
    }

    $recentFolder = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
    if (-not (Test-Path -LiteralPath $recentFolder -PathType Container)) {
        Write-Host "[WARN] Recent folder is unavailable; regression test skipped: $recentFolder"
        return
    }

    $testPath = Join-Path $recentFolder "001_canary_guardian_false_positive_test.lnk"
    $testPathLiteral = ConvertTo-SingleQuotedPowerShellLiteral -Value $testPath

    $script = @"
`$ErrorActionPreference = 'Stop'
try {
    Set-Content -LiteralPath $testPathLiteral -Value 'GUARDIAN_FALSE_POSITIVE_TEST'
    Add-Content -LiteralPath $testPathLiteral -Value 'WRITE_ALLOWED_OUTSIDE_0_CANARY'
    Remove-Item -LiteralPath $testPathLiteral -Force
    exit 0
} catch {
    [Console]::Error.WriteLine(`$_.Exception.GetType().FullName)
    [Console]::Error.WriteLine(`$_.Exception.Message)
    exit 6
}
"@

    $result = Invoke-GuardianChildScript -Script $script

    if ($result.ExitCode -eq 0) {
        Write-Host "[PASS] Recent\001_canary_*.lnk allowed outside 0_Canary"
        return
    }

    Write-Host "[FAIL] Global 001_canary_ prefix is still blocked: $testPath"
    if ($result.Output.Trim().Length -gt 0) {
        Write-Host $result.Output
    }
}

function Test-GuardianBlockedOperation {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Script,
        [scriptblock]$OnUnexpectedAllow
    )

    $result = Invoke-GuardianChildScript -Script $Script
    $text = $result.Output

    if ($result.ExitCode -ne 0 -and
        $text -match "UnauthorizedAccessException|Access.*denied|Access is denied|denied") {
        Write-Host "[PASS] $Name blocked with Access Denied"
        return $true
    }

    Write-Host "[FAIL] $Name was not blocked"

    if ($text.Trim().Length -gt 0) {
        Write-Host $text
    }

    if ($null -ne $OnUnexpectedAllow) {
        & $OnUnexpectedAllow
    }

    return $false
}

function Test-RecoveryTrapAllowed {
    param([Parameter(Mandatory = $true)][string]$Folder)

    $trapFolder = Split-Path -Parent $Folder
    $trapFolder = Join-Path $trapFolder "0_RecoveryTrap"
    $trapPath = Join-Path $trapFolder "000_recovery_allow_test.bin"
    $renamedTrapPath = Join-Path $trapFolder "000_recovery_allow_test_renamed.bin"
    $trapFolderLiteral = ConvertTo-SingleQuotedPowerShellLiteral -Value $trapFolder
    $trapLiteral = ConvertTo-SingleQuotedPowerShellLiteral -Value $trapPath
    $renamedLeafLiteral = ConvertTo-SingleQuotedPowerShellLiteral -Value (Split-Path -Leaf $renamedTrapPath)
    $renamedTrapLiteral = ConvertTo-SingleQuotedPowerShellLiteral -Value $renamedTrapPath

    if (Test-Path -LiteralPath $trapPath) {
        Remove-Item -LiteralPath $trapPath -Force
    }

    if (Test-Path -LiteralPath $renamedTrapPath) {
        Remove-Item -LiteralPath $renamedTrapPath -Force
    }

    $script = @"
`$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $trapFolderLiteral -Force | Out-Null
Set-Content -LiteralPath $trapLiteral -Value 'GUARDIAN_RECOVERY_TRAP_ALLOW_TEST'
Add-Content -LiteralPath $trapLiteral -Value 'WRITE_ALLOWED'
Rename-Item -LiteralPath $trapLiteral -NewName $renamedLeafLiteral
Remove-Item -LiteralPath $renamedTrapLiteral -Force
exit 0
"@

    $result = Invoke-GuardianChildScript -Script $script

    if ($result.ExitCode -eq 0) {
        Write-Host "[PASS] Recovery trap 000_ open/write/rename allowed"
        return
    }

    Write-Host "[FAIL] Recovery trap 000_ was unexpectedly blocked"

    if ($result.Output.Trim().Length -gt 0) {
        Write-Host $result.Output
    }
}

$target = Get-GuardianCanaryPaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $target) {
    Write-Host "[ERROR] No 001_ detection canary found. Run GuardianService.exe --create-canary first."
    exit 1
}

$backup = Join-Path $env:TEMP ("guardian_canary_backup_" + [guid]::NewGuid().ToString("N") + ".bin")
$renameTarget = $target + ".rename_test"
$renameLeaf = Split-Path -Leaf $renameTarget
$targetLiteral = ConvertTo-SingleQuotedPowerShellLiteral -Value $target
$renameLeafLiteral = ConvertTo-SingleQuotedPowerShellLiteral -Value $renameLeaf

Copy-Item -LiteralPath $target -Destination $backup -Force

try {
    Write-Host "[*] Testing 001_ detection canary: $target"

    Test-GlobalCanaryPrefixAllowed
    Test-RecoveryTrapAllowed -Folder (Split-Path -Parent $target)

    $writeScript = @"
`$ErrorActionPreference = 'Stop'
try {
    Add-Content -LiteralPath $targetLiteral -Value 'GUARDIAN_SIMULATED_WRITE'
    exit 0
} catch {
    [Console]::Error.WriteLine(`$_.Exception.GetType().FullName)
    [Console]::Error.WriteLine(`$_.Exception.Message)
    exit 5
}
"@

    Test-GuardianBlockedOperation `
        -Name "Canary write" `
        -Script $writeScript `
        -OnUnexpectedAllow {
            Copy-Item -LiteralPath $backup -Destination $target -Force
        } | Out-Null

    $renameScript = @"
`$ErrorActionPreference = 'Stop'
try {
    Rename-Item -LiteralPath $targetLiteral -NewName $renameLeafLiteral
    exit 0
} catch {
    [Console]::Error.WriteLine(`$_.Exception.GetType().FullName)
    [Console]::Error.WriteLine(`$_.Exception.Message)
    exit 5
}
"@

    Test-GuardianBlockedOperation `
        -Name "Canary rename" `
        -Script $renameScript `
        -OnUnexpectedAllow {
            if (Test-Path -LiteralPath $renameTarget) {
                Rename-Item -LiteralPath $renameTarget -NewName (Split-Path -Leaf $target) -Force
            }
        } | Out-Null

    $deleteScript = @"
`$ErrorActionPreference = 'Stop'
try {
    Remove-Item -LiteralPath $targetLiteral -Force
    exit 0
} catch {
    [Console]::Error.WriteLine(`$_.Exception.GetType().FullName)
    [Console]::Error.WriteLine(`$_.Exception.Message)
    exit 5
}
"@

    Test-GuardianBlockedOperation `
        -Name "Canary delete" `
        -Script $deleteScript `
        -OnUnexpectedAllow {
            Copy-Item -LiteralPath $backup -Destination $target -Force
        } | Out-Null
}
finally {
    if ((Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $target)) {
        Copy-Item -LiteralPath $backup -Destination $target -Force
    }

    if (Test-Path -LiteralPath $backup) {
        Remove-Item -LiteralPath $backup -Force
    }
}
