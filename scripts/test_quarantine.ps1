param(
    [string]$ServicePath = "",
    [string]$CanaryPath = ""
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this Phase 7 test from an elevated PowerShell window (Run as administrator)"
}

function Assert-GuardianTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-GuardianCommand {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $lines = & $script:ResolvedServicePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = ($lines | Out-String)
    }
}

function Get-QuarantineId {
    param([Parameter(Mandatory = $true)][string]$Output)

    $match = [regex]::Match(
        $Output,
        "(?:QUARANTINE_)?ID=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    )

    if (-not $match.Success) {
        throw "Quarantine ID was not returned"
    }

    return $match.Groups[1].Value
}

function Find-QuarantineEntryBlock {
    param(
        [Parameter(Mandatory = $true)][string]$ListOutput,
        [Parameter(Mandatory = $true)][string]$OriginalPath
    )

    return [regex]::Split($ListOutput, "(?m)(?=^ID=)") |
        Where-Object {
            $_.IndexOf(
                "Original=$OriginalPath",
                [StringComparison]::OrdinalIgnoreCase
            ) -ge 0
        } |
        Select-Object -First 1
}

function Build-HarmlessStub {
    & $script:Csc /nologo /target:exe "/out:$script:StubPath" $script:StubSource
    Assert-GuardianTest `
        ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $script:StubPath)) `
        "Failed to build harmless test executable"
}

if ([string]::IsNullOrWhiteSpace($ServicePath)) {
    $ServicePath = Join-Path $PSScriptRoot "..\..\GuardianService\x64\Release\GuardianService.exe"
}

$script:ResolvedServicePath = (Resolve-Path -LiteralPath $ServicePath).Path
$script:StubSource = (Resolve-Path -LiteralPath (
    Join-Path $PSScriptRoot "QuarantineTestStub.cs"
)).Path

$cscCandidates = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
)
$script:Csc = $cscCandidates |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1

if (-not $script:Csc) {
    throw "C# compiler not found; cannot build the harmless test executable"
}

$work = Join-Path $env:TEMP ("GuardianPhase7_" + [guid]::NewGuid().ToString("N"))
$script:StubPath = Join-Path $work "guardian_phase7_test_stub.exe"
$stubStdout = Join-Path $work "stub_stdout.txt"
$stubStderr = Join-Path $work "stub_stderr.txt"
$activeIds = New-Object System.Collections.Generic.List[string]
$cleanupErrors = New-Object System.Collections.Generic.List[string]
$stubProcess = $null
$primaryError = $null
$liveTestRan = $false

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    Build-HarmlessStub
    $originalHash = (Get-FileHash -LiteralPath $script:StubPath -Algorithm SHA256).Hash

    $quarantine = Invoke-GuardianCommand @("--quarantine-file", $script:StubPath)
    Assert-GuardianTest ($quarantine.ExitCode -eq 0) $quarantine.Output
    $firstId = Get-QuarantineId $quarantine.Output
    $activeIds.Add($firstId)
    Assert-GuardianTest (-not (Test-Path -LiteralPath $script:StubPath)) `
        "Source still exists after manual quarantine"

    $list = Invoke-GuardianCommand @("--list-quarantine")
    Assert-GuardianTest ($list.ExitCode -eq 0 -and $list.Output.Contains($firstId)) `
        "List did not contain the manual quarantine ID"

    $verify = Invoke-GuardianCommand @("--verify-quarantine", $firstId)
    Assert-GuardianTest ($verify.ExitCode -eq 0) $verify.Output

    $restore = Invoke-GuardianCommand @("--restore-quarantine", $firstId)
    Assert-GuardianTest `
        ($restore.ExitCode -eq 0 -and (Test-Path -LiteralPath $script:StubPath)) `
        $restore.Output
    $activeIds.Remove($firstId) | Out-Null
    Assert-GuardianTest `
        ((Get-FileHash -LiteralPath $script:StubPath -Algorithm SHA256).Hash -eq $originalHash) `
        "Restored executable hash changed"
    Write-Host "[PASS] Manual quarantine/list/verify/restore preserved SHA-256"

    $windowsBinary = Join-Path $env:WINDIR "System32\notepad.exe"
    if (Test-Path -LiteralPath $windowsBinary) {
        $policy = Invoke-GuardianCommand @("--quarantine-file", $windowsBinary)
        Assert-GuardianTest `
            ($policy.ExitCode -ne 0 -and (Test-Path -LiteralPath $windowsBinary)) `
            "Windows binary policy test failed"
        Write-Host "[PASS] Windows binary was refused and remains present"
    }

    $selfPolicy = Invoke-GuardianCommand @(
        "--quarantine-file",
        $script:ResolvedServicePath
    )
    Assert-GuardianTest `
        ($selfPolicy.ExitCode -ne 0 -and (
            Test-Path -LiteralPath $script:ResolvedServicePath
        )) `
        "GuardianService self-protection policy test failed"
    Write-Host "[PASS] GuardianService was refused and remains present"

    $victimFile = Join-Path $work "victim_document.txt"
    Set-Content -LiteralPath $victimFile -Value "GUARDIAN_PHASE7_VICTIM_FILE"
    $policy = Invoke-GuardianCommand @("--quarantine-file", $victimFile)
    Assert-GuardianTest `
        ($policy.ExitCode -ne 0 -and (Test-Path -LiteralPath $victimFile)) `
        "Victim-file exclusion policy test failed"
    Write-Host "[PASS] Non-executable victim file was refused"

    $quarantine = Invoke-GuardianCommand @("--quarantine-file", $script:StubPath)
    Assert-GuardianTest ($quarantine.ExitCode -eq 0) $quarantine.Output
    $secondId = Get-QuarantineId $quarantine.Output
    $activeIds.Add($secondId)

    $delete = Invoke-GuardianCommand @("--delete-quarantine", $secondId)
    Assert-GuardianTest ($delete.ExitCode -eq 0) $delete.Output
    $activeIds.Remove($secondId) | Out-Null
    Write-Host "[PASS] Manual quarantine deletion succeeded"

    if ([string]::IsNullOrWhiteSpace($CanaryPath)) {
        Write-Host "[SKIP] Live auto-terminate test not run; pass -CanaryPath and keep an elevated monitor running"
    }
    else {
        $liveTestRan = $true
        $resolvedCanaryPath = (Resolve-Path -LiteralPath $CanaryPath).Path
        Assert-GuardianTest `
            ($resolvedCanaryPath -match "(?i)\\0_Canary\\001_canary_") `
            "-CanaryPath must reference an existing real detection canary"

        $monitorProcesses = @(
            Get-Process -Name "GuardianService" -ErrorAction SilentlyContinue
        )
        Assert-GuardianTest ($monitorProcesses.Count -gt 0) `
            "Start GuardianService.exe --monitor in another elevated terminal first"
        $monitorProcessIds = @($monitorProcesses | ForEach-Object Id)

        $systemProcess = Get-Process -Id 4 -ErrorAction Stop
        Assert-GuardianTest (-not $systemProcess.HasExited) "System PID 4 is unavailable"

        Build-HarmlessStub
        $liveOriginalHash = (
            Get-FileHash -LiteralPath $script:StubPath -Algorithm SHA256
        ).Hash

        $quotedCanaryPath = '"' + $resolvedCanaryPath.Replace('"', '\"') + '"'
        $stubProcess = Start-Process `
            -FilePath $script:StubPath `
            -ArgumentList $quotedCanaryPath `
            -RedirectStandardOutput $stubStdout `
            -RedirectStandardError $stubStderr `
            -WindowStyle Hidden `
            -PassThru

        $ready = $false
        for ($attempt = 0; $attempt -lt 50 -and -not $ready; $attempt++) {
            if (Test-Path -LiteralPath $stubStdout) {
                $readyText = Get-Content -LiteralPath $stubStdout -Raw -ErrorAction SilentlyContinue
                $ready = $readyText -match "STUB_READY PID=$($stubProcess.Id)"
            }

            if (-not $ready) {
                Start-Sleep -Milliseconds 100
            }
        }

        $stubProcess.Refresh()
        Assert-GuardianTest ($ready -and -not $stubProcess.HasExited) `
            "Stub was not confirmed running before its canary write"
        Write-Host "[PASS] Harmless stub was running before the canary event"

        $terminatedWithinWindow = $stubProcess.WaitForExit(12000)
        Assert-GuardianTest $terminatedWithinWindow `
            "Service did not terminate the blocked stub within the test window"

        $stubProcess.Refresh()
        $expectedExitCode = [BitConverter]::ToInt32(
            [BitConverter]::GetBytes([Convert]::ToUInt32("E0470001", 16)),
            0
        )
        Assert-GuardianTest ($stubProcess.ExitCode -eq $expectedExitCode) `
            "Stub exit code does not match Guardian TerminateProcess"
        Write-Host "[PASS] Service terminated the harmless stub"

        for ($attempt = 0; $attempt -lt 50 -and (
            Test-Path -LiteralPath $script:StubPath
        ); $attempt++) {
            Start-Sleep -Milliseconds 100
        }
        Assert-GuardianTest (-not (Test-Path -LiteralPath $script:StubPath)) `
            "Executable source still exists after automatic quarantine"
        Write-Host "[PASS] Executable source disappeared after termination"

        $list = Invoke-GuardianCommand @("--list-quarantine")
        Assert-GuardianTest ($list.ExitCode -eq 0) $list.Output
        $entryBlock = Find-QuarantineEntryBlock $list.Output $script:StubPath
        Assert-GuardianTest (-not [string]::IsNullOrWhiteSpace($entryBlock)) `
            "Automatic quarantine entry was not listed"

        $automaticId = Get-QuarantineId $entryBlock
        $activeIds.Add($automaticId)
        $entryRoot = Join-Path $env:ProgramData "Guardian\Quarantine\$automaticId"
        Assert-GuardianTest `
            ((Test-Path -LiteralPath (Join-Path $entryRoot "payload.bin")) -and
             (Test-Path -LiteralPath (Join-Path $entryRoot "metadata.json"))) `
            "Payload or metadata is missing from the quarantine store"
        Write-Host "[PASS] Executable payload and metadata appeared in quarantine"

        $verify = Invoke-GuardianCommand @("--verify-quarantine", $automaticId)
        Assert-GuardianTest ($verify.ExitCode -eq 0) $verify.Output
        $hashMatch = [regex]::Match($verify.Output, "SHA256=([0-9a-fA-F]{64})")
        Assert-GuardianTest `
            ($hashMatch.Success -and $hashMatch.Groups[1].Value -eq $liveOriginalHash) `
            "Quarantined executable SHA-256 changed"
        Write-Host "[PASS] Quarantined executable SHA-256 is unchanged"

        $systemProcess = Get-Process -Id 4 -ErrorAction Stop
        Assert-GuardianTest (-not $systemProcess.HasExited) `
            "Windows System PID 4 was unexpectedly terminated"
        foreach ($monitorProcessId in $monitorProcessIds) {
            $monitor = Get-Process -Id $monitorProcessId -ErrorAction Stop
            Assert-GuardianTest (-not $monitor.HasExited) `
                "GuardianService monitor PID $monitorProcessId was unexpectedly terminated"
        }
        Assert-GuardianTest (Test-Path -LiteralPath $script:ResolvedServicePath) `
            "GuardianService executable was unexpectedly removed"
        Write-Host "[PASS] Windows PID 4 and GuardianService were not terminated"

        $delete = Invoke-GuardianCommand @("--delete-quarantine", $automaticId)
        Assert-GuardianTest ($delete.ExitCode -eq 0) $delete.Output
        $activeIds.Remove($automaticId) | Out-Null
    }
}
catch {
    $primaryError = $_
}
finally {
    if ($null -ne $stubProcess) {
        try {
            $stubProcess.Refresh()
            if (-not $stubProcess.HasExited) {
                Stop-Process -Id $stubProcess.Id -Force -ErrorAction Stop
                $stubProcess.WaitForExit(5000) | Out-Null
            }
        }
        catch {
            $cleanupErrors.Add("Cannot stop harmless stub PID $($stubProcess.Id): $($_.Exception.Message)")
        }
    }

    if (Test-Path -LiteralPath $script:ResolvedServicePath) {
        try {
            $list = Invoke-GuardianCommand @("--list-quarantine")
            if ($list.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($script:StubPath)) {
                $entryBlock = Find-QuarantineEntryBlock $list.Output $script:StubPath
                if (-not [string]::IsNullOrWhiteSpace($entryBlock)) {
                    $discoveredId = Get-QuarantineId $entryBlock
                    if (-not $activeIds.Contains($discoveredId)) {
                        $activeIds.Add($discoveredId)
                    }
                }
            }
        }
        catch {
            $cleanupErrors.Add("Cannot discover leftover quarantine entry: $($_.Exception.Message)")
        }
    }

    foreach ($id in @($activeIds)) {
        try {
            $cleanup = Invoke-GuardianCommand @("--delete-quarantine", $id)
            if ($cleanup.ExitCode -ne 0) {
                throw $cleanup.Output
            }
        }
        catch {
            $cleanupErrors.Add("Cannot delete quarantine entry ${id}: $($_.Exception.Message)")
        }
    }

    if (Test-Path -LiteralPath $work) {
        try {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Stop
        }
        catch {
            $cleanupErrors.Add("Cannot remove test directory ${work}: $($_.Exception.Message)")
        }
    }
}

if ($null -ne $primaryError) {
    foreach ($cleanupError in $cleanupErrors) {
        Write-Warning $cleanupError
    }
    throw $primaryError
}

if ($cleanupErrors.Count -gt 0) {
    throw ($cleanupErrors -join [Environment]::NewLine)
}

if ($liveTestRan) {
    Write-Host "[PASS] All live auto-terminate and quarantine tests passed"
}
else {
    Write-Host "[PASS] Manual Phase 7 quarantine tests passed; live auto-terminate remained skipped"
}
