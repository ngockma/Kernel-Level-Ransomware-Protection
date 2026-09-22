$ErrorActionPreference = "Continue"

$instancesKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Guardian\Instances"

Write-Host "[*] Stopping Guardian"
& sc.exe stop Guardian

Write-Host "[*] Deleting Guardian service"
& sc.exe delete Guardian

if (Test-Path -LiteralPath $instancesKey) {
    Write-Host "[*] Removing Guardian instance registry key"
    Remove-Item -LiteralPath $instancesKey -Recurse -Force
}

Write-Host "[OK] Guardian uninstall script completed"
