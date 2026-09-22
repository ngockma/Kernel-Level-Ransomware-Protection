param(
    [Parameter(Mandatory = $true)]
    [string]$SysPath
)

$ErrorActionPreference = "Stop"

$resolvedSysPath = (Resolve-Path -LiteralPath $SysPath).Path
$serviceRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\Guardian"
$instancesKey = Join-Path $serviceRoot "Instances"
$instanceKey = Join-Path $instancesKey "Guardian Instance"
$quotedSysPath = '"' + $resolvedSysPath + '"'

Write-Host "[*] Creating Guardian minifilter service"
& sc.exe create Guardian type= filesys binPath= $quotedSysPath start= demand

Write-Host "[*] Writing minifilter registry instance"
New-Item -Path $instancesKey -Force | Out-Null
New-Item -Path $instanceKey -Force | Out-Null

New-ItemProperty `
    -Path $instancesKey `
    -Name "DefaultInstance" `
    -Value "Guardian Instance" `
    -PropertyType String `
    -Force | Out-Null

New-ItemProperty `
    -Path $instanceKey `
    -Name "Altitude" `
    -Value "363636" `
    -PropertyType String `
    -Force | Out-Null

New-ItemProperty `
    -Path $instanceKey `
    -Name "Flags" `
    -Value 0 `
    -PropertyType DWord `
    -Force | Out-Null

Write-Host "[*] Starting Guardian"
& sc.exe start Guardian

Write-Host "[*] Current minifilter list"
& fltmc filters
