<#
.SYNOPSIS
    win-sec-audit - A PowerShell security tool that audits Windows systems against hardening best standards

.DESCRIPTION
    A PowerShell security tool that audits Windows systems against hardening best standards

.AUTHOR
    Joshua Blankenship (blankenshipSec)

.LINK
    https://github.com/blankenshipSec/win-sec-audit

.LICENSE
    MIT
#>

# ------ Parameters ------
param(
    [switch]$Detailed,
    [switch]$Export,
    [string]$OutputPath = ".\audit-report.txt"
)

# ------ Constants ------
$PASS = "PASS"
$FAIL = "FAIL"
$WARN = "WARN"
$INFO = "INFO"

$PassColor = "Green"
$FailColor = "Red"
$WarnColor = "Yellow"
$InfoColor = "Cyan"

$script:Results   = New-Object System.Collections.ArrayList
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0

# ------ Helper Functions ------
function Write-Result {
    param(
        [string]$Status,
        [string]$Message,
        [string]$Category,
        [string]$Detail = ""
    )

    $color = switch ($Status) {
        "PASS" { $PassColor }
        "FAIL" { $FailColor }
        "WARN" { $WarnColor }
        default { $InfoColor }
    }

    Write-Host "  [$Status]" -ForegroundColor $color -NoNewline
    Write-Host " $Category" -ForegroundColor White -NoNewline
    Write-Host " - $Message" -ForegroundColor Gray

    if ($Detailed -and $Detail -ne "") {
        Write-Host "        $Detail" -ForegroundColor DarkGray
    }

    [void]$script:Results.Add([PSCustomObject]@{
        Status = $Status
        Category = $Category
        Message = $Message
        Detail = $Detail
    })

    switch ($Status) {
        "PASS" { $script:PassCount++ }
        "FAIL" { $script:FailCount++ }
        "WARN" { $script:WarnCount++ }
    }
}

function Write-SectionHeader {
    param ([string]$Title)
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  $("-" * $Title.Length)" -ForegroundColor DarkCyan
}

# ------ Security Checks ------
function Test-FirewallStatus {
    Write-SectionHeader "Windows Firewall"

    $profiles = Get-NetFirewallProfile

    foreach ($profile in $profiles) {
        if ($profile.Enabled) {
            Write-Result    -Status $PASS `
                            -Category "Firewall" `
                            -Message "$($profile.Name) profile is enabled" `
                            -Detail "Profile: $($profile.Name) - Enabled: $($profile.Enabled)"
        } else {
            Write-Result    -Status $FAIL `
                            -Category "Firewall" `
                            -Message "$($profile.Name) profile is disabled" `
                            -Detail "Profile: $($profile.Name) - Enabled: $($profile.Enabled)"
        }
    }
}

function Test-WindowsUpdateStatus {
    Write-SectionHeader "Windows Update"

    try {
        $updateService = Get-Service -Name "wuauserv" -ErrorAction Stop

        if ($updateService.Status -eq "Running") {
            Write-Result    -Status $PASS `
                            -Category "Windows Update" `
                            -Message "Windows Update service is running" `
                            -Detail "Service: wuauserv - Status: $($updateService.Status)"
        } else {
            Write-Result    -Status $WARN `
                            -Category "Windows Update" `
                            -Message "Windows Update service is not running" `
                            -Detail "Service: wuauserv - Status: $($updateService.Status)"
        }
    } catch {
        Write-Result    -Status $FAIL `
                        -Category "Windows Update" `
                        -Message "Could not retrieve Windows Update service status" `
                        -Detail "Error: $($_.Exception.Message)"
    }
}

function Test-GuestAccount {
    Write-SectionHeader "Guest Account"

    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        
        if ($guest.Enabled) {
            Write-Result    -Status $FAIL `
                            -Category "Guest Account" `
                            -Message "Guest account is enabled" `
                            -Detail "Account: Guest - Enabled: $($guest.Enabled)"
        } else {
            Write-Result    -Status $PASS `
                            -Category "Guest Account" `
                            -Message "Guest account is disabled" `
                            -Detail "Account: Guest - Enabled: $($guest.Enabled)"
        }
    } catch {
        Write-Result    -Status $WARN `
                        -Category "Guest Account" `
                        -Message "Could not retrieve Guest account status" `
                        -Detail "Error: $($_.Exception.Message)"
    }
}

function Test-PasswordPolicy {
    Write-SectionHeader "Password Policy"

    try {
        $policy = net accounts 2>&1

        $minLength    = ($policy | Select-String "Minimum password length").ToString().Split(":")[-1].Trim()
        $maxAge       = ($policy | Select-String "Maximum password age").ToString().Split(":")[-1].Trim()
        $lockout      = ($policy | Select-String "Lockout threshold").ToString().Split(":")[-1].Trim()

        # ------ Minimum Password Length ------
        if ([int]$minLength -ge 12) {
            Write-Result    -Status $PASS `
                            -Category "Password Policy" `
                            -Message "Minimum password length is $minLength characters" `
                            -Detail "Recommended: 12 or more characters"
        } elseif ([int]$minLength -ge 8) {
            Write-Result    -Status $WARN `
                            -Category "Password Policy" `
                            -Message "Minimum password length is $minLength - recommended to be 12 or more characters" `
                            -Detail "Recommended: 12 or more characters"
        } else {
            Write-Result    -Status $FAIL `
                            -Category "Password Policy" `
                            -Message "Minimum password length is $minLength - too short" `
                            -Detail "Recommended: 12 or more characters"
        }
        # ------ Account Lockout ------
        if ($lockout -eq "Never") {
            Write-Result    -Status $FAIL `
                            -Category "Password Policy" `
                            -Message "Account lockout is not configured" `
                            -Detail "Recommended: Lock after 5 failed attempts"
        } else {
            Write-Result    -Status $PASS `
                            -Category "Password Policy" `
                            -Message "Account lockout is configured at $lockout attempts" `
                            -Detail "Lockout threshold: $lockout"
        }

    } catch {
        Write-Result    -Status $WARN `
                        -Category "Password Policy" `
                        -Message "Could not retrieve password policy" `
                        -Detail "Error: $($_.Exception.Message)"
    }
}

function Test-AuditPolicy {
    Write-SectionHeader "Audit Policy"

    try {
        $auditPolicy = auditpol /get /category:* 2>&1

        $logon     = $auditPolicy | Select-String "Logon"
        $accountMgmt = $auditPolicy | Select-String "User Account Management"

        if ($logon) {
            Write-Result    -Status $PASS `
                            -Category "Audit Policy" `
                            -Message "Logon auditing is configured" `
                            -Detail $logon.ToString().Trim()
        } else {
            Write-Result    -Status $FAIL `
                            -Category "Audit Policy" `
                            -Message "Logon auditing is not configured" `
                            -Detail "Recommended: Audit logon success and failure"
        }

        if ($accountMgmt) {
            Write-Result    -Status $PASS `
                            -Category "Audit Policy" `
                            -Message "User Account Management auditing is configured" `
                            -Detail $accountMgmt.ToString().Trim()
        } else {
            Write-Result    -Status $FAIL `
                            -Category "Audit Policy" `
                            -Message "User Account Management auditing is not configured" `
                            -Detail "Recommended: Audit account management success and failure"
        }

    } catch {
        Write-Result    -Status $WARN `
                        -Category "Audit Policy" `
                        -Message "Could not retrieve audit policy" `
                        -Detail "Error: $($_.Exception.Message)"
    }
}

function Test-UnnecessaryServices {
    Write-SectionHeader "Unnecessary Services"

    $riskyServices = @(
        @{ Name = "Telnet";       DisplayName = "Telnet" },
        @{ Name = "RemoteRegistry"; DisplayName = "Remote Registry" },
        @{ Name = "SharedAccess"; DisplayName = "Internet Connection Sharing" },
        @{ Name = "XboxGipSvc";   DisplayName = "Xbox Accessory Management" },
        @{ Name = "WMPNetworkSvc"; DisplayName = "Windows Media Player Sharing" }
    )

    foreach ($svc in $riskyServices) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction Stop

            if ($service.Status -eq "Running") {
                Write-Result    -Status $FAIL `
                                -Category "Services" `
                                -Message "$($svc.DisplayName) is running — should be disabled" `
                                -Detail "Service: $($svc.Name) — Status: $($service.Status)"
            } else {
                Write-Result    -Status $PASS `
                                -Category "Services" `
                                -Message "$($svc.DisplayName) is not running" `
                                -Detail "Service: $($svc.Name) — Status: $($service.Status)"
            }
        } catch {
            Write-Result    -Status $INFO `
                            -Category "Services" `
                            -Message "$($svc.DisplayName) is not installed" `
                            -Detail "Service: $($svc.Name) — Not found on this system"
        }
    }
}

function Test-BitLockerStatus {
    Write-SectionHeader "BitLocker Encryption"

    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop

        foreach ($volume in $volumes) {
            if ($volume.ProtectionStatus -eq "On") {
                Write-Result    -Status $PASS `
                                -Category "BitLocker" `
                                -Message "Bitlocker is enabled on drive $($volume.MountPoint)" `
                                -Detail "Drive: $($volume.MountPoint) - Status: $($volume.ProtectionStatus)"
            } else {
                Write-Result    -Status $FAIL `
                                -Category "BitLocker" `
                                -Message "BitLocker is not enabled on drive $($volume.MountPoint)" `
                                -Detail "Drive: $($volume.MountPoint) - Status: $($volume.ProtectionStatus)"
            }
        }
    } catch {
        Write-Result    -Status $WARN `
                        -Category "BitLocker" `
                        -Message "Could not retrieve BitLocker Status, or not available for this edition" `
                        -Detail "Error: $($_.Exception.Message)"
    }
}

# ------ Summary ------
function Write-Summary {
    $total = $PassCount + $FailCount + $WarnCount
    $score = if ($total -gt 0) { [math]::Round(($PassCount / $total) * 100) } else { 0 }

    Write-Host ""
    Write-Host " ============================" -ForegroundColor Cyan
    Write-Host " Audit Complete" -ForegroundColor Cyan
    Write-Host " ============================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Score:  $score%" -ForegroundColor White
    Write-Host "  Pass:   $PassCount" -ForegroundColor Green
    Write-Host "  Fail:   $FailCount" -ForegroundColor Red
    Write-Host "  Warn:   $WarnCount" -ForegroundColor Yellow
    Write-Host ""

    if ($score -ge 80) {
        Write-Host "  Result: Good security posture" -ForegroundColor Green
    } elseif ($score -ge 60) {
        Write-Host "  Result: Moderate security posture - review failures" -ForegroundColor Yellow
    } else {
        Write-Host "  Result: Poor security posture - immediate action required" -ForegroundColor Red
    }

    Write-Host ""

    if ($Export) {
        $report = "win-sec-audit Report`n"
        $report += "Date: $(Get-Date)`n"
        $report += "Score: $score%`n"
        $report += "Pass: $PassCount  Fail: $FailCount  Warn: $WarnCount`n"
        $report += "=" * 50 + [Environment]::NewLine + [Environment]::NewLine

        foreach ($result in $Results) {
            $report += "[$($result.Status)] $($result.Category) - $($result.Message)`n"
            if ($result.Detail -ne "") {
                $report += "  $($result.Detail)`n"
            }
        }

        $report | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "  Report saved to $OutputPath" -ForegroundColor Cyan
    }
}

# ------- Main -------
Write-Host ""
Write-Host "  ==============================" -ForegroundColor Cyan
Write-Host "  blankenshipSec win-sec-audit" -ForegroundColor Cyan
Write-Host "  Windows Security Auditor" -ForegroundColor Cyan
Write-Host "  ==============================" -ForegroundColor Cyan
Write-Host "  For authorized use only." -ForegroundColor DarkGray
Write-Host ""

# ------ Run All Checks ------
Test-FirewallStatus
Test-WindowsUpdateStatus
Test-GuestAccount
Test-PasswordPolicy
Test-AuditPolicy
Test-UnnecessaryServices
Test-BitLockerStatus

# ------ Display Summary ------
Write-Summary