# 🛡️ win-sec-audit

> A PowerShell security tool that audits Windows systems against hardening best practices, scoring your security posture and surfacing misconfigurations.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Built by [blankenshipSec](https://github.com/blankenshipSec) | [Portfolio](https://jblankenship.me)

## ✨ Features

- **Firewall Audit** — Checks Domain, Private, and Public firewall profile status
- **Windows Update** — Verifies Windows Update service is running
- **Guest Account** — Checks if the Guest account is enabled
- **Password Policy** — Audits minimum password length and account lockout threshold
- **Audit Policy** — Verifies logon and account management auditing is configured
- **Unnecessary Services** — Checks for risky services that should be disabled
- **BitLocker** — Checks drive encryption status on all volumes
- **Scoring** — Calculates an overall security posture score with PASS/FAIL/WARN results
- **Export** — Saves a full audit report to a text file

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1 or PowerShell 7+
- Administrator privileges for accurate results

## 🚀 Installation
```powershell
git clone git@github.com:blankenshipSec/win-sec-audit.git
cd win-sec-audit
```

## 🛠️ Usage

> ⚠️ Must be run as Administrator for accurate audit results.
```powershell
# Basic audit
.\auditor.ps1

# Show detailed output for each check
.\auditor.ps1 -Detailed

# Export report to file
.\auditor.ps1 -Export

# Export report to custom path
.\auditor.ps1 -Export -OutputPath "C:\reports\audit.txt"

# Combine flags
.\auditor.ps1 -Detailed -Export
```

## 📊 Example Output
```
  ==============================
  blankenshipSec win-sec-audit
  Windows Security Auditor
  ==============================
  For authorized use only.

  Windows Firewall
  ----------------
  [PASS] Firewall - Domain profile is enabled
  [PASS] Firewall - Private profile is enabled
  [PASS] Firewall - Public profile is enabled

  Windows Update
  --------------
  [WARN] Windows Update - Windows Update service is not running

  Password Policy
  ---------------
  [FAIL] Password Policy - Minimum password length is 0 - too short
  [PASS] Password Policy - Account lockout is configured at 10 attempts

  ============================
  Audit Complete
  ============================

  Score:  79%
  Pass:   11
  Fail:   1
  Warn:   2

  Result: Moderate security posture - review failures
```

## 🔍 Checks Reference

| Check | Tool/Cmdlet | Requires Admin |
|-------|-------------|----------------|
| Firewall status | `Get-NetFirewallProfile` | No |
| Windows Update | `Get-Service` | No |
| Guest account | `Get-LocalUser` | No |
| Password policy | `net accounts` | No |
| Audit policy | `auditpol` | Yes |
| Unnecessary services | `Get-Service` | No |
| BitLocker | `Get-BitLockerVolume` | Yes |

## 🎯 Scoring

| Score | Result |
|-------|--------|
| 80%+ | Good security posture |
| 60–79% | Moderate security posture — review failures |
| Below 60% | Poor security posture — immediate action required |

## ⚠️ Known Limitations & Roadmap

### Current Limitations
- BitLocker check may timeout on some configurations
- Password policy check reads local policy only — not domain GPO
- Requires UTF-8 with BOM encoding for PowerShell 5.1 compatibility

### Planned Improvements
- [ ] Add RDP status check
- [ ] Add Windows Defender status check
- [ ] Add SMB signing check
- [ ] Add domain GPO password policy support
- [ ] Add HTML report export

## ⚖️ Legal Disclaimer

This tool is intended for **authorized security auditing and educational purposes only**.
Always obtain proper authorization before auditing systems you do not own.
The author assumes no liability for misuse of this tool.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

*Built with PowerShell | [blankenshipSec](https://github.com/blankenshipSec)*