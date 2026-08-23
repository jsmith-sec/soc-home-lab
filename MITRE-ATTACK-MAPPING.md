# MITRE ATT&CK Coverage: SOC/SIEM Detection Lab

Detection rules built in this lab, mapped to MITRE ATT&CK. Every rule is a
custom detection written from scratch and validated against a live simulated
attack on the DC01 Windows endpoint.

## Detection-to-technique mapping

| # | Detection Rule | Tactic | Technique | ID | Log Source | Severity |
|---|---|---|---|---|---|---|
| 1 | Office Application Spawning Command or Script Interpreter | Initial Access / Execution | Phishing, User Execution: Malicious File, PowerShell | T1566, T1204.002, T1059.001 | Sysmon EID 1 | High |
| 2 | Registry Run Key Persistence | Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 | Sysmon EID 13 | Medium |
| 3 | New Windows Service Installed | Persistence | Create or Modify System Process: Windows Service | T1543.003 | Windows System EID 7045 | High |
| 4 | Scheduled Task Created via schtasks.exe | Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Sysmon EID 1 | Medium |
| 5 | Credential Dumping: LSASS Memory Access | Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Sysmon EID 10 | Critical |
| 6 | Windows Security Event Log Cleared | Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | Windows Security EID 1102 | High |

## Tactic coverage (Windows endpoint)

| ATT&CK Tactic | Covered | By |
|---|---|---|
| Initial Access (TA0001) | Yes | Rule 1 |
| Execution (TA0002) | Yes | Rule 1 |
| Persistence (TA0003) | Yes | Rules 2, 3, 4 |
| Defense Evasion (TA0005) | Yes | Rule 6 |
| Credential Access (TA0006) | Yes | Rule 5 |

## Attack chain represented

The detections cover a realistic intrusion end to end:

Phishing macro (T1566) to PowerShell execution (T1059.001) to persistence via
Run key / service / scheduled task (T1547.001, T1543.003, T1053.005) to
credential dumping from LSASS (T1003.001) to log clearing to cover tracks
(T1070.001).

## Detection engineering notes

- Rules key on **behavior**, not file hashes. For example, LSASS access is
  detected by the requested access mask (0x1fffff and other memory-read masks),
  which separates a real dump from the roughly 93% background noise of benign
  0x1000 and 0x1400 reads.
- The LSASS detection required **tuning the Sysmon config**: the SwiftOnSecurity
  ProcessAccess (EID 10) section shipped empty, so lsass access was invisible
  until a TargetImage rule was added. A real sensor visibility gap, found and
  closed.

## Also present from the original lab (Linux / auth)

| Detection | Tactic | Technique | ID |
|---|---|---|---|
| SSH Brute Force | Credential Access | Brute Force | T1110 |
| Suspicious Account Creation/Modification | Persistence | Create Account | T1136 |
