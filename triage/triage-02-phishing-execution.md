# Triage Report 02 - Office Application Spawning PowerShell

| Field | Value |
|---|---|
| Alert | Office Application Spawning Command or Script Interpreter |
| Rule ID | Custom query rule (Sysmon Event ID 1, parent/child process) |
| Severity | High (Risk 73) |
| Host | DC01 |
| Date/Time | 2026-08-23, ~12:51 UTC |
| Analyst | J. Smith |
| MITRE ATT&CK | T1566 (Phishing), T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell) |

## 1. What fired
The rule fired on a Sysmon Event ID 1 (Process Creation) showing a Microsoft Office
process (`winword.exe`) spawning `powershell.exe`. Office applications do not launch
script interpreters during normal use, so this parent-child relationship is a
high-signal indicator of a malicious macro.

> **Lab note:** to reproduce this safely, `winword.exe` here was a renamed `cmd.exe`
> launching an encoded PowerShell command. That generates the exact
> `winword.exe` to `powershell.exe` telemetry a real malicious macro produces, which is
> what the rule keys on, without running live malware.

## 2. Triage questions
- **What triggered it?** `winword.exe` started `powershell.exe`, the classic
  document-macro-to-execution pattern.
- **Which asset and user?** Host `DC01`. Parent `winword.exe` running from
  `C:\Users\ADMINI~1\AppData\Local\Temp\`, child `powershell.exe` launched with
  `-NoProfile -EncodedCommand <base64>`.
- **Has it happened before?** No. There is no baseline of Office processes spawning
  shells on this host.
- **Corroborating evidence?** The child command line used `-EncodedCommand` (base64),
  a common obfuscation technique for download-and-execute payloads. In a real intrusion,
  an Office process spawning an encoded PowerShell child is the download-and-execute
  fingerprint of a malicious macro.
- **Potential impact?** This is an initial-access and code-execution foothold.
  Encoded PowerShell launched from a document commonly pulls down a next-stage
  payload, so untreated this can lead to persistence and lateral movement.

## 3. Investigation
Reviewed the Sysmon Event ID 1 record: `process.parent.name = winword.exe`,
`process.name = powershell.exe`, with an encoded command line. Decoded the base64
argument to confirm what the command actually does (benign in this lab simulation).
Checked for follow-on activity from the PowerShell process (child processes, network
connections, file writes) to determine whether a second stage executed.

## 4. Verdict
**True positive.** An Office process launched an encoded PowerShell command, matching
the initial-access-to-execution behavior of a phishing macro. (Reproduced in the lab as
noted above; in production this would be treated as a confirmed phishing-execution
attempt.)

## 5. Action
- **Contain:** isolate DC01; capture the originating document/attachment for analysis.
- **Investigate scope:** check the mail gateway for other recipients of the same
  attachment or sender, and block the sender.
- **Escalate:** to Tier 2 if any second-stage activity (downloads, new processes,
  persistence) is confirmed.
- **Technique:** T1566 (Phishing), T1204.002 (User Execution), T1059.001 (PowerShell).
