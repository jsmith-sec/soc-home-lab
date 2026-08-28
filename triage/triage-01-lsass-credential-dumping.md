# Triage Report 01 - Credential Dumping (LSASS Memory Access)

| Field | Value |
|---|---|
| Alert | Credential Dumping - LSASS Memory Access |
| Rule ID | Custom query rule (Sysmon Event ID 10, GrantedAccess mask) |
| Severity | Critical (Risk 90) |
| Host | DC01 (domain controller) |
| Date/Time | 2026-08-23, ~14:38 UTC |
| Analyst | J. Smith |
| MITRE ATT&CK | T1003.001 (OS Credential Dumping: LSASS Memory) |

## 1. What fired
The rule fired on a Sysmon Event ID 10 (ProcessAccess) showing a process opening
`lsass.exe` with `GrantedAccess: 0x1fffff` (PROCESS_ALL_ACCESS, which includes the
memory-read rights required to dump credentials).

## 2. Triage questions
- **What triggered it?** A process requested full access to lsass memory, an access
  mask that credential-dumping tools use and that legitimate processes almost never
  request.
- **Which asset and user?** Host `DC01` (a domain controller, so high value).
  SourceImage `procdump64.exe` (PID 5904), SourceUser `ADLAB\Administrator`.
- **Has it happened before?** No. Baseline access to lsass on this host is limited
  to benign `0x1000` / `0x1400` reads from the Elastic agent and VBoxService. This
  `0x1fffff` access is a clear outlier (about 0.2 percent of all lsass access).
- **Corroborating evidence?** The event CallTrace includes `dbgcore.dll`
  (MiniDumpWriteDump), consistent with a memory dump. A `lsass.dmp` file was written
  to `C:\Windows\Temp` and then removed. Windows Defender real-time protection was
  disabled shortly before the event, a defense-evasion precursor (T1562.001).
- **Potential impact?** A full LSASS dump on a domain controller can expose cached
  credentials, password hashes, and Kerberos tickets, enabling domain-wide lateral
  movement and privilege escalation.

## 3. Investigation
Queried Sysmon Event ID 10 in Kibana and confirmed `procdump64.exe` accessing
`lsass.exe` (TargetProcessId 596) with `0x1fffff`. Compared against the access-mask
distribution for the host: 93 percent of lsass access is benign `0x1000`, so the
`0x1fffff` request stands out immediately. Reviewed the CallTrace (dbgcore.dll,
MiniDumpWriteDump) which confirms a memory-dump operation rather than a routine
query. Noted the preceding Defender real-time-protection change as part of the same
activity window.

## 4. Verdict
**True positive.** A process performed a memory dump of LSASS on a domain
controller using an access mask specific to credential theft, preceded by disabling
endpoint protection. (In this lab the action was an intentional simulation using
procdump; in production this would be treated as a confirmed credential-dumping
attempt.)

## 5. Action
- **Contain:** isolate DC01 from the network; suspend the involved account.
- **Remediate:** given a domain controller is affected, force a domain-wide
  credential reset, including resetting the krbtgt account twice, and rotate any
  service-account credentials that may have been cached.
- **Escalate:** immediately to Tier 2 / Incident Response. Credential access on a
  DC is a high-severity, time-sensitive event.
- **Technique:** T1003.001 (LSASS Memory), with T1562.001 (Impair Defenses) as a
  related precursor.
