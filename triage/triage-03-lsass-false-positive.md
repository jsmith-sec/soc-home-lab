# Triage Report 03 - Benign LSASS Access (False Positive)

| Field | Value |
|---|---|
| Alert | Credential Dumping - LSASS Memory Access |
| Rule ID | Custom query rule (Sysmon Event ID 10) - early iteration |
| Severity | Critical (Risk 90) |
| Host | DC01 |
| Date/Time | 2026-08-23 (during rule development) |
| Analyst | J. Smith |
| MITRE ATT&CK | T1003.001 (rule intent); this instance benign |

## 1. What fired
An early version of the LSASS detection alerted on a Sysmon Event ID 10 where
`agentbeat.exe` accessed `lsass.exe`. This is a good example of why access to lsass
alone is not enough to alert on, the access rights matter.

## 2. Triage questions
- **What triggered it?** A process accessed `lsass.exe`, and the initial rule flagged
  any access to lsass regardless of the requested rights.
- **Which asset and user?** Host `DC01`. SourceImage
  `C:\Program Files\Elastic\Agent\...\agentbeat.exe` (the Elastic Agent),
  SourceUser `NT AUTHORITY\SYSTEM`, `GrantedAccess: 0x1000`.
- **Has it happened before?** Yes, constantly. `agentbeat.exe` queries lsass every
  few seconds. A recurring, high-frequency pattern from a signed security agent points
  to routine software behavior, not an attack.
- **Corroborating evidence?** `0x1000` is `PROCESS_QUERY_LIMITED_INFORMATION`, which
  does **not** include the memory-read rights (`PROCESS_VM_READ`) needed to dump
  credentials. The CallTrace points back into agentbeat, with no `dbgcore.dll` /
  MiniDump activity. The binary is the expected, signed Elastic Agent.
- **Potential impact?** None. This is legitimate endpoint-agent telemetry.

## 3. Investigation
Confirmed the SourceImage is the signed Elastic Agent. Examined the access mask:
`0x1000` cannot read process memory, so a credential dump is not possible with it.
Compared against the confirmed-malicious pattern (`0x1fffff` plus a `dbgcore.dll`
MiniDump CallTrace). Reviewed the access-mask distribution for the host: about 93
percent of lsass access is this benign `0x1000` query. All evidence points to normal
agent operation.

## 4. Verdict
**False positive.** Legitimate Elastic Agent process-information query, not
credential dumping.

## 5. Action
- **Close** the alert as benign, no escalation.
- **Tune the detection:** restrict the rule to the memory-read access masks
  (`0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`) so routine `0x1000` / `0x1400`
  queries no longer generate alerts. This removed the noise while preserving detection
  of a real LSASS dump (see Triage Report 01).
- **Outcome:** false-positive rate on this rule dropped to near zero, and the rule now
  fires only on the access masks that credential-dumping tools request.
