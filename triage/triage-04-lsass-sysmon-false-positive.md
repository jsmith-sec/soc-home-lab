# Triage Report 04 - LSASS Access Surge from Sysmon (False Positive)

| Field | Value |
|---|---|
| Alert | Credential Dumping - LSASS Memory Access |
| Rule ID | Custom query rule (Sysmon Event ID 10) |
| Severity | Critical (Risk 90) |
| Host | DC01 |
| Date/Time | 2026-08-24, ~19:32 UTC (during lateral-movement testing) |
| Analyst | J. Smith |
| MITRE ATT&CK | T1003.001 (rule intent); this instance benign |

## 1. What fired
A sudden surge of about 104 Critical LSASS credential-dumping alerts fired within
roughly one second, all from the same rule and host. Alert volume alone was the first
red flag: a real credential dump is a handful of accesses, not a hundred in a second.

## 2. Triage questions
- **What triggered it?** 104 near-simultaneous alerts on the LSASS rule.
- **Which asset and user?** Host `DC01`. Highlighted fields showed
  `process.executable: C:\Windows\Sysmon64.exe` and `process.name: Sysmon64.exe`.
- **Has it happened before?** Not at this volume. The spike lined up with authorized
  lateral-movement testing (a wmiexec logon), which caused a burst of process activity
  that Sysmon then inspected.
- **Corroborating evidence?** The source is the **signed Sysmon binary** in
  `C:\Windows`, the endpoint's own monitoring agent, not an external tool. There was no
  procdump, Mimikatz, or unknown process in the surge.
- **Potential impact?** None. This is the monitoring tool inspecting processes as part
  of normal operation.

## 3. Investigation
Reviewed the alert's highlighted fields and found every event in the surge had
`Sysmon64.exe` as the source process accessing `lsass.exe`. Root cause: Sysmon opens
handles to processes (including lsass) to generate its ProcessAccess telemetry. Because
the Sysmon configuration was tuned to log **all** access to lsass (see Triage Report 01),
Sysmon's own inspection access is also captured, and its access mask falls within the
rule's dumping-mask list. In effect, the sensor watching lsass trips the rule that
watches lsass. Confirmed no attacker tooling was present in the surge.

## 4. Verdict
**False positive.** The endpoint's monitoring agent (Sysmon) accessing lsass during
normal operation, not credential dumping.

## 5. Action
- **Close** all 104 alerts as benign (bulk-closed after filtering to
  `process.name : "Sysmon64.exe"` so real detections were not touched).
- **Tune the rule:** add `and not process.name : ("Sysmon64.exe" or "Sysmon.exe")` so
  the sensor's own access no longer alerts. This is the second tuning iteration on this
  rule: Report 01/03 filtered benign low-access reads by access mask, this filters the
  monitoring agent by source.
- **Lesson:** when you instrument a sensor to watch a sensitive process, the sensor's
  own access can create a feedback false positive. Known-good infrastructure sources
  should be excluded from the detection.
