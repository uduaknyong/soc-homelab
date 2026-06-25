# SOC Homelab — L1 Detection & Investigation

A hands-on Security Operations Center (SOC) Level 1 lab: a real attack is simulated end-to-end,
then investigated from the initial alert through to a formal incident report — using the same
tooling and workflow as a production SOC.

---

## Featured lab

### [Lab 01 — Phishing → Credential Compromise](./lab-01-phishing-credential-compromise/) · ✅ Complete

A **SEV3** alert (repeated failed logons followed by a success from the same source) is triaged
from scratch: scope the activity in Splunk, identify the compromised account, build a timeline,
and deliver a formal incident report with IOCs and response recommendations.

- **Techniques:** Password Spraying (`T1110.003`), Valid Accounts (`T1078`), Type 3 network logon
- **Key telemetry:** Windows Security `4625` / `4624`, logon-type analysis
- **Deliverables:**
  [investigation notes](./lab-01-phishing-credential-compromise/investigation-notes.md) ·
  [incident report](./lab-01-phishing-credential-compromise/incident-report.md) ·
  [SPL query library](./lab-01-phishing-credential-compromise/splunk-queries.md)

---

## Skills demonstrated

- Alert triage and scoping from a single starting alert
- Splunk / SPL investigation and timeline reconstruction
- Windows authentication & logon-type analysis (Type 3 / NTLM)
- MITRE ATT&CK technique mapping
- Incident reporting for both technical and non-technical audiences

---

## Lab environment

Lab 01 was investigated on a small, isolated cloud lab — a Windows Server 2022 domain controller
(`soclab.local`) as the monitored endpoint, a separate attacker host, and a dedicated Splunk SIEM
aggregating Sysmon and Windows Event telemetry. Live infrastructure details and credentials are
intentionally not published.

---

*More SOC projects — identity-attack detection, phishing triage automation, and endpoint
detection-as-code — are in progress and will land in their own repositories.*
