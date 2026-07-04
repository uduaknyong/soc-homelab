# SOC Homelab — L1 Detection & Investigation

A hands-on Security Operations Center (SOC) Level 1 lab: a real attack is simulated end-to-end,
then investigated from the initial alert through to a formal incident report — using the same
tooling and workflow as a production SOC.

---

## Featured labs

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

### [Lab 02 — Kerberoasting Detection](./lab-02-kerberoasting/) · ✅ Complete

A **SEV3** alert (anomalous Kerberos service-ticket request volume) worked cold: confirm the true
positive, trace the compromised host and the 28 service accounts it targeted, and show why raw
request volume is a misleading signal — the busiest account in the whole dataset was the domain
controller itself. Delivered as a formal incident report mapped to MITRE ATT&CK.

- **Technique:** Kerberoasting (`T1558.003`), Credential Access
- **Key telemetry:** Windows Security `4769`, ticket-encryption (RC4 `0x17`) and request-status analysis
- **Deliverables:**
  [investigation notes](./lab-02-kerberoasting/investigation-notes.md) ·
  [incident report](./lab-02-kerberoasting/incident-report.md) ·
  [SPL query library](./lab-02-kerberoasting/splunk-queries.md)

### [Lab 03 — DCSync Detection](./lab-03-dcsync/) · ✅ Complete

A **SEV2** alert (a burst of sensitive Active Directory object-access events on a domain controller)
worked cold: split the burst by acting account, decode the control-access rights, and confirm a
successful **DCSync** — a non-DC user account exercising Active Directory replication rights to
replicate directory secrets. Shows why "volume" was the wrong lens and identity was the real signal.
Escalated as a domain-wide credential compromise.

- **Technique:** DCSync (`T1003.006`), Credential Access
- **Key telemetry:** Windows Security `4662` control-access, replication-right GUIDs, Audit Success, preceding `4624`
- **Deliverables:**
  [investigation notes](./lab-03-dcsync/investigation-notes.md) ·
  [incident report](./lab-03-dcsync/incident-report.md) ·
  [SPL query library](./lab-03-dcsync/splunk-queries.md)

### [Lab 04 — Pass-the-Hash Detection](./lab-04-pass-the-hash/) · ✅ Complete

A **SEV2** alert (anomalous NTLM network logons in a Kerberos-first environment) triaged to a
confirmed **Pass-the-Hash**: a single account authenticated over NTLM from an unrecognized workstation,
corroborated across two hosts, and proven abnormal against the user's own Kerberos baseline. Scoped an
unrelated failed-brute-force thread with source-IP enrichment, then raised the severity and escalated.

- **Technique:** Pass-the-Hash (`T1550.002`), Lateral Movement
- **Key telemetry:** Windows Security `4624` / `4625`, Logon Type 3, NTLM-vs-Kerberos and workstation-name analysis
- **Deliverables:**
  [investigation notes](./lab-04-pass-the-hash/investigation-notes.md) ·
  [incident report](./lab-04-pass-the-hash/incident-report.md) ·
  [SPL query library](./lab-04-pass-the-hash/splunk-queries.md)

---

## Skills demonstrated

- Alert triage and scoping from a single starting alert
- Splunk / SPL investigation and timeline reconstruction
- Windows authentication analysis: logon types, Kerberos (`4769`), NTLM vs Kerberos, DCSync (`4662`) and Pass-the-Hash (`4624`/`4625`)
- Distinguishing malicious activity from a legitimate baseline (the recurring lesson across every lab)
- Source-IP / IOC enrichment with threat intelligence
- MITRE ATT&CK technique mapping
- Incident reporting for both technical and non-technical audiences

---

## Lab environment

Lab 01 was investigated on a small, isolated cloud lab — a Windows Server 2022 domain controller
(`soclab.local`) as the monitored endpoint, a separate attacker host, and a dedicated Splunk SIEM
aggregating Sysmon and Windows Event telemetry. Labs 02–04 use real public attack telemetry (the
[splunk/attack_data](https://github.com/splunk/attack_data) project) ingested into a self-hosted
Splunk instance, so the work centres on the analysis rather than on standing up infrastructure.
Live infrastructure details and credentials are intentionally not published.

---

*More labs in progress — broadening L1 alert-triage coverage across the major alert categories an
analyst sees day to day: email (phishing), identity, endpoint, and network.*
