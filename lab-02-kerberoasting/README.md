# Lab 02 — Kerberoasting Detection (T1558.003)

An investigation lab built on real Windows attack telemetry from the
[splunk/attack_data](https://github.com/splunk/attack_data) project, ingested into a self-hosted
Splunk instance. The goal is to take a single SOC alert end to end: triage it in Splunk, confirm or
deny it, scope the attack, and write it up as a formal incident report mapped to MITRE ATT&CK.

| Technique | MITRE ATT&CK | Status |
|-----------|--------------|--------|
| Kerberoasting | T1558.003 (Credential Access) | Complete |

Workflow: orient on the dataset, run down the alert with SPL, build the timeline and IOCs, reach a
verdict, map the technique to ATT&CK, and write the incident report.

## Lab environment

| | |
|---|---|
| SIEM | Splunk Enterprise 10.4.0 (single GCP VM, `splunk-lab`) |
| Access | IAP tunnel to `http://localhost:8000` |
| Index | `kerberoast` (sourcetype `kerberoast:winxml`) |
| Data | Windows Security event logs, EventID 4769 (160 events) |
| Time range | Events are dated Feb–Apr 2024. Set the time picker to All time or the search returns nothing. |

## The alert

> [SEV3] Anomalous Kerberos Service-Ticket Request Volume
> Source host: `AR-WIN-DC` (Domain Controller, `ATTACKRANGE.LOCAL`)
> Trigger: a single internal host requested Kerberos service tickets (TGS) at a volume well above
> the rolling baseline. Several requests reference service principals that do not map to known
> services.

A Tier-1 analyst picks this up cold. Working from the alert alone: true positive or benign? If
malicious, what technique and goal, which account and host, and what was targeted? What separates
the malicious traffic from legitimate Kerberos activity, and what detection should be deployed?

## Files

| File | Description |
|------|-------------|
| [investigation-notes.md](./investigation-notes.md) | Working notes: SPL queries, findings, timeline, IOCs, verdict |
| [incident-report.md](./incident-report.md) | Formal incident report submitted after triage |
| [splunk-queries.md](./splunk-queries.md) | Reusable SPL query library from this lab |
| [evidence/](./evidence/) | Screenshots captured during the investigation |

## Outcome

Confirmed true positive: Kerberoasting. A compromised host (`AR-WIN-2`, operating as machine account
`AR-WIN-2$`) requested Kerberos service tickets for 28 distinct service accounts, forcing RC4
encryption on every request. The DC granted all of them (Status 0x0), so the attack succeeded.
Activity ran low and slow over about four days (2024-02-29 to 2024-03-04), which would defeat any
short-window volume rule.

A useful observation from the investigation: raw request volume was a misleading signal, since the
single busiest account in the dataset was the Domain Controller itself. What actually set the
attacker apart was the variety of services touched, 25 distinct services in a day versus 2 for the
high-volume but low-variety DC.
