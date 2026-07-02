# Lab 03 — DCSync Detection (T1003.006)

> Status: Complete

An investigation lab built on real Windows attack telemetry from the
[splunk/attack_data](https://github.com/splunk/attack_data) project, ingested into a self-hosted
Splunk instance. The goal is to take a single SOC alert end to end: triage it in Splunk, confirm or
deny it, scope the activity, and write it up as a formal incident report mapped to MITRE ATT&CK.

| Technique | MITRE ATT&CK | Status |
|-----------|--------------|--------|
| DCSync | T1003.006 (Credential Access — OS Credential Dumping) | Confirmed true positive |

Workflow: orient on the dataset, run down the alert with SPL, build the timeline and IOCs, reach a
verdict, map the technique to ATT&CK, and write the incident report.

## Lab environment

| | |
|---|---|
| SIEM | Splunk Enterprise 10.4.0 (single GCP VM, `splunk-lab`) |
| Access | IAP tunnel to `http://localhost:8000` |
| Index | `dcsync` (sourcetype `dcsync:winxml`) |
| Data | Windows Security event logs from a domain controller (Event IDs 4662 / 4624) |
| Time range | Events are dated 2024-01-05. Set the time picker to **All time** or the search returns nothing. |

## The alert

> **[SEV2] Sensitive Active Directory Object Access on Domain Controller**
> Source host: `AR-WIN-DC` (Domain Controller, `ATTACKRANGE.LOCAL`)
> Trigger: the DC's security log shows a burst of directory-service object-access events
> (Event ID 4662) against the domain root object within a narrow window early on 2024-01-05.
> The control-access rights referenced and the volume are outside the rolling baseline.

A Tier-1 analyst picks this up cold. Working from the alert alone: true positive or benign? If
malicious, what technique and goal, which account and host, and what was accessed? What separates
the suspicious activity from legitimate directory-service access on a domain controller?

## Files

| File | Description |
|------|-------------|
| [investigation-notes.md](./investigation-notes.md) | Working notes: SPL queries, findings, timeline, IOCs, verdict |
| [incident-report.md](./incident-report.md) | Formal incident report submitted after triage |
| [splunk-queries.md](./splunk-queries.md) | Reusable SPL query library from this lab |
| [LEARN-resources.md](./LEARN-resources.md) | Curated reading to go deeper on DCSync & AD replication |
| [evidence/](./evidence/) | Screenshots captured during the investigation |

## Outcome

Confirmed true positive: DCSync (T1003.006). A burst of 16 directory-service access events
(Event ID 4662) on the domain controller resolved into two very different stories. Six were the DC's
own machine account (`AR-WIN-DC$`) performing normal Active Directory replication. Those were benign,
and I cleared them. The other ten were the `Administrator` user account exercising AD replication
extended rights (`DS-Replication-Get-Changes` / `-Get-Changes-All`) against the domain root. That is
something only a domain controller should ever do.

The replication was launched remotely. A Type 3 NTLM network logon as `Administrator` from `10.0.1.15`
at 2024-01-05 06:05:57 UTC was immediately followed by the replication requests, and the DC granted
them (all events Audit Success). Object access spanned User and Computer account objects at the domain
(Domain-DNS) level, so the attacker could replicate the secrets of every principal in the domain. That
includes the `krbtgt` hash, the key to forging Golden Tickets. The incident was escalated as a
successful domain-wide credential compromise (assume-breach).

One thing worth noting from the investigation: the alert's "volume" framing was a red herring. The
busiest pattern of replication access is normal for a domain controller. The real discriminator was
who was doing it, a non-DC user account using replication rights, not the count of events.
