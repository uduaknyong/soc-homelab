# Lab 04 — Pass-the-Hash — Investigation Notes

> Working notes written live during triage. Queries, findings, timeline, IOCs, and verdict.

## Alert

[SEV2] Anomalous NTLM Network Authentication — NTLM (Logon Type 3) logons flagged in a Kerberos-first
environment across the retained Windows security logs. Notable `NTLM-ANOM-2607031042`, MITRE T1550.002,
playbook PB-CRED-014.

## 0. Orientation

Before chasing the alert, get the lay of the index — what event types, which hosts, what time span.

```spl
index=passthehash | stats count by EventCode host
```

- ~10 hosts in the data. **Two dominate** — `destDeviceA` and `observerDeviceA` — both carrying a large
  volume of **4624** (successful logon). That is the baseline of normal here.
- A scatter of other Security event codes across the remaining low-volume hosts.
- Data spans **2019-01-09/10** and **2020-10-15** (searched at All time).

The point of orienting first: know what "normal" looks like before deciding what is abnormal.

## 1. Triage the alert — is NTLM really an outlier here?

The alert is about NTLM in a Kerberos-first shop, so break the logons down by the protocol that handled
them. `Logon_Process` names the subsystem (`Kerberos`, `NtLmSsp` = NTLM, `Seclogo` = Secondary Logon).

```spl
index=passthehash EventCode=4624 | stats count by Logon_Process
```

| Logon_Process | count |
|---|---|
| Kerberos | 235 |
| **NtLmSsp** (NTLM) | **5** |
| Seclogo (Secondary Logon) | 1 |

Kerberos is the wallpaper; **5 NTLM logons are the outlier** the alert is built to catch. Small enough
to inspect by hand.

## 2. Who and what — the successful NTLM logons

Filter to the successful NTLM logons and lay out who / from where.

```spl
index=passthehash Logon_Process=NtLmSsp EventCode=4624
| table _time host Account_Name Source_Network_Address Workstation_Name Logon_Type
```

| _time | host | Account_Name | Source_Network_Address | Workstation_Name | Logon_Type |
|---|---|---|---|---|---|
| 2019-01-09 09:20:30 | observerDeviceA | userA | *(blank)* | **SZUFS** | 3 |
| 2019-01-09 09:20:30 | destDeviceA | userA | *(blank)* | **SZUFS** | 3 |

Reading it:
- **Identical timestamp, same account, same workstation, two hosts** → this is **one logon seen twice**:
  once by the destination (`destDeviceA`) and once by an observer (`observerDeviceA`). Two independent
  logs of the same event = it is real, corroborated, not a logging artifact.
- **Logon Type 3** = network logon — matches the alert exactly.
- **`Source_Network_Address` is blank** — normal for NTLM network logons; the source IP often is not
  populated, so pivot to the next identifier: the workstation name.
- **`Workstation_Name = SZUFS`** — an out-of-place machine name that does not match the estate. An
  unfamiliar workstation riding an NTLM logon is a classic Pass-the-Hash fingerprint.

## 3. Know normal — is NTLM abnormal *for this user*?

Something is only abnormal once you measure the user's own baseline.

```spl
index=passthehash Account_Name=userA | stats count by Logon_Process
```

| Logon_Process | count |
|---|---|
| Kerberos | 216 |
| NtLmSsp (NTLM) | 2 |

`userA` authenticates with **Kerberos essentially always** (216) and NTLM only twice — and those 2 NTLM
events are the *same* logon seen on two hosts. So in this user's entire history there is effectively
**one** out-of-character authentication. NTLM is abnormal for `userA`. This is the discriminator between
a true positive and noise.

## 4. Scope — is userA the whole story?

The whole-index count showed NTLM = 5, but grouping by account only showed 2 (userA). `stats count by
<field>` silently drops events where that field is empty, so 3 NTLM events with a blank account were
hidden. Regroup by fields that are always populated (`EventCode`, `host`) to recover all 5.

```spl
index=passthehash Logon_Process=NtLmSsp | stats count by EventCode host
```

| EventCode | host | count |
|---|---|---|
| 4624 (success) | destDeviceA | 1 |
| 4624 (success) | observerDeviceA | 1 |
| **4625 (fail)** | **win-dc-800** | **3** |

The 3 hidden events are **failed** NTLM logons on a host not seen before, `win-dc-800`. A second thread.

## 5. The failed thread — win-dc-800

```spl
index=passthehash Logon_Process=NtLmSsp
| table _time Account_Name EventCode host Logon_Type Source_Network_Address Workstation_Name
```

| _time | Account | EventCode | host | Src IP | Workstation |
|---|---|---|---|---|---|
| 2019-01-09 09:20:30 | userA | 4624 | destDeviceA | – | SZUFS |
| 2019-01-09 09:20:30 | userA | 4624 | observerDeviceA | – | SZUFS |
| 2020-10-15 12:17:28 | *(blank)* | 4625 | win-dc-800 | 212.129.6.106 | – |
| 2020-10-15 12:19:44 | *(blank)* | 4625 | win-dc-800 | 212.129.6.106 | – |
| 2020-10-15 12:21:59 | *(blank)* | 4625 | win-dc-800 | 212.129.6.106 | – |

Two things separate this from the userA logon:
- **Time.** The successes are **January 2019**; these failures are **October 2020** — 21 months later,
  different host, different (blank) account, different source. **These are two unrelated incidents that
  happen to share the index.** Do not merge them into one story.
- **Outcome + origin.** All three are **4625 (failed)**, from a **public/external** IP
  `212.129.6.106`, ~2 minutes apart — consistent with opportunistic remote credential attempts that
  were rejected.

Did the external attempts ever succeed? Checking win-dc-800 for successes vs failures:

```spl
index=passthehash host="win-dc-800" EventCode IN (4624,4625)
| table _time EventCode Account_Name Source_Network_Address Logon_Type | sort _time
```

No successful logon originated from `212.129.6.106` — every event from that IP is a 4625 failure.

**Enrichment (source IP).** `212.129.6.106` — **no detections on VirusTotal**, **0% abuse confidence on
AbuseIPDB**. No known-bad reputation. Combined with "all attempts failed," Thread B is low-priority,
unsuccessful external authentication. Recorded here because a checked-and-clean result still belongs in
the ticket. (Lab caveat: data is synthetic, so a clean reputation is expected; the point is the
pivot-to-threat-intel workflow on any external IOC.)

## 6. Timeline

| Time | Event | Account | Host | Detail |
|---|---|---|---|---|
| 2019-01-09 09:20:30 | 4624 (Type 3, NTLM) | `userA` | destDeviceA + observerDeviceA | **Pass-the-Hash** — successful NTLM network logon, workstation `SZUFS`, seen by destination and observer |
| 2020-10-15 12:17:28 | 4625 (Type 3, NTLM) | *(blank)* | win-dc-800 | Failed NTLM logon from external `212.129.6.106` |
| 2020-10-15 12:19:44 | 4625 (Type 3, NTLM) | *(blank)* | win-dc-800 | Failed NTLM logon from external `212.129.6.106` |
| 2020-10-15 12:21:59 | 4625 (Type 3, NTLM) | *(blank)* | win-dc-800 | Failed NTLM logon from external `212.129.6.106` |

## 7. IOCs

- **Compromised/abused account:** `userA`
- **Attacker-controlled workstation name:** `SZUFS`
- **Affected hosts (PtH):** `destDeviceA` (destination), `observerDeviceA` (observer)
- **Time (PtH):** 2019-01-09 09:20:30
- **Technique:** Pass-the-Hash — T1550.002 (Use Alternate Authentication Material)
- **Telemetry signature:** Event 4624, Logon Type 3, `Logon_Process=NtLmSsp` in a Kerberos-first
  environment, with an unrecognized `Workstation_Name`
- **Secondary (separate, failed):** external IP `212.129.6.106` → 3× Event 4625 on `win-dc-800`,
  2020-10-15 (no known-bad reputation, all failed)

## 8. Verdict

**True positive — Pass-the-Hash (T1550.002), successful.** `userA` was authenticated over **NTLM**
(Logon Type 3) from an unrecognized workstation (`SZUFS`) in an environment where the user — and the
environment — authenticate with Kerberos by default. The logon **succeeded** (Event 4624) and was
corroborated by two independent hosts. NTLM here is not typed credentials; it is a hash being **replayed**.

**Severity: High. Escalate to L2 / IR.** This is a confirmed successful credential-replay lateral-movement
event. Severity is **High rather than Critical** because the confirmed scope is one account on one
destination and the privilege level of `userA`/the machine is not yet established. Depending on the
rights that account and host hold, the replayed hash can be used to move to other devices on the network
— so it is escalated to L2 to determine blast radius (is `userA` privileged? did `SZUFS` touch other
hosts?), not closed.

**Secondary observation (handed up, not investigated at L1):** while scoping the NTLM alert, the same
index showed unrelated failed external NTLM attempts on `win-dc-800` (Oct 2020, source clean on TI, all
rejected). Additionally, `win-dc-800` produced explicit-credential (4648) and privileged (4672) logon
events unrelated to this alert — **recommend L2/IR review** for possible lateral movement on that host.
Pursuing it is threat-hunting, outside the L1 alert-triage mandate.
