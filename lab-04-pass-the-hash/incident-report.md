# Incident Report — INC-2026-0704-01

| | |
|---|---|
| **Incident ID** | INC-2026-0704-01 |
| **Source notable** | `NTLM-ANOM-2607031042` — Windows Anomalous NTLM Network Logon (Possible Pass-the-Hash) |
| **Title** | Successful Pass-the-Hash — NTLM credential replay against `userA` |
| **Severity** | **High** (raised from SEV2/Medium on confirmation) |
| **Status** | Confirmed true positive — escalated to L2 / Incident Response |
| **Analyst** | Tier-1 SOC |
| **Playbook** | PB-CRED-014 |
| **Technique** | MITRE ATT&CK **T1550.002** — Use Alternate Authentication Material: Pass-the-Hash (Lateral Movement) |
| **Affected account** | `userA` |
| **Affected hosts** | `destDeviceA` (destination), `observerDeviceA` (observer) |
| **Activity time** | 2019-01-09 09:20:30 |

## 1. Summary

The `NTLM-ANOM` notable fired for anomalous NTLM network logons in an otherwise Kerberos-first
environment. Triage confirmed a **successful Pass-the-Hash**: the account `userA` was authenticated over
**NTLM** (Event 4624, Logon Type 3) from an unrecognized workstation named **`SZUFS`**. The same logon
was recorded by two independent hosts — the destination (`destDeviceA`) and an observer
(`observerDeviceA`) — confirming it is a real authentication, not a logging artifact. `userA`'s own
history is 216 Kerberos logons to 2 NTLM (and those 2 are this single event seen twice), so NTLM is
firmly out of character for the user. NTLM authentication that is *replayed* rather than typed, from a
machine name that does not belong to the estate, is the signature of Pass-the-Hash.

A second, **unrelated** cluster of NTLM activity in the same index (3 failed logons on `win-dc-800` from
an external IP, 21 months later) was scoped, enriched, and cleared as failed opportunistic attempts —
see §7.

## 2. Severity justification

Raised from the initial **SEV2 / Medium** to **High** because: (a) the activity is a confirmed
credential-replay attack, not a misconfiguration; (b) it **succeeded** (Event 4624); and (c) Pass-the-Hash
is a lateral-movement primitive — the replayed hash can be reused against other systems.

Held at **High rather than Critical** because the confirmed scope is a single account on a single
destination, and the privilege level of `userA` (and the rights the source machine holds) is **not yet
established**. If L2 confirms `userA` is privileged or that `SZUFS` reached additional hosts, the
incident should be re-rated Critical.

## 3. Timeline

| Time | Event | Account | Host | Detail |
|---|---|---|---|---|
| 2019-01-09 09:20:30 | 4624 (Type 3, NTLM) | `userA` | destDeviceA | Successful NTLM network logon, workstation `SZUFS` — **Pass-the-Hash** (destination view) |
| 2019-01-09 09:20:30 | 4624 (Type 3, NTLM) | `userA` | observerDeviceA | Same logon, corroborated (observer view) |

## 4. Findings (evidence chain)

1. **NTLM is an outlier here.** Across all logons, protocol split is Kerberos 235 vs NTLM 5 — Kerberos
   is the norm, NTLM the exception.
2. **The successful NTLM logon.** Filtering to successful NTLM (4624) returns `userA`, Logon Type 3,
   workstation **`SZUFS`**, at 2019-01-09 09:20:30, recorded on **two hosts** at the identical
   timestamp = one corroborated event.
3. **Unrecognized workstation.** `Workstation_Name = SZUFS` does not match the estate; the source IP is
   blank (normal for NTLM), so the workstation name is the identifying artifact — a classic PtH tell.
4. **Abnormal for the user.** `userA` baseline is 216 Kerberos to 2 NTLM (the 2 being this event seen
   twice) — a single out-of-character authentication in the user's entire history.
5. **It succeeded.** Event 4624 (not 4625) — this is a completed logon, not a blocked attempt.

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Account abused | `userA` |
| Attacker-controlled workstation name | `SZUFS` |
| Affected hosts | `destDeviceA`, `observerDeviceA` |
| Time | 2019-01-09 09:20:30 |
| Technique | T1550.002 (Pass-the-Hash) |
| Telemetry signature | Event 4624, Logon Type 3, `Logon_Process=NtLmSsp` in a Kerberos-first environment, unrecognized `Workstation_Name` |

## 6. Impact assessment

An attacker holding `userA`'s NTLM hash successfully authenticated to `destDeviceA` without ever
knowing the plaintext password. Pass-the-Hash establishes a foothold and a lateral-movement capability:
the same hash can be replayed against any system that accepts NTLM for that account. Actual blast radius
depends on `userA`'s privileges and the systems that trust the credential — both to be confirmed by L2 —
so this is handled as an active lateral-movement incident pending scope confirmation.

## 7. Secondary observation (separate incident — handed to L2, not investigated at L1)

While scoping the NTLM alert, the same index contained an **unrelated** cluster: 3× Event **4625**
(failed NTLM) on `win-dc-800` from external IP `212.129.6.106` on **2020-10-15** — 21 months after the
PtH, different host, blank account. The source IP was enriched (**no VirusTotal detections, 0% AbuseIPDB
confidence**) and every attempt **failed**; assessed as low-priority opportunistic activity.

Separately, `win-dc-800` produced explicit-credential (4648) and privileged (4672) logon events that are
outside the scope of this NTLM alert. Investigating them is proactive threat-hunting (L2). **Recommend
L2/IR review of `win-dc-800`** for possible lateral movement; flagged, not pursued at Tier-1.

## 8. Recommendations

**Immediate (containment — for L2/IR):**
- Confirm `userA`'s privilege level and force a credential reset (password + invalidate sessions).
- Investigate `destDeviceA` for follow-on activity; scope where else the hash may have been replayed.
- Identify the physical/virtual source behind workstation name `SZUFS`.

**Recovery:**
- Reset `userA`'s credentials; review any systems `userA` can authenticate to over NTLM.
- Where feasible, reduce reliance on NTLM for the affected account/segment (Kerberos-only, disable
  legacy NTLM) — an environment-hardening recommendation for IT.

**Detection (recommendation to detection-engineering / L2 — out of L1 scope):**
- Consider alerting on Event 4624 with `Logon_Process=NtLmSsp` / Logon Type 3 for accounts whose
  baseline is Kerberos, especially with an unrecognized `Workstation_Name`. (Detection authoring/tuning
  is L2; raised here as a recommendation only.)

## 9. Analyst note — why the workstation name, not the IP

NTLM network logons frequently do not populate a source IP, and this one did not. A junior analyst can
stall on the blank field. The move that cracked it was pivoting to the next identifier — the
`Workstation_Name` — and measuring the user's own protocol baseline. The signal was not *where from* (an
empty field) but *how* (NTLM instead of Kerberos) and *from what name* (`SZUFS`, which does not belong).
