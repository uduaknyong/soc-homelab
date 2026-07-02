# Incident Report — INC-2026-0629-01

| | |
|---|---|
| **Incident ID** | INC-2026-0629-01 |
| **Title** | Successful DCSync — domain-wide credential compromise on `AR-WIN-DC` |
| **Severity** | **SEV1 / Critical** (escalated from SEV2 on confirmation) |
| **Status** | Confirmed true positive — escalated to Incident Response |
| **Analyst** | Tier-1 SOC |
| **Technique** | MITRE ATT&CK **T1003.006** — OS Credential Dumping: DCSync (Credential Access) |
| **Affected asset** | `AR-WIN-DC` (`ar-win-dc.attackrange.local`), domain `ATTACKRANGE.LOCAL` |
| **Activity time** | 2024-01-05 06:05:57 UTC |

## 1. Summary

An alert fired for a burst of sensitive Active Directory object-access events (Event ID 4662) on the
domain controller `AR-WIN-DC`. Triage confirmed a **successful DCSync attack**: the `Administrator`
user account, authenticating remotely from `10.0.1.15`, exercised Active Directory **replication
rights** to impersonate a domain controller and replicate directory secrets. The domain controller
granted the requests (Audit Success). Because replication at the domain level exposes the password
hashes of every account — including `krbtgt` — this is treated as a **domain-wide credential
compromise** and was escalated to Incident Response. A second cluster of replication events in the
same window was the DC's own machine account performing normal replication and was cleared as benign.

## 2. Severity justification

Escalated from the initial **SEV2** to **SEV1 / Critical** because: (a) the activity is a confirmed
credential-access attack, not a misconfiguration; (b) it **succeeded** (Audit Success); and (c) the
blast radius is the entire domain's credential material, including `krbtgt`, which enables Golden
Ticket forgery and durable domain dominance. Standard handling for a successful DCSync is
assume-breach for the whole domain.

## 3. Timeline (UTC)

| Time | Event | Account | Detail |
|---|---|---|---|
| 2024-01-05 06:05:57.784 | Logon 4624 (Type 3, NTLMv2) | `Administrator` | Network logon from `10.0.1.15` (attacker host) |
| 2024-01-05 06:05:57.787–.800 | 10× 4662 Control Access | `Administrator` | **DCSync** — replication rights on User/Computer/Domain objects; **Audit Success** |
| 2024-01-05 06:17:10.999 | Logon 4624 (Type 3) | `AR-WIN-DC$` | Network logon from `10.0.1.30` — benign |
| 2024-01-05 06:17:11.064–.071 | 6× 4662 replication | `AR-WIN-DC$` | Normal DC replication — **benign, cleared** |

## 4. Findings (evidence chain)

1. **Burst confirmed.** 16× Event 4662 on `AR-WIN-DC`, far above the rolling baseline.
2. **Two actors.** Splitting by `SubjectUserName`: `AR-WIN-DC$` (machine account, ×6) and
   `Administrator` (user account, ×10).
3. **Replication rights exercised.** The `Administrator` 4662 events used **Control Access**
   (`%%7688`, AccessMask `0x100`) on the AD replication extended rights:
   `DS-Replication-Get-Changes` (`1131f6aa-…`), `-Get-Changes-All` (`1131f6ad-…`),
   `-Get-Changes-In-Filtered-Set` (`89e95b76-…`). Replication is a domain-controller function; a user
   account performing it is the definition of DCSync.
4. **Domain-level scope.** `ObjectType` shows access to **User** and **Computer** account objects (where
   hashes are stored) and the **Domain-DNS** (domain root) object.
5. **It succeeded.** All `Administrator` 4662 events are **Audit Success** (`Keywords 0x8020…`) — the DC
   permitted the replication.
6. **Launched remotely.** A Type 3 NTLM logon as `Administrator` from `10.0.1.15` immediately preceded
   the replication, identifying the attacker's source host.
7. **Benign noise cleared.** The `AR-WIN-DC$` replication is the DC doing its normal job; excluded from
   the incident.

## 5. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Account abused | `ATTACKRANGE\Administrator` |
| Attacker source host | `10.0.1.15` |
| Target | `AR-WIN-DC` / `ar-win-dc.attackrange.local` / `ATTACKRANGE.LOCAL` |
| Technique | T1003.006 (DCSync) |
| Rights abused | `DS-Replication-Get-Changes`, `-Get-Changes-All`, `-Get-Changes-In-Filtered-Set` |
| Telemetry signature | Event 4662 Control Access (`%%7688`, mask `0x100`) by a non-DC account; preceding 4624 Type 3 / NTLM |

## 6. Impact assessment

The attacker successfully replicated directory secrets at the domain level. **Assume the password
hashes of all domain accounts are compromised**, including:
- the **`krbtgt`** account hash → enables **Golden Ticket** forgery (authenticate as any user
  indefinitely; survives password resets until `krbtgt` is rotated **twice**);
- all **privileged/admin** account hashes → lateral movement and persistence.

This is a full-domain compromise scenario.

## 7. Recommendations

**Immediate (containment):**
- Isolate attacker source host `10.0.1.15`; disable / force-reset `Administrator` and any account that
  logged on from it.
- Treat the domain as compromised: begin IR escalation.

**Recovery (IR / IT):**
- Reset `krbtgt` **twice** (per Microsoft guidance) to invalidate any forged Golden Tickets.
- Force-reset privileged and service account credentials; review Domain Admins and accounts holding
  the replication rights (`Get-Changes` / `Get-Changes-All`) — these should be DCs only.
- Hunt for follow-on activity (new accounts, group changes, persistence) using the attacker host and
  account as pivots.

**Detection (recommendation to detection-engineering / L2):**
- Recommend monitoring Event 4662 for the replication GUIDs where `SubjectUserName` is **not** a
  domain-controller machine account or `SYSTEM`. (Detection authoring/tuning is out of L1 scope and is
  raised here as a recommendation only.)

## 8. Analyst note — why "volume" was the wrong lens

The alert framed this as anomalous *volume*. In practice the volume of replication access is normal for
a domain controller — the DC's own machine account is expected to generate it continuously. The signal
that mattered was **identity, not count**: a non-DC user account exercising replication rights.
