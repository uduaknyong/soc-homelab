# Lab 03 — DCSync — Investigation Notes

> Working notes written live during triage. Queries, findings, timeline, IOCs, and verdict.

## Alert

[SEV2] Sensitive Active Directory Object Access on Domain Controller — `AR-WIN-DC` (`ATTACKRANGE.LOCAL`).
Burst of Event ID 4662 directory-service object access against the domain root, early 2024-01-05.

## 0. Orientation

Before chasing the alert, get the lay of the index — what event types, which host.

```spl
index=dcsync | stats count by EventCode
```

- Two event types: **4662** (directory-service object access) ×16, and **4624** (successful logon) ×2.
- All events logged on a single host: **`ar-win-dc.attackrange.local`** — the domain controller named
  in the alert. Scope confirmed to one box.

The 4662 burst is real. 4662 = "An operation was performed on an Active Directory object," written on
the DC because that's where AD lives.

## 1. Triage the alert — who is behind the 4662 burst?

```spl
index=dcsync EventCode=4662 | stats count by SubjectUserName
```

| SubjectUserName | count |
|---|---|
| `AR-WIN-DC$` | 6 |
| `Administrator` | 10 |

Two actors. `AR-WIN-DC$` ends in `$` → a **machine (computer) account** — specifically the DC's own
account. `Administrator` → a **user account**. Same kind of AD access from two very different identities.

## 2. What did they actually access?

Expanded the `Administrator` 4662 events and read the **`Properties`** field (the control-access rights
exercised). The interesting access type is **`%%7688` = Control Access** — i.e. an *extended right* was
used. The GUID(s) under Control Access were looked up:

| GUID | Right |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | `DS-Replication-Get-Changes` |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | `DS-Replication-Get-Changes-All` |
| `89e95b76-444d-4c62-991a-0facbeda640c` | `DS-Replication-Get-Changes-In-Filtered-Set` |

These are **Active Directory replication** rights. Replication = the mechanism DCs use to sync the
directory (including password hashes) to each other. **A user account has no legitimate reason to
request replication.** This is the signature of **DCSync**.

## 3. Scope — what was targeted?

```spl
index=dcsync EventCode=4662 SubjectUserName=Administrator | stats count by ObjectType
```

`ObjectName` is the target's `objectGUID` (a unique instance ID — not publicly resolvable), so the
object *class* was read from `ObjectType` instead:

| ObjectType GUID | Class |
|---|---|
| `19195a5b-6da0-11d0-afd3-00c04fd930c9` | Domain-DNS (the domain root object) |
| `bf967a86-0de6-11d0-a285-00aa003049e2` | Computer |
| `bf967aba-0de6-11d0-a285-00aa003049e2` | User |

Replication touched **User and Computer account objects** (where password hashes live) at the
**domain level** → domain-wide credential exposure.

## 4. Did it succeed?

Opened the raw `Administrator` 4662 events. `Keywords = 0x8020000000000000` = **Audit Success** on all
ten — the DC permitted the replication. `Administrator` is a privileged account that holds these
rights, so the grant is consistent. **The attack succeeded; this is not a blocked attempt.**

## 5. Where did it come from? (the logons)

```spl
index=dcsync EventCode=4624 | table _time, TargetUserName, IpAddress, LogonType
```

| Time (UTC) | TargetUserName | IpAddress | LogonType | Auth |
|---|---|---|---|---|
| 2024-01-05 06:05:57 | `Administrator` | **10.0.1.15** | 3 (network) | NTLM (NTLMv2) |
| 2024-01-05 06:17:10 | `AR-WIN-DC$` | 10.0.1.30 | 3 (network) | — |

The `Administrator` DCSync was preceded — by milliseconds — by a **Type 3 network logon as
`Administrator` from `10.0.1.15` over NTLM**. So the replication was launched **remotely** from
`10.0.1.15`, the attacker's host. (The 06:17 logon from `10.0.1.30` belongs to the benign DC
replication.)

## 6. Timeline (UTC)

| Time | Event | Account | Detail |
|---|---|---|---|
| 2024-01-05 06:05:57.784 | 4624 logon (Type 3, NTLM) | Administrator | From `10.0.1.15` — attacker host |
| 2024-01-05 06:05:57.787–.800 | 10× 4662 Control Access | Administrator | DCSync — replication rights on User/Computer/Domain objects, **Audit Success** |
| 2024-01-05 06:17:10.999 | 4624 logon (Type 3) | AR-WIN-DC$ | From `10.0.1.30` — **benign** |
| 2024-01-05 06:17:11.064–.071 | 6× 4662 replication | AR-WIN-DC$ | Normal DC-to-DC replication — **benign, cleared** |

## 7. IOCs

- **Compromised/abused account:** `ATTACKRANGE\Administrator`
- **Attacker source host:** `10.0.1.15` (Type 3 NTLM logon → immediate replication)
- **Victim / target:** `AR-WIN-DC` (`ar-win-dc.attackrange.local`), domain `ATTACKRANGE.LOCAL`
- **Time:** 2024-01-05 06:05:57 UTC
- **Technique:** DCSync — T1003.006 (OS Credential Dumping)
- **Rights abused:** `DS-Replication-Get-Changes`, `-Get-Changes-All`, `-Get-Changes-In-Filtered-Set`
- **Telemetry:** Event 4662 Control Access (`%%7688`, AccessMask `0x100`), Audit Success; preceding Event 4624 Type 3 / NTLM

## 8. Verdict

**True positive — DCSync (T1003.006), successful.** A user account (`Administrator`), operating remotely
from `10.0.1.15`, impersonated a domain controller and successfully replicated Active Directory secrets
at the domain level. Worst-case impact = exposure of all domain credential material, including the
`krbtgt` hash (→ Golden Ticket / persistent domain dominance). The `AR-WIN-DC$` replication in the same
window is normal DC behaviour and was cleared. Recommend treating as a confirmed domain-wide credential
compromise (assume-breach) and escalating to IR.
