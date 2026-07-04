# 📚 Lab 03 — DCSync — Study Resources

Curated reading to go deeper on what this lab covered: how AD replication works, what DCSync
abuses, and how analysts detect it in Event 4662. Ordered roughly easy → deep.

## Start here
- **MITRE ATT&CK — T1003.006 (OS Credential Dumping: DCSync)** — the canonical technique page:
  what it is, procedure examples, detection & mitigation pointers.
  https://attack.mitre.org/techniques/T1003/006/
- **Netwrix — Mastering DCSync Attacks: Techniques, Detection, and Defense** — clear end-to-end
  overview from a defender's lens.
  https://netwrix.com/en/cybersecurity-glossary/cyber-security-attacks/dcsync-attack/

## 1. Foundation — *why* domain controllers replicate
*(So "a DC replicating = normal" is intuition, not a memorized rule.)*
- **Microsoft Learn — Features of the AD DS Replication Model** — multi-master, USNs, "last writer
  wins." The authoritative source.
  https://learn.microsoft.com/en-us/windows/win32/ad/features-of-the-replication-model-for-active-directory-domain-services
- **What is multimaster replication?** — short, plain-English primer.
  https://www.itprotoday.com/it-infrastructure/what-is-multimaster-replication-
- **AD Replication: what it is and how it works** — beginner-friendly walkthrough.
  https://www.windows-active-directory.com/active-directory-replication.html

## 2. The attack — how DCSync abuses replication
- **Quest — Everything you need to know about DCSync attacks** — mechanics: how an attacker
  impersonates a DC and pulls hashes (incl. `krbtgt` → Golden Ticket).
  https://blog.quest.com/everything-you-need-to-know-about-dcsync-attacks/
- **AlteredSecurity — A primer on DCSync attack and detection** — attack + detection together.
  https://www.alteredsecurity.com/post/a-primer-on-dcsync-attack-and-detection
- **NCC Group — Defending Your Directory: Securing AD Against DCSync** — who *legitimately* holds
  replication rights, and how to lock it down.
  https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/

## 3. Detection — Event 4662, the analyst's view
*(This is your lane: how you spotted it, formalized.)*
- **BlackLantern Security — Detecting DCSync** — exactly the 4662 + replication-GUID logic you
  worked through, explained well.
  https://blog.blacklanternsecurity.com/p/detecting-dcsync
- **Splunk Security Content — AD Replication Request Initiated by User Account** — the Splunk
  detection that matches your finding (a *user* account, not a DC, requesting replication). Read
  the logic and the "how to implement / known false positives" sections.
  https://research.splunk.com/endpoint/51307514-1236-49f6-8686-d46d93cc2821/
- **Splunk Security Content — AD Replication Request Initiated from Unsanctioned Location** — the
  source-host angle on the same attack.
  https://research.splunk.com/endpoint/50998483-bb15-457b-a870-965080d9e3d3/

## Quick reference — the replication right GUIDs (Event 4662 `Properties`)
| GUID | Right |
|------|-------|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | `DS-Replication-Get-Changes` |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | `DS-Replication-Get-Changes-All` |
| `89e95b76-444d-4c62-991a-0facbeda640c` | `DS-Replication-Get-Changes-In-Filtered-Set` |

- Access type **`%%7688` = Control Access**, **AccessMask `0x100`** — the "extended right was used" signal.
- **Benign baseline:** `SubjectUserName` = a domain controller machine account (`…$`) or `SYSTEM`.
  **Suspicious:** any *user* account or non-DC principal exercising these rights.

> 💡 Also worth bookmarking: **adsecurity.org** (Sean Metcalf) and **The Hacker Recipes** — both have
> deep, respected AD-attack writeups including DCSync.
