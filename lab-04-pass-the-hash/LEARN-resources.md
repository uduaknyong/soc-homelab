# 📚 Lab 04 — Pass-the-Hash — Study Resources

Curated reading to go deeper on what this lab covered: how NTLM authentication works, what
Pass-the-Hash abuses, and how analysts spot it in logon events (4624/4625, Logon Type 3, NTLM).
Ordered roughly easy → deep.

## Start here
- **MITRE ATT&CK — T1550.002 (Use Alternate Authentication Material: Pass the Hash)** — the canonical
  technique page: what it is, procedure examples, detection & mitigation pointers.
  https://attack.mitre.org/techniques/T1550/002/
- **CrowdStrike — Pass-the-Hash Attack Explained** — clear defender's-lens overview of the technique
  and why NTLM makes it possible.
  https://www.crowdstrike.com/cybersecurity-101/pass-the-hash/

## 1. Foundation — how NTLM authentication works
*(So "NTLM where Kerberos is the norm = suspicious" is intuition, not a memorized rule.)*
- **Microsoft Learn — NTLM Overview** — the authoritative primer on NTLM challenge/response and where
  it still gets used.
  https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview
- **Kerberos vs NTLM** — plain-English comparison of the two Windows auth protocols and why modern
  domains prefer Kerberos.
  https://www.thehacker.recipes/ad/movement/ntlm/
- **Windows Logon Types (2 vs 3 vs 10)** — what "Logon Type 3 = network logon" actually means.
  https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624

## 2. The attack — how Pass-the-Hash abuses NTLM
- **The Hacker Recipes — Pass the Hash** — mechanics: how a stolen NTLM hash is replayed without the
  plaintext password.
  https://www.thehacker.recipes/ad/movement/ntlm/pass-the-hash
- **Microsoft — Mitigating Pass-the-Hash and Other Credential Theft** — the classic defender guidance
  (why PtH works and how to contain it).
  https://www.microsoft.com/en-us/download/details.aspx?id=36036
- **Netwrix — Pass-the-Hash Attack: How It Works and How to Defend** — attack + detection together.
  https://www.netwrix.com/pass_the_hash_attack_explained.html

## 3. Detection — the analyst's view (4624/4625, NTLM, workstation name)
*(This is your lane: how you spotted it, formalized.)*
- **Splunk Security Content — detections for T1550.002** — browse the NTLM / anomalous-logon detections
  and read their logic and "known false positives" sections.
  https://research.splunk.com/tags/T1550.002/
- **Event 4624 — reading the fields** — Logon Type, Authentication Package, Workstation Name, source
  address; the columns you triaged.
  https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
- **Event 4625 — failed logons** — the failure side, and the sub-status codes that say *why* a logon
  failed.
  https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625

## Quick reference — the Pass-the-Hash signal
| Field | Benign baseline | Suspicious |
|---|---|---|
| `Logon_Process` / `Authentication_Package` | `Kerberos` | `NtLmSsp` / `NTLM` in a Kerberos-first env |
| `Logon_Type` | interactive / service as expected | `3` (network) for a replayed credential |
| `Workstation_Name` | a known estate machine | an **unrecognized** name (e.g. `SZUFS`) |
| `Source_Network_Address` | populated internal IP | often **blank** on NTLM → pivot to workstation |
| Outcome | 4624 from expected hosts | 4624 **success** for an out-of-character account |

> 💡 Also worth bookmarking: **adsecurity.org** (Sean Metcalf) and **The Hacker Recipes** — both have
> deep, respected writeups on NTLM, Pass-the-Hash, and related lateral-movement techniques.
