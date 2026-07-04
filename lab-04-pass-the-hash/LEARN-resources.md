# Lab 04 — Study Resources (Pass-the-Hash)

A study path for the concepts behind this lab. All free. Work top to bottom; the ideas stack.

## 1. NTLM authentication itself (build the mental model first)

Understand the protocol before the attack that abuses it. The whole attack turns on one fact: NTLM
proves you know a *hash*, never the plaintext password.

- [Microsoft Learn — NTLM Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
  — the authoritative primer on the NTLM challenge/response handshake and where it still gets used.
- [The Hacker Recipes — NTLM](https://www.thehacker.recipes/ad/movement/ntlm/) — a concise modern map:
  what the NT hash is, how the client proves possession of it, and why that is the weak point. If you
  read one thing, read this.

## 2. Pass-the-Hash (the attack you investigated)

- [MITRE ATT&CK T1550.002](https://attack.mitre.org/techniques/T1550/002/) — canonical reference. Read
  the Procedure, Mitigation, and Detection sections.
- [The Hacker Recipes — Pass the Hash](https://www.thehacker.recipes/ad/movement/ntlm/pass-the-hash) —
  the practical mechanics: how a stolen NT hash is replayed to authenticate without ever cracking it.
- [CrowdStrike — Pass-the-Hash Attack Explained](https://www.crowdstrike.com/cybersecurity-101/pass-the-hash/)
  — clean defender's-lens overview of the technique and the credential-theft chain it belongs to.
- [Microsoft — Mitigating Pass-the-Hash and Other Credential Theft (v2)](https://www.microsoft.com/en-us/download/details.aspx?id=36036)
  — the classic whitepaper on *why* PtH works and how to contain it. Dense but foundational.

## 3. The details that cracked this lab (know them cold)

The two sharpest signals you used: NTLM where Kerberos is the norm, and Logon Type 3 from an
out-of-place workstation.

- [Kerberos vs NTLM](https://www.thehacker.recipes/ad/movement/kerberos/) — why modern domains prefer
  Kerberos, so an NTLM logon stands out. (Context for "Kerberos-first environment.")
- [Ultimate Windows Security — Windows Logon Types](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624)
  — the field-by-field 4624 reference, including the Logon Type table. Type 3 = network logon, the type
  a replayed credential produces. Bookmark it.
- Why the **source IP was blank and the Workstation Name mattered:** NTLM network logons frequently do
  not populate the source address, so the client-announced `Workstation_Name` becomes the identifying
  artifact. An unrecognized name riding an NTLM logon is a classic PtH tell — the lesson from this lab.

## 4. Event 4624 / 4625 and detection (your actual lane)

- [Ultimate Windows Security — 4624 (successful logon)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624)
  and [4625 (failed logon)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625)
  — the two events this whole triage rides on; 4625 sub-status codes tell you *why* a logon failed.
- [Splunk Security Content — detections tagged T1550.002](https://research.splunk.com/tags/T1550.002/)
  — read the logic and the "known false positives" sections, then compare them to your own queries in
  `splunk-queries.md`.
- [MITRE ATT&CK T1550.002 — Detection](https://attack.mitre.org/techniques/T1550/002/) — the
  data-sources and detection guidance, framed as behaviour rather than a single rule.

## 5. Practice it free (hands-on)

- [CyberDefenders — blue-team CTF challenges](https://cyberdefenders.org/blueteam-ctf-challenges/) —
  free investigations of real attack data; look for Windows-authentication / credential-attack cases to
  repeat this kind of triage on fresh telemetry.
- [Splunk BOTS datasets (Boss of the SOC)](https://github.com/splunk/botsv3) — free, downloadable
  attack telemetry you can ingest into your own Splunk and hunt through, the same setup this lab uses.
- [The Hacker Recipes — Credential movement index](https://www.thehacker.recipes/ad/movement/) — a map
  of the neighbouring techniques (Pass-the-Ticket, Overpass-the-Hash, NTLM relay) so you can tell them
  apart in an alert.

---

## Quick self-check (can you answer these from memory?)

1. What exactly is an NTLM hash, and why can an attacker authenticate with it **without** knowing the
   plaintext password?
2. Which Logon Type marks a network logon, and why is it the relevant one for Pass-the-Hash?
3. The source IP on the malicious logon was blank. What field did you pivot to instead, and why is it a
   PtH tell?
4. NTLM is not malicious by itself. How did you prove *this* NTLM logon was abnormal?
5. Why does a Kerberos-first environment make an NTLM logon a useful signal in the first place?
6. After confirming Pass-the-Hash, what is the key containment action for the affected account, and why
   is rotating the credential (not just a session kill) what actually stops the replay?
