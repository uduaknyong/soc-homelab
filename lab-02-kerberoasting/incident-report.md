# Incident Report — Lab 02 / Detection 1

| Field | Value |
|-------|-------|
| Report ID | INC-2026-0628-01 |
| Analyst | Uduak |
| Date / time (UTC) | 2026-06-28 |
| Severity | High |
| Status | Confirmed True Positive, escalated to L2 |

## Executive summary

A single internal host (`AR-WIN-2`) conducted a Kerberoasting attack (MITRE ATT&CK T1558.003)
against the `ATTACKRANGE.LOCAL` domain. Operating as the machine account `AR-WIN-2$`, it requested
Kerberos service tickets (EventID 4769) for 28 distinct service accounts, forcing weak RC4
encryption on every request. The Domain Controller `AR-WIN-DC` granted all requests (Status 0x0), so
the attacker obtained crackable tickets for real service accounts. Activity ran from 2024-02-29 to
2024-03-04, concentrated on 2024-03-02. The targeted service-account credentials must be treated as
compromised and rotated immediately.

## Affected assets / accounts

- Source host (compromised): `AR-WIN-2`
- Attacker identity: `AR-WIN-2$@ATTACKRANGE.LOCAL` (machine account)
- Domain Controller (KDC): `AR-WIN-DC` (`ATTACKRANGE.LOCAL`)
- Victims: 28 service accounts whose tickets were issued (passwords now at risk of offline cracking)

## Timeline of events (UTC)

| Time | Event |
|------|-------|
| 2024-02-29 05:23:56 | First service-ticket request from `AR-WIN-2$` (low tail) |
| 2024-03-02 | Main attack: 94 requests across 25 distinct services, all RC4, all granted |
| 2024-03-03 to 03-04 | Tail activity (2–5 requests/day) |
| 2024-03-04 06:53:49 | Final request, 111 requests total over the window |

## Technique (MITRE ATT&CK)

Kerberoasting, T1558.003 (Tactic: Credential Access). The attacker requested TGS tickets for
accounts with SPNs; each ticket is encrypted with the target service account's password. With the
RC4 tickets exported, the attacker can brute-force the passwords offline, invisibly, then
authenticate as those (often privileged) service accounts.

## Evidence (key events / queries)

- `index=kerberoast | stats count by TargetUserName` gives `AR-WIN-2$` at 111 (vs DC 44,
  Administrator 1).
- `... TargetUserName="AR-WIN-2$..." | stats count by ServiceName` gives 28 distinct SPNs.
- `... | stats count by TicketEncryptionType` gives all `0x17` (RC4).
- `... | stats count by ServiceName Status` gives all `0x0` (granted, attack succeeded).
- `index=kerberoast | bin _time span=1d | stats dc(ServiceName) by _time, TargetUserName` gives
  attacker 25 distinct services/day vs DC 2, the variety that separates the two.
- See `evidence/` for screenshots.

## Impact assessment

High. A successful credential-access attack: tickets for 28 service accounts were issued and are
assumed to be undergoing offline cracking. Service accounts are frequently privileged, so successful
cracking enables lateral movement and privilege escalation across the domain. Host `AR-WIN-2` is
compromised.

## Recommended actions

1. Rotate all 28 targeted service-account passwords immediately (long and random). Time-critical.
2. Isolate and perform IR on `AR-WIN-2`.
3. Hunt for follow-on authentication using the targeted service accounts.
4. Harden: migrate service accounts to AES-only / gMSA; alert on RC4 service-ticket requests.

## Escalation

Escalated to L2 / Incident Response with full timeline, IOCs, and evidence. Priority: contain
`AR-WIN-2` and rotate the affected service-account credentials before offline cracking completes.
