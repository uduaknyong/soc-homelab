# Lab 02 / Detection 1 — Investigation Working Notes

**Analyst:** Uduak
**Alert:** Anomalous Kerberos Service-Ticket Request Volume — AR-WIN-DC
**Investigation started:** 2026-06-28

## Data orientation

- Index `kerberoast`, sourcetype `kerberoast:winxml`, 160 total events.
- Single event type present: Windows Security EventID 4769 (a Kerberos service ticket was requested).
- Events span 2024-02-29 to 2024-04-08, so I searched All time (`earliest=0`).
- Key fields: `TargetUserName` (who requested), `ServiceName` (the SPN requested),
  `TicketEncryptionType` (cipher), `Status` (grant or fail), `Computer`, `IpAddress`.

## Timeline (events)

| Time (UTC) | Event | Account / Host | Notes |
|------------|-------|----------------|-------|
| 2024-02-29 05:23:56 | First 4769 from this actor | AR-WIN-2$ | Low-tail activity (1–4 reqs/day) |
| 2024-03-02 | Main attack window | AR-WIN-2$ | 94 requests across 25 distinct services, all RC4, all granted |
| 2024-03-03 to 03-04 | Tail activity | AR-WIN-2$ | 2–5 reqs/day |
| 2024-03-04 06:53:49 | Last 4769 from this actor | AR-WIN-2$ | End of window |

Window: 2024-02-29 05:23:56 to 2024-03-04 06:53:49 (about 4 days), 111 requests total, the bulk
concentrated on 2024-03-02. Spreading the activity thin across days looks like deliberate evasion of
short-window volume thresholds (low and slow).

## SPL queries used

Query 1, baseline request volume per account:
```
index=kerberoast | stats count by TargetUserName | sort -count
```
Looking for the account responsible for the abnormal volume the alert flagged.
Found: `AR-WIN-2$` at 111 requests, far above `AR-WIN-DC$` (44) and `Administrator` (1). The two
high-volume accounts are both machine accounts (`$` suffix).

Query 2, what the outlier requested:
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL" | stats count by ServiceName | sort -count
```
Looking for which services/SPNs the suspect account targeted.
Found: 28 distinct services, most with bogus or auto-generated names that don't map to real
services. That is enumeration/spraying, not a host using the few services it actually needs.

Query 3, encryption type:
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL" | stats count by TicketEncryptionType
```
Looking for the cipher of the issued tickets.
Found: all `0x17` (RC4-HMAC), the weakest, deprecated cipher and a downgrade from the AES (`0x12`)
a modern domain issues by default. RC4 tickets crack fastest offline.

Query 4, did it succeed:
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL" | stats count by ServiceName Status | sort -count
```
Looking for whether the DC actually granted the tickets.
Found: all `Status = 0x0` (success). Every requested ticket was issued, so the attack succeeded and
the targeted service-account passwords must be treated as compromised.

Query 5, timeline:
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL" | stats count, min(_time) as first, max(_time) as last | eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
```
Found: 111 requests over about 4 days (see timeline table).

Query 6, distinct services per account per day:
```
index=kerberoast | bin _time span=1d | stats dc(ServiceName) as distinct_services count by _time, TargetUserName | sort -distinct_services
```
Looking for an observation that survives the low-and-slow spread and separates the attacker from the
busy DC.
Found: `AR-WIN-2$` on 2024-03-02 hit 25 distinct services (94 reqs). The DC `AR-WIN-DC$` that same
day touched only 2 distinct services despite 31 reqs. Every legitimate row was 5 or fewer distinct
services. `dc(ServiceName)` cleanly isolates the attack where raw count does not.

## Key findings

- A single non-DC machine account (`AR-WIN-2$`) requested service tickets for 28 distinct services,
  most with fabricated names. That is enumeration behaviour, not normal service usage.
- All requests forced RC4 (`0x17`), a downgrade to enable fast offline cracking.
- All requests succeeded (`Status 0x0`), so the attacker obtained crackable tickets for real service
  accounts. The attack completed.
- Activity was deliberately low and slow (about 1–2/hr over 4 days, bulk on 2024-03-02), which would
  evade a naive short-window volume rule.
- The reliable discriminator is distinct services per account per window (attack 25, legit 5 or
  fewer), not raw request count, which the DC's normal traffic inflates.

## IOCs (Indicators of Compromise)

| Type | Value | Context |
|------|-------|---------|
| Account (attacker identity) | `AR-WIN-2$@ATTACKRANGE.LOCAL` | Machine account that issued the requests |
| Host | `AR-WIN-2` | Source of the Kerberoasting activity |
| Behaviour | 28 distinct SPNs requested by one account | Enumeration / roasting |
| Encryption | `TicketEncryptionType = 0x17` (RC4) | Downgrade for offline cracking |
| Targeted DC | `AR-WIN-DC` (`ATTACKRANGE.LOCAL`) | KDC that issued the tickets |

## Distinguishing malicious from benign

- Benign baseline: the Domain Controller machine account `AR-WIN-DC$` is high volume but low
  variety. It repeatedly requests the same 2 or so services (normal KDC operation). High raw count
  alone would false-positive on it.
- Malicious: `AR-WIN-2$` is high variety, 25 distinct services in a day, all forced to RC4.
- The separator is therefore distinct service count (`dc(ServiceName)`) combined with RC4, not
  request volume.

## Preliminary verdict

- Incident or false positive: confirmed incident (true positive).
- Technique (ATT&CK): Kerberoasting, T1558.003 (Credential Access).
- Responsible account/host: `AR-WIN-2$@ATTACKRANGE.LOCAL` on host `AR-WIN-2`.
- What was targeted: 28 service accounts in `ATTACKRANGE.LOCAL` (tickets issued via `AR-WIN-DC`).
- Recommended immediate action: treat all targeted service-account passwords as compromised and
  rotate them immediately (long and random); isolate and IR `AR-WIN-2`; hunt for follow-on auth with
  the cracked accounts. Escalate to L2.
