# Splunk Query Library — Lab 04 (Pass-the-Hash)

Reusable SPL from this investigation. Deliberately kept at a level any analyst can read and explain:
basic filters, the `stats count by …` family, simple `table`/`sort`, boolean `OR`/`IN`. No advanced
one-liners — clarity over cleverness.

> All searches assume **time range = All time** (the data is dated 2019-01-09/10 and 2020-10-15).

## Orientation — the shape of the data

```spl
# What event types are here, and on which hosts?
index=passthehash | stats count by EventCode host
```

Read the terrain before chasing the alert: which hosts dominate, what the baseline event is (here,
4624 successful logons).

## Triage — is NTLM an outlier?

```spl
# Break successful logons down by the protocol that handled them
index=passthehash EventCode=4624 | stats count by Logon_Process
```

Reading: `Kerberos` = Kerberos, **`NtLmSsp` = NTLM**, `Seclogo` = Secondary Logon (runas). In a
Kerberos-first environment a handful of NTLM logons is the outlier. The sibling field
`Authentication_Package` (values `Kerberos` / `NTLM` / `Negotiate`) answers the same question — run both
to confirm they agree.

## Who / from where — inspect the needle

```spl
# Pull the successful NTLM logons and lay out the identifying fields
index=passthehash Logon_Process=NtLmSsp EventCode=4624
| table _time host Account_Name Source_Network_Address Workstation_Name Logon_Type
```

Reading: `Logon_Type=3` is a network logon. `Source_Network_Address` is often **blank** on NTLM — when a
field is empty, pivot to the next identifier (`Workstation_Name`). An unrecognized workstation name is a
Pass-the-Hash tell.

## Know normal — is NTLM abnormal *for this user*?

```spl
# Measure the user's own protocol baseline
index=passthehash Account_Name=userA | stats count by Logon_Process
```

Reading: if the user is overwhelmingly Kerberos with a tiny NTLM count, NTLM is out of character — the
discriminator between a true positive and noise. You can only call something abnormal after you measure
normal.

## Scope — recover events hidden by an empty field

```spl
# Group by fields that are ALWAYS populated (EventCode, host) so nothing is dropped
index=passthehash Logon_Process=NtLmSsp | stats count by EventCode host
```

**Gotcha:** `stats count by <field>` silently drops events where that field is null. Grouping by
`Account_Name` hid the failed logons (blank account). When a grouped total is smaller than a count you
already trust, suspect a null group-by field and regroup on something always-present.

## See successes and failures together

```spl
# All NTLM events in one view, to contrast 4624 (success) vs 4625 (fail)
index=passthehash Logon_Process=NtLmSsp
| table _time Account_Name EventCode host Logon_Type Source_Network_Address Workstation_Name
```

## Did an external source ever succeed?

```spl
# Match two event codes with a boolean operator. OR / IN (both correct):
index=passthehash host="win-dc-800" (EventCode=4624 OR EventCode=4625)
| table _time EventCode Account_Name Source_Network_Address Logon_Type | sort _time

# IN() is cleaner for 2+ values:
index=passthehash host="win-dc-800" EventCode IN (4624, 4625)
| table _time EventCode Account_Name Source_Network_Address Logon_Type | sort _time
```

**Operator notes:** `OR` / `AND` / `NOT` must be **UPPERCASE** in SPL (lowercase is treated as a search
term — a silent bug). Each side of `OR` needs the full expression (`EventCode=4624 OR EventCode=4625`,
not `EventCode=4624 OR 4625`). Wrap OR groups in parentheses.

## Quick reference — logon codes & fields

| Item | Meaning |
|---|---|
| Event **4624** | Logon **succeeded** |
| Event **4625** | Logon **failed** |
| `Logon_Type=3` | Network logon |
| `Logon_Process=NtLmSsp` | NTLM authentication |
| `Authentication_Package` | Protocol: `NTLM` / `Kerberos` / `Negotiate` |
| `Workstation_Name` | Name the client machine announced (identifier when source IP is blank) |
| `Source_Network_Address` | Source IP (often empty on NTLM network logons) |

**Baseline vs suspicious:** Kerberos for a Kerberos-first account = normal. NTLM (Type 3) for that same
account, from an unrecognized workstation, succeeding = Pass-the-Hash.
