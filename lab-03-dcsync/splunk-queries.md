# Splunk Query Library — Lab 03 (DCSync)

Reusable SPL from this investigation. Deliberately kept at a level any analyst can read and explain:
basic filters, the `stats count by …` family, simple `table`/`sort`, and reading raw events. No
advanced one-liners — clarity over cleverness.

> All searches assume **time range = All time** (the data is dated 2024-01-05).

## Orientation

```spl
# What event types are in the index?
index=dcsync | stats count by EventCode

# Which host logged them?
index=dcsync | stats count by Computer
```

## Triage — who is behind the 4662 burst?

```spl
# Split the directory-access events by the acting account
index=dcsync EventCode=4662 | stats count by SubjectUserName
```

Reading: an account ending in `$` is a **machine (computer) account** (e.g. the DC itself); an account
without `$` is a **user account**. A user account in this list is the thing to investigate.

## What rights / objects were accessed?

```spl
# Focus on the suspicious account, then expand an event and read the Properties field
index=dcsync EventCode=4662 SubjectUserName=Administrator

# Object class that was accessed (look the GUID up: 19195a5b... = Domain-DNS, bf967aba... = User, bf967a86... = Computer)
index=dcsync EventCode=4662 SubjectUserName=Administrator | stats count by ObjectType
```

Reading the raw event: the `Properties` field lists access types and GUIDs. **`%%7688` = Control
Access** (an extended right). Look up the GUID(s) under it — the AD **replication** rights
(`DS-Replication-Get-Changes` `1131f6aa-…`, `-Get-Changes-All` `1131f6ad-…`) are the DCSync signature.

## Did it succeed?

```spl
# Open a raw event and read Keywords: 0x8020000000000000 = Audit Success, 0x8010000000000000 = Audit Failure
index=dcsync EventCode=4662 SubjectUserName=Administrator
```

## Where did it come from? (logons)

```spl
index=dcsync EventCode=4624 | table _time, TargetUserName, IpAddress, LogonType
```

## Timeline

```spl
index=dcsync | sort _time | table _time, SubjectUserName, EventCode, ObjectType
```

## Confirm benign vs malicious (the key distinction)

```spl
# The DC's own machine account uses the SAME replication rights — but that's normal DC behaviour.
# The discriminator is WHO, not how many.
index=dcsync EventCode=4662 SubjectUserName="AR-WIN-DC$" | stats count by ObjectType
```

## Quick reference — replication right GUIDs (in 4662 `Properties`, under `%%7688` Control Access)

| GUID | Right |
|------|-------|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | `DS-Replication-Get-Changes` |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | `DS-Replication-Get-Changes-All` |
| `89e95b76-444d-4c62-991a-0facbeda640c` | `DS-Replication-Get-Changes-In-Filtered-Set` |

Benign actor = a DC machine account (`…$`) or `SYSTEM`. Suspicious actor = any user / non-DC account.
