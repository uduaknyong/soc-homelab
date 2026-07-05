# SPL Query Library — Lab 01: Password Spray / Credential Compromise

Reusable queries for investigating password spray and credential compromise alerts.

---

## 1. Find all failed logons on a host
```spl
index=wineventlog host="win-dc-01" EventCode=4625
```

---

## 2. Count failed logons by source IP — identify spray sources
```spl
index=wineventlog host="win-dc-01" EventCode=4625
| stats count by Source_Network_Address
| sort - count
```

---

## 3. Count failed logons per account — detect blind spray vs targeted attack
```spl
index=wineventlog host="win-dc-01" EventCode=4625 Source_Network_Address="10.0.0.5"
| stats count by Account_Name
| sort - count
```
> Even distribution = blind spray. Skewed = targeted account.

---

## 4. Find successful logons from same source as spray
```spl
index=wineventlog host="win-dc-01" EventCode=4624 Source_Network_Address="10.0.0.5"
| table _time, Account_Name, Source_Network_Address, Logon_Type
```

---

## 5. Confirm logon method (Logon Type)
```spl
index=wineventlog Source_Network_Address="10.0.0.5" Account_Name=jsmith Logon_Type=3 EventCode=4624
```
> Logon Type 3 = Network (SMB). Type 10 = RemoteInteractive (RDP).

---

## 6. Full timeline — failures then success from same IP
```spl
index=wineventlog host="win-dc-01" Source_Network_Address="10.0.0.5" (EventCode=4625 OR EventCode=4624)
| table _time, EventCode, Account_Name, Logon_Type, Source_Network_Address
| sort _time
```

---

## 7. Check post-compromise activity in Sysmon
```spl
index=sysmon host="win-dc-01" earliest="05/08/2026:06:55:15" latest="05/08/2026:07:10:00"
```

---

## 8. All activity on a compromised account from attacker IP
```spl
index=wineventlog Account_Name=jsmith Source_Network_Address="10.0.0.5"
| table _time, EventCode, Logon_Type, Source_Network_Address
| sort _time
```

---

## Logon Type Reference

| Type | Meaning |
|------|---------|
| 2 | Interactive (local console) |
| 3 | Network (SMB, mapped drives) |
| 4 | Batch |
| 5 | Service |
| 7 | Unlock |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |
