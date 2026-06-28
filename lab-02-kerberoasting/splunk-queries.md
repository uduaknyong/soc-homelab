# Splunk Query Library — Lab 02 (Kerberoasting)

Reusable SPL built during this lab. Each query keeps a note on its purpose.

Data is dated Feb–Apr 2024, so search All time.

## Kerberoasting (T1558.003)

Orientation, see everything in the index:
```
index=kerberoast
```

1. Baseline request volume per account (find the outlier):
```
index=kerberoast | stats count by TargetUserName | sort -count
```

2. What services a suspect account requested (the SPN spray):
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL" | stats count by ServiceName | sort -count
```

3. Encryption type used (spot the RC4 downgrade):
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL" | stats count by TicketEncryptionType
```

4. Whether the requests succeeded (grant vs fail):
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL" | stats count by ServiceName Status | sort -count
```

5. Attack window (first, last, count):
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL"
| stats count, min(_time) as first, max(_time) as last
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
```

6. Tempo over time (low and slow vs burst):
```
index=kerberoast TargetUserName="AR-WIN-2$@ATTACKRANGE.LOCAL" | timechart span=1h count
```

7. Distinct services per account per day (what separates the attacker from the noisy DC):
```
index=kerberoast | bin _time span=1d
| stats dc(ServiceName) as distinct_services count by _time, TargetUserName
| sort -distinct_services
```
