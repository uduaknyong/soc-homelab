# SPL Query Library — Lab 05: Phishing Triage

Reusable SPL from this lab, grouped by the triage step it supports. Each is a query actually run during
the investigation. Kept simple and defensible (Tier-1 level) — the searches an L1 uses to work the alert.

> Data: `index=email` (`pps:message`) · `index=proxy` (`zscaler:web`) · `index=identity` (`okta:system`).
> Run with the time picker on **All time** (events are dated 2026-07-03).

---

## Sender authenticity (email)

Confirm the authentication verdicts across the whole campaign in one line — `by` takes multiple fields,
so this collapses to one row per unique spf/dkim/dmarc combination:

```
index=email senderIP=185.220.101.47
| stats count by spf dkim dmarc
```

To eyeball the individual messages:

```
index=email senderIP=185.220.101.47
| table _time sender senderIP spf dkim dmarc headerFrom recipient
```

## Delivery scope (email)

The candidate victim list — who received the phish. Corroborate the count with a second pivot
(sender address here; the payload domain is an even more independent check) to be sure you haven't
under-counted:

```
index=email senderIP=185.220.101.47
| stats count by recipient
```
```
index=email sender="bounce@mail.micros0ft-verify.com"
| stats count by recipient
```

## Click-through (proxy)

Who acted on the link. **Scope to the phishing host, not one exact URL** — an over-specific URL filter
(with the `?id=` query string) returns only the landing `GET`s and hides the credential-submission
`POST`s. The method breakdown is what separates "viewed" from "submitted":

```
index=proxy url="https://microsoftonline-verify.review*"
| table _time user method
| sort user _time
```

## Account-compromise check (identity)

For the users who submitted, look for an anomalous **successful** sign-in against their own baseline.
Match one field to several values with `IN (...)` (not `field=a b`, which ANDs a bare keyword):

```
index=identity user IN ("rgarcia@soclab.io","dwilson@soclab.io")
| table _time user result city country src_ip user_agent
| sort user _time
```

The anomaly: a `SUCCESS` from a new country / IP / user-agent (here `python-requests` from Amsterdam)
sitting apart from the user's normal browser logins from the office network.
