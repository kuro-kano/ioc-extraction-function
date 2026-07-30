# `example_data.txt` — provenance & safety

Test fixture for the IoC extraction pipeline. Same envelope as
`elastic_alert_format_sample.txt` (n8n webhook → Kibana rule alert:
`headers` / `params` / `query` / `body.context.hits[]` / `sourceFields` /
`state` / `webhookUrl`), but carrying **real** threat-intelligence indicators
instead of placeholders.

---

## ⚠️ Safety

**The URLs and hashes below are real malware indicators. Do not visit the URLs,
do not fetch the payloads, and do not run anything they return.** Several were
still flagged `online` on URLhaus on 2026-07-28, meaning they were actively
serving payloads at the time this file was generated.

Safe to do: parse this file, extract IoCs, look the values up on VirusTotal /
URLhaus / MISP, use them as detection-rule test input.

If you need it inert, run the extractor and work from the `defanged` field
(`hxxps://customcreationsmaine[.]com/...`), which is emitted for every network
indicator.

---

## What is real vs. synthetic

The split matters: real values make VirusTotal/MISP lookups actually resolve,
while synthetic values keep this from being a report about real victims.

### Real — pulled from public feeds on 2026-07-28

| Type | Value | Attribution | Source |
|---|---|---|---|
| url | `https://customcreationsmaine.com/fed/remcosraw.exe` | RemcosRAT | [URLhaus 3891436](https://urlhaus.abuse.ch/url/3891436/) |
| url | `https://customcreationsmaine.com/db22/bin.exe` | Formbook | [URLhaus 3891435](https://urlhaus.abuse.ch/url/3891435/) |
| url | `https://drive.google.com/uc?export=download&id=1EznN9ZSMbkarOKxIJQJNw-P_JNXqHJQz` | GuLoader → RemcosRAT | [URLhaus 3891433](https://urlhaus.abuse.ch/url/3891433/) |
| url | `https://broadwalkindia.com/1.exe` | AnimateClipper | [URLhaus 3892187](https://urlhaus.abuse.ch/url/3892187/) |
| url | `http://tampareroofing.com/curl/f293a6dc…` | Atomic/AMOS infostealer | [URLhaus 3892194](https://urlhaus.abuse.ch/url/3892194/) |
| url | `http://blakcinwhitexn.cc/1557fad8…` | Atomic/AMOS, ClickFix fake-captcha | [URLhaus 3886113](https://urlhaus.abuse.ch/url/3886113/) |
| md5 | `e3aaa940c8c30f0571cc42a6e9260f60` | payload of URLhaus 3892594 | URLhaus tag |
| md5 | `f0e7dc585ba3ebf586da7b92aedbfc64` | AnimateClipper payload | URLhaus tag |
| sha256 | `f293a6dc24a4cfe46895e7bc4f91ffcf276ac71a74b13fed54458ad51af9dbb3` | Amos infostealer | URLhaus |
| sha256 | `1557fad8649e638f43f20cccf5794a440c70eae03204f5af9fe9850b3197b8ff` | Atomic/AMOS | URLhaus |
| ipv4 | `50.16.16.211` | QakBot C2 (online) | Feodo Tracker |
| ipv4 | `162.243.103.246` | Emotet C2 | Feodo Tracker |
| ipv4 | `34.204.119.63` | QakBot C2 | Feodo Tracker |
| ipv4 | `178.62.3.223` | QakBot C2 | Feodo Tracker |

Feeds: [URLhaus](https://urlhaus.abuse.ch/) `csv_recent`,
[Feodo Tracker](https://feodotracker.abuse.ch/) `ipblocklist.csv` (abuse.ch,
CC0). Attribution is the feed's, not mine.

### Real but harmless — EICAR

The `INV-88421.exe` attachment on hit 0 uses the **EICAR anti-malware test file**
hashes. Real and universally detected (great for proving your enrichment
pipeline works), but the file itself is a 68-byte inert ASCII string, not
malware. Computed locally, not recalled:

```
md5     44d88612fea8a8f36de82e1278abb02f
sha1    3395856ce81f2b7382dee72602f798b642f14140
sha256  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### Synthetic — invented for this fixture

Everything identifying a victim: `kmitl.ac.th` recipients, sender domains
(`invoice-kmitl-secure.com`, `kmitl-payroll.net`), hostnames (`mail-gw-01`,
`WKS-ENG-114`, `MBP-PIMCHANOK`), usernames, message-IDs, internal `10.x` IPs,
`203.150.19.44`, timestamps, rule name, and the webhook UUID.

> Note on the compromised sites: `customcreationsmaine.com`, `heroestales.com`,
> `broadwalkindia.com`, and `tampareroofing.com` are real domains that appear to
> be **compromised legitimate websites** being abused to host payloads — not
> attacker-owned. They are used here only as payload URLs, never as the phishing
> *sender*, which is why all sender domains are synthetic.

---

## Scenario

Five hits modelling one intrusion, so IoCs correlate across stages rather than
sitting in isolation:

| # | `event.category` | Stage |
|---|---|---|
| 0 | email | Invoice-lure phish with EICAR-hashed `.exe` attachment |
| 1 | email | Payroll-lure phish, GuLoader dropper via Google Drive link |
| 2 | process | Formbook execution on the endpoint, Run-key persistence |
| 3 | network | AnimateClipper download, C2 callout |
| 4 | network | macOS AMOS infostealer via ClickFix paste-and-run |

## Coverage vs. the original sample

Deliberately exercises fields the original never had, so the extractor is tested
beyond email:

`file.name` · `file.path` · `file.hash.{md5,sha1,sha256}` · `process.command_line` ·
`process.parent.*` · `registry.path` · `dns.question.name` · `destination.ip` ·
`user_agent.original` · `email.cc.address` · `vulnerability.id` (CVE) ·
`threat.indicator.*` · `threat.technique.*`

It also embeds indicators *inside* container fields (a URL and a SHA-256 inside
`process.command_line`) to test the deep-scan path, and includes a payload URL
whose path component *is* its own hash — the `hash in url path` pivot.

## Regenerating

`build_sample.py` (in the session scratchpad) derives `sourceFields` from the
hits automatically, so the two representations can't drift apart the way
hand-edited fixtures do. To refresh with current feed data, re-pull
`csv_recent` and swap the indicator values.

## Expected result

```
$ python3 extract_ioc.py example_data.txt -f table --allow kmitl.ac.th
Variables split  : 230
IoCs extracted   : 44
```

`--allow kmitl.ac.th` drops the victim org so only adversary infrastructure
remains — without it you also get the targeted addresses, which should not go
into an IoC feed.
