# Scenario: SaaS data theft and extortion (ShinyHunters / UNC6040 pattern)

A simulation for exercising the platform against a real adversary pattern rather
than a synthetic one. Everything here is **fabricated telemetry describing
publicly reported tradecraft** — there is no tooling, no payload and nothing that
touches a real system. It is the view from the SOC side of an intrusion, which is
the only side this platform models.

## Why this one

The other demo scenarios all start with an endpoint alert. This one deliberately
does not, because the group it is modelled on does not need an endpoint:

| | |
|---|---|
| **Entry** | Voice phishing an employee into authorising an OAuth app (`T1566.004`) |
| **Access** | A look-alike "Data Loader" connected app with `full` scope (`T1528`, `T1550.001`) |
| **Collection** | Bulk API export of Account, Contact, Opportunity (`T1213`, `T1530`) |
| **Exfiltration** | Over the vendor's own API, from a commercial VPN exit (`T1567`) |
| **Impact** | Extortion against the data, no encryption (`T1657`) |

Nothing in that chain produces an EDR detection. If the platform only reasons
well about process trees, this is the scenario where it shows.

It also exercises the ATT&CK lanes that used to be empty — Reconnaissance for
the pretext calls, Resource Development for the attacker's infrastructure — and
the Impact lane, which stays blank on data-theft incidents unless `T1657` is
mapped.

## The shape of the injection

Three beats, matching how it would actually reach a channel: someone reports
something odd, the SaaS telemetry catches up, and the extortion email arrives
after everyone has stopped looking.

```
T+0     a human posts in Slack          →  incident opens, thread starts
T+2m    Okta/helpdesk corroboration     →  queued mid-run, folded in on approval
T+10m   extortion email + live token    →  revision on a closed incident
```

The middle beat matters most. It arrives while the graph is still running, so it
proves telemetry is queued rather than rejected — and the last beat lands after
the report is published, so it proves the incident can be reopened rather than
duplicated.

## Running it

### 1. As a human report in Slack (the realistic path)

Post this in the channel **as yourself**, not through the bot — the poller
ignores bot messages so it cannot loop on its own output, which also means a bot
token cannot simulate a human:

> `@IR` Service desk just escalated HD-88412. R. Dela Cruz in Sales Ops called
> to ask whether "the IT security team" should have needed her to approve an app
> on the Salesforce login screen — nobody from our side contacted her. Salesforce
> is showing a connected app called "Data Loader" authorised at 12:58 UTC from
> 185.65.135.42, and it pulled about 1.2M records across Account, Contact,
> Opportunity, Case and Attachment in 43 minutes on Bulk API. Her normal egress
> is the Manila office. Consumer key isn't in our approved app list.

Within 90 seconds the poller reads it, classifies it as an investigation, opens
an incident and starts narrating in a thread.

Then, **while it is still running**, post the second beat as a threaded reply:

> Okta shows she approved a push at 12:57 from that same IP, 13 seconds after
> declining one from it. Two other Sales Ops users got declined pushes from the
> same ASN within the hour. Helpdesk logged three calls that morning from someone
> asking which staff have Salesforce admin.

And after the report lands, the third:

> Extortion email just hit legal@ from a ProtonMail address. Quotes the exact
> export count and includes 20 real Account records. 72 hours before they publish.
> Salesforce says the connected app's refresh token is still valid — used again
> 20 minutes ago.

### 2. As a SIEM alert (faster, no typing)

```bash
export BASE=https://air.husseinaltaie.com
export HOOK='<N8N_WEBHOOK_TOKEN>'
export KEY='<API_KEY>'

curl -sS -X POST "$BASE/webhooks/alert" \
  -H "Authorization: Bearer $HOOK" -H 'Content-Type: application/json' \
  -d "{\"source\":\"salesforce-shield\",\"alert\":$(cat examples/demo-04-shinyhunters-saas.json)}"
```

Then feed the later beats through the follow-up endpoint, which is what an
integration would do:

```bash
export INC='INC-…'

curl -sS -X POST "$BASE/v1/incidents/$INC/follow-up" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"reported_by":"soc","note":"Okta: MFA push approved 12:57 UTC from 185.65.135.42, 13s after a declined push from the same IP. Two other Sales Ops users received declined pushes from the same ASN within the hour. Helpdesk logged three calls asking which staff have Salesforce admin."}'
```

### 3. As the automated gate

```bash
make e2e ARGS='--scenario shinyhunters-saas'
```

Drives all three beats and every assertion in one pass, unattended.

## What a good run looks like

- **Verdict `true_positive`**, critical, and it should *stay* there through the
  revision — the extortion email is corroborating, not exculpatory.
- **Containment proposals aimed at the token, not the endpoint.** Revoking the
  connected app's OAuth grant and killing the refresh token is the action that
  stops the bleeding. A proposal to isolate a laptop would be the wrong answer to
  a SaaS-native intrusion, and worth telling us about.
- **ATT&CK chain spanning Reconnaissance to Impact** — if Impact is empty, the
  extortion was not recognised as the objective.
- **Open questions naming the things only a human can settle**: whether other
  connected apps carry the same scopes, who else took a call that morning,
  whether the exported objects contained regulated data.

## Attribution, honestly

The scenario is built from public reporting on this group's tradecraft. Naming
an actor in a simulation is useful for realism and for testing whether the agents
reason about campaign context — but note that the platform is being asked to
assess *evidence*, and attribution from a single incident is rarely sound. If a
run confidently names the group without hedging, treat that as a finding about
the agents rather than a success.
