# Threat intelligence

Until this existed, `enrich_ioc` answered from a dictionary someone had typed by
hand. That is fine for a demo and indefensible in an investigation: every
verdict the critic reached, every severity, every containment plan, rested on a
lookup table that knew about four indicators.

This is the replacement — a local corpus, fed on a schedule, queried in SQL
while an incident is live.

The schema and the ingestion method are adapted from the
[Cognitive CTI](https://github.com/Al-T4ie/muraqib-cognitiveCTI) project, which
built them for a standalone strategic-intelligence pipeline. What is kept: the
layered source model, the tiered routing, the entity/report/link shape. What is
dropped: OpenCTI and local Ollama. That project uses OpenCTI to aggregate and
normalise into STIX before analysis, and says plainly that it "is not performing
the analysis" — but everything an incident asks of intelligence here is a SQL
query, so the aggregation layer would be an Elasticsearch, RabbitMQ, MinIO and
worker fleet in service of tables the feeds can populate directly. Adding
OpenCTI later changes nothing below: point it at the same feeds and have it
write the same tables.

## What an investigation can ask

Four tools, available to every specialist:

| Tool | Question it answers |
| --- | --- |
| `check_indicator` | Has any source reported this IP, domain, URL, hash or CVE — and who, when, alongside what? |
| `actor_profile` | What does the corpus hold on this group: tooling, techniques, sectors, known indicators? |
| `technique_context` | Which actors and malware are reported using this ATT&CK technique? |
| `campaign_check` | What has been reported lately — is this incident isolated or part of something? |

`campaign_check` is the one that has no equivalent in a per-lookup vendor API.
"This is the third OAuth-token abuse against a SaaS tenant this month" is the
observation a human analyst makes and a stateless system cannot.

## The rule that governs every answer

**An indicator we have not seen returns `unknown`, never `clean`.**

A fabricated clean verdict is how a real detection gets suppressed, and it is
worse than no answer because it arrives with the authority of a lookup. Every
"not found" response says so in words, and reports the corpus size alongside —
because "not found" against an empty corpus and "not found" against one holding
fifty thousand entities are completely different facts, and only one of them is
about the indicator.

Provenance travels with every hit. "Malicious" from a CISA advisory (layer 1)
and "malicious" from a Telegram channel (layer 5) are not the same claim, and
the layer comes back so the agent can weigh them.

## Sources

| Layer | Trust | Feeds wired |
| --- | --- | --- |
| 1 | Government / vendor advisory | **CISA KEV** — CVEs with confirmed exploitation. No API key. |
| 2 | Independent research | *(none yet — needs the narrative analysis stage)* |
| 3 | Sector-specific | *(left open; depends on your sector)* |
| 4 | IOC feeds | **abuse.ch ThreatFox**, **abuse.ch URLhaus** — needs a free key from auth.abuse.ch |
| 5 | Threat-actor channels | *(not wired; lowest trust, earliest signal)* |

A feed whose key is missing is skipped and logged once, not failed — an
operator with no abuse.ch account still gets CISA KEV.

## Tiered routing

The original project's hardest-won finding: processing all ~5,000 items per
cycle did not merely cost time, it made the output *worse*, because small models
hallucinated more as volume rose. Routing cut it to 50–80 items worth reasoning
about.

The same guard applies here for a different reason — a corpus stuffed with
noise answers "have we seen this" with noise:

    tier 1  narrative intelligence — worth a model call
    tier 2  structured feed data — ingested as metadata, no model
    tier 0  dropped, with the reason recorded

Dropped, currently:

- **Unroutable addresses.** A public feed reporting `10.0.0.5` says nothing
  about *your* `10.0.0.5`, and a corpus that answers "known malicious" for
  RFC 1918 is worse than an empty one.
- **Unclassifiable indicators.** They could never be matched later, so they only
  inflate the corpus count that the tools report as confidence.
- **Stale indicators**, past `CTI_RETENTION_DAYS`.

Nothing is dropped silently — every run reports a tally by reason. A feed that
quietly bins half its input is indistinguishable from one that is broken.

**Retention applies to indicators only.** An address that was command-and-control
two years ago has almost certainly been re-allocated; CVE-2021-44228 is as
exploited today as it was on publication. This rule was written the wrong way
round first, and only running it against the live KEV feed exposed it — 1,399 of
1,665 entries were being discarded, Log4Shell among them.

## Operating it

The caretaker (`app/services/upkeep.py`) pulls **one feed per tick**, so a cold
start with three feeds fills the corpus over three minutes rather than blocking
one tick on every provider at once. A feed is due when its last success is older
than `CTI_REFRESH_HOURS`.

```bash
# Is the corpus alive?
curl -s -H "X-API-Key: $KEY" https://air.husseinaltaie.com/v1/intel | jq

# Pull everything now rather than waiting
curl -s -X POST -H "X-API-Key: $KEY" https://air.husseinaltaie.com/v1/intel/refresh | jq
```

`/v1/intel` exists because the failure mode is silent: a corpus whose feeds have
been returning 401 for a week keeps answering every lookup with "not found", and
"not found" is exactly what a healthy corpus says about a clean indicator. The
`stale` flag and `failing` list are what separate them.

Metrics and logs:

```
agenticir_upkeep_actions_total{action="intel_refresh"}
agenticir_tool_calls_total{tool="check_indicator"}

feeds.ingested          a successful run, with fetched/ingested/dropped
feeds.fetch_failed      a provider that did not answer
feeds.skipped_no_key    a feed configured but missing its credential
feeds.truncated         a batch larger than the per-run cap
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CTI_ENABLED` | `true` | Register the tools and run the ingest at all |
| `CTI_FEEDS` | *(blank)* | Comma-separated feed names; blank runs every feed with a credential |
| `CTI_REFRESH_HOURS` | `6` | How often each feed is re-pulled |
| `CTI_RETENTION_DAYS` | `365` | Indicator age limit; `0` disables. Never applies to CVEs, actors or malware |
| `ABUSECH_API_KEY` | *(blank)* | Free from auth.abuse.ch; unlocks ThreatFox and URLhaus |

## Not built yet

**Narrative sources and the AI analysis stage.** Tier 1 routing exists and
nothing produces tier-1 items, because that needs RSS ingestion plus a
per-report extraction model call. That stage is where the original project's
prompts earn their keep — including its negative rules, which are worth having
verbatim (*"Do NOT assign MITRE ATT&CK techniques to law enforcement actions"*,
*"Nation states in military conflict are NOT cyber threat_actors"*).

**Cross-report correlation.** The most interesting idea in the source project —
a second, larger model reasoning over a whole batch to find what no single
report reveals — needs a corpus of narrative reports to correlate. Wiring it
against a few thousand IOC rows would produce confident nonsense.

**Cross-incident correlation.** The same idea applied to incidents rather than
reports, which is arguably more valuable here and needs a corpus of incidents
this deployment does not yet have.
