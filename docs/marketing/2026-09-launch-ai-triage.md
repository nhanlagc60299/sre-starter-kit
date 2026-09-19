# Your alerts can now explain themselves

*SRE Starter Kit Pro: a self-hosted monitoring stack for teams with no SRE, now with AI triage notes
that run on your own machines, with your own Anthropic key.*

Most small teams have the same monitoring: a Grafana somebody set up two years ago, a handful of
alert rules nobody trusts, and a Slack channel where "ServiceDown" arrives at 3 am with no context.
The person on call opens six tabs and starts guessing.

SRE Starter Kit is the stack I wanted to hand those teams. One command installs Prometheus,
Alertmanager, Grafana, Loki and Alloy on Docker Compose or Kubernetes. Every alert has a written
runbook behind it. And since this week, in Pro, every critical alert comes with a triage note.

## What a note looks like

This is a real one from today, from a stack running on AWS, posted to Discord about a minute after
the alert:

```
Triage: ServiceDown on prometheus-self: blackbox HTTP probe to prometheus:9090/-/healthy failing since 07:56        (confidence: low)
Probable cause
  1. Prometheus itself may be down or unreachable, causing the health probe to fail. — rule query: probe_success{job="blackbox-http"} == 0, alert active since 2026-09-19T07:56:17Z
  2. Underlying host/node may be down, which could take the Prometheus container with it. — NodeDown alert on node-exporter:9100 firing since 07:48:03Z, ~8 min before ServiceDown
Also firing: NodeDown on node-exporter:9100 (started 07:48, ~8 min before ServiceDown; possibly same underlying host issue but not confirmed)
Check first (from runbook)
  curl -sv <url>
  docker compose ps <service>
  docker logs --tail 50 <service>
Not seen: grafana: empty; loki: empty; query: empty; query_range: empty; no deploys recorded in last 2 hours, so no deploy correlation to check
Pack: docker compose logs triage-agent
```

Three things to notice. Every cause cites the number or alert it rests on. The commands come from
the runbook, verbatim, never invented. And it says what it could not see. A note that guesses is
worse than no note, so the agent is built to refuse: if the model answers with a command that is
not in your runbook, the command is dropped; if it forgets to mention a deploy that happened, a
line is added; if anything fails at all, nothing is posted and one line goes to the log.

## How it works, and what leaves your network

A small Python agent inside the stack (standard library only, about 500 lines you can read)
receives a copy of every critical alert. It gathers the firing rule and a 30-minute trend from
Prometheus, the last error lines from Loki, the other firing alerts, deploy annotations from the
last two hours, and the alert's runbook. It redacts passwords, tokens, keys, webhook URLs and
emails, trims the pack to 40 KB, and sends it from your host straight to the Anthropic API with
your key. There is no server of mine in the path. No subscription, no quota, no data of yours on
my side.

Dry run is the default: the agent prints the pack to its own log and sends nothing, so you can read
exactly what would leave before you paste a key. The free tier stops there.

Measured today with a real key and a real pack: about 2,600 input and 500 output tokens on Claude
Sonnet 5, roughly one cent per note; about a third of that on Haiku. Ten critical alerts a day is
under $4 a month.

## What else Pro adds

- AWS CloudWatch alerts for RDS, ALB and EC2 through YACE, with an instance role, no access key.
- A Postgres module that works against RDS: connections, replica lag, idle-in-transaction,
  deadlocks, dead tuples.
- An ops module: a one-line backup dead man's switch, RDS snapshot age, a watchdog to
  healthchecks.io, an AWS billing threshold.
- Airflow and Kubernetes modules, a Helm chart tested on EKS.
- SLO burn-rate alerts and deploy markers on every dashboard.
- 62 runbooks, one per alert, same headings every time, linked from every notification. A test
  fails the build if an alert has no runbook.

Everything above was run on a real AWS account this week, not inferred from documentation: EC2,
RDS Postgres 16, CloudWatch, and a Discord channel that received the alerts and the notes.

## Pricing

Pro is $199, one payment, for your organisation on any number of hosts, source included, twelve
months of updates. No support contract; that is what the runbooks are for. The free tier is MIT
and public; install it first, it is the same stack without the modules, so you can judge the code
before paying for more of it.

- Free: https://github.com/nhanlagc60299/sre-starter-kit
- Pro: https://lagcian.gumroad.com/l/sre-starter-kit-pro
- Overview: https://nhanlagc60299.github.io/sre-starter-kit/

If a note is wrong, reply to your receipt with the pack from `docker compose logs triage-agent`.
That is the whole feedback loop this year, and it is enough to keep fixing the prompt.
