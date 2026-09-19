# SRE Starter Kit — feature report, Free vs Pro

Last verified 2026-09-19 on a real AWS account (EC2 t3.medium, RDS Postgres 16, CloudWatch), with a
real Anthropic key for the AI triage notes. Everything below is either in the public repo or was run
that day; nothing is planned-but-not-built.

## The one-paragraph version

A self-hosted Prometheus, Alertmanager, Grafana, Loki and Alloy stack for teams of 3 to 20 with no
dedicated SRE. One command installs it on Docker Compose (both tiers) or Kubernetes (Pro). The
free tier is MIT-licensed and public. Pro is a one-time $199 licence for your organisation: more
modules, a written runbook behind every alert, deploy markers, SLO burn-rate alerts, a Helm chart,
and AI triage notes that run inside your own network with your own Anthropic key.

## Side by side

| Capability | Free | Pro |
|---|---|---|
| Install | `make init` wizard → `.env` → `make up`, Docker Compose | Same wizard, plus a Helm chart for Kubernetes / EKS |
| Host metrics | node_exporter (host network namespace, so it sees the real host) | ✓ |
| Container metrics | cAdvisor (optional profile) | ✓ |
| HTTP probes | blackbox exporter for every service you list (`SERVICES=`) | ✓ |
| Logs | Loki + Grafana Alloy (Promtail is EOL and not used) | ✓ |
| Alert rules | 16 Prometheus (infra + app) + 4 Loki (log bursts, HTTP 5xx in access logs, SSH failed-login burst, root login) | 40 to 65 Prometheus depending on modules + 4 Loki + 5 recording rules |
| Receivers | Slack, Discord, email (SMTP), Telegram, MS Teams. Any one is enough | ✓ |
| Routing | critical → now, repeats hourly; warning → batched every 30 min; NodeDown silences the node's other alerts | + service down silences its error/latency/SLO alerts; exporter down silences its AWS alerts (12 inhibit rules) |
| Alert documentation | `docs/ALERTS.md`: one section per alert, what fires it and where to look first | `runbooks/<Alert>.md`: 69 files, same headings every time (meaning, first checks, usual causes, mitigation, root-cause fix), linked from every notification; a test fails the build if an alert has no runbook or a runbook has no alert |
| Dashboards | Overview, Node, App | + Container, Logs, AWS, Airflow, Kubernetes, SLO, Postgres (9 total) |
| AWS CloudWatch module | — | YACE discovers RDS, ALB, EC2 and NAT gateways by tag: RDS storage, CPU, connections, replica lag, CPU credits, gp2 burst balance; ALB 5xx and unhealthy targets; EC2 status checks, CPU credits, surplus-credit charges; NAT gateway port-allocation errors and drops; on-demand vCPU quota (`EC2_VCPU_QUOTA`); billing threshold. Instance role or access key |
| Ops module | — | Backup dead man's switch (one line at the end of each backup job), RDS snapshot age, Watchdog → healthchecks.io, AWS billing threshold |
| Postgres module | — | postgres_exporter: connections vs max_connections, replica lag, idle-in-transaction, deadlocks, dead tuples; works against RDS with `sslmode=require` |
| Airflow module | — | Scheduler health, DAG failures, run duration vs a 7-day baseline, queue backlog, via StatsD (no plugin) |
| Kubernetes module | — | Node, pod, job and deployment health from kube-state-metrics; Helm chart installs everything |
| SLO | — | Error-ratio recording rules (app metrics, blackbox fallback) and burn-rate alerts: BurnRateFast (14.4×, critical), BurnRateSlow (6×, warning), guarded against the first-hour false positive |
| Deploy markers | — | `scripts/deploy-annotate.sh` writes a Grafana annotation and a 5-minute silence for the service |
| AI triage agent | Dry run only: gathers a context pack per critical alert and prints it to its log; nothing leaves your network | Live mode: the same redacted pack goes from your host straight to the model with **your** key, and a triage note is posted to your alert channel. Anthropic by default, or any OpenAI-compatible endpoint: your internal vLLM/Ollama/LiteLLM, DeepSeek, GLM, OpenAI |
| Token caps for the model | — | `TRIAGE_MAX_INPUT_TOKENS` bounds the pack (default: half the model's known context window, else 10k; never above the 40 KB hard cap), `TRIAGE_MAX_OUTPUT_TOKENS` bounds the answer |
| Finding a dashboard | Grafana opens on Overview; every dashboard has an "SRE Kit" dropdown listing the others; every alert links the dashboard for its module next to the runbook | ✓ |
| Updates | Public repo | Private repo, 12 months of tagged releases |
| Support | Community | Email, for the 12 months of updates; that is why every alert has a runbook |
| Licence | MIT | Perpetual, your organisation, any number of hosts, source included |

## What the AI triage note is, exactly

When a critical alert fires, Alertmanager sends a copy to a small agent inside the stack
(`scripts/triage_agent.py`, standard-library Python, readable end to end). The agent gathers, from
the kit's own services only:

- the firing rule, its current value and a 30-minute trend from Prometheus
- the last error lines for the service from Loki
- every other firing alert
- Grafana deploy annotations from the last two hours
- the alert's runbook (Pro: the real `runbooks/<Alert>.md` file)

It redacts passwords, tokens, API keys, webhook URLs and emails, trims the pack to 40 KB, and in Pro
asks Claude for a note with a fixed shape: probable causes with the number or log line each rests
on, whether a deploy lines up, what to check first (only commands that appear verbatim in the
runbook), and what it did not see. The note is at most 25 lines and ends with where to find the
pack. If anything fails, the agent logs one line and posts nothing: a wrong note in an alert channel
at 3 am is worse than no note.

Companies with an internal serving endpoint or a non-Anthropic vendor set `TRIAGE_PROVIDER=openai` and
`TRIAGE_ENDPOINT_URL`; the agent asks for structured output and falls back to plain JSON for servers
that do not support it, and validates the answer the same way either way.

Measured 2026-09-19 with a real key and a real 2.9 KB pack: about 2,600 input and 500 output tokens
on Claude Sonnet 5 (about $0.01 per note), about 2,100 / 300 on Claude Haiku 4.5 (about $0.004),
billed to your own Anthropic account. There is no subscription and no server of ours in the path.

## What was verified on 2026-09-19

- Pro compose stack on an EC2 t3.medium (Ubuntu 24.04, Docker 29): 11 targets UP, 40 alert rules
  and 5 recording rules loaded with the AWS, ops, Postgres and triage profiles on.
- Postgres module against a real RDS Postgres 16 instance over `sslmode=require`: `pg_up = 1`.
- AWS module with an instance role (no access key): CloudWatch metrics for EC2, RDS and billing
  arrived within one scrape interval.
- 8 Grafana dashboards rendered with live data (Overview, Node, Container, App, Logs, Postgres,
  AWS, SLO).
- Pro Helm chart on EKS 1.33 (eksctl, 2 nodes, EBS CSI, gp3): 16 targets UP, 35 alerts loaded, a real
  crash-looping pod fired `KubePodCrashLooping` and the Discord notification carried the Kubernetes
  dashboard link next to the runbook.
- A real incident, not a synthetic alert: the VM's access to RDS was cut at the security group;
  `PostgresExporterDown` (critical) fired after its 5-minute window and the AI triage note was in
  Discord 39 seconds later, generated by Claude Sonnet 5 with the owner's own key.

## What is deliberately not in either tier

- No hosted service, no data of yours on our side. The only thing that ever leaves your network is
  the redacted triage pack, and only in Pro, and only to Anthropic with your key.
- No on-call scheduling or escalation; PagerDuty and friends do that better.
- No automatic remediation. The kit reads; people act.
- No support for Alertmanagers outside the kit.
- The Helm chart has no triage agent yet; AI triage is Compose-only today.

## Links

- Free tier: https://github.com/nhanlagc60299/sre-starter-kit
- Pro, $199 one payment: https://lagcian.gumroad.com/l/sre-starter-kit-pro
- Overview page: https://nhanlagc60299.github.io/sre-starter-kit/
