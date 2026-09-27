# SRE Starter Kit (free)

Production-tuned Prometheus + Grafana + Loki stack for small teams on VMs/EC2. One command, sane alerts, no noise.

**Who it is for:** 3–20 devs, 5–30 hosts, no SRE. If you have one host and one service, use Sentry + an uptime pinger instead.

## 5-minute install

Requirements: Docker + Compose v2 (or Podman: `CONTAINER_ENGINE=podman make up`), bash, `curl`, `envsubst` (`apt install gettext-base` / `brew install gettext`), `python3` (ships with virtually every Linux/macOS; used by the render and validate scripts).

```bash
git clone https://github.com/nhanlagc60299/sre-starter-kit && cd sre-starter-kit
make init      # answers -> .env
make up        # http://localhost:3000  (admin / your password)
```

Re-run `make init` any time; previous answers are the defaults. A blank answer on re-run keeps the previous value; to clear a value, edit `.env` directly.

`make up` re-renders `build/` from `.env` and reloads Prometheus, Alertmanager and Alloy in place, so it is also the command to run after any config change. Changing the Grafana admin password this way reaches
the already-running Grafana too: `make up` resets the persisted admin password to match `.env`
(`GF_SECURITY_ADMIN_PASSWORD` alone only takes effect the first time Grafana creates that account, not on
a later change). There is no published default to leave in place: `make init` generates a random one for
you if you don't set your own. If you set one by hand, it must be at least 4 characters -- Grafana's own
`reset-admin-password` refuses anything shorter, and `render.sh` refuses it first, before that ever runs.

**Podman hosts:** set `NODE_EXPORTER_TARGET` (see "Exposure" — rootless Podman cannot scrape
node-exporter at all, and you lose every host metric and infra alert if you skip this), set
`CONTAINER_ENGINE=podman`, point `CONTAINER_SOCK` at your Podman socket, and leave `COMPOSE_PROFILES` empty in `.env` — cAdvisor needs Docker's `/var/lib/docker` and will not start. Its scrape target then shows DOWN in Prometheus and stays quiet: `ContainerMetricsMissing` only fires when cAdvisor is up and reporting nothing, so running without it is a supported choice rather than a permanent page. You get no container metrics, and the alerts built on them never fire.

## Exposure

Prometheus (9090), Alertmanager (9093) and Loki (3100) have **no authentication** — anyone who can
reach the port can read your metrics and logs and silence your alerts. Grafana (3000) has a password.
So every published port binds to `127.0.0.1` by default (`BIND_ADDR` in `.env`) — with one
exception, node-exporter, below. The triage agent (9096) is never published, and accepts alerts only
with `TRIAGE_WEBHOOK_TOKEN` once it is set (`make init` generates it; see AI triage). That token
authenticates only the Alertmanager-to-agent hop: Alertmanager's own API has no authentication, so
anyone who can reach it can still trigger triage runs with labels they choose, up to
`TRIAGE_MAX_RUNS_PER_HOUR` -- restrict who can send it alerts with Alertmanager's own
`--web.config.file` basic auth or a NetworkPolicy.

To reach Grafana from your laptop, tunnel instead of opening the port:

```bash
ssh -L 3000:127.0.0.1:3000 you@your-host   # then http://localhost:3000
```

Only set `BIND_ADDR=0.0.0.0` if a reverse proxy in front of the host is doing the authentication.

Every alert links back to Alertmanager at `ALERTMANAGER_EXTERNAL_URL`; set it to whatever your team can actually open, the default is only right on the monitoring host itself.
`GRAFANA_EXTERNAL_URL` (default `http://localhost:3000`) is the dashboard link on every alert: each
alert names the dashboard for its module, next to the runbook. Grafana opens on Overview after login,
and every dashboard carries an "SRE Kit" dropdown listing the others.

**node-exporter (9100) is the exception, and it is deliberate.** It runs in the host network
namespace (`network_mode: host`) because `/proc/net` is namespace-scoped at read time: a
container-networked node-exporter reports its own veth as `node_network_*`, so the Node dashboard's
Network Traffic panels would be drawing the container's traffic under the host's name. The cost of
getting those numbers right is that 9100 binds on every host interface and ignores `BIND_ADDR`. It
exposes host telemetry (interfaces, filesystems, load) unauthenticated, so firewall it. A host
already running its own node-exporter on 9100 will collide; stop that one, or drop the host
networking back out and accept container-scoped network metrics.

Being in the host namespace also takes node-exporter off the compose network, so Prometheus can no
longer reach it by service name. `NODE_EXPORTER_TARGET` in `.env` is the address it uses instead.
The default, `node-exporter:9100`, resolves through the `host-gateway` alias on the Prometheus
service and is correct on Docker. **Under rootless Podman it cannot work at all, and the whole
`node` job goes down with it — not just the network panels, but every host CPU, memory and disk
metric and every infra alert built on them.** A rootless container on a bridge network has no route
into the host network namespace. Rootful Podman works: set `NODE_EXPORTER_TARGET` to the bridge
gateway (`podman network inspect podman` prints it, commonly `10.88.0.1:9100`). Rootless Podman has
no fix here; run node-exporter on the host as a systemd unit and point `NODE_EXPORTER_TARGET` at it,
or accept that host metrics are absent.

## What you get

| | |
|---|---|
| Metrics | node_exporter, cAdvisor, blackbox HTTP probes for every service you list |
| Logs | Loki + Grafana Alloy (Promtail is EOL — this kit does not use it) |
| Alerts | critical → your receiver now, repeats hourly. warning → batched every 30 min. NodeDown silences the other infra alerts on that node; DiskFull silences DiskLow, HighErrorRate silences ElevatedErrorRate. Two log-based alerts (error bursts, HTTP 5xx in access logs) cover services that expose no metrics. |
| Receivers | Slack, Discord, email (SMTP), Telegram, MS Teams. Any one is enough. |
| Dashboards | Overview (is anything wrong?), Node, App |
| Early warning | SSH failed-login bursts, root logins. **Not a security control.** |

Full alert list: [core/prometheus/rules](core/prometheus/rules) (infra + app),
[core/loki/rules/fake/security.yml](core/loki/rules/fake/security.yml) (SSH early warning) and
[core/loki/rules/fake/logs.yml](core/loki/rules/fake/logs.yml) (log-based).
Every alert carries a `runbook_url` annotation pointing at its entry in [docs/ALERTS.md](docs/ALERTS.md), which says what makes the alert fire and where to look first. Full runbooks with usual causes, mitigation and the root-cause fix are a Pro feature, see below. To use your own documentation instead, edit the `runbook_url` lines under `core/`.

## App metrics (optional)

Error-rate and latency alerts fire if your service exposes Prometheus metrics named
`http_requests_total{status}` and `http_request_duration_seconds_bucket`. Most client libraries
(prom-client, prometheus_client, promhttp middleware) emit these by default. Add the scrape target
to `core/prometheus/prometheus.yml.tpl` under a job with a `service` label (`build/` is regenerated on every `make up`).

Name each probe after its compose service name (`api=http://...` for compose service `api`) so logs and
metrics line up in the dashboards: `service` is the probe name in Prometheus but the container's compose
service name in Loki, so the App and Overview log panels stay empty when the two differ.

`build/` contains rendered secrets (Slack/Discord/Teams webhooks, the Telegram bot token, the SMTP
password) readable by other local users — run the kit on a host you control.

## AI triage (optional)

Answer `y` to the triage question in `make init` and the kit runs a small agent
(`scripts/triage_agent.py`, standard-library Python) that receives a copy of every critical alert. It
gathers the alert's rule and current values from Prometheus, the last error lines from Loki, other
firing alerts, recent deploy annotations and the alert's runbook section, and makes a best-effort
pass at redacting common credential shapes (passwords and API keys, `Authorization`/`Bearer`/`Cookie`
headers, signed-URL parameters, PEM keys, emails) before any of it is written anywhere. It cannot
catch a passphrase containing spaces or a secret described in prose (`api key is X`) -- keep those out
of alert text and logs.

`TRIAGE_DRY_RUN=true` is the default, and nothing leaves your network in that mode: the context pack
is only printed to the agent's own log (`docker compose logs triage-agent`). The free tier runs the
agent in dry run only; the note itself (the model call, with your own Anthropic key) is a Pro feature.

`TRIAGE_REDACT` adds your own regexes (separated by `;;`) to strip from log lines before anything is
sent, on top of the built-in shapes above.

Alertmanager authenticates to the agent with `TRIAGE_WEBHOOK_TOKEN`. `make init` generates one (hex)
when you turn triage on and keeps it on every re-run; `render.sh` adds it to the `webhook-triage`
receiver as a Bearer credential, and the agent answers 401 to any alert that does not carry it. Empty
means no header and no check. Use ASCII only — `render.sh` refuses anything else, because such a
token could never match. This only authenticates the Alertmanager-to-agent hop, though: Alertmanager's
own API has no authentication, so anyone who can reach it can still trigger a triage run with labels
of their choosing, up to the cap below — restrict who may send it alerts with Alertmanager's
`--web.config.file` basic auth or a NetworkPolicy. `TRIAGE_MAX_RUNS_PER_HOUR` caps triage runs in any rolling hour (empty = 30,
`0` = unlimited), so a burst of alert groups cannot turn into a burst of dry-run packs. A run the cap
refuses logs `skip: hourly triage run cap reached`, and its alert group is still marked triaged, so a
repeat of it within the hour is skipped too.

The agent also carries a read-only tool registry (`prom_query`, `prom_range`, `loki_query`, `alerts`,
`deploys`, `runbook`) that Pro's engine may call while it thinks, and Pro prints one `triage-trace`
line per run summarising what the model asked for. Without the engine (this tier) nothing calls the
tools and no trace line is printed: dry run behaves exactly as before.

## Sizing

| Scale | Machine | Disk |
|---|---|---|
| ≤10 hosts, 5 services | 2 vCPU, 2 GB | 30 GB |
| ≤30 hosts, 15 services | 2 vCPU, 4 GB | 100 GB |

Rule of thumb: ~1 GB per host for 15 days of metrics, ~2 GB per service for 7 days of logs.
Prometheus stops at `PROM_RETENTION_SIZE` (default 20 GB). Loki is capped by time only
(`LOKI_RETENTION_PERIOD`), so its disk use follows how much you log — size the disk for your peak
ingest rate and watch the DiskLow alert.

## Layout

`core/` is environment-agnostic config. `compose/` only runs it. `make render` turns `core/*.tpl` + `.env` into `build/`.
Edit `core/`, never `build/`.

## Test

```bash
make validate     # promtool/amtool/loki config checks, <10s
make test-rules   # promtool unit tests
make smoke        # full stack up, all targets UP, down
```

`make smoke` starts a second stack (`sre-kit-smoke`) on the same ports and overwrites `build/` with
throwaway config; on exit it restores your `.env` and re-renders `build/`. Do not run it on a host that
is serving production traffic.

## Pro

AWS CloudWatch alerts (RDS/ELB/EC2/NAT gateway, CPU credits, vCPU quota), a Kubernetes module (node, pod and job health from
kube-state-metrics), an Airflow module (scheduler health, DAG failures, run duration against a
7-day baseline, queue backlog), a Postgres module (connections, replica lag, idle transactions,
deadlocks, dead tuples), SLO burn-rate alerts, backup dead-man's switch, monitoring watchdog,
deploy markers on every dashboard, and a written runbook for all 69 alerts (65 from Prometheus
metrics, 4 from Loki logs).

Both flavours ship: `docker compose` for VMs, and a Helm chart for Kubernetes.

**[Pro is $199, one payment](https://lagcian.gumroad.com/l/sre-starter-kit-pro)** -- a perpetual
licence for your organisation on any number of hosts, source included, 12 months of updates.
Support is not included; that is why every alert ships with a runbook. Two of those runbooks are in this repo unchanged, [ServiceDown](docs/runbooks/ServiceDown.md) and [DiskWillFillIn24h](docs/runbooks/DiskWillFillIn24h.md), so you can see what you are paying for.

### AI triage notes

When a critical alert fires, the agent already in this kit gathers the rule's numbers, a 30-minute
trend, recent error logs, and any Grafana deploy annotation from the last two hours. In Pro it then
asks Claude, with your own Anthropic API key, and posts a short note back to your alert channel:
probable cause with the numbers it rests on, whether a deploy lines up, and what to check first from
your runbook. Nothing goes through us; the free tier stops at the dry-run pack you can read in
`docker compose logs triage-agent`.

Install this free tier first. It is the same stack without the modules above, so it is the honest
way to judge the code before paying for more of it. Questions: **nhanlagc60299@gmail.com**.

## Feature report

A side-by-side of the free and Pro tiers, last verified on a real AWS account: [docs/FEATURES.md](docs/FEATURES.md).

## License

MIT. See [LICENSE](LICENSE).
