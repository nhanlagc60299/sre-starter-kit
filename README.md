# SRE Starter Kit (free)

Production-tuned Prometheus + Grafana + Loki stack for small teams on VMs/EC2. One command, sane alerts, no noise.

**Who it is for:** 3–20 devs, 5–30 hosts, no SRE. If you have one host and one service, use Sentry + an uptime pinger instead.

## 5-minute install

Requirements: Docker + Compose v2 (or Podman: `CONTAINER_ENGINE=podman make up`), bash, `envsubst` (`apt install gettext-base` / `brew install gettext`).

```bash
git clone https://gitlab.com/nhanlagc60299/sre-starter-kit && cd sre-starter-kit
make init      # answers -> .env
make up        # http://localhost:3000  (admin / your password)
```

Re-run `make init` any time; previous answers are the defaults.

**Podman hosts:** set `CONTAINER_ENGINE=podman`, point `CONTAINER_SOCK` at your Podman socket, and leave `COMPOSE_PROFILES` empty in `.env` — cAdvisor needs Docker's `/var/lib/docker` and will not start. Its scrape target then shows DOWN in Prometheus; no alert keys on it.

## What you get

| | |
|---|---|
| Metrics | node_exporter, cAdvisor, blackbox HTTP probes for every service you list |
| Logs | Loki + Grafana Alloy (Promtail is EOL — this kit does not use it) |
| Alerts | critical → Slack now, repeats hourly. warning → batched every 30 min. NodeDown silences the rest of that node. |
| Receivers | Slack (required), Telegram, MS Teams |
| Dashboards | Overview (is anything wrong?), Node, App |
| Early warning | SSH failed-login bursts, root logins. **Not a security control.** |

Full alert list: [core/prometheus/rules](core/prometheus/rules). Every alert links to a runbook page.

## App metrics (optional)

Error-rate and latency alerts fire if your service exposes Prometheus metrics named
`http_requests_total{status}` and `http_request_duration_seconds_bucket`. Most client libraries
(prom-client, prometheus_client, promhttp middleware) emit these by default. Add the scrape target
to `core/prometheus/prometheus.yml.tpl` under a job with a `service` label (`build/` is regenerated on every `make up`).

## Sizing

| Scale | Machine | Disk |
|---|---|---|
| ≤10 hosts, 5 services | 2 vCPU, 2 GB | 30 GB |
| ≤30 hosts, 15 services | 2 vCPU, 4 GB | 100 GB |

Rule of thumb: ~1 GB per host for 15 days of metrics, ~2 GB per service for 7 days of logs.
Prometheus stops at `PROM_RETENTION_SIZE` (default 20 GB) so it cannot fill the disk.

## Layout

`core/` is environment-agnostic config. `compose/` only runs it. `make render` turns `core/*.tpl` + `.env` into `build/`.
Edit `core/`, never `build/`.

## Test

```bash
make validate     # promtool/amtool/loki config checks, <10s
make test-rules   # promtool unit tests
make smoke        # full stack up, all targets UP, down
```

## Pro

Helm chart for EKS, AWS CloudWatch alerts (RDS/ELB/EC2), Airflow module, SLO burn-rate alerts,
backup dead-man's switch, watchdog, deploy markers, runbooks for every alert. → *link when live*
