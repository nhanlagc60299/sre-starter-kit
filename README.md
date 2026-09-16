# SRE Starter Kit (free)

Production-tuned Prometheus + Grafana + Loki stack for small teams on VMs/EC2. One command, sane alerts, no noise.

**Who it is for:** 3–20 devs, 5–30 hosts, no SRE. If you have one host and one service, use Sentry + an uptime pinger instead.

## 5-minute install

Requirements: Docker + Compose v2 (or Podman: `CONTAINER_ENGINE=podman make up`), bash, `envsubst` (`apt install gettext-base` / `brew install gettext`), `python3` (ships with virtually every Linux/macOS; used by the render and validate scripts).

```bash
git clone https://github.com/nhanlagc60299/sre-starter-kit && cd sre-starter-kit
make init      # answers -> .env
make up        # http://localhost:3000  (admin / your password)
```

Re-run `make init` any time; previous answers are the defaults. A blank answer on re-run keeps the previous value; to clear a value, edit `.env` directly.

`make up` re-renders `build/` from `.env` and reloads Prometheus, Alertmanager and Alloy in place, so it is also the command to run after any config change.

**Podman hosts:** set `NODE_EXPORTER_TARGET` (see "Exposure" — rootless Podman cannot scrape
node-exporter at all, and you lose every host metric and infra alert if you skip this), set
`CONTAINER_ENGINE=podman`, point `CONTAINER_SOCK` at your Podman socket, and leave `COMPOSE_PROFILES` empty in `.env` — cAdvisor needs Docker's `/var/lib/docker` and will not start. Its scrape target then shows DOWN in Prometheus and stays quiet: `ContainerMetricsMissing` only fires when cAdvisor is up and reporting nothing, so running without it is a supported choice rather than a permanent page. You get no container metrics, and the alerts built on them never fire.

## Exposure

Prometheus (9090), Alertmanager (9093) and Loki (3100) have **no authentication** — anyone who can
reach the port can read your metrics and logs and silence your alerts. Grafana (3000) has a password.
So every published port binds to `127.0.0.1` by default (`BIND_ADDR` in `.env`) — with one
exception, node-exporter, below.

To reach Grafana from your laptop, tunnel instead of opening the port:

```bash
ssh -L 3000:127.0.0.1:3000 you@your-host   # then http://localhost:3000
```

Only set `BIND_ADDR=0.0.0.0` if a reverse proxy in front of the host is doing the authentication.

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
| Alerts | critical → Slack now, repeats hourly. warning → batched every 30 min. NodeDown silences the other infra alerts on that node; DiskFull silences DiskLow, HighErrorRate silences ElevatedErrorRate. |
| Receivers | Slack (required), Telegram, MS Teams |
| Dashboards | Overview (is anything wrong?), Node, App |
| Early warning | SSH failed-login bursts, root logins. **Not a security control.** |

Full alert list: [core/prometheus/rules](core/prometheus/rules) (infra + app) and
[core/loki/rules/fake/security.yml](core/loki/rules/fake/security.yml) (SSH early warning).
Every alert carries a `runbook_url` annotation pointing at its entry in [docs/ALERTS.md](docs/ALERTS.md), which says what makes the alert fire and where to look first. Full runbooks with usual causes, mitigation and the root-cause fix are a Pro feature, see below. To use your own documentation instead, edit the `runbook_url` lines under `core/`.

## App metrics (optional)

Error-rate and latency alerts fire if your service exposes Prometheus metrics named
`http_requests_total{status}` and `http_request_duration_seconds_bucket`. Most client libraries
(prom-client, prometheus_client, promhttp middleware) emit these by default. Add the scrape target
to `core/prometheus/prometheus.yml.tpl` under a job with a `service` label (`build/` is regenerated on every `make up`).

Name each probe after its compose service name (`api=http://...` for compose service `api`) so logs and
metrics line up in the dashboards: `service` is the probe name in Prometheus but the container's compose
service name in Loki, so the App and Overview log panels stay empty when the two differ.

`build/` contains rendered secrets (Slack/Telegram/Teams webhooks) readable by other local users — run
the kit on a host you control.

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

AWS CloudWatch alerts (RDS/ELB/EC2), a Kubernetes module (node, pod and job health from
kube-state-metrics), an Airflow module (scheduler health, DAG failures, run duration against a
7-day baseline, queue backlog), SLO burn-rate alerts, backup dead-man's switch, monitoring
watchdog, deploy markers on every dashboard, and a written runbook for all 53 alerts (51 from
Prometheus metrics, 2 from Loki logs).

Both flavours ship: `docker compose` for VMs, and a Helm chart for Kubernetes.

To buy Pro or ask what it covers, email **nhanlagc60299@gmail.com**.

## License

MIT. See [LICENSE](LICENSE).
