# Alert reference

Every alert in this kit sets a `runbook_url` annotation pointing at its section below, so the link
in Slack, Telegram or Teams always resolves to something.

Each entry states what makes the alert fire and the first thing worth looking at. Full runbooks —
usual causes, mitigation, and the root-cause fix for every alert in the free and Pro rule sets —
are part of the Pro tier. Two of those runbooks are included here unchanged so you can judge the format before paying: [ServiceDown](runbooks/ServiceDown.md) and [DiskWillFillIn24h](runbooks/DiskWillFillIn24h.md). To point these links at your own documentation instead, edit the
`runbook_url` lines under `core/prometheus/rules/` and `core/loki/rules/`.

## Service and probe alerts

### ServiceDown
Critical, after 2m. A blackbox HTTP probe of a service in `SERVICES` has failed for two minutes.
Check whether the service is actually down or only unreachable from the monitoring host.

Full Pro runbook, included as a sample: [ServiceDown](runbooks/ServiceDown.md).

### BlackboxExporterDown
Critical, after 5m. The blackbox exporter itself is not scrapeable, so no probe is running and
`ServiceDown` cannot fire. Check the `blackbox` container before trusting any probe result.

Reads `up{job="blackbox"}` -- the exporter's own `/metrics`, which is scraped whether or not
`SERVICES` lists anything. Do not point it at `job="blackbox-http"`: that job has one series per
probe target, so on a stack with `SERVICES` empty it has none, and an alert reading it can never
fire. It did read that until 2026-09-17.

### CertExpiresIn7d
Warning, after 1m. The TLS certificate served by a probed HTTPS endpoint expires within 7 days.
Renew it, then confirm the new certificate is the one actually being served.

### HighErrorRate
Critical, after 5m. The service's HTTP 5xx rate over 5 minutes crossed the critical threshold.
Look at which endpoint carries the errors before assuming the whole service is broken.

### ElevatedErrorRate
Warning, after 15m. A lower 5xx rate sustained over 15 minutes. This catches a slow bleed that
`HighErrorRate` is deliberately too blunt to see.

### HighP95Latency
Warning, after 10m. The service's 95th-percentile request latency stayed above the threshold.
Compare against deploy times and downstream dependency latency.

## Log alerts

Both read Loki, not Prometheus, and both count lines per compose `service` over five minutes. They exist for
services that expose no metrics: the error-rate alerts above need `http_requests_total`, which most small
apps do not emit, and these two need only stdout. The kit's own containers are excluded by name.

### LogErrorBurst
Warning, after 5m. More than 50 lines in 5 minutes matched `error`, `exception`, `fatal`, `panic` or
`traceback` (case-insensitive, whole word). Open the Logs panel on the App dashboard for that service and
read the first error of the burst, not the last.

### Http5xxInLogs
Warning, after 5m. More than 20 access-log lines in 5 minutes carried a 5xx status in common log format
(`"GET /path HTTP/1.1" 502`). JSON access logs do not match this pattern; edit the regex in
`core/loki/rules/fake/logs.yml` if yours are JSON. Check whether the 5xx come from the app or from the proxy
in front of it: a proxy 502 with a quiet app means the app is not answering.

## Host alerts

### NodeDown
Critical, after 2m. node_exporter on the host stopped responding. Distinguish a dead host from a
dead exporter before paging anyone.

### DiskFull
Critical, after 2m. Free space on the mount point fell below `DISK_CRIT_PCT`. Find the largest
recent growth rather than deleting the first big file you see.

### DiskLow
Warning, after 10m. Free space fell below `DISK_WARN_PCT`. This is the one you act on so
`DiskFull` never fires.

### DiskWillFillIn24h
Warning, after 30m. Linear prediction from recent usage says the mount fills within 24 hours.
It fires while free space still looks comfortable, which is the point.

Full Pro runbook, included as a sample: [DiskWillFillIn24h](runbooks/DiskWillFillIn24h.md).

### HighCPU
Warning, after 15m. Host CPU stayed above 85% for 15 minutes. Sustained saturation, not a spike.

### HighMemory
Warning, after 10m. Host memory stayed above 90% for 10 minutes. Check for a leak before adding RAM.

## Container alerts

### ContainerMetricsMissing
Critical, after 5m. cAdvisor is being scraped successfully and is reporting no containers at all.
Every other alert on this page that names a container is blind while this is firing, which is why
it pages rather than waits.

The usual cause is a cAdvisor too old for the host's Docker. Docker 29 made the containerd image
store the default, which removes the layer database older cAdvisor builds read to identify a
container; cAdvisor then fails to register every container and reports only host cgroups. Nothing
about this looks broken from outside: the container is healthy, the scrape target is UP, and
metrics keep flowing. Measured on Docker 29.2.1, cAdvisor v0.52.1 produced 1857 `container_*`
series and not one of them named a container.

First check which storage driver the host uses and what the cAdvisor log says:

```bash
docker info --format '{{.Driver}}'
docker compose --env-file .env -f compose/docker-compose.yml logs cadvisor | grep -i "layer"
```

A line reading `failed to identify the read-write layer ID` on every container confirms it. This
kit ships cAdvisor v0.60.5, which handles both the `overlayfs` and `overlay2` drivers; if you
pinned an older image, that is the fix.

### ContainerMemoryNearLimit
Warning, after 10m. A container has held above 80% of its memory limit for ten minutes. The limit
and the workload disagree; find out which one is wrong, while the container is still up.

Containers started without a memory limit are excluded, not silently included: cAdvisor reports
their limit as 0, and the rule filters those out rather than dividing by zero.

### ContainerAtMemoryCeiling
Warning, after 15m. The kernel has been refusing this container's allocations at its memory limit,
without pause, for fifteen minutes.

This is not the same thing as `ContainerMemoryNearLimit`, and it catches what that rule cannot.
Working set counts memory that cannot be reclaimed, so a container whose pressure is page cache
sits at a *low* working set while hammering its limit continuously: measured at 4% of its limit
with the kernel refusing 213 allocations at that limit over the same period. The container is not
dying, but every one of those refusals costs it a reclaim cycle, and it is one workload change
away from not surviving them.

There is no count threshold on purpose. A container that touches its ceiling once and reclaims is
healthy, and no number of hits is meaningfully "too many". Fifteen unbroken minutes is the signal.

Requires cgroup v2, since the counter comes from the kernel's `memory.events`. On a cgroup v1 host
the series does not exist and this alert is silent rather than wrong.

### ContainerRestartLoop
Critical. A container has restarted more than three times in fifteen minutes. Every restart drops
in-flight requests, and if other services depend on this one, the failures cascade.

This alert was removed once and restored. On cAdvisor v0.52.1 it could not fire:
`container_start_time_seconds` was frozen at the container's first start and never moved again.
Measured side by side on one host, one container, five automatic restarts, v0.52.1 reported the
same value throughout while v0.60.5 tracked every restart. This kit ships v0.60.5.

## What container alerts cannot see

Stated here rather than left for you to discover during an outage.

**A container that is OOM-killed outright is not detected.** cAdvisor only publishes metrics for
containers that are currently **running**, so a container the kernel kills disappears from the
metrics along with the evidence. Measured on Docker 29.2.1: a container that allocated hard and
was killed with exit 137 showed a memory-events counter of 0 at every scrape while it lived, and
no series at all one second later. `ContainerAtMemoryCeiling` and `ContainerMemoryNearLimit` both
cover the approach to that point — memory pressure while the container is still alive — and both
will miss a container killed by a sudden allocation between two scrapes.

**A container that dies instantly is not detected either.** Docker backs off exponentially between
restarts, so a container that exits immediately spends nearly all of its time in `Restarting`,
where cAdvisor publishes nothing about it. `ContainerRestartLoop` sees a crash loop in proportion
to how long the container survives each cycle. Measured on cAdvisor v0.60.5, sampling every four
seconds:

| Lifetime per cycle | Visible to cAdvisor |
|---|---|
| 15s | every sample |
| 5s | 70% of samples |
| 2s | 20% of samples |
| exits immediately | never |

A container in the last row restarts endlessly with nothing to show for it. If it serves HTTP, add
it to `SERVICES` in `.env` and the blackbox probe will catch it going down, which is the coverage
cAdvisor cannot give you.

**On Kubernetes both cases are covered** by the Pro Helm chart's `kubernetes` module, which reads
kube-state-metrics rather than cAdvisor: `KubePodCrashLooping` and `KubeContainerOOMKilled`.
kube-state-metrics reports a pod that is gone, which is the whole difference.

## Security alerts

These are early warnings from `auth.log`, not a security control. Treat them as a signal to look,
not as intrusion detection.

### SSHFailedLoginBurst
Warning, after 1m. More than 20 failed SSH logins in 5 minutes from one address. Usually noise
from the public internet; worth attention when the source is inside your network.

### RootLoginDetected
Warning, fires immediately. An SSH login as root was accepted. Expected on some setups, alarming
on others, which is why it only warns.
