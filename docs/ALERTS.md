# Alert reference

Every alert in this kit sets a `runbook_url` annotation pointing at its section below, so the link
in Slack, Telegram or Teams always resolves to something.

Each entry states what makes the alert fire and the first thing worth looking at. Full runbooks —
usual causes, mitigation, and the root-cause fix for all 32 alerts across the free and Pro rule
sets — are part of the Pro tier. To point these links at your own documentation instead, edit the
`runbook_url` lines under `core/prometheus/rules/` and `core/loki/rules/`.

## Service and probe alerts

### ServiceDown
Critical, after 2m. A blackbox HTTP probe of a service in `SERVICES` has failed for two minutes.
Check whether the service is actually down or only unreachable from the monitoring host.

### BlackboxExporterDown
Critical, after 5m. The blackbox exporter itself is not scrapeable, so no probe is running and
`ServiceDown` cannot fire. Check the `blackbox` container before trusting any probe result.

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

### HighCPU
Warning, after 15m. Host CPU stayed above 85% for 15 minutes. Sustained saturation, not a spike.

### HighMemory
Warning, after 10m. Host memory stayed above 90% for 10 minutes. Check for a leak before adding RAM.

## Container alerts

### OOMKilled
Critical, fires immediately. A container was killed by the kernel out-of-memory killer. The limit
and the workload disagree; find out which one is wrong.

### ContainerRestartLoop
Critical, fires immediately. A container restarted more than three times in 15 minutes. Read the
logs from the previous run, not the current one.

## Security alerts

These are early warnings from `auth.log`, not a security control. Treat them as a signal to look,
not as intrusion detection.

### SSHFailedLoginBurst
Warning, after 1m. More than 20 failed SSH logins in 5 minutes from one address. Usually noise
from the public internet; worth attention when the source is inside your network.

### RootLoginDetected
Warning, fires immediately. An SSH login as root was accepted. Expected on some setups, alarming
on others, which is why it only warns.
