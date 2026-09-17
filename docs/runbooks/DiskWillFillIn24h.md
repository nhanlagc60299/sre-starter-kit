# DiskWillFillIn24h

**Severity:** warning | **Module:** infra | **Fires when:** the linear trend of free space over the last 6h projects to zero within 24h, for 30m.

## What it means
Disk usage is climbing at a rate that will exhaust the mount within a day if nothing changes. This is a
predictive alert (`predict_linear`), not a current-state one — DiskFull/DiskLow may not have fired yet.

## First checks
```bash
df -h                                                                      # current free space on the mount
find / -xdev -size +500M -mmin -360 2>/dev/null                            # files >500MB written in the last 6h
docker ps --format '{{.Names}}' | xargs -I{} sh -c 'echo {}; docker logs {} 2>&1 | wc -c'  # which container is logging the most
```

## Usual causes
- A runaway log or a debug flag left on in one container.
- A batch or export job dumping large files to this disk.
- A backup job landing its dump on the wrong (smaller) disk.

## Quick mitigation
Stop or throttle the writer identified above, then delete what it has produced so far to buy back headroom.

## Root-cause fix
Rate-limit or cap the output of that writer, and give it its own volume so it can't starve the host disk.
