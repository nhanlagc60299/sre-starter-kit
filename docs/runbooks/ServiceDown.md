# ServiceDown

**Severity:** critical | **Module:** app | **Fires when:** the blackbox HTTP probe for a service fails for 2m.

## What it means
The service is not answering HTTP checks at all. Users hitting it get errors or timeouts right now.

## First checks
```bash
curl -sv <url>                                    # what actually happens: refused, timeout, 5xx?
docker compose ps <service>                       # is the container even running?
docker logs --tail 50 <service>                    # why it's not answering
```

## Usual causes
- The process crashed and did not come back.
- A deploy is in progress and the container is mid-restart.
- A TLS certificate just changed and the app can't bind/serve.
- A dependency (database, cache) it needs at startup is down.

## Quick mitigation
Restart the service; if it was the last deploy, roll back to the previous known-good image.

## Root-cause fix
Add a real readiness probe, use zero-downtime deploys, and make the app retry its DB connection instead of
crashing on first failure.
