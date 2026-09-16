# SRE Starter Kit (free tier)

A self-hosted Prometheus + Grafana + Loki stack for teams of 3 to 20 developers running 5 to 30 hosts
with no dedicated SRE. One command to install, alerts tuned to be quiet enough that nobody turns them
off. Customers run it on their own VMs with `docker compose`.

**This repository is public and MIT licensed.** Anything committed here is visible to the world, so
never add a real webhook, token, hostname or customer name. `.env.example` ships empty placeholders on
purpose.

GitHub is the canonical home: https://github.com/nhanlagc60299/sre-starter-kit (remote `github`). A
private GitLab mirror exists as remote `origin`; push both. CI is GitHub Actions in
`.github/workflows/ci.yml`. There is no `.gitlab-ci.yml`: GitLab is a mirror, its free-plan compute
ran out, and a CI config that cannot run is a second definition of "tested" that drifts from the one
actually enforced. `git log -- .gitlab-ci.yml` has the original if it is ever needed.

There is a paid tier in a separate private repo which merges this one in periodically. Keep changes
here self-contained and avoid restructuring shared files without reason, or that merge gets painful.

## How a render works

`core/` holds configuration with no environment values in it. `scripts/render.sh` reads `.env`,
substitutes `core/**/*.tpl` through `envsubst`, copies everything else as-is, and writes `build/`.
Compose mounts `build/`, never `core/`. `scripts/init.sh` is the wizard that writes `.env`, and
re-running it offers previous answers as defaults.

A new `.env` key must appear in both `.env.example` and the wizard, and be referenced from a `.tpl`
file to have any effect.

## Alert and runbook rules, enforced by tests

Every alert carries `severity` (`critical` or `warning`, never `info`), `module`, and a `runbook_url`
pointing at its section in `docs/ALERTS.md`. `tests/validate.sh` fails if any `runbook_url` names a
heading that does not exist in that file, so adding an alert means adding its section.

Runbook links point at an in-repo document rather than a wiki deliberately: GitHub only creates a
wiki's git repository after someone adds the first page through the web UI, so wiki links would have
404'd on a freshly published repo. The in-repo file also survives a fork.

Full runbooks with causes, mitigation and root-cause fixes are the paid tier's differentiator. Keep
`docs/ALERTS.md` to what fires an alert and where to look first.

## Running the tests

```bash
env -u CONTAINER_SOCK CONTAINER_ENGINE=podman make test
```

The `env -u CONTAINER_SOCK` matters. `scripts/init.sh` reads `CONTAINER_SOCK` from the environment as a
question default, so an exported value makes `tests/test_init.sh` fail for a reason unrelated to your
change. Drop `CONTAINER_ENGINE=podman` if you are on Docker.

Smoke tests bring the whole stack up and are the one place you do export the socket:

```bash
CONTAINER_ENGINE=podman CONTAINER_SOCK=/run/user/501/podman/podman.sock SMOKE_SKIP_JOBS=cadvisor,node make smoke
```

cAdvisor needs Docker's `/var/lib/docker` and cannot start under Podman, hence the skip.

## Things worth knowing before you change something

**The wizard answers questions positionally.** `tests/test_init.sh` pipes fixed answer sequences into
`scripts/init.sh`. Inserting a question in the middle shifts every later answer and breaks them all.
Append new questions at the end, where old sequences hit EOF and take defaults.

**`scripts/init.sh` must stay bash 3.2 compatible**, since that is the system bash on macOS. No
associative arrays, no `${var^^}`.

**promtool unit tests are not portable if you write them carelessly.** Sample finely enough that a
range selector holds several samples, and never assert a long float for equality: Go emits fused
multiply-add on arm64 and not on amd64, so a test that passes on an Apple Silicon laptop can fail on a
CI runner. Assert exact integers.

**The README is a sales document.** A reader decides whether to trust the product from it, so every
claim in it must be true of what actually ships. Counts, feature lists and tier comparisons have all
drifted here before and had to be corrected.

## Documentation the user sees

`README.md` for install and operation, `docs/ALERTS.md` for the alert reference. Both are English;
the product is sold internationally.
