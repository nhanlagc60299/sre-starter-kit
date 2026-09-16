SHELL := /bin/bash
CONTAINER_ENGINE ?= docker
export CONTAINER_ENGINE
COMPOSE := $(CONTAINER_ENGINE) compose --env-file .env -f compose/docker-compose.yml
PROM_IMG := prom/prometheus:v3.4.0
AM_IMG := prom/alertmanager:v0.28.1

.PHONY: init render up down logs reload validate test-rules smoke test

init:            ## interactive wizard -> .env, then render
	@bash scripts/init.sh && $(MAKE) render

render:          ## .env + core/*.tpl -> build/
	@bash scripts/render.sh

up: render       ## start the stack (re-renders build/ and reloads the running config)
	@$(COMPOSE) up -d
	@$(MAKE) --no-print-directory reload

reload:          ## make Prometheus/Alertmanager/Alloy re-read build/ (compose does not watch bind mounts)
	@# The ports bind to ${BIND_ADDR:-127.0.0.1}, so a non-default BIND_ADDR is the only address
	@# they answer on and a hardcoded 127.0.0.1 here would just time out into the WARN below.
	@# 0.0.0.0 is a bind wildcard, not a destination: reach it on the loopback.
	@a=$$(sed -n 's/^BIND_ADDR=//p' .env 2>/dev/null | tail -1 | tr -d '"'"'"'"'); \
	 a=$${a:-127.0.0.1}; [ "$$a" = "0.0.0.0" ] && a=127.0.0.1; \
	 r() { n=$$1; shift; for i in $$(seq 10); do if "$$@" >/dev/null 2>&1; then echo "reloaded $$n"; return 0; fi; sleep 3; done; \
	       echo "WARN: could not reload $$n after 30s - if it was still starting, run 'make reload'"; }; \
	 r prometheus   curl -fsS -XPOST http://$$a:9090/-/reload; \
	 r alertmanager curl -fsS -XPOST http://$$a:9093/-/reload; \
	 r alloy        $(COMPOSE) kill -s HUP alloy

down:
	@$(COMPOSE) down

logs:
	@$(COMPOSE) logs -f --tail=100

validate:        ## static checks (<10s)
	@bash tests/validate.sh

test-rules:      ## promtool unit tests for alert rules
	@$(CONTAINER_ENGINE) run --rm -v "$(PWD)/core/prometheus:/p" -v "$(PWD)/tests/rules:/t" --entrypoint promtool $(PROM_IMG) test rules $(patsubst tests/rules/%,/t/%,$(wildcard tests/rules/*.test.yml))

smoke:           ## bring stack up, check all targets UP, tear down
	@bash tests/smoke.sh

test: validate test-rules
	@bash tests/test_render.sh
	@bash tests/test_init.sh
	@bash tests/test_env_example.sh
