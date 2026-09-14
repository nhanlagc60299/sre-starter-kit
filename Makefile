SHELL := /bin/bash
CONTAINER_ENGINE ?= docker
export CONTAINER_ENGINE
COMPOSE := $(CONTAINER_ENGINE) compose --env-file .env -f compose/docker-compose.yml
PROM_IMG := prom/prometheus:v3.4.0
AM_IMG := prom/alertmanager:v0.28.1

.PHONY: init render up down logs validate test-rules smoke test

init:            ## interactive wizard -> .env, then render
	@bash scripts/init.sh && $(MAKE) render

render:          ## .env + core/*.tpl -> build/
	@bash scripts/render.sh

up: render       ## start the stack
	@$(COMPOSE) up -d

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
