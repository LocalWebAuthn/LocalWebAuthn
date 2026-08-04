# LocalWebAuthn development targets.
#
# Preferred environment (Node 22, sqlite, pg-start/pg-stop):
#   nix develop
#   make install   # if node_modules is missing
#   make test
#   make check
#
# From outside the shell, prefix any target with nix-:
#   make nix-test
#   make nix-check
#   make nix-test-postgres
#
# PostgreSQL store tests need a local server once per shell:
#   pg-start && make test
#   make test-postgres   # fail if Postgres is unreachable (CI-style)

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help all install build typecheck lint fmt fmt-check
.PHONY: test test-unit test-channels test-demo test-demo-install test-all test-postgres
.PHONY: ensure-postgres coverage check release-check
.PHONY: demo demo-reset demo-test starter-hono clean

all: check

help:
	@printf '%s\n' \
		'LocalWebAuthn make targets (use inside: nix develop)' \
		'' \
		'  make install          npm ci' \
		'  make build            build all workspaces' \
		'  make test             unit + store + channels-cf-worker tests' \
		'  make test-unit        vitest (server/browser/demo API; PG suite skips if down)' \
		'  make test-channels    channels Cloudflare worker (Miniflare)' \
		'  make test-demo        Playwright lifecycle e2e' \
		'  make test-demo-install  playwright install chromium' \
		'  make test-all         test + demo e2e' \
		'  make test-postgres    test with LOCALWEBAUTHN_REQUIRE_POSTGRES=1' \
		'  make coverage         vitest coverage + channels tests' \
		'  make check            typecheck, lint, format, coverage, package gates' \
		'  make demo             build and run lifecycle demo' \
		'  make demo-reset       wipe demo sqlite db' \
		'  make starter-hono     run minimal Hono starter' \
		'  make clean            remove build and coverage artifacts' \
		'' \
		'Nix wrappers: make nix-<target>  e.g. make nix-test' \
		'Postgres:     pg-start | pg-stop  (from flake shell)'

install:
	npm ci --no-audit --no-fund

build:
	npm run build

typecheck:
	npm run typecheck

lint:
	npm run lint

fmt:
	npm run format

fmt-check:
	npm run format:check

# --- tests -------------------------------------------------------------------

# Core unit + adapter conformance (Postgres optional; skips if unreachable).
test-unit:
	npx vitest run

# Twilio/Resend delivery worker (mock fetch + Miniflare).
test-channels:
	npm test --workspace @localwebauthn/channels-cf-worker

# Default developer test entry: everything that does not need Playwright browsers.
test: test-unit test-channels

test-demo-install:
	npx playwright install chromium

test-demo:
	npm run test:demo:e2e

test-all: test test-demo

# Start throwaway Postgres when the flake helper is on PATH (no-op if already up).
ensure-postgres:
	@if command -v pg-start >/dev/null 2>&1; then \
		pg-start; \
	elif [ -n "$${LOCALWEBAUTHN_TEST_POSTGRES_URL:-}" ]; then \
		echo 'pg-start not on PATH; assuming Postgres at $$LOCALWEBAUTHN_TEST_POSTGRES_URL'; \
	else \
		echo 'No pg-start and no LOCALWEBAUTHN_TEST_POSTGRES_URL; Postgres suite will skip.'; \
	fi

# CI-style: Postgres must be up (pg-start in the flake shell).
test-postgres: ensure-postgres
	@if [ -z "$${LOCALWEBAUTHN_TEST_POSTGRES_URL:-}" ]; then \
		echo 'LOCALWEBAUTHN_TEST_POSTGRES_URL is unset. Enter the flake shell (nix develop) or export the URL.'; \
		exit 1; \
	fi
	LOCALWEBAUTHN_REQUIRE_POSTGRES=1 npx vitest run tests/server/store-conformance.test.ts
	$(MAKE) test-channels

# Coverage needs Postgres for adapter files; start it when the flake provides pg-start.
coverage: ensure-postgres
	npm run test:coverage

check:
	npm run typecheck
	npm run lint
	npm run format:check
	$(MAKE) coverage
	npm run check:packages

release-check:
	npm run release:check
	$(MAKE) test-channels

# --- examples ----------------------------------------------------------------

demo:
	@printf 'Preparing demo...\n'
	@cd examples/demo && ../../node_modules/.bin/vite build --logLevel error && node --import tsx src/server.ts

demo-reset:
	npm run demo:reset

# Alias used by README / CI docs.
demo-test: test-demo

starter-hono:
	npm run start --workspace @localwebauthn/starter-hono

clean:
	rm -rf coverage \
		packages/server/dist packages/browser/dist \
		examples/demo/dist \
		test-results playwright-report

# Run any target inside the flake devShell (Node 22, tools, PG URL).
# Example: make nix-test
nix-%:
	nix develop $(NIX_OPTS) --command $(MAKE) $*
