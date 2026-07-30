SHELL := /bin/bash

.PHONY: all install build typecheck lint fmt fmt-check test coverage check clean
.PHONY: demo demo-reset demo-test

all: check

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

test:
	npm test

coverage:
	npm run test:coverage

check:
	npm run check

demo:
	npm run demo

demo-reset:
	npm run demo:reset

demo-test:
	npm run test:demo:e2e

clean:
	rm -rf coverage packages/server/dist packages/browser/dist examples/demo/dist

nix-%:
	nix develop $(NIX_OPTS) --command make $*
