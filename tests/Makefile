.PHONY: test deps clean

GODOG := go run github.com/cucumber/godog/cmd/godog@v0.14.1

deps:
	go mod tidy

test: deps
	$(GODOG) --format pretty ./features/

test-kernel:
	$(GODOG) --format pretty --tags @kernel ./features/

test-bridge:
	$(GODOG) --format pretty --tags @bridge ./features/

test-shim:
	$(GODOG) --format pretty --tags @shim ./features/

clean:
	go clean -testcache
