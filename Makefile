BINARY := wgsteer
PKG := ./cmd/wgsteer
LDFLAGS := -s -w
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all build build-arm64 test vet fmt integration clean

all: build

build:
	$(GOBUILD) -o $(BINARY) $(PKG)

build-arm64:
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BINARY)-arm64 $(PKG)

test:
	gofmt -l . | (! grep .)
	go vet ./...
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# Privileged tests: Go packages that need CAP_NET_ADMIN, then the namespace
# suite. Both run inside an unprivileged user + network namespace.
integration: build
	go test -c -o .nftable.test ./internal/nftable
	unshare -rn ./.nftable.test -test.v; s=$$?; rm -f .nftable.test; exit $$s
	go test -c -o .wgdev.test ./internal/wgdev
	unshare -rn ./.wgdev.test -test.v; s=$$?; rm -f .wgdev.test; exit $$s
	python3 tests/integration/test_daemon.py -v

clean:
	rm -f $(BINARY) $(BINARY)-arm64 .nftable.test .wgdev.test
