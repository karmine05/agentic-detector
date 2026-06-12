# agentic-detector — cross-platform osquery extension build.
#
# `make build-all` produces the per-platform binaries named exactly as Fleet's
# TUF/agent_options mechanism expects (see README "Deploy via Fleet"):
#
#   build/agentic_detector_macos.ext          (universal: amd64 + arm64)
#   build/agentic_detector_linux.ext          (amd64)
#   build/agentic_detector_linux_arm64.ext    (arm64)
#   build/agentic_detector_windows.ext.exe    (amd64)
#   build/agentic_detector_windows_arm64.ext.exe (arm64)

BINARY  := agentic_detector
PKG     := ./cmd/agentic_detector
BUILD   := build
VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: all check build-all macos linux windows test vet fmt fmtcheck lint sec clean

all: check build-all

## ---- quality gates (run before pushing) ----
check: fmtcheck vet test

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmtcheck:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# Static analysis (parity with CodeQL/gosec in CI). Install:
#   go install github.com/securego/gosec/v2/cmd/gosec@latest
sec:
	gosec -severity medium ./...

## ---- cross-platform build ----
build-all: macos linux windows

macos:
	@mkdir -p $(BUILD)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD)/.macos_amd64 $(PKG)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD)/.macos_arm64 $(PKG)
	lipo -create -output $(BUILD)/$(BINARY)_macos.ext $(BUILD)/.macos_amd64 $(BUILD)/.macos_arm64
	@rm -f $(BUILD)/.macos_amd64 $(BUILD)/.macos_arm64
	@echo "built $(BUILD)/$(BINARY)_macos.ext"

linux:
	@mkdir -p $(BUILD)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD)/$(BINARY)_linux.ext $(PKG)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD)/$(BINARY)_linux_arm64.ext $(PKG)
	@echo "built $(BUILD)/$(BINARY)_linux.ext and _linux_arm64.ext"

windows:
	@mkdir -p $(BUILD)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD)/$(BINARY)_windows.ext.exe $(PKG)
	GOOS=windows GOARCH=arm64 $(GOBUILD) -o $(BUILD)/$(BINARY)_windows_arm64.ext.exe $(PKG)
	@echo "built $(BUILD)/$(BINARY)_windows.ext.exe and _windows_arm64.ext.exe"

# --- signing (run after build, before distribution) ---
# osquery refuses to autoload extensions that are world-writable or not owned by
# root/Administrator. Distribution signing is platform-specific:
#   macOS:   codesign -s "Developer ID Application: <ORG>" --options runtime \
#              build/agentic_detector_macos.ext
#            xcrun notarytool submit ... && xcrun stapler staple ...
#   Windows: signtool sign /fd SHA256 /a build/agentic_detector_windows.ext.exe

## ---- local run against osqueryi ----
# Requires osquery installed (`brew reinstall --cask osquery`).
# --allow_unsafe relaxes osquery's root-owned/non-world-writable extension check
# for local testing only. Run plain = your user (sees your home + your sockets);
# `make run-root` = root (sees all users + all sockets, like fleetd).
EXT_MAC := $(CURDIR)/$(BUILD)/$(BINARY)_macos.ext
# --extensions_require blocks osqueryi until our extension registers; without it,
# a one-shot `osqueryi "QUERY"` runs before async registration completes and
# reports "no such table". --extensions_timeout caps the wait.
OSQ_FLAGS := --allow_unsafe --extension "$(EXT_MAC)" --extensions_require=agentic_detector --extensions_timeout=10

run: macos
	osqueryi $(OSQ_FLAGS)

run-root: macos
	sudo osqueryi $(OSQ_FLAGS)

# One-shot sanity query (non-interactive).
osq-verify: macos
	osqueryi $(OSQ_FLAGS) \
	  "SELECT kind, count(*) AS rows, sum(running) AS running FROM agentic_software GROUP BY kind"

clean:
	rm -rf $(BUILD)
