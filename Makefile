LIBOQS_DIR ?= vendor/liboqs
BUILD_DIR := build
LIBOQS_BUILD_DIR := $(BUILD_DIR)/liboqs
LIBOQS_PREFIX := $(LIBOQS_BUILD_DIR)/install
LIBOQS_A := $(LIBOQS_PREFIX)/lib/liboqs.a

GO ?= go
CMAKE ?= cmake
GOFLAGS ?= -mod=mod
VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
SOURCE_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
LIBOQS_COMMIT ?= $(shell git -C $(LIBOQS_DIR) rev-parse HEAD 2>/dev/null || echo unknown)
DEPLOYMENT_MANIFEST := $(BUILD_DIR)/daochi.manifest.json
LIBOQS_CMAKE_OPTIONS := -DCMAKE_INSTALL_PREFIX=$(abspath $(LIBOQS_PREFIX)) \
	-DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF \
	-DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
	-DOQS_MINIMAL_BUILD=SIG_ml_dsa_44

CGO_ENV := CGO_ENABLED=1 \
	GOFLAGS="$(GOFLAGS)" \
	CGO_CFLAGS="-I$(abspath $(LIBOQS_PREFIX))/include" \
	CGO_LDFLAGS="-L$(abspath $(LIBOQS_PREFIX))/lib -loqs"

.PHONY: all build test run clean liboqs generate test-ziran test-ziran-ir

all: build

# The Go is generated from the Zi sources and never committed; builds
# regenerate it when a source or the pinned toolchain changes. CI and the
# deploy generate it with the pinned Ziran before building.
ZIRAN ?= ziran
GENERATED := ziran_entry.zi.go
generate:
	ZIRAN="$(ZIRAN)" python3 scripts/generate_go.py

$(GENERATED): $(wildcard *.zi) ziran.lock
	ZIRAN="$(ZIRAN)" python3 scripts/generate_go.py

test-ziran: test test-ziran-ir

test-ziran-ir: liboqs $(GENERATED)
	$(CGO_ENV) ZIRAN="$(ZIRAN)" GOCACHE=/tmp/daochi-gocache python3 scripts/test_saved_ir.py

liboqs:
	set -e; \
	status=0; \
	python3 -B scripts/verify_deployment_inputs.py check-native-build \
		--source-dir "$(LIBOQS_DIR)" --build-dir "$(LIBOQS_BUILD_DIR)" \
		--artifact "$(LIBOQS_A)" --cmake "$(CMAKE)" \
		--cmake-options "$(LIBOQS_CMAKE_OPTIONS)" || status=$$?; \
	if [ "$$status" -eq 0 ]; then \
		:; \
	elif [ "$$status" -eq 2 ]; then \
		rm -rf "$(LIBOQS_BUILD_DIR)"; \
		$(CMAKE) -S $(LIBOQS_DIR) -B $(LIBOQS_BUILD_DIR) $(LIBOQS_CMAKE_OPTIONS); \
		$(CMAKE) --build $(LIBOQS_BUILD_DIR) --target install; \
		python3 -B scripts/verify_deployment_inputs.py record-native-build \
			--source-dir "$(LIBOQS_DIR)" --build-dir "$(LIBOQS_BUILD_DIR)" \
			--artifact "$(LIBOQS_A)" --cmake "$(CMAKE)" \
			--cmake-options "$(LIBOQS_CMAKE_OPTIONS)"; \
	else \
		exit "$$status"; \
	fi

build: liboqs $(GENERATED)
	$(CGO_ENV) $(GO) build -ldflags "-X main.BuildVersion=$(VERSION)" -o daochi .
	$(CGO_ENV) python3 -B scripts/verify_deployment_inputs.py record-artifact-manifest \
		--output daochi --manifest "$(DEPLOYMENT_MANIFEST)" \
		--source-commit "$(SOURCE_COMMIT)" --liboqs-commit "$(LIBOQS_COMMIT)" \
		--native-metadata "$(LIBOQS_BUILD_DIR)/.daochi-native-build.json"

test: liboqs $(GENERATED)
	$(CGO_ENV) GO="$(GO)" GOCACHE=/tmp/daochi-gocache python3 scripts/test_go.py

run: liboqs $(GENERATED)
	$(CGO_ENV) $(GO) run .

clean:
	rm -rf $(BUILD_DIR) daochi ksync *.zi.go *.zi_test.go
