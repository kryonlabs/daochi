LIBOQS_DIR ?= vendor/liboqs
BUILD_DIR := build
LIBOQS_BUILD_DIR := $(BUILD_DIR)/liboqs
LIBOQS_PREFIX := $(LIBOQS_BUILD_DIR)/install
LIBOQS_A := $(LIBOQS_PREFIX)/lib/liboqs.a

GO ?= go
CMAKE ?= cmake
GOFLAGS ?= -mod=mod

CGO_ENV := CGO_ENABLED=1 \
	GOFLAGS="$(GOFLAGS)" \
	CGO_CFLAGS="-I$(abspath $(LIBOQS_PREFIX))/include" \
	CGO_LDFLAGS="-L$(abspath $(LIBOQS_PREFIX))/lib -loqs"

.PHONY: all build test run clean liboqs

all: build

liboqs: $(LIBOQS_A)

$(LIBOQS_A): $(LIBOQS_DIR)/CMakeLists.txt
	$(CMAKE) -S $(LIBOQS_DIR) -B $(LIBOQS_BUILD_DIR) \
		-DCMAKE_INSTALL_PREFIX="$(abspath $(LIBOQS_PREFIX))" \
		-DCMAKE_INSTALL_LIBDIR=lib \
		-DBUILD_SHARED_LIBS=OFF \
		-DOQS_BUILD_ONLY_LIB=ON \
		-DOQS_USE_OPENSSL=OFF \
		-DOQS_MINIMAL_BUILD=SIG_ml_dsa_44
	$(CMAKE) --build $(LIBOQS_BUILD_DIR) --target install

build: $(LIBOQS_A)
	$(CGO_ENV) $(GO) build -o daochi .

test: $(LIBOQS_A)
	$(CGO_ENV) GOCACHE=/tmp/daochi-gocache $(GO) test ./...

run: $(LIBOQS_A)
	$(CGO_ENV) $(GO) run .

clean:
	rm -rf $(BUILD_DIR) daochi ksync
