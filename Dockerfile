FROM debian:stable-slim@sha256:13e0a2e78aa0554ad5ff66e4e260c6dbcdff807eb1f39d43b9fb0288aae88b04 AS liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates cmake gcc git libc6-dev ninja-build \
    && rm -rf /var/lib/apt/lists/*
COPY vendor/liboqs /src/liboqs
WORKDIR /src/liboqs
RUN cmake -GNinja -S . -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_MINIMAL_BUILD=SIG_ml_dsa_44 \
    && cmake --build build \
    && cmake --install build

FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
ARG VERSION=dev
COPY --from=liboqs /usr/local /usr/local
WORKDIR /src
COPY . .
ENV CGO_ENABLED=1
RUN go build -mod=mod -ldflags "-X main.BuildVersion=${VERSION}" -o /out/daochi .

FROM debian:stable-slim@sha256:13e0a2e78aa0554ad5ff66e4e260c6dbcdff807eb1f39d43b9fb0288aae88b04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && useradd --system --uid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin daochi \
    && mkdir -p /data \
    && chown daochi:daochi /data \
    && rm -rf /var/lib/apt/lists/*
COPY --from=liboqs /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=build /out/daochi /usr/local/bin/daochi
ENV LD_LIBRARY_PATH=/usr/local/lib
EXPOSE 8080
USER daochi
CMD ["daochi"]
