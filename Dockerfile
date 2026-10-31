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
RUN go build -mod=mod -ldflags "-X main.BuildVersion=${VERSION}" -o /out/daochi . && mkdir -p /out/data

FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:6a2a3346335b94d3be0732472245f42ca3ce3cc1135a9521a2bda4b677f2ef0d
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=liboqs /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=build /out/daochi /usr/local/bin/daochi
ENV LD_LIBRARY_PATH=/usr/local/lib
WORKDIR /data
EXPOSE 8080
USER 65532:65532
CMD ["/usr/local/bin/daochi"]
