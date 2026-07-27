FROM debian:stable-slim AS liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates cmake gcc git libc6-dev ninja-build \
    && rm -rf /var/lib/apt/lists/*
COPY vendor/liboqs /src/liboqs
WORKDIR /src/liboqs
RUN cmake -GNinja -S . -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_MINIMAL_BUILD=SIG_ml_dsa_44 \
    && cmake --build build \
    && cmake --install build

FROM golang:1.24-bookworm AS build
COPY --from=liboqs /usr/local /usr/local
WORKDIR /src
COPY . .
ENV CGO_ENABLED=1
RUN go build -o /out/ksync .

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && useradd --system --uid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin ksync \
    && mkdir -p /data \
    && chown ksync:ksync /data \
    && rm -rf /var/lib/apt/lists/*
COPY --from=liboqs /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=build /out/ksync /usr/local/bin/ksync
ENV LD_LIBRARY_PATH=/usr/local/lib
EXPOSE 8080
USER ksync
CMD ["ksync"]
