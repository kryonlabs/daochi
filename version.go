package main

// version identifies the running build. It is set at build time via
// -ldflags "-X main.version=..." (Makefile, Dockerfile, CI); "dev"
// marks an unstamped local build.
var version = "dev"
