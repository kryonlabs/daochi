# Native make shim. The canonical build is the GNU Makefile.
GMAKE ?= gmake

.PHONY: all build test run clean liboqs generate check-generated test-ziran test-ziran-ir

.MAIN: all

all:
	$(GMAKE) -f Makefile $@

build test run clean liboqs generate check-generated test-ziran test-ziran-ir:
	$(GMAKE) -f Makefile $@
