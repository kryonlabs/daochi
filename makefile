# Native make shim. The canonical build is the GNU Makefile.
GMAKE ?= gmake

.PHONY: all build test run clean liboqs

.MAIN: all

all:
	$(GMAKE) -f Makefile $@

.DEFAULT:
	$(GMAKE) -f Makefile $@
