#
# Makefile for 'parec'
#
# Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
# License: LGPLv2.1

include VERSION

IF_MAJOR=$(shell echo $(INTERFACE_VERSION) | cut -d. -f 1)
IF_MINOR=$(shell echo $(INTERFACE_VERSION) | cut -d. -f 2)
IF_PATCH=$(shell echo $(INTERFACE_VERSION) | cut -d. -f 3)

BINS = checksums parec-test
LIBS = libparec.so
CFLAGS = -g -std=c99 -I. -Wall -W -Wmissing-prototypes

default: $(BINS) $(LIBS)

help:
	@echo "possible targets: default test install tarball clean changelog"

%: %.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $< -L. -lparec

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

parec_log4c.o: parec_log4c.c parec_log4c.h
parec.o: parec.c parec.h parec_log4c.h

libparec.so: parec.o parec_log4c.o
	$(CC) -shared -o $@.$(INTERFACE_VERSION) -Xlinker -soname=$@.$(IF_MAJOR) $^ -lcrypto
	ln -sf $@.$(INTERFACE_VERSION) $@.$(IF_MAJOR).$(IF_MINOR)
	ln -sf $@.$(IF_MAJOR).$(IF_MINOR) $@.$(IF_MAJOR)
	ln -sf $@.$(IF_MAJOR) $@

install: $(BINS) $(LIBS)
	install -d -m 0755 $(prefix)/lib
	install -m 0755 libparec.so.$(INTERFACE_VERSION) $(prefix)/lib/
	ln -sf libparec.so.$(INTERFACE_VERSION) $(prefix)/lib/libparec.so.$(IF_MAJOR).$(IF_MINOR)
	ln -sf libparec.so.$(IF_MAJOR).$(IF_MINOR) $(prefix)/lib/libparec.so.$(IF_MAJOR)
	ln -sf libparec.so.$(IF_MAJOR) $(prefix)/lib/libparec.so
	install -d -m 0755 $(prefix)/bin
	install -m 0755 checksums $(prefix)/bin/
	install -d -m 0755 $(prefix)/share/doc/$(PACKAGE)
	install -m 0644 README $(prefix)/share/doc/$(PACKAGE)/
	install -d -m 0755 $(prefix)/include
	install -m 0644 parec.h parec_log4c.h $(prefix)/include/

test: $(BINS)
	LD_LIBRARY_PATH=$(CURDIR) ./parec-test
	LD_LIBRARY_PATH=$(CURDIR) ./checksums-test

clean: 
	rm -f $(BINS) $(LIBS) *.o *.so.*
	rm -rf dataset

distclean: clean
	rm -f $(PACKAGE)-$(VERSION).tar.gz

tarball:
	-rm -rf $(PACKAGE)-$(VERSION)
	mkdir $(PACKAGE)-$(VERSION)
	cp *.c *.h Makefile VERSION README checksums-test $(PACKAGE)-$(VERSION)/
	tar -czf $(PACKAGE)-$(VERSION).tar.gz $(PACKAGE)-$(VERSION)
	rm -rf $(PACKAGE)-$(VERSION)

changelog:
	git log $(shell git tag | tail -1).. >changes
	dch -v $(VERSION)-$(AGE)
	-rm -f changes
	awk ' BEGIN { inchangelog = 0 } { if(inchangelog == 0) print } /^%changelog/ { inchangelog = 1 }' rpm/chroot-envs.spec >rpm/chroot-envs.spec.tmp
	rpm/deblog2rpmlog >>rpm/chroot-envs.spec.tmp
	mv rpm/chroot-envs.spec.tmp rpm/chroot-envs.spec

.PHONY: default distclean clean help install changelog tarball
