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
LIBS = libparec.so parecmodule.so
MAN1 = checksums.1
MAN3 = man3/parec.h.3 man3/parec_log4c.h.3
CFLAGS = -g -std=c99 -I. -Wall -W -Wmissing-prototypes

ifeq ($(prefix), $(EMPTY))
prefix=/usr
endif

ifeq ($(XSLTPROC), $(EMPTY))
XSLTPROC=xsltproc
endif
XSLTPROCFLAGS = --nonet
MAN_STYLESHEET = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

ifeq ($(DOXYGEN), $(EMPTY))
DOXYGEN=doxygen
endif
DOXYCONF = doxygen.conf

PYTHON_VERSION=$(shell python -c "import sys; print sys.version[:3]")
PYTHON_PREFIX=$(shell python -c "import os; import sys; print os.path.normpath(sys.prefix)")
PYTHON_INC=-I$(shell python -c "from distutils import sysconfig; print sysconfig.get_python_inc(0)")
PYTHON_LIB=$(shell python -c "from distutils import sysconfig; print sysconfig.get_python_lib(0,1)")
PYTHON_INSTALL=$(shell python -c "from distutils import sysconfig; print sysconfig.get_python_lib(0,0,prefix='$(prefix)')")

default: $(BINS) $(LIBS)

help:
	@echo "possible targets: default test install tarball clean changelog"

%: %.c $(LIBS)
	$(CC) $(CFLAGS) -o $@ $< -L. -lparec

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

parec_log4c.o: parec_log4c.c parec_log4c.h
parec.o: parec.c parec.h parec_log4c.h

parecmodule.so: parecmodule.c libparec.so
	$(CC) -shared -o $@ $< -L . -lparec -L$(PYTHON_LIB) $(PYTHON_INC) -I$(CURDIR)

libparec.so: parec.o parec_log4c.o
	$(CC) -shared -o $@.$(INTERFACE_VERSION) -Xlinker -soname=$@.$(IF_MAJOR) $^ -lcrypto
	ln -sf $@.$(INTERFACE_VERSION) $@.$(IF_MAJOR).$(IF_MINOR)
	ln -sf $@.$(IF_MAJOR).$(IF_MINOR) $@.$(IF_MAJOR)
	ln -sf $@.$(IF_MAJOR) $@

doc: $(MAN1) $(MAN3)

version.xml:
	echo "$(VERSION)" >version.xml

%.1: %.1.xml version.xml
	mkdir -p man1
	$(XSLTPROC) $(XSLTPROCFLAGS) $(MAN_STYLESHEET) $<

man3/%.3: $(DOXYCONF) $(wildcard *.h)
	$(DOXYGEN) $(DOXYCONF)

install: $(BINS) $(LIBS) $(MAN1) $(MAN3)
	install -d -m 0755 $(prefix)/lib
	install -m 0755 libparec.so.$(INTERFACE_VERSION) $(prefix)/lib/
	ln -sf libparec.so.$(INTERFACE_VERSION) $(prefix)/lib/libparec.so.$(IF_MAJOR).$(IF_MINOR)
	ln -sf libparec.so.$(IF_MAJOR).$(IF_MINOR) $(prefix)/lib/libparec.so.$(IF_MAJOR)
	ln -sf libparec.so.$(IF_MAJOR) $(prefix)/lib/libparec.so
	install -d -m 0755 $(prefix)/bin
	install -m 0755 checksums $(prefix)/bin/
	install -d -m 0755 $(prefix)/share/doc/$(PACKAGE)
	install -m 0644 README $(prefix)/share/doc/$(PACKAGE)/
	install -d -m 0755 $(prefix)/share/doc/$(PACKAGE)/examples
	install -m 0644 parec-test.c parecmodule-test $(prefix)/share/doc/$(PACKAGE)/examples/
	install -d -m 0755 $(prefix)/share/doc/$(PACKAGE)/html
	install -m 0644 html/* $(prefix)/share/doc/$(PACKAGE)/html/
	install -d -m 0755 $(prefix)/share/man/man1
	install -m 0644 $(MAN1) $(prefix)/share/man/man1/
	install -d -m 0755 $(prefix)/share/man/man3
	install -m 0644 $(MAN3) $(prefix)/share/man/man3/
	install -d -m 0755 $(prefix)/include
	install -m 0644 parec.h parec_log4c.h $(prefix)/include/
	install -d -m 0755 $(PYTHON_INSTALL)
	install -m 0755 parecmodule.so $(PYTHON_INSTALL)/

test: $(BINS)
	LD_LIBRARY_PATH=$(CURDIR) ./parec-test
	LD_LIBRARY_PATH=$(CURDIR) ./parecmodule-test
	LD_LIBRARY_PATH=$(CURDIR) ./checksums-test

clean: 
	rm -f $(BINS) $(LIBS) *.o *.so.* version.xml *.1
	rm -rf dataset pdataset html man3

distclean: clean
	rm -f $(PACKAGE)-$(VERSION).tar.gz

tarball:
	-rm -rf $(PACKAGE)-$(VERSION)
	mkdir $(PACKAGE)-$(VERSION)
	cp *.c *.h *.xml $(DOXYCONF) Makefile VERSION README checksums-test parecmodule-test $(PACKAGE)-$(VERSION)/
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
