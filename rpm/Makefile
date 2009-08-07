#
# RPM Makefile for 'parec'
#
# Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
# License: LGPLv2.1

include ../VERSION

BUILD=build
DEFAULT_KEY=$(shell awk '/^default-key/ { print $$2 }' $(HOME)/.gnupg/options)

default: rpm

tarball: 
	make -C .. tarball

rpm: tarball
	-rm -rf $(BUILD)
	mkdir -p $(BUILD)
	mkdir -p $(BUILD)/BUILD
	mkdir -p $(BUILD)/RPMS
	mkdir -p $(BUILD)/SRPMS
	mkdir -p $(BUILD)/SOURCES
	mkdir -p $(BUILD)/SPECS
	cp ../$(PACKAGE)-$(VERSION).tar.gz $(BUILD)/SOURCES
	sed -e 's/@VERSION@/$(VERSION)/g; s/@AGE@/$(AGE)/g' $(PACKAGE).spec >$(BUILD)/SPECS/$(PACKAGE).spec
	cd $(BUILD); rpmbuild --define "_topdir $(CURDIR)/$(BUILD)" -ba SPECS/$(PACKAGE).spec
	cp $(BUILD)/RPMS/*/*.rpm .
	cp $(BUILD)/SRPMS/*.rpm .
	rpm --define "__signature gpg" --define "_gpg_name $(DEFAULT_KEY)" --addsign $(PACKAGE)*.rpm

clean:
	-rm -rf $(BUILD)

distclean: clean
	-rm -f *.rpm

