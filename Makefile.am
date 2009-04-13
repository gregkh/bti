bin_PROGRAMS = \
	bti
	bti-shrink-urls

bti_SOURCES = \
	bti.c

dist_man_MANS = \
	bti.1 \
	bti-shrink-urls.1

EXTRA_DIST = \
	bti.xml \
	bti-shrink-urls.xml

%.1: %.xml
        $(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

MAINTAINERCLEANFILES = \
	$(dist_man_MANS)

git-clean:
	rm -f Makefile.in

distclean-local:
	rm -rf autom4te.cache

PREVIOUS_VERSION = 0`expr $(VERSION) - 1`

changelog:
	@ head -1 ChangeLog | grep -q "to v$(PREVIOUS_VERSION)"
	@ mv ChangeLog ChangeLog.tmp
	@ echo "Summary of changes from v$(PREVIOUS_VERSION) to v$(VERSION)" >> ChangeLog
	@ echo "============================================" >> ChangeLog
	@ echo >> ChangeLog
	@ git log --pretty=short $(PREVIOUS_VERSION)..HEAD | git shortlog  >> ChangeLog
	@ echo >> ChangeLog
	@ cat ChangeLog
	@ cat ChangeLog.tmp >> ChangeLog
	@ rm ChangeLog.tmp

git-release:
	head -1 ChangeLog | grep -q "to v$(VERSION)"
	head -1 RELEASE-NOTES | grep -q "bti $(VERSION)"
	git commit -a -m "release $(VERSION)"
	cat .git/refs/heads/master > .git/refs/tags/$(VERSION)
	git gc
	git prune

AUTOMAKE_OPTIONS = foreign