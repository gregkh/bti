bin_PROGRAMS = \
	bti

bin_SCRIPTS = \
	bti-shrink-urls

bti_SOURCES = \
	bti.h \
	config.c \
	bti.c

bti_CFLAGS = \
	$(LIBCURL_CFLAGS) \
	$(XML_CFLAGS) \
	$(JSON_CFLAGS) \
	$(LIBPCRE_CFLAGS) \
	$(LIBOAUTH_CFLAGS)

bti_LDADD = \
	$(LIBCURL_LIBS) \
	$(XML_LIBS) \
	$(JSON_LIBS) \
	$(LIBPCRE_LIBS) \
	$(LIBOAUTH_LIBS)

dist_man_MANS = \
	bti.1 \
	bti-shrink-urls.1

bashcompdir = @bashcompdir@
dist_bashcomp_DATA = bti-bashcompletion

EXTRA_DIST = \
	bti.xml \
	bti-shrink-urls.xml \
	bti.example \
	RELEASE-NOTES \
	bti-shrink-urls

%.1: %.xml
	$(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

MAINTAINERCLEANFILES = \
	$(dist_man_MANS)

git-clean:
	rm -f Makefile.in

distclean-local:
	rm -rf autom4te.cache

install-data-hook:
	mv $(DESTDIR)$(bashcompdir)/bti-bashcompletion \
	   $(DESTDIR)$(bashcompdir)/bti

uninstall-hook:
	$(RM) $(DESTDIR)$(bashcompdir)/bti

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
