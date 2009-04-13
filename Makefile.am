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

%.1 : %.xml
        $(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<


AUTOMAKE_OPTIONS = foreign
