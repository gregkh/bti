AC_INIT([bti], [034], [greg@kroah.com])
AC_PREREQ(2.60)

AM_INIT_AUTOMAKE(bti, 034)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_INSTALL

AC_CONFIG_MACRO_DIR([m4])

AC_PATH_PROG([XSLTPROC], [xsltproc])

PKG_PROG_PKG_CONFIG()

PKG_CHECK_MODULES(LIBOAUTH, oauth)
PKG_CHECK_MODULES(LIBPCRE, libpcre)
PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([XML], [libxml-2.0])
PKG_CHECK_MODULES([JSON], [json-c])

AC_SEARCH_LIBS([dlopen], [dl])

PKG_CHECK_VAR(bashcompdir, [bash-completion], [completionsdir], ,
    bashcompdir="${sysconfdir}/bash_completion.d")
AC_SUBST(bashcompdir)

AC_CONFIG_FILES([Makefile])

AC_OUTPUT


echo "
	bti $VERSION
	=======

	prefix:                 ${prefix}
	datarootdir:            ${datarootdir}
	mandir:                 ${mandir}
	bashcompdir:            ${bashcompdir}

	compiler:               ${CC}
	cflags:                 ${CFLAGS}
	ldflags:                ${LDFLAGS}

	xsltproc:               ${XSLTPROC}
"

