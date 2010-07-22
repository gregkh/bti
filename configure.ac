AC_INIT([bti], [026], [greg@kroah.com])
AC_PREREQ(2.60)

AM_INIT_AUTOMAKE(bti, 026)
dnl AM_CONFIG_HEADER([check-news foreign 1.9 dist-bzip2])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_INSTALL

AC_CONFIG_MACRO_DIR([m4])

AC_PATH_PROG([XSLTPROC], [xsltproc])

dnl FIXME: Replace `main' with a function in `-lnsl':
AC_CHECK_LIB([nsl], [main])

AC_CHECK_LIB([pcre], [main])

AC_CHECK_LIB([oauth], [main])

# CURL
LIBCURL_CHECK_CONFIG([yes], [], [have_libcurl="yes"], [have_libcurl="no"])
if test "${have_libcurl}" != yes; then
	AC_MSG_ERROR([libcurl library not found, please install it])
else
	CPPFLAGS="$CPPFLAGS $LIBCURL_CPPFLAGS"
	LIBS="${LIBS} ${LIBCURL}"
fi

# libxml2
AM_PATH_XML2([], [have_libxml="yes"], [have_libxml="no"])
if test "${have_libxml}" != yes; then
	AC_MSG_ERROR([libxml not found, please install it])
else
	CPPFLAGS="$CPPFLAGS $XML_CPPFLAGS"
	LIBS="$LIBS $XML_LIBS"
fi

# explicitly link DSOs
LIBS="$LIBS -ldl -loauth"


dnl Checks for header files.
#AC_CHECK_HEADERS([fcntl.h stddef.h stdlib.h string.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
#AC_TYPE_PID_T
#AC_TYPE_SIZE_T
#AC_TYPE_SSIZE_T

dnl Checks for library functions.
#AC_FUNC_ALLOCA
#AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
#AC_CHECK_FUNCS([strcasecmp strchr strdup strncasecmp strndup])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT


echo "
	bti $VERSION
	=======

	prefix:                 ${prefix}
	datarootdir:            ${datarootdir}
	mandir:                 ${mandir}

	compiler:               ${CC}
	cflags:                 ${CFLAGS}
	ldflags:                ${LDFLAGS}

	xsltproc:               ${XSLTPROC}
"

