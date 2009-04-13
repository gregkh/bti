#!/bin/sh -e

autoreconf --install --symlink

CFLAGS="-g -Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat=2 -Wtype-limits"

case "$1" in
	*install|"")
		export CFLAGS="$CFLAGS -O2"
		echo "   configure:  $args"
		echo
		./configure $args
		;;
	*devel)
		export CFLAGS="$CFLAGS -O0"
		echo "   configure:  $args"
		echo
		./configure $args
		;;
	*clean)
		./configure
		make maintainer-clean
		git clean -f -X
		exit 0
		;;
	*)
		echo "Usage: $0 [--install|--devel|--clean]"
		exit 1
		;;
esac
