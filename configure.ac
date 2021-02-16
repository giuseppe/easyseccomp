AC_PREREQ([2.69])
AC_INIT([easyseccomp], [0.1], [giuseppe@scrivano.org])
AC_CONFIG_SRCDIR([src/lexer.l])
AC_CONFIG_HEADERS([src/config.h])

AM_INIT_AUTOMAKE([1.11.2 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_PROG_YACC
AC_PROG_CC
AC_PROG_LEX
AC_PROG_RANLIB

dnl libseccomp
AC_ARG_ENABLE([seccomp],
	AS_HELP_STRING([--disable-seccomp], [Ignore libseccomp and disable support]))
AS_IF([test "x$enable_seccomp" != "xno"], [
	AC_CHECK_HEADERS([seccomp.h], [], [AC_MSG_ERROR([*** Missing libseccomp headers])])
	AS_IF([test "$ac_cv_header_seccomp_h" = "yes"], [
		AC_SEARCH_LIBS(seccomp_rule_add, [seccomp], [AC_DEFINE([HAVE_SECCOMP], 1, [Define if seccomp is available])], [AC_MSG_ERROR([*** libseccomp headers not found])])
		AC_SEARCH_LIBS(seccomp_arch_resolve_name, [seccomp], [AC_DEFINE([SECCOMP_ARCH_RESOLVE_NAME], 1, [Define if seccomp_arch_resolve_name is available])], [ ])
	])
])

AC_CHECK_HEADERS([stddef.h stdlib.h string.h unistd.h])

AC_TYPE_SIZE_T

AC_FUNC_ERROR_AT_LINE
AC_CHECK_FUNCS([memset strdup])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
