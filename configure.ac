#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([tcpeek], [0.1.0], [https://github.com/pandax381/tcpeek/issues/])
AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_SRCDIR([src/tcpeek.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for typedefs, structures, and compiler characteristics.
AC_DEFINE([_BSD_SOURCE], 1, [Enable _BSD_SOURCE])
AC_DEFINE([__USE_BSD], 1, [Enable __USE_BSD])
AC_DEFINE([__FAVOR_BSD], 1, [Enable __FAVOR_BSD])

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday localtime_r memmove memset socket strchr strdup strerror strndup strstr strtol])
AX_PTHREAD

# Checks for libpcap
AC_ARG_WITH([libpcap],[AC_HELP_STRING([--with-libpcap=DIR],[location of the libpcap installed directory])],[PCAP_PATH="$withval"],[])
if test "$PCAP_PATH"; then
    PCAP_LDFLAGS="-L${PCAP_PATH}/lib -Wl,-rpath,${PCAP_PATH}/lib"
    PCAP_CPPFLAGS="-I${PCAP_PATH}/include"
fi
AX_CHECK_LIBRARY([PCAP],[pcap/pcap.h],[pcap],[],[AC_MSG_ERROR([libpcap not found])])
AC_ARG_ENABLE([libpcap-static],[AC_HELP_STRING([--enable-libpcap-static],[libpcap static link])],[PCAP_STATIC="yes"],[])
if test "$PCAP_STATIC" = "yes"; then
    PCAP_LIBS="${PCAP_PATH}/lib/libpcap.a"
else
    PCAP_LIBS="-lpcap"
fi
AC_SUBST(PCAP_LDFLAGS)
AC_SUBST(PCAP_CPPFLAGS)
AC_SUBST(PCAP_LIBS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
