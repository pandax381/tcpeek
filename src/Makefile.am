CFLAGS += -W -Wall -Wno-unused-parameter

sbin_PROGRAMS = tcpeek
dist_sbin_SCRIPTS = tcpeekstat

tcpeek_SOURCES = tcpeek.c tcpeek.h init.c disassemble.c session.c cksum.c lnklist.c lnklist.h hashtable.c hashtable.h common.c checker.c listener.c filter.c
tcpeek_CFLAGS = $(PCAP_CPPFLAGS) $(PTHREAD_CFLAGS)
tcpeek_LDADD = $(PCAP_LIBS) $(PTHREAD_LIBS)
tcpeek_LDFLAGS = $(PCAP_LDFLAGS)

MAINTAINERCLEANFILES = Makefile.in
