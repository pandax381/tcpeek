#ifndef __TCPEEK_H__
#define __TCPEEK_H__ 1
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <limits.h>
#include <syslog.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <net/if.h> 
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include "lnklist.h"
#include "hashtable.h"

#define error_abort(fmt, ...) \
	do { fprintf(stderr, "%s: [error] " fmt "\n", __func__, ## __VA_ARGS__); tcpeek_terminate(1); } while(0);

#define lprintf(level, fmt, ...) \
	fprintf(stderr, fmt "\n", ## __VA_ARGS__)
	//fprintf(stderr, "%s: " fmt "\n", __func__, ## __VA_ARGS__)

#define TCPEEK_SOCKET_FILE "/var/run/tcpeek/tcpeek.sock"

#define TCPEEK_SESSION_TABLE_SIZE  9973
#define TCPEEK_CHECKER_INTERVAL_SEC   1

#define TCPEEK_FILTER_DIR_RX 1
#define TCPEEK_FILTER_DIR_TX 2

#define TCPEEK_SESSION_FAILURE_TIMEOUT 1
#define TCPEEK_SESSION_FAILURE_REJECT  2
#define TCPEEK_SESSION_FAILURE_UNREACH 3

#define TCPEEK_CKSUM_NONE 0x00
#define TCPEEK_CKSUM_IP   0x01
#define TCPEEK_CKSUM_TCP  0x02
#define TCPEEK_CKSUM_BOTH 0x03

enum {
	TCPEEK_TCP_CLOSED = 1,
	TCPEEK_TCP_LISTEN,
	TCPEEK_TCP_SYN_SENT,
	TCPEEK_TCP_SYN_RECV,
	TCPEEK_TCP_ESTABLISHED
};

struct {
	struct {
		char user[128];
		char ifname[IFNAMSIZ];
		char socket[PATH_MAX];
		int checksum;
		int timeout;
        int buffer;
		int loglevel;
		int quiet;
		int promisc;
		int icmp;
		struct lnklist *expression;
	} option;
	struct {
		struct in_addr unicast;
	} addr;
	struct {
		pcap_t *pcap;
		int datalink;
		int snapshot;
	} pcap;
	struct {
		pthread_mutex_t mutex;
		struct hashtable *table;
		struct timeval timestamp;
	} session;
	struct lnklist *filter;
	int soc;
	int terminate;
} g;

struct tcpeek_stat {
	struct {
		uint32_t total;
		uint32_t dupsyn;
		uint32_t dupsynack;
		uint32_t dupack;
	} success;
	struct {
		uint32_t total;
		uint32_t timeout;
		uint32_t reject;
		uint32_t unreach;
	} failure;
};

struct tcpeek_filter {
	struct tcpeek_stat *stat;
	char name[128];
	int dir;
	struct lnklist *rule;
};

struct tcpeek_filter_rule {
	struct in_addr addr;
	uint8_t prefix;
	struct lnklist *port;
};

struct tcpeek_session_key {
	uint32_t addr[2];
	uint16_t port[2];
} __attribute__ ((__packed__));

struct tcpeek_session {
	struct tcpeek_session_key key;
	struct {
		uint32_t fseq[2];
		uint32_t lseq[2];
		uint32_t fack[2];
		uint32_t lack[2];
		uint8_t state[2];
		struct timeval timestamp[2];
	} sequence;
	struct {
		uint32_t dupsyn;
		uint32_t dupsynack;
		uint32_t dupack;
	} counter;
	uint16_t failure;
	struct lnklist *stat;
};

struct tcpeek_segment_datalink {
	union {
		struct ether_header ether;
		struct sll_header sll;
	} hdr;
};

struct tcpeek_segment_ip {
	struct tcpeek_segment_datalink datalink;
	struct ip hdr;
	uint8_t opt[40];
};

struct tcpeek_segment_tcp {
	struct tcpeek_segment_ip ip;
	struct tcphdr hdr;
	uint8_t opt[40];
	uint16_t psize;
};

struct tcpeek_segment {
	struct timeval timestamp;
	int icmp_unreach;
	struct tcpeek_segment_tcp tcp;
};

// tcpeek.c
extern void
tcpeek_signal_handler(int signo);
extern void
tcpeek_terminate(int status);
extern void
tcpeek_print_segment(struct tcpeek_segment *segment, int pos, const char *msg);

// init.c
extern void
tcpeek_init(int argc, char *argv[]);

// disassemble.c
extern uint8_t *
tcpeek_disassemble(const uint8_t *data, uint16_t size, int datalink, struct tcpeek_segment *dst);

// filter.c
extern struct tcpeek_filter *
tcpeek_filter_create(void);
extern void
tcpeek_filter_destroy(struct tcpeek_filter *filter);
extern struct tcpeek_filter_rule *
tcpeek_filter_rule_create(void);
extern void
tcpeek_filter_rule_destroy(struct tcpeek_filter_rule *rule);
extern int
tcpeek_filter_parse(struct tcpeek_filter *filter, const char *expression);
extern struct lnklist *
tcpeek_filter_lookup(struct tcpeek_segment *segment);

// session.c
extern void
tcpeek_session_destroy(struct tcpeek_session *session);
extern struct tcpeek_session *
tcpeek_session_get(struct tcpeek_segment *segment);
extern struct tcpeek_session *
tcpeek_session_open(struct tcpeek_segment *segment, struct lnklist *stats);
extern void
tcpeek_session_close(struct tcpeek_session *session);
extern void
tcpeek_session_timeout(struct tcpeek_session *session);
extern int
tcpeek_session_isestablished(struct tcpeek_session *session);
extern int
tcpeek_session_isclosed(struct tcpeek_session *session);
extern int
tcpeek_session_istimeout(struct tcpeek_session *session);
extern int
tcpeek_session_recv_syn(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_synack(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_ack(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_rst(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern void
tcpeek_session_print(struct tcpeek_session *session);

// checker.c
extern void *
tcpeek_checker_thread(void *arg);

// listener.c
extern void *
tcpeek_listener_thread(void *arg);

// checksum.c
extern uint16_t
cksum16(uint16_t *data, uint16_t size, uint32_t init);

// common.c
extern int
strisempty(const char *str);
extern int
strisequal(const char *str1, const char *str2);
extern char *
strtrim(char *str);
extern int
strisdigit(const char *str);
extern struct lnklist *
strsplit(const char *str, const char *sep, size_t num);
#ifndef __USE_GNU
extern char *
strndup(const char *s1, size_t n);
#endif
extern void *
memdup(const void *s, size_t n);
extern struct timeval *
tvsub(struct timeval *a, struct timeval *b, struct timeval *res);
extern struct timeval *
tvadd(struct timeval *a, struct timeval *b);
extern ssize_t
recvsz(int socket, void *buffer, size_t length, int flags, int timeout);
extern ssize_t
recvln(int socket, char *buffer, size_t length, int flags, int *fin, int timeout);

#endif
