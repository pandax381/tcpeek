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
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/if.h> 
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "lnklist.h"
#include "hashtable.h"

#define TCPEEK_SESSION_TABLE_SIZE 9973
#define TCPEEK_CHECKER_INTERVAL_SEC 1

#define TCPEEK_CKSUM_NONE 0x00
#define TCPEEK_CKSUM_IP   0x01
#define TCPEEK_CKSUM_TCP  0x02
#define TCPEEK_CKSUM_BOTH 0x03

enum {
	TCPEEK_TCP_ESTABLISHED = 1,
	TCPEEK_TCP_SYN_SENT,
	TCPEEK_TCP_SYN_RECV,
	TCPEEK_TCP_FIN_WAIT1,
	TCPEEK_TCP_FIN_WAIT2,
	TCPEEK_TCP_TIME_WAIT,
	TCPEEK_TCP_CLOSED,
	TCPEEK_TCP_CLOSE_WAIT,
	TCPEEK_TCP_LAST_ACK,
	TCPEEK_TCP_LISTEN,
	TCPEEK_TCP_CLOSING
};

struct {
	struct {
		char ifname[IFNAMSIZ];
		int  promisc;
		int  timeout;
		char checksum;
		char expression[1024];
	} option;
	struct {
		pcap_t *pcap;
		int datalink;
		int snapshot;
	} pcap;
	struct {
		pthread_mutex_t mutex;
		struct hashtable *table;
		struct {
			uint32_t total;
			uint32_t active;
			uint32_t max;
			uint32_t timeout;
			struct timeval lifetime_total;
			struct timeval lifetime_avg;
			struct timeval lifetime_max;
			uint32_t retrans_session;
			uint32_t retrans_syn;
			uint32_t retrans_synack;
			uint32_t retrans_retrans;
		} stat;
		struct timeval timestamp;
	} session;
	int terminate;
} g;

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
		uint16_t rwin[2];
		uint8_t state[2];
		struct timeval timestamp[2];
		struct lnklist *segments[2];
	} sequence;
	struct {
		uint32_t syn;
		uint32_t synack;
		uint32_t retrans;
		uint32_t rst;
		uint32_t err;
		uint32_t timeout;
	} stat;
};
/*
struct tcpeek_session {
	struct tcpeek_session_key key;
	uint32_t fseq[2];
	uint32_t lseq[2];
	uint32_t fack[2];
	uint32_t lack[2];
	uint16_t rwin[2];
	uint8_t state[2];
	struct timeval firsttime;
	struct timeval lasttime;
	struct {
		uint32_t syn;
		uint32_t synack;
		uint32_t retrans;
		uint32_t rst;
		uint32_t err;
	} count;
	int timeout;
	struct lnklist *segments[2];
};
*/

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

// session.c
extern struct tcpeek_session *
tcpeek_session_get(struct tcpeek_segment *segment);
extern struct tcpeek_session *
tcpeek_session_open(struct tcpeek_segment *segment);
extern void
tcpeek_session_close(struct tcpeek_session *session);
extern void
tcpeek_session_timeout(struct tcpeek_session *session);
extern int
tcpeek_session_isclosed(struct tcpeek_session *session);
extern int
tcpeek_session_istimeouted(struct tcpeek_session *session);
extern int
tcpeek_session_isowner(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern struct tcpeek_segment *
tcpeek_session_add_segment(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_syn(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_synack(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_ack(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_fin(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_finack(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_rst(struct tcpeek_session *session, struct tcpeek_segment *segment);
extern int
tcpeek_session_recv_isretransmit(struct tcpeek_session *session, struct tcpeek_segment *segment);
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
extern void *
__memdup(const void *s, size_t n);
extern struct timeval *
__tvsub(struct timeval *a, struct timeval *b, struct timeval *res);
extern struct timeval *
__tvadd(struct timeval *a, struct timeval *b);

#endif
