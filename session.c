#include "tcpeek.h"

static struct tcpeek_session *
tcpeek_session_create(void);
static int
tcpeek_session_isowner(struct tcpeek_session *session, struct tcpeek_segment *segment);

static struct tcpeek_session *
tcpeek_session_create(void) {
	struct tcpeek_session *session;

	session = (struct tcpeek_session *)malloc(sizeof(struct tcpeek_session));
	if(session) {
		memset(session, 0x00, sizeof(struct tcpeek_session));
		session->sequence.state[0] = TCPEEK_TCP_CLOSED;
		session->sequence.state[1] = TCPEEK_TCP_CLOSED;
	}
	return session;
}

void
tcpeek_session_destroy(struct tcpeek_session *session) {
	if(session) {
		lnklist_destroy(session->stat);
		free(session);
	}
}

struct tcpeek_session *
tcpeek_session_get(struct tcpeek_segment *segment) {
	struct tcpeek_session_key key;
	struct tcpeek_session *session;

	key.addr[0] = segment->tcp.ip.hdr.ip_src.s_addr;
	key.addr[1] = segment->tcp.ip.hdr.ip_dst.s_addr;
	key.port[0] = segment->tcp.hdr.th_sport;
	key.port[1] = segment->tcp.hdr.th_dport;
	session = hashtable_get(g.session.table, &key, sizeof(key));
	if(!session) {
		key.addr[0] = segment->tcp.ip.hdr.ip_dst.s_addr;
		key.addr[1] = segment->tcp.ip.hdr.ip_src.s_addr;
		key.port[0] = segment->tcp.hdr.th_dport;
		key.port[1] = segment->tcp.hdr.th_sport;
		session = hashtable_get(g.session.table, &key, sizeof(key));
	}
	return session;
}

struct tcpeek_session *
tcpeek_session_open(struct tcpeek_segment *segment, struct lnklist *stat) {
	struct tcpeek_session *session;

	session = tcpeek_session_create();
	if(!session) {
		return NULL;
	}
	session->key.addr[0] = segment->tcp.ip.hdr.ip_src.s_addr;
	session->key.addr[1] = segment->tcp.ip.hdr.ip_dst.s_addr;
	session->key.port[0] = segment->tcp.hdr.th_sport;
	session->key.port[1] = segment->tcp.hdr.th_dport;
	session->sequence.timestamp[0] = segment->timestamp;
	session->sequence.timestamp[1] = segment->timestamp;
	session->stat = stat;
	return hashtable_put(g.session.table, &session->key, sizeof(session->key), session);
}

void
tcpeek_session_close(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;

	lnklist_iter_init(session->stat);
	while(lnklist_iter_hasnext(session->stat)) {
		stat = lnklist_iter_next(session->stat);
		stat->total++;
		if(session->counter.dupsyn) stat->dupsyn++;
		if(session->counter.dupsynack) stat->dupsynack++;
		if(session->counter.dupack) stat->dupack++;
	}
	tcpeek_session_print(session);
	hashtable_remove(g.session.table, &session->key, sizeof(session->key));
	tcpeek_session_destroy(session);
}

void
tcpeek_session_timeout(struct tcpeek_session *session) {
	gettimeofday(&session->sequence.timestamp[1], NULL);
	tcpeek_session_close(session);
}

int
tcpeek_session_isestablished(struct tcpeek_session *session) {
	return (session->sequence.state[0] == TCPEEK_TCP_ESTABLISHED && session->sequence.state[1] == TCPEEK_TCP_ESTABLISHED) ? 1 : 0;
}

int
tcpeek_session_isclosed(struct tcpeek_session *session) {
	return (session->sequence.state[0] == TCPEEK_TCP_CLOSED && session->sequence.state[1] == TCPEEK_TCP_CLOSED) ? 1 : 0;
}

int
tcpeek_session_istimeout(struct tcpeek_session *session) {
    struct timeval now, difftime;

	gettimeofday(&now, NULL);
	tvsub(&now, &session->sequence.timestamp[1], &difftime);
	return (difftime.tv_sec >= g.option.timeout) ? 1 : 0;
}

static int
tcpeek_session_isowner(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	return session->key.addr[0] == segment->tcp.ip.hdr.ip_src.s_addr ? 1 : 0;
}

int
tcpeek_session_recv_syn(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	session->sequence.timestamp[1] = segment->timestamp;
	switch(session->sequence.state[self]) {
		case TCPEEK_TCP_CLOSED:
			session->sequence.state[self] = TCPEEK_TCP_SYN_SENT;
			session->sequence.state[peer] = TCPEEK_TCP_LISTEN;
			session->sequence.fseq[self] = session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
			session->sequence.fack[self] = session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
			break;
		case TCPEEK_TCP_LISTEN: /* simultaneous open */
			if(!(ntohl(segment->tcp.hdr.th_ack) == session->sequence.lseq[peer] + 1)) {
				lprintf(LOG_WARNING, "Duplicate connection.");
				return -1;
			}
			session->sequence.state[self] = TCPEEK_TCP_SYN_SENT;
			session->sequence.fseq[self] = session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
			session->sequence.fack[self] = session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
			break;
		case TCPEEK_TCP_SYN_SENT: /* retransmit */
			if(!(ntohl(segment->tcp.hdr.th_seq) == session->sequence.fseq[self] && ntohl(segment->tcp.hdr.th_ack) == session->sequence.fack[self])) {
				lprintf(LOG_WARNING, "Duplicate connection.");
				return -1;
			}
			session->counter.dupsyn++;
			break;
		default:
			lprintf(LOG_WARNING, "Duplicate connection.");
			return -1;
	}
	return 0;
}

int
tcpeek_session_recv_synack(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;
	char msg[128];

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	session->sequence.timestamp[1] = segment->timestamp;
	switch(session->sequence.state[self]) {
		case TCPEEK_TCP_LISTEN:
			if(!(ntohl(segment->tcp.hdr.th_ack) == session->sequence.lseq[peer] + 1)) {
				snprintf(msg, sizeof(msg), "%s: sequence error. %d/%d", __func__, session->sequence.state[self], session->sequence.state[peer]);
				tcpeek_print_segment(segment, self, msg);
				return -1;
			}
			session->sequence.state[self] = TCPEEK_TCP_SYN_RECV;
			session->sequence.fseq[self] = session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
			session->sequence.fack[self] = session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
			break;
		case TCPEEK_TCP_SYN_SENT: /* simultaneous open */
			if(!(ntohl(segment->tcp.hdr.th_seq) == session->sequence.lseq[self] && ntohl(segment->tcp.hdr.th_ack) == session->sequence.lseq[peer] + 1)) {
				snprintf(msg, sizeof(msg), "%s: sequence error. %d/%d", __func__, session->sequence.state[self], session->sequence.state[peer]);
				tcpeek_print_segment(segment, self, msg);
				return -1;
			}
			session->sequence.state[self] = TCPEEK_TCP_SYN_RECV;
			session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
			break;
		case TCPEEK_TCP_SYN_RECV: /* retransmit */
			if(!(ntohl(segment->tcp.hdr.th_seq) == session->sequence.lseq[self] && ntohl(segment->tcp.hdr.th_ack) == session->sequence.lack[self])) {
				snprintf(msg, sizeof(msg), "%s: sequence error. %d/%d", __func__, session->sequence.state[self], session->sequence.state[peer]);
				tcpeek_print_segment(segment, self, msg);
				return -1;
			}
			session->counter.dupsynack++;
			break;
		default:
			snprintf(msg, sizeof(msg), "%s: sequence error. %d/%d", __func__, session->sequence.state[self], session->sequence.state[peer]);
			tcpeek_print_segment(segment, self, msg);
			return -1;
	}
	return 0;
}

int
tcpeek_session_recv_ack(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;
	char msg[128];

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	session->sequence.timestamp[1] = segment->timestamp;
	switch(session->sequence.state[self]) {
		case TCPEEK_TCP_SYN_SENT:
			if(ntohl(segment->tcp.hdr.th_seq) == session->sequence.lseq[self] && ntohl(segment->tcp.hdr.th_ack) == session->sequence.lseq[peer] + 1) {
				snprintf(msg, sizeof(msg), "%s: sequence error. %d/%d", __func__, session->sequence.state[self], session->sequence.state[peer]);
				tcpeek_print_segment(segment, self, msg);
				return -1;
			}
			session->sequence.state[self] = session->sequence.state[peer] = TCPEEK_TCP_ESTABLISHED;
			session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
			break;
		case TCPEEK_TCP_SYN_RECV:
			if(ntohl(segment->tcp.hdr.th_seq) == session->sequence.lseq[self] + 1 && ntohl(segment->tcp.hdr.th_ack) == session->sequence.lseq[peer] + 1) {
				snprintf(msg, sizeof(msg), "%s: sequence error. %d/%d", __func__, session->sequence.state[self], session->sequence.state[peer]);
				tcpeek_print_segment(segment, self, msg);
				return -1;
			}
			session->sequence.state[self] = session->sequence.state[peer] = TCPEEK_TCP_ESTABLISHED;
			session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
			session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
			break;
		case TCPEEK_TCP_ESTABLISHED:
			// TODO:
			break;
		default:
			snprintf(msg, sizeof(msg), "%s: sequence error. %d/%d", __func__, session->sequence.state[self], session->sequence.state[peer]);
			tcpeek_print_segment(segment, self, msg);
			return -1;
	}
	return 0;
}

int
tcpeek_session_recv_rst(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	session->sequence.timestamp[1] = segment->timestamp;
	session->sequence.state[self] = TCPEEK_TCP_CLOSED;
	session->sequence.state[peer] = TCPEEK_TCP_CLOSED;
	session->counter.rst++;
	return 0;
}

void
tcpeek_session_print(struct tcpeek_session *session) {
	static int firsttime = 1;
	struct tm tm;
	char timestamp[128];
	char src[128], dst[128];
	struct timeval difftime;

	if(firsttime && firsttime--) {
		lprintf(LOG_INFO, " TIME(s) |       TIMESTAMP       |      SRC IP:PORT            DST IP:PORT     | SYN  S/A  ACK ");
		lprintf(LOG_INFO, "-----------------------------------------------------------------------------------------------");
	}
	tvsub(&session->sequence.timestamp[1], &session->sequence.timestamp[0], &difftime);
	localtime_r(&session->sequence.timestamp[0].tv_sec, &tm);
	strftime(timestamp, sizeof(timestamp), "%y-%m-%d %T", &tm);
	lprintf(LOG_INFO, "%4d.%03d | %s.%03d | %15s:%-5u %15s:%-5u | %3u  %3u  %3u ",
		(int)(difftime.tv_sec),
		(int)(difftime.tv_usec / 1000),
		timestamp,
		(int)(session->sequence.timestamp[0].tv_usec / 1000),
		inet_ntop(AF_INET, &session->key.addr[0], src, sizeof(src)),
		ntohs(session->key.port[0]),
		inet_ntop(AF_INET, &session->key.addr[1], dst, sizeof(dst)),
		ntohs(session->key.port[1]),
		session->counter.dupsyn,
		session->counter.dupsynack,
		session->counter.dupack
	);
}
