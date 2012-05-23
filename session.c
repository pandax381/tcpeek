#include "tcpeek.h"

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
tcpeek_session_open(struct tcpeek_segment *segment) {
	struct tcpeek_session *session;

	session = (struct tcpeek_session *)malloc(sizeof(struct tcpeek_session));
	if(!session) {
		return NULL;
	}
	g.session.stat.total++;
	g.session.stat.active++;
	if(g.session.stat.active > g.session.stat.max) {
		g.session.stat.max = g.session.stat.active;
	}
	memset(session, 0x00, sizeof(struct tcpeek_session));
	session->key.addr[0] = segment->tcp.ip.hdr.ip_src.s_addr;
	session->key.addr[1] = segment->tcp.ip.hdr.ip_dst.s_addr;
	session->key.port[0] = segment->tcp.hdr.th_sport;
	session->key.port[1] = segment->tcp.hdr.th_dport;
	session->sequence.state[0] = TCPEEK_TCP_CLOSED;
	session->sequence.state[1] = TCPEEK_TCP_CLOSED;
	session->sequence.segments[0] = lnklist_create();
	session->sequence.segments[1] = lnklist_create();
	session->sequence.timestamp[0] = segment->timestamp;
	session->sequence.timestamp[1] = segment->timestamp;
	return hashtable_put(g.session.table, &session->key, sizeof(session->key), session);
}

void
tcpeek_session_close(struct tcpeek_session *session) {
	struct timeval difftime;
	g.session.stat.active--;
	if(session->stat.timeout) {
		g.session.stat.timeout++;
	}
	else {
		__tvsub(&session->sequence.timestamp[1], &session->sequence.timestamp[0], &difftime);
		if(g.session.stat.lifetime_max.tv_sec < difftime.tv_sec ||
			(g.session.stat.lifetime_max.tv_sec == difftime.tv_sec && g.session.stat.lifetime_max.tv_usec < difftime.tv_usec)) {
			g.session.stat.lifetime_max = difftime;
		}
		__tvadd(&g.session.stat.lifetime_total, &difftime);
	}
	if(session->stat.syn || session->stat.synack || session->stat.retrans) {
		g.session.stat.retrans_session++;
		if(session->stat.syn) {
			g.session.stat.retrans_syn += session->stat.syn;
		}
		if(session->stat.synack) {
			g.session.stat.retrans_synack += session->stat.synack;
		}
		if(session->stat.retrans) {
			g.session.stat.retrans_retrans += session->stat.retrans;
		}
	}
	tcpeek_session_print(session);
	free(hashtable_remove(g.session.table, &session->key, sizeof(session->key)));
}

void
tcpeek_session_timeout(struct tcpeek_session *session) {
	gettimeofday(&session->sequence.timestamp[1], NULL);
	session->stat.timeout = 1;
	tcpeek_session_close(session);
}

int
tcpeek_session_isestablished(struct tcpeek_session *session) {
	return (session->sequence.state[0] == TCPEEK_TCP_ESTABLISHED && session->sequence.state[1] == TCPEEK_TCP_ESTABLISHED) ? 1 : 0;
}

int
tcpeek_session_isclosed(struct tcpeek_session *session) {
	if ((session->sequence.state[0] == TCPEEK_TCP_CLOSED && session->sequence.state[1] == TCPEEK_TCP_CLOSED) ||
		(session->sequence.state[0] == TCPEEK_TCP_CLOSED && session->sequence.state[1] == TCPEEK_TCP_TIME_WAIT) ||
		(session->sequence.state[1] == TCPEEK_TCP_CLOSED && session->sequence.state[0] == TCPEEK_TCP_TIME_WAIT)) {
		return 1;
	}
	return 0;
}

int
tcpeek_session_istimeouted(struct tcpeek_session *session) {
    struct timeval now, difftime;

	gettimeofday(&now, NULL);
	__tvsub(&now, &session->sequence.timestamp[1], &difftime);
	if(difftime.tv_sec >= g.option.timeout) {
		return 1;
	}
	return 0;
}

int
tcpeek_session_isowner(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	return session->key.addr[0] == segment->tcp.ip.hdr.ip_src.s_addr ? 1 : 0;
}

struct tcpeek_segment *
tcpeek_session_add_segment(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self;
	struct tcpeek_segment *_segment;

	session->sequence.timestamp[1] = segment->timestamp;
	_segment = __memdup(segment, sizeof(struct tcpeek_segment));
	self = tcpeek_session_isowner(session, segment) ^ 0x01;
	return lnklist_add(session->sequence.segments[self], _segment, lnklist_size(session->sequence.segments[self]));
}

int
tcpeek_session_recv_syn(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	if (tcpeek_session_isclosed(session)) {
		session->sequence.state[self] = TCPEEK_TCP_SYN_SENT;
		session->sequence.fseq[self] = session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
		session->sequence.fack[self] = session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
		session->sequence.rwin[self] = ntohs(segment->tcp.hdr.th_win);
	}
	else if (session->sequence.fseq[self] == ntohl(segment->tcp.hdr.th_seq) && session->sequence.fack[self] == ntohl(segment->tcp.hdr.th_ack)) {
		session->stat.syn++;
		return -1;
	}
	else {
		syslog(LOG_WARNING, "%s [warning] Duplicate connection.", __func__);
		return -1;
	}
	return 0;
}

int
tcpeek_session_recv_synack(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	if (session->sequence.state[peer] == TCPEEK_TCP_SYN_SENT && session->sequence.state[self] == TCPEEK_TCP_CLOSED) {
		if (ntohl(segment->tcp.hdr.th_ack) == session->sequence.lseq[peer] + 1) {
			session->sequence.state[self] = TCPEEK_TCP_SYN_RECV;
			session->sequence.fseq[self] = session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
			session->sequence.fack[self] = session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
			session->sequence.rwin[self] = ntohs(segment->tcp.hdr.th_win);
			return 0;
		}
	}
	//tcpeek_print_segment(segment, self, "tcpeek_session_recv_synack");
	//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
	return -1;
}

int
tcpeek_session_recv_ack(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	if (session->sequence.state[self] == TCPEEK_TCP_SYN_SENT && session->sequence.state[peer] == TCPEEK_TCP_SYN_RECV) {
		session->sequence.state[self] = TCPEEK_TCP_ESTABLISHED;
		session->sequence.state[peer] = TCPEEK_TCP_ESTABLISHED;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_ESTABLISHED && session->sequence.state[peer] == TCPEEK_TCP_ESTABLISHED) {
		// keep current status.
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_CLOSE_WAIT && session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT2) {
		// keep current status.
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_FIN_WAIT2 && session->sequence.state[peer] == TCPEEK_TCP_CLOSE_WAIT) {
		// keep current status.
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_ESTABLISHED && session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT1) {
		session->sequence.state[self] = TCPEEK_TCP_CLOSE_WAIT;
		session->sequence.state[peer] = TCPEEK_TCP_FIN_WAIT2;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_FIN_WAIT2 && session->sequence.state[peer] == TCPEEK_TCP_LAST_ACK) {
		session->sequence.state[self] = TCPEEK_TCP_TIME_WAIT;
		session->sequence.state[peer] = TCPEEK_TCP_CLOSED;
	}
	else {
		//tcpeek_print_segment(segment, self, "tcpeek_session_recv_ack");
		//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
		return -1;
	}
	session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
	session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
	return 0;
}

int
tcpeek_session_recv_fin(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	if (session->sequence.state[self] == TCPEEK_TCP_ESTABLISHED && session->sequence.state[peer] == TCPEEK_TCP_ESTABLISHED) {
		session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_CLOSE_WAIT && session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT2) {
		session->sequence.state[self] = TCPEEK_TCP_LAST_ACK;
	}
	else {
		//tcpeek_print_segment(segment, self, "tcpeek_session_recv_fin");
		//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
		return -1;
	}
	session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
	session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
	return 0;
}

int
tcpeek_session_recv_finack(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	if (session->sequence.state[self] == TCPEEK_TCP_SYN_RECV && session->sequence.state[peer] == TCPEEK_TCP_ESTABLISHED) {
		session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_ESTABLISHED && session->sequence.state[peer] == TCPEEK_TCP_ESTABLISHED) {
		session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_ESTABLISHED && session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT1) {
		session->sequence.state[self] = TCPEEK_TCP_LAST_ACK;
		session->sequence.state[peer] = TCPEEK_TCP_FIN_WAIT2;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_CLOSE_WAIT && session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT2) {
		session->sequence.state[self] = TCPEEK_TCP_LAST_ACK;
	}
	else {
		//tcpeek_print_segment(segment, self, "tcpeek_session_recv_finack");
		//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
		return -1;
	}
	session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
	session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
	return 0;
}

int
tcpeek_session_recv_rst(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	session->stat.rst++;
	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	session->sequence.state[self] = TCPEEK_TCP_CLOSED;
	session->sequence.state[peer] = TCPEEK_TCP_CLOSED;
	return 0;
}

int
tcpeek_session_recv_isretransmit(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;
	struct tcpeek_segment *_segment;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	lnklist_iter_init(session->sequence.segments[self]);
	while (lnklist_iter_hasnext(session->sequence.segments[self])) {
		_segment = lnklist_iter_next(session->sequence.segments[self]);
		if (_segment->tcp.hdr.th_seq == segment->tcp.hdr.th_seq && _segment->tcp.hdr.th_ack == segment->tcp.hdr.th_ack &&
			_segment->tcp.hdr.th_flags == segment->tcp.hdr.th_flags && _segment->tcp.psize == segment->tcp.psize) {
			return 1;
		}
	}
	return 0;
}

void
tcpeek_session_print(struct tcpeek_session *session) {
	static int isfirsttime = 1;
	struct tm tm;
	char timestamp[128];
	char src[128], dst[128];
	struct timeval difftime;

	if (isfirsttime) {
		isfirsttime = 0;
		syslog(LOG_INFO, " TIME(s) |       TIMESTAMP       |      SRC IP:PORT           DST IP:PORT      |  STATE  SEG_NUM  SYN_DUP  S/A_DUP  RETRANS  ERR");
		syslog(LOG_INFO, "----------------------------------------------------------------------------------------------------------------------------------");
	}
	__tvsub(&session->sequence.timestamp[1], &session->sequence.timestamp[0], &difftime);
	localtime_r(&session->sequence.timestamp[0].tv_sec, &tm);
	strftime(timestamp, sizeof(timestamp), "%y-%m-%d %T", &tm);
	syslog(LOG_INFO, "%4d.%03d | %s.%03d | %15s:%-5u %15s:%-5u | %s %7ld  %7u  %7u  %7u  %3u",
		(int)difftime.tv_sec,
		(int)(difftime.tv_usec / 1000),
		timestamp,
		(int)(session->sequence.timestamp[0].tv_usec / 1000),
		inet_ntop(AF_INET, &session->key.addr[0], src, sizeof(src)),
		ntohs(session->key.port[0]),
		inet_ntop(AF_INET, &session->key.addr[1], dst, sizeof(dst)),
		ntohs(session->key.port[1]),
		session->stat.timeout ? "TIMEOUT" : (session->stat.rst ? " RESET " : " CLOSE "),
		lnklist_size(session->sequence.segments[0]) + lnklist_size(session->sequence.segments[1]),
		session->stat.syn,
		session->stat.synack,
		session->stat.retrans,
		session->stat.err
	);
}
