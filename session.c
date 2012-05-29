#include "tcpeek.h"

void
tcpeek_session_destroy(struct tcpeek_session *session) {
	if (!session) {
		return;
	}
	hashtable_remove(g.session.table, &session->key, sizeof(session->key));
	while (lnklist_size(session->sequence.segments[0]) > 0) {
		free(lnklist_remove(session->sequence.segments[0], 0));
	}
	lnklist_destroy(session->sequence.segments[0]);
	while (lnklist_size(session->sequence.segments[1]) > 0) {
		free(lnklist_remove(session->sequence.segments[1], 0));
	}
	lnklist_destroy(session->sequence.segments[1]);
	free(session);
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
tcpeek_session_open(struct tcpeek_segment *segment) {
	struct tcpeek_session *session;

	session = (struct tcpeek_session *)malloc(sizeof(struct tcpeek_session));
	if(!session) {
		return NULL;
	}
	g.stat.session.total++;
	g.stat.session.active++;
	if(g.stat.session.active > g.stat.session.max) {
		g.stat.session.max = g.stat.session.active;
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

	g.stat.session.active--;
	if(session->stat.timeout) {
		g.stat.session.timeout++;
	}
	else {
		__tvsub(&session->sequence.timestamp[1], &session->sequence.timestamp[0], &difftime);
		if(g.stat.lifetime.max.tv_sec < difftime.tv_sec || (g.stat.lifetime.max.tv_sec == difftime.tv_sec && g.stat.lifetime.max.tv_usec < difftime.tv_usec)) {
			g.stat.lifetime.max = difftime;
		}
		__tvadd(&g.stat.lifetime.total, &difftime);
	}
	g.stat.segment.total += (lnklist_size(session->sequence.segments[0]) + lnklist_size(session->sequence.segments[1]));
	g.stat.segment.err += session->stat.err;
	if(session->stat.dupsyn || session->stat.dupsynack || session->stat.retrans || session->stat.retrans) {
		//g.stat.retrans_session++;
		g.stat.segment.dupsyn += session->stat.dupsyn;
		g.stat.segment.dupsynack += session->stat.dupsynack;
		g.stat.segment.dupack += session->stat.dupack;
		g.stat.segment.retrans += session->stat.retrans;
	}
	tcpeek_session_print(session);
	tcpeek_session_destroy(session);
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
		(session->sequence.state[0] == TCPEEK_TCP_TIME_WAIT && session->sequence.state[1] == TCPEEK_TCP_TIME_WAIT) ||
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
	if (session->sequence.state[self] == TCPEEK_TCP_CLOSED) {
		session->sequence.state[self] = TCPEEK_TCP_SYN_SENT;
		session->sequence.fseq[self] = session->sequence.lseq[self] = session->sequence.nseq[self] = ntohl(segment->tcp.hdr.th_seq);
		session->sequence.fack[self] = session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
		session->sequence.rwin[self] = ntohs(segment->tcp.hdr.th_win);
		if (session->sequence.state[peer] == TCPEEK_TCP_SYN_SENT) {
			syslog(LOG_DEBUG, "%s [debug simultaneous open.", __func__);
		}
	}
	else if (session->sequence.fseq[self] == ntohl(segment->tcp.hdr.th_seq) && session->sequence.fack[self] == ntohl(segment->tcp.hdr.th_ack)) {
		session->stat.dupsyn++;
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
	if (session->sequence.state[self] == TCPEEK_TCP_CLOSED) { // passive open
		session->sequence.state[self] = TCPEEK_TCP_SYN_RECV;
		session->sequence.fseq[self] = session->sequence.lseq[self] = session->sequence.nseq[self] = ntohl(segment->tcp.hdr.th_seq);
		session->sequence.fack[self] = session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
		session->sequence.rwin[self] = ntohs(segment->tcp.hdr.th_win);
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_SYN_SENT) { // simultaneous open
		session->sequence.state[self] = TCPEEK_TCP_ESTABLISHED;
		session->sequence.lseq[self] = session->sequence.nseq[self] = ntohl(segment->tcp.hdr.th_seq);
		session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
	}
	else if (ntohl(segment->tcp.hdr.th_ack) == session->sequence.fseq[peer] + 1) {
		session->stat.dupsynack++;
	}
	else {
		char msg[128];
		snprintf(msg, sizeof(msg), "tcpeek_session_recv_synack: %d/%d", session->sequence.state[self], session->sequence.state[peer]);
		tcpeek_print_segment(segment, self, msg);
		return -1;
	}
	return 0;
}

int
tcpeek_session_recv_ack(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	if (session->sequence.lseq[self] > ntohl(segment->tcp.hdr.th_seq)) {
		if (segment->tcp.psize) {
			if (tcpeek_session_recv_isretransmit(session, segment)) {
				session->stat.retrans++;
			}
		}
		return 0;
	}
	if (session->sequence.state[self] == TCPEEK_TCP_SYN_SENT) {
		session->sequence.state[self] = TCPEEK_TCP_ESTABLISHED;
		session->sequence.state[peer] = TCPEEK_TCP_ESTABLISHED;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_ESTABLISHED) {
 		if (session->sequence.state[peer] == TCPEEK_TCP_ESTABLISHED) {
			if (segment->tcp.psize == 0) {
				if (session->sequence.lack[self] >= ntohl(segment->tcp.hdr.th_ack)) {
					session->stat.dupack++;
					return 0;
				}
			}
		}
		else if (session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT1) {
			if (ntohl(segment->tcp.hdr.th_ack) == session->sequence.nseq[peer] + 1) {
				session->sequence.state[self] = TCPEEK_TCP_CLOSE_WAIT;
				session->sequence.state[peer] = TCPEEK_TCP_FIN_WAIT2;
			}
		}
		else {
			tcpeek_print_segment(segment, self, "tcpeek_session_recv_ack");
			fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_FIN_WAIT1) {
		if (session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT1) {
			session->sequence.state[self] = TCPEEK_TCP_CLOSING;
		}
		else if (session->sequence.state[peer] == TCPEEK_TCP_CLOSING) {
			session->sequence.state[self] = TCPEEK_TCP_CLOSING;
		}
		else {
			tcpeek_print_segment(segment, self, "tcpeek_session_recv_ack");
			fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_FIN_WAIT2) {
		if (session->sequence.state[peer] == TCPEEK_TCP_CLOSE_WAIT) {
			if (segment->tcp.psize == 0) {
				if (session->sequence.lack[self] >= ntohl(segment->tcp.hdr.th_ack)) {
					session->stat.dupack++;
					return 0;
				}
			}
		}
		else if (session->sequence.state[peer] == TCPEEK_TCP_LAST_ACK) {
			session->sequence.state[self] = TCPEEK_TCP_TIME_WAIT;
			session->sequence.state[peer] = TCPEEK_TCP_CLOSED;
		}
		else {
			tcpeek_print_segment(segment, self, "tcpeek_session_recv_ack");
			fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_CLOSING) {
		if (session->sequence.state[peer] == TCPEEK_TCP_CLOSING) {
			session->sequence.state[self] = TCPEEK_TCP_TIME_WAIT;
			session->sequence.state[peer] = TCPEEK_TCP_TIME_WAIT;
		}
		else {
			tcpeek_print_segment(segment, self, "tcpeek_session_recv_ack");
			fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_CLOSE_WAIT) {
		if (session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT2) {
			if (segment->tcp.psize == 0) {
				if (session->sequence.lack[self] >= ntohl(segment->tcp.hdr.th_ack)) {
					session->stat.dupack++;
					return 0;
				}
			}
		}
		else {
			tcpeek_print_segment(segment, self, "tcpeek_session_recv_ack");
			fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else {
		tcpeek_print_segment(segment, self, "tcpeek_session_recv_ack");
		fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
		return -1;
	}
	session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
	session->sequence.nseq[self] = session->sequence.lseq[self] + segment->tcp.psize;
	if(session->sequence.lack[self] < ntohl(segment->tcp.hdr.th_ack)) {
		session->sequence.lack[self] = ntohl(segment->tcp.hdr.th_ack);
	}
	return 0;
}

int
tcpeek_session_recv_fin(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	if (session->sequence.state[self] == TCPEEK_TCP_SYN_RECV) {
		session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_ESTABLISHED) {
		if (session->sequence.state[peer] == TCPEEK_TCP_ESTABLISHED) {
			session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
		}
		else if (session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT1) {
			session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
		}
		else {
			tcpeek_print_segment(segment, self, "tcpeek_session_recv_fin");
			fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_CLOSE_WAIT) {
		if (session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT2) {	
			session->sequence.state[self] = TCPEEK_TCP_LAST_ACK;
		}
		else {
			tcpeek_print_segment(segment, self, "tcpeek_session_recv_fin");
			fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else {
		tcpeek_print_segment(segment, self, "tcpeek_session_recv_fin");
		fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
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
	if (session->sequence.state[self] == TCPEEK_TCP_SYN_RECV) {
		session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_ESTABLISHED) {
		if (session->sequence.state[peer] == TCPEEK_TCP_ESTABLISHED) {
			session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
		}
		else if (session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT1) {
			if (ntohl(segment->tcp.hdr.th_ack) == session->sequence.nseq[peer] + 1) { // ACK of FIN
				session->sequence.state[self] = TCPEEK_TCP_LAST_ACK;
				session->sequence.state[peer] = TCPEEK_TCP_FIN_WAIT2;
			}
			else { // simultaneous close.
				session->sequence.state[self] = TCPEEK_TCP_FIN_WAIT1;
			}
		}
		else {
			//tcpeek_print_segment(segment, self, "tcpeek_session_recv_finack");
			//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_FIN_WAIT1) {
		if (session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT1) {
			session->sequence.state[self] = TCPEEK_TCP_CLOSING;
		}
		else if (session->sequence.state[peer] == TCPEEK_TCP_CLOSING) {
			session->sequence.state[self] = TCPEEK_TCP_TIME_WAIT;
			session->sequence.state[peer] = TCPEEK_TCP_TIME_WAIT;
		}
		else {
			//tcpeek_print_segment(segment, self, "tcpeek_session_recv_finack");
			//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_FIN_WAIT2) {
		if (session->sequence.state[peer] == TCPEEK_TCP_LAST_ACK) {
			session->sequence.state[self] = TCPEEK_TCP_TIME_WAIT;
			session->sequence.state[peer] = TCPEEK_TCP_CLOSED;
		}
		else {
			//tcpeek_print_segment(segment, self, "tcpeek_session_recv_finack");
			//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else if (session->sequence.state[self] == TCPEEK_TCP_CLOSE_WAIT) {
		if (session->sequence.state[peer] == TCPEEK_TCP_FIN_WAIT2) {	
			session->sequence.state[self] = TCPEEK_TCP_LAST_ACK;
		}
		else {
			//tcpeek_print_segment(segment, self, "tcpeek_session_recv_finack");
			//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
			return -1;
		}
	}
	else {
		//tcpeek_print_segment(segment, self, "tcpeek_session_recv_finack");
		//fprintf(stderr, "self: %d, peer: %d\n", session->sequence.state[self], session->sequence.state[peer]);
		return -1;
	}
	session->sequence.lseq[self] = ntohl(segment->tcp.hdr.th_seq);
	session->sequence.nseq[self] = session->sequence.lseq[self] + segment->tcp.psize;
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
tcpeek_session_recv_isdupack(struct tcpeek_session *session, struct tcpeek_segment *segment) {
	int self, peer;
	struct tcpeek_segment *_segment;

	peer = (self = tcpeek_session_isowner(session, segment) ^ 0x01) ^ 0x01;
	lnklist_iter_init(session->sequence.segments[self]);
	while (lnklist_iter_hasnext(session->sequence.segments[self])) {
		_segment = lnklist_iter_next(session->sequence.segments[self]);
		if (_segment->tcp.hdr.th_ack == segment->tcp.hdr.th_ack && _segment->tcp.psize == 0) {
			return 1;
		}
	}
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
		if (_segment->tcp.hdr.th_seq == segment->tcp.hdr.th_seq && _segment->tcp.psize) {
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
		syslog(LOG_INFO, " TIME(s) |       TIMESTAMP       |      SRC IP:PORT           DST IP:PORT      |  STATE  SEG_NUM  SYN_DUP  S/A_DUP  ACK_DUP RETRANS  ERR   S/P");
		syslog(LOG_INFO, "------------------------------------------------------------------------------------------------------------------------------------------------");
	}
	__tvsub(&session->sequence.timestamp[1], &session->sequence.timestamp[0], &difftime);
	localtime_r(&session->sequence.timestamp[0].tv_sec, &tm);
	strftime(timestamp, sizeof(timestamp), "%y-%m-%d %T", &tm);
	syslog(LOG_INFO, "%4d.%03d | %s.%03d | %15s:%-5u %15s:%-5u | %s %7ld  %7u  %7u  %7u %7u  %3u | %d/%d",
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
		session->stat.dupsyn,
		session->stat.dupsynack,
		session->stat.dupack,
		session->stat.retrans,
		session->stat.err,
		session->sequence.state[0],
		session->sequence.state[1]
	);
}
