#include "tcpeek.h"

static void
tcpeek_execute(void);
static void
tcpeek_fetch(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *pktdata);
static void
tcpeek_terminate_session(void);
static void
tcpeek_print_pcap_status(void);
static void
tcpeek_print_summary(void);

int
main(int argc, char *argv[]) {
	tcpeek_init(argc, argv);
	tcpeek_execute();
	tcpeek_terminate(0);
	return 0; /* does not reached */
}

void
tcpeek_signal_handler(int signo) {
	if(signo == SIGINT || signo == SIGTERM) {
		g.terminate = 1;
		if(g.pcap.pcap) {
			pcap_breakloop(g.pcap.pcap); /* signal safe */
		}
	}
}

static void
tcpeek_execute(void) {
	int err, ready;
	pthread_t checker, listener;
	struct pollfd pfds[1];

	err = pthread_create(&checker, NULL, tcpeek_checker_thread, NULL);
	if(err) {
		error_abort("%s", strerror(err));
	}
	err = pthread_create(&listener, NULL, tcpeek_listener_thread, NULL);
	if(err) {
		error_abort("%s", strerror(err));
	}
	tcpeek_print_pcap_status();
	gettimeofday(&g.session.timestamp, NULL);
	pfds[0].fd = pcap_fileno(g.pcap.pcap);
	pfds[0].events = POLLIN;
	while(!g.terminate) {
		if((ready = poll(pfds, sizeof(pfds) / sizeof(struct pollfd), 1000)) == -1) {
			if(errno != EINTR) {
				error_abort("%s", strerror(err));
			}
		}
		else if(ready == 0) {
			/* timeout */
		}
		else {
			if(pcap_dispatch(g.pcap.pcap, 0, tcpeek_fetch, NULL) == -1) {
				error_abort("%s", pcap_geterr(g.pcap.pcap));
			}
		}
	}
	err = pthread_join(checker, NULL);
	if(err) {
		lprintf(LOG_WARNING, "%s", strerror(err));
	}
	err = pthread_join(listener, NULL);
	if(err) {
		lprintf(LOG_WARNING, "%s", strerror(err));
	}
	tcpeek_print_summary();
}

static void
tcpeek_fetch(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *pktdata) {
	struct tcpeek_segment segment;
	uint8_t *payload;
	struct tcpeek_session *session;
	struct lnklist *stat;

	memset(&segment, 0x00, sizeof(segment));
	segment.timestamp = pkthdr->ts;
	payload = tcpeek_disassemble((uint8_t *)pktdata, (uint16_t)pkthdr->caplen, g.pcap.datalink, &segment);
	if(!payload) {
		return;
	}
	pthread_mutex_lock(&g.session.mutex);
	session = tcpeek_session_get(&segment);
	if(!session) {
		if(segment.tcp.hdr.th_flags != TH_SYN) {
			pthread_mutex_unlock(&g.session.mutex);
			return;
		}
		stat = tcpeek_filter_lookup(&segment);
		if(!stat) {
			pthread_mutex_unlock(&g.session.mutex);
			return;
		}
		session = tcpeek_session_open(&segment, stat);
		if(!session) {
			lprintf(LOG_WARNING, "%s", "session open error.");
			pthread_mutex_unlock(&g.session.mutex);
			return;
		}
	}
	if(segment.icmp_unreach) {
		session->failure = TCPEEK_SESSION_FAILURE_UNREACH;
		tcpeek_session_close(session);
		pthread_mutex_unlock(&g.session.mutex);
		return;
	}
	switch(segment.tcp.hdr.th_flags & (TH_SYN | TH_ACK | TH_RST | TH_FIN)) {
		case TH_SYN:
			tcpeek_session_recv_syn(session, &segment);
			break;
		case TH_SYN | TH_ACK:
			tcpeek_session_recv_synack(session, &segment);
			break;
		case TH_ACK:
			tcpeek_session_recv_ack(session, &segment);
			break;
		case TH_RST:
		case TH_RST | TH_ACK:
			tcpeek_session_recv_rst(session, &segment);
			break;
		default:
			break;
	}
	if(tcpeek_session_isestablished(session) || tcpeek_session_isclosed(session)) {
		tcpeek_session_close(session);
	}
	pthread_mutex_unlock(&g.session.mutex);
}

void
tcpeek_terminate(int status) {
	if(g.option.expression) {
		lnklist_destroy_with_destructor(g.option.expression, free);
	}
	if(g.pcap.pcap) {
		pcap_close(g.pcap.pcap);
	}
	if(g.session.table) {
		tcpeek_terminate_session();
	}
	if(g.filter) {
		lnklist_destroy_with_destructor(g.filter, (void (*)(void *))tcpeek_filter_destroy);
	}
	if(g.soc != -1) {
		close(g.soc);
		unlink(TCPEEK_SOCKET_FILE);
	}
	exit(status);
}

static void
tcpeek_terminate_session(void) {
	struct lnklist *keys;
	struct hashtable_key *key;
	struct tcpeek_session *session;

	keys = hashtable_get_keys(g.session.table);
	lnklist_iter_init(keys);
	while(lnklist_iter_hasnext(keys)) {
		key = lnklist_iter_remove_next(keys);
		session = hashtable_get(g.session.table, hashtable_key_get_key(key), hashtable_key_get_len(key));
		tcpeek_session_close(session);
	}
	lnklist_destroy(keys);
	hashtable_destroy(g.session.table);
}

static void
tcpeek_print_pcap_status(void) {
    lprintf(LOG_INFO, "listening on %s, link-type %s (%s), capture size %d bytes, buffer size %d MB",
		g.option.ifname,
		pcap_datalink_val_to_name(g.pcap.datalink),
		pcap_datalink_val_to_description(g.pcap.datalink),
		g.pcap.snapshot,
        g.option.buffer
	);
}

static void
tcpeek_print_summary(void) {
	struct timeval now, difftime;
	struct tm tm;
	char from[128], to[128];
	struct tcpeek_filter *filter;
	struct tcpeek_stat *stat;
    struct pcap_stat ps;

    memset(&ps, 0, sizeof(ps));
    pcap_stats(g.pcap.pcap, &ps);
	gettimeofday(&now, NULL);
	strftime(from, sizeof(from), "%Y-%m-%d %T", localtime_r(&g.session.timestamp.tv_sec, &tm));
	strftime(to, sizeof(to), "%Y-%m-%d %T", localtime_r(&now.tv_sec, &tm));
	tvsub(&now, &g.session.timestamp, &difftime);
	lprintf(LOG_INFO, "");
	lprintf(LOG_INFO, "========== TCPEEK SUMMARY ==========");
	lprintf(LOG_INFO, "     from : %s", from);
	lprintf(LOG_INFO, "       to : %s", to);
	lprintf(LOG_INFO, "     time : %9d.%03d (sec)", (int)difftime.tv_sec, (int)(difftime.tv_usec / 1000));
	lnklist_iter_init(g.filter);
	while(lnklist_iter_hasnext(g.filter)) {
		filter = lnklist_iter_next(g.filter);
		if(!(stat = filter->stat)) {
			continue;
		}
		lprintf(LOG_INFO, "------------------------------------");
		lprintf(LOG_INFO, " %s", filter->name);
		lprintf(LOG_INFO, "   Success: %d session", stat[0].success.total);
		lprintf(LOG_INFO, "     SYN Segment Duplicate : %6d", stat[0].success.dupsyn);
		lprintf(LOG_INFO, "     S/A Segment Duplicate : %6d", stat[0].success.dupsynack);
		lprintf(LOG_INFO, "   Failure: %d session", stat[0].failure.total);
		lprintf(LOG_INFO, "     Connection Timed Out  : %6d", stat[0].failure.timeout);
		lprintf(LOG_INFO, "     Connection Rejected   : %6d", stat[0].failure.reject);
		if(g.option.icmp) {
			lprintf(LOG_INFO, "     ICMP Unreachable      : %6d", stat[0].failure.unreach);
		}
	}
    lprintf(LOG_INFO, "------------------------------------");
    lprintf(LOG_INFO, " pcap stats");
    lprintf(LOG_INFO, "   recv   : %u", ps.ps_recv);
    lprintf(LOG_INFO, "   drop   : %u", ps.ps_drop);
    lprintf(LOG_INFO, "   ifdrop : %u", ps.ps_ifdrop);
	lprintf(LOG_INFO, "====================================");
}

void
tcpeek_print_segment(struct tcpeek_segment *segment, int pos, const char *msg) {
	struct tcphdr *tcphdr;
	struct ip *ip;
	char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];

	tcphdr = &segment->tcp.hdr;
	ip = &segment->tcp.ip.hdr;
	lprintf(LOG_DEBUG, "TCP/IP %s:%u %s%c%c%c%c%c%c%s %s:%u (%08X / %08X) %d | %s",
		inet_ntop(AF_INET, pos == 0 ? &ip->ip_src : &ip->ip_dst, saddr, sizeof(saddr)),
		ntohs(pos == 0 ? tcphdr->th_sport : tcphdr->th_dport),
		pos == 0 ? " " : "<",
		tcphdr->th_flags & TH_URG  ? 'U' : '-',
		tcphdr->th_flags & TH_ACK  ? 'A' : '-',
		tcphdr->th_flags & TH_PUSH ? 'P' : '-',
		tcphdr->th_flags & TH_RST  ? 'R' : '-',
		tcphdr->th_flags & TH_SYN  ? 'S' : '-',
		tcphdr->th_flags & TH_FIN  ? 'F' : '-',
		pos == 0 ? ">" : " ",
		inet_ntop(AF_INET, pos == 0 ? &ip->ip_dst : &ip->ip_src, daddr, sizeof(daddr)),
		ntohs(pos == 0 ? tcphdr->th_dport : tcphdr->th_sport),
		ntohl(tcphdr->th_seq),
		ntohl(tcphdr->th_ack),
		segment->tcp.psize,
		msg ? msg : "");
}
