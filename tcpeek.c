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
	return 0; // does not reached.
}

void
tcpeek_signal_handler(int signo) {
	switch(signo){
		case SIGINT:
		case SIGTERM:
			if(g.pcap.pcap)
				pcap_breakloop(g.pcap.pcap); // signal safe.
			g.terminate = 1;
			break;
		case SIGPIPE:
		case SIGUSR1:
		case SIGUSR2:
		case SIGALRM:
		default:
			// ignore
			break;
	}
}

static void
tcpeek_execute(void) {
	int err, ready;
	pthread_t checker, listener;
	struct pollfd pfds[1];
	struct lnklist *keys;
	struct hashtable_key *key;
	struct tcpeek_session *session;

	err = pthread_create(&checker, NULL, tcpeek_checker_thread, NULL);
	if(err) {
		syslog(LOG_ERR, "%s: [error] %s\n", __func__, strerror(err));
		tcpeek_terminate(1);
		// does not reached.
	}
	err = pthread_create(&listener, NULL, tcpeek_listener_thread, NULL);
	if(err) {
		syslog(LOG_ERR, "%s: [error] %s\n", __func__, strerror(err));
		tcpeek_terminate(1);
		// does not reached.
	}
	tcpeek_print_pcap_status();
	gettimeofday(&g.session.timestamp, NULL);
	pfds[0].fd = pcap_fileno(g.pcap.pcap);
	pfds[0].events = POLLIN;
	while(!g.terminate) {
		ready = poll(pfds, sizeof(pfds) / sizeof(struct pollfd), 1000);
		if(ready == 0) {
			// timeout.
		}
		else if(ready == -1) {
			if(errno != EINTR) {
				syslog(LOG_ERR, "%s: [error] %s\n", __func__, strerror(errno));
				tcpeek_terminate(1);
				break; // does not reached.
			}
		}
		else {
			if(pcap_dispatch(g.pcap.pcap, 0, tcpeek_fetch, NULL) == -1) {
				syslog(LOG_ERR, "%s: [error] %s\n", __func__, pcap_geterr(g.pcap.pcap));
				tcpeek_terminate(1);
				break; // does not reached.
			}
		}
	}
	pthread_join(checker, NULL);
	pthread_join(listener, NULL);
	keys = hashtable_get_keys(g.session.table);
	lnklist_iter_init(keys);
	while(lnklist_iter_hasnext(keys)) {
		key = lnklist_iter_next(keys);
		session = hashtable_get(g.session.table, hashtable_key_get_key(key), hashtable_key_get_len(key));
		tcpeek_session_cancel(session);
	}
	lnklist_destroy(keys);
	tcpeek_print_summary();
}

static void
tcpeek_fetch(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *pktdata) {
	struct tcpeek_segment segment;
	uint8_t *payload;
	struct tcpeek_session *session;
	struct tcpeek_filter *filter;
	int err;

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
		filter = tcpeek_filter_lookup(&segment);
		if(!filter) {
			pthread_mutex_unlock(&g.session.mutex);
			return;
		}
		session = tcpeek_session_open(&segment, filter->stat);
		if(!session) {
			syslog(LOG_WARNING, "%s: [warning] %s\n", __func__, "session add error.");
			pthread_mutex_unlock(&g.session.mutex);
			return;
		}
	}
	//tcpeek_print_segment(&segment, tcpeek_session_isowner(session, &segment) ^ 0x01, "");
	switch(segment.tcp.hdr.th_flags & (TH_SYN | TH_ACK | TH_RST | TH_FIN)) {
		case TH_SYN:
			err = tcpeek_session_recv_syn(session, &segment);
			break;
		case TH_ACK:
			err = tcpeek_session_recv_ack(session, &segment);
			break;
		case TH_SYN | TH_ACK:
			err = tcpeek_session_recv_synack(session, &segment);
			break;
		case TH_FIN:
			err = tcpeek_session_recv_fin(session, &segment);
			break;
		case TH_FIN | TH_ACK:
			err = tcpeek_session_recv_finack(session, &segment);
			break;
		case TH_RST:
		case TH_RST | TH_ACK:
			err = tcpeek_session_recv_rst(session, &segment);
			break;
		default:
			//tcpeek_session_recv_error(session, &segment);
			err = 1;
			break;
	}
	tcpeek_session_add_segment(session, &segment);
	if(err) {
		session->counter.err++;
	}
	if (tcpeek_session_isclosed(session)) {
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
	if(g.stat) {
		lnklist_destroy_with_destructor(g.stat, (void (*)(void *))tcpeek_stat_destroy);
	}
	if(g.filter) {
		lnklist_destroy_with_destructor(g.filter, (void (*)(void *))tcpeek_filter_destroy);
	}
	unlink(TCPEEK_SOCKET_FILE);
	closelog();
	exit(status);
	// does not reached.
}

static void
tcpeek_terminate_session(void) {
	struct lnklist *keys;
	struct hashtable_key *key;

	keys = hashtable_get_keys(g.session.table);
	lnklist_iter_init(keys);
	while(lnklist_iter_hasnext(keys)) {
		key = lnklist_iter_remove_next(keys);
		tcpeek_session_destroy(hashtable_get(g.session.table, hashtable_key_get_key(key), hashtable_key_get_len(key)));
	}
	lnklist_destroy(keys);
	hashtable_destroy(g.session.table);
}

static void
tcpeek_print_pcap_status(void) {
	syslog(LOG_INFO, "listening on %s, link-type %s (%s), capture size %d bytes",
		g.option.ifname,
		pcap_datalink_val_to_name(g.pcap.datalink),
		pcap_datalink_val_to_description(g.pcap.datalink),
		g.pcap.snapshot
	);
}

static void
tcpeek_print_summary(void) {
	struct timeval now, difftime;
	struct tm tm;
	char from[128], to[128];
	struct tcpeek_filter *filter;
	struct tcpeek_stat *stat;
	uint64_t tmp;

	gettimeofday(&now, NULL);
	strftime(from, sizeof(from), "%Y-%m-%d %T", localtime_r(&g.session.timestamp.tv_sec, &tm));
	strftime(to, sizeof(to), "%Y-%m-%d %T", localtime_r(&now.tv_sec, &tm));
	tvsub(&now, &g.session.timestamp, &difftime);
	syslog(LOG_INFO, "====== TCPEEK SUMMARY ======");
	syslog(LOG_INFO, " from : %s", from);
	syslog(LOG_INFO, "   to : %s", to);
	syslog(LOG_INFO, " time : %3d.%03d", (int)difftime.tv_sec, (int)(difftime.tv_usec / 1000));
	lnklist_iter_init(g.filter);
	while(lnklist_iter_hasnext(g.filter)) {
		filter = lnklist_iter_next(g.filter);
		stat = filter->stat;
		if(stat->session.total - stat->session.active - stat->session.timeout > 0) {
			tmp = (stat->lifetime.total.tv_sec * 1000) + (stat->lifetime.total.tv_usec / 1000);
			tmp = tmp / (stat->session.total - stat->session.active - stat->session.timeout);
			stat->lifetime.avg.tv_sec = tmp / 1000;
			stat->lifetime.avg.tv_usec = (tmp % 1000) * 1000;
		}
		syslog(LOG_INFO, "----------------------------");
		syslog(LOG_INFO, " %s", filter->name);
		syslog(LOG_INFO, "----------------------------");
/*
		syslog(LOG_INFO, " packet");
		syslog(LOG_INFO, "              cap : %7d", stat->packet.cap);
		syslog(LOG_INFO, "              tcp : %7d", stat->packet.tcp);
		syslog(LOG_INFO, "              oos : %7d", stat->packet.oos);
		syslog(LOG_INFO, "              err : %7d", stat->packet.err);
*/
		syslog(LOG_INFO, " session");
		syslog(LOG_INFO, "            total : %7d", stat->session.total);
		syslog(LOG_INFO, "              max : %7d", stat->session.max);
		syslog(LOG_INFO, "           active : %7d", stat->session.active);
		syslog(LOG_INFO, "          timeout : %7d", stat->session.timeout);
		syslog(LOG_INFO, " lifetime");
		syslog(LOG_INFO, "              avg : %3d.%03d", (int)stat->lifetime.avg.tv_sec, (int)(stat->lifetime.avg.tv_usec / 1000));
		syslog(LOG_INFO, "              max : %3d.%03d", (int)stat->lifetime.max.tv_sec, (int)(stat->lifetime.max.tv_usec / 1000));
		syslog(LOG_INFO, " segment");
		syslog(LOG_INFO, "            total : %7d", stat->segment.total);
		syslog(LOG_INFO, "              err : %7d", stat->segment.err);
		syslog(LOG_INFO, "           dupsyn : %7d", stat->segment.dupsyn);
		syslog(LOG_INFO, "        dupsynack : %7d", stat->segment.dupsynack);
		syslog(LOG_INFO, "           dupack : %7d", stat->segment.dupack);
		syslog(LOG_INFO, "          retrans : %7d", stat->segment.retrans);
	}
	syslog(LOG_INFO, "============================");
}

void
tcpeek_print_segment(struct tcpeek_segment *segment, int pos, const char *msg) {
	struct tcphdr *tcphdr;
	struct ip *ip;
	char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];

	tcphdr = &segment->tcp.hdr;
	ip = &segment->tcp.ip.hdr;
	syslog(LOG_DEBUG, "%s: [debug] TCP/IP %s:%u %s%c%c%c%c%c%c%s %s:%u (%08X / %08X) %d | %s\n", __func__,
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
