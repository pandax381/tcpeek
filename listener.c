#include "tcpeek.h"

static void
tcpeek_listener_stat_json(int soc, const char *method);

void *
tcpeek_listener_thread(void *arg) {
	struct pollfd pfds[1];
	int ready, acc;
	char method[128];

	if(listen(g.soc, SOMAXCONN) == -1) {
		lprintf(LOG_ERROR, "%s", strerror(errno));
		return NULL;
	}
	pfds[0].fd = g.soc;
	pfds[0].events = POLLIN | POLLERR;
	while(!g.terminate) {
		if((ready = poll(pfds, sizeof(pfds) / sizeof(struct pollfd), 1000)) == -1) {
			if(errno != EINTR) {
				lprintf(LOG_ERROR, "%s", strerror(errno));
				break;
			}
		}
		else if(ready == 0) {
			/* timeout */
		}
		else {
			if((acc = accept(g.soc, NULL, NULL)) == -1) {
				continue;
			}
			if(recvln(acc, method, sizeof(method), 0, NULL, 1000) != -1) {
				tcpeek_listener_stat_json(acc, strtrim(method));
			}
			close(acc);
		}
	}
	return NULL;
}

static void
tcpeek_listener_stat_json(int soc, const char *method) {
	struct tcpeek_filter *filter;
	struct tcpeek_stat *stat;
	char success[128], failure[128], buf[512];
	int isrefresh = 0, isfirst = 1;

	pthread_mutex_lock(&g.session.mutex);
	send(soc, "[", 1, 0);
	lnklist_iter_init(g.filter);
	while(lnklist_iter_hasnext(g.filter)) {
		filter = lnklist_iter_next(g.filter);
		if(!filter->stat) {
			continue;
		}
		if(strisequal(method, "REFRESH")) {
			isrefresh = 1;
		}
		stat = filter->stat;
		snprintf(success, sizeof(success), "{\"total\":%u,\"dupsyn\":%u,\"dupsynack\":%u}",
			stat[0].success.total - (isrefresh ? stat[1].success.total : 0),
			stat[0].success.dupsyn - (isrefresh ? stat[1].success.dupsyn : 0),
			stat[0].success.dupsynack - (isrefresh ? stat[1].success.dupsynack : 0)
		);
		if(strisequal(method, "REFRESH")) {
			snprintf(failure, sizeof(failure), "{\"total\":%u,\"timeout\":%u,\"reject\":%u}",
				stat[0].failure.total - (isrefresh ? stat[1].failure.total : 0),
				stat[0].failure.timeout - (isrefresh ? stat[1].failure.timeout : 0),
				(stat[0].failure.reject - (isrefresh ? stat[1].failure.reject : 0)) + (stat[0].failure.unreach - (isrefresh ? stat[1].failure.unreach : 0))
			);
		}
		else {
			snprintf(failure, sizeof(failure), "{\"total\":%u,\"timeout\":%u,\"reject\":%u, \"unreach\":%u}",
				stat[0].failure.total - (isrefresh ? stat[1].failure.total : 0),
				stat[0].failure.timeout - (isrefresh ? stat[1].failure.timeout : 0),
				stat[0].failure.reject - (isrefresh ? stat[1].failure.reject : 0),
				stat[0].failure.unreach - (isrefresh ? stat[1].failure.unreach : 0)
			);
		}
		snprintf(buf, sizeof(buf), "%s{\"%s\":{\"success\":%s,\"failure\":%s}}", isfirst ? "" : ",", filter->name, success, failure);
		send(soc, buf, strlen(buf), 0);
		if(strisequal(method, "REFRESH")) {
			memcpy(&stat[1], &stat[0], sizeof(struct tcpeek_stat));
		}
		if(isfirst) isfirst = 0;
	}
    if(!strisequal(method, "REFRESH")) {
        struct pcap_stat ps;
        memset(&ps, 0, sizeof(ps));
        pcap_stats(g.pcap.pcap, &ps);
        snprintf(buf, sizeof(buf), ",{\"pcap\":{\"stats\":{\"recv\":%u,\"drop\":%u,\"ifdrop\":%u}}}", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
        send(soc, buf, strlen(buf), 0);
    }
	send(soc, "]", 1, 0);
	pthread_mutex_unlock(&g.session.mutex);
}
