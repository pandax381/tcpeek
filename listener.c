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
	char session[128], buf[512];
	int isfirst = 1;

	pthread_mutex_lock(&g.session.mutex);
	send(soc, "[", 1, 0);
	lnklist_iter_init(g.filter);
	while(lnklist_iter_hasnext(g.filter)) {
		filter = lnklist_iter_next(g.filter);
		if(!filter->stat) {
			continue;
		}
		stat = strisequal(method, "REFRESH") ? &filter->stat[1]: &filter->stat[0];
		snprintf(session, sizeof(session), "{\"total\":%u,\"dupsyn\":%u,\"dupsynack\":%u,\"dupack\":%u}", stat->total, stat->dupsyn, stat->dupsynack, stat->dupack);
		snprintf(buf, sizeof(buf), "%s{\"%s\":%s}", isfirst ? "" : ",", filter->name, session);
		send(soc, buf, strlen(buf), 0);
		if(strisequal(method, "REFRESH")) {
			memset(stat, 0x00, sizeof(struct tcpeek_stat));
		}
		if(isfirst) isfirst = 0;
	}
	send(soc, "]", 1, 0);
	pthread_mutex_unlock(&g.session.mutex);
}
