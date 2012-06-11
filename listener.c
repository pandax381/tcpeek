#include "tcpeek.h"

static void
tcpeek_listener_stat_json(int soc, const char *method);

void *
tcpeek_listener_thread(void *arg) {
	struct pollfd pfds[1];
	int ready, acc;
	char method[128];

	listen(g.soc, SOMAXCONN);
	pfds[0].fd = g.soc;
	pfds[0].events = POLLIN | POLLERR;
	while(!g.terminate) {
		ready = poll(pfds, sizeof(pfds) / sizeof(struct pollfd), 1000);
		if(ready == 0) {
			// timeout.
		}
		else if(ready == -1) {
			if(errno != EINTR) {
				break;
			}
		}
		else {
			acc = accept(g.soc, NULL, NULL);
			if(acc == -1) {
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
	uint64_t tmp;
	char session[128], lifetime[128], segment[128], buf[512];
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
		if(stat->session.total - stat->session.active - stat->session.timeout > 0) {
			tmp = (stat->lifetime.total.tv_sec * 1000) + (stat->lifetime.total.tv_usec / 1000);
			tmp = tmp / (stat->session.total - stat->session.active - stat->session.timeout);
			stat->lifetime.avg.tv_sec = tmp / 1000;
			stat->lifetime.avg.tv_usec = (tmp % 1000) * 1000;
		}
		snprintf(session, sizeof(session), "{\"total\":%u,\"max\":%u,\"active\":%u,\"timeout\":%u,\"cancel\":%u}",
			stat->session.total,
			stat->session.max,
			stat->session.active,
			stat->session.timeout,
			stat->session.cancel
		);
		snprintf(lifetime, sizeof(lifetime), "{\"total\":%lu,\"avg\":%lu,\"max\":%lu}",
			(stat->lifetime.total.tv_sec * 1000) + (stat->lifetime.total.tv_usec / 1000),
			(stat->lifetime.avg.tv_sec * 1000) + (stat->lifetime.avg.tv_usec / 1000),
			(stat->lifetime.max.tv_sec * 1000) + (stat->lifetime.max.tv_usec / 1000)
		);
		snprintf(segment, sizeof(segment), "{\"total\":%u,\"err\":%u,\"dupsyn\":%u,\"dupsynack\":%u,\"dupack\":%u,\"retrans\":%u}",
			stat->segment.total,
			stat->segment.err,
			stat->segment.dupsyn,
			stat->segment.dupsynack,
			stat->segment.dupack,
			stat->segment.retrans
		);
		snprintf(buf, sizeof(buf), "%s{\"%s\":{\"session\":%s,\"lifetime\":%s,\"segment\":%s}}",
			isfirst ? "" : ",", filter->name, session, lifetime, segment
		);
		send(soc, buf, strlen(buf), 0);
		if(strisequal(method, "REFRESH")) {
			memset(stat, 0x00, sizeof(struct tcpeek_stat));
			stat->session.active = filter->stat[0].session.active; 
		}
		if(isfirst) isfirst = 0;
	}
	send(soc, "]", 1, 0);
	pthread_mutex_unlock(&g.session.mutex);
}
