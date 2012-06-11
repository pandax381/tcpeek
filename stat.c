#include "tcpeek.h"

struct tcpeek_stat *
tcpeek_stat_create(void) {
	struct tcpeek_stat *stat;

	stat = malloc(sizeof(struct tcpeek_stat) * 2);
	if(stat) {
		memset(stat, 0x00, sizeof(struct tcpeek_stat) * 2);
	}
	return stat;
}

void
tcpeek_stat_destroy(struct tcpeek_stat *stat) {
	if(stat) {
		free(stat);
	}
}

void
tcpeek_stat_session_open(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;

	lnklist_iter_init(session->stat);
	while(lnklist_iter_hasnext(session->stat)) {
		stat = lnklist_iter_next(session->stat);
		stat[0].session.total++;
		stat[1].session.total++;
		stat[0].session.active++;
		stat[1].session.active++;
		if(stat[0].session.active > stat[0].session.max) {
			stat[0].session.max = stat[0].session.active;
		}
		if(stat[1].session.active > stat[1].session.max) {
			stat[1].session.max = stat[1].session.active;
		}
	}
}

void
tcpeek_stat_session_close(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;
	struct timeval difftime;

	if(session->reason == TCPEEK_SESSION_REASON_TIMEOUT) {
		lnklist_iter_init(session->stat);
		while(lnklist_iter_hasnext(session->stat)) {
			stat = lnklist_iter_next(session->stat);
			stat[0].session.timeout++;
			stat[1].session.timeout++;
			stat[0].session.active--;
			stat[1].session.active--;
		}
	}
	else if(session->reason == TCPEEK_SESSION_REASON_CANCEL) {
		lnklist_iter_init(session->stat);
		while(lnklist_iter_hasnext(session->stat)) {
			stat = lnklist_iter_next(session->stat);
			stat[0].session.cancel++;
			stat[1].session.cancel++;
			stat[0].session.active--;
			stat[1].session.active--;
		}
	}
	else {
		tvsub(&session->sequence.timestamp[1], &session->sequence.timestamp[0], &difftime);
		lnklist_iter_init(session->stat);
		while(lnklist_iter_hasnext(session->stat)) {
			stat = lnklist_iter_next(session->stat);
			stat[0].session.active--;
			stat[1].session.active--;
			if(stat[0].lifetime.max.tv_sec < difftime.tv_sec || (stat[0].lifetime.max.tv_sec == difftime.tv_sec && stat[0].lifetime.max.tv_usec < difftime.tv_usec)) {
				stat[0].lifetime.max = difftime;
			}
			tvadd(&stat[0].lifetime.total, &difftime);
			if(stat[1].lifetime.max.tv_sec < difftime.tv_sec || (stat[1].lifetime.max.tv_sec == difftime.tv_sec && stat[1].lifetime.max.tv_usec < difftime.tv_usec)) {
				stat[1].lifetime.max = difftime;
			}
			tvadd(&stat[1].lifetime.total, &difftime);
		}
	}
}

void
tcpeek_stat_segment_add(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;

	lnklist_iter_init(session->stat);
	while(lnklist_iter_hasnext(session->stat)) {
		stat = lnklist_iter_next(session->stat);
		stat[0].segment.total++;
		stat[1].segment.total++;
	}
}

void
tcpeek_stat_segment_dupsyn(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;

	lnklist_iter_init(session->stat);
	while(lnklist_iter_hasnext(session->stat)) {
		stat = lnklist_iter_next(session->stat);
		stat[0].segment.dupsyn++;
		stat[1].segment.dupsyn++;
	}
	session->counter.dupsyn++;
}

void
tcpeek_stat_segment_dupsynack(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;

	lnklist_iter_init(session->stat);
	while(lnklist_iter_hasnext(session->stat)) {
		stat = lnklist_iter_next(session->stat);
		stat[0].segment.dupsynack++;
		stat[1].segment.dupsynack++;
	}
	session->counter.dupsynack++;
}

void
tcpeek_stat_segment_dupack(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;

	lnklist_iter_init(session->stat);
	while(lnklist_iter_hasnext(session->stat)) {
		stat = lnklist_iter_next(session->stat);
		stat[0].segment.dupack++;
		stat[1].segment.dupack++;
	}
	session->counter.dupack++;
}

void
tcpeek_stat_segment_retrans(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;

	lnklist_iter_init(session->stat);
	while(lnklist_iter_hasnext(session->stat)) {
		stat = lnklist_iter_next(session->stat);
		stat[0].segment.retrans++;
		stat[1].segment.retrans++;
	}
	session->counter.retrans++;
}

void
tcpeek_stat_segment_rst(struct tcpeek_session *session) {
	session->counter.rst++;
}

void
tcpeek_stat_segment_err(struct tcpeek_session *session) {
	struct tcpeek_stat *stat;

	lnklist_iter_init(session->stat);
	while(lnklist_iter_hasnext(session->stat)) {
		stat = lnklist_iter_next(session->stat);
		stat[0].segment.err++;
		stat[1].segment.err++;
	}
	session->counter.err++;
}
