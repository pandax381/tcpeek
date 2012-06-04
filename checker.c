#include "tcpeek.h"

void *
tcpeek_checker_thread(void *arg) {
	struct timespec ts = {TCPEEK_CHECKER_INTERVAL_SEC, 0};
	struct lnklist *keys;
	struct hashtable_key *key;
	struct tcpeek_session *session;

	while(!g.terminate) {
		nanosleep(&ts, NULL);
		pthread_mutex_lock(&g.session.mutex);
		keys = hashtable_get_keys(g.session.table);
		lnklist_iter_init(keys);
		while(lnklist_iter_hasnext(keys)) {
			key = lnklist_iter_next(keys);
			session = hashtable_get(g.session.table, hashtable_key_get_key(key), hashtable_key_get_len(key));
			if(tcpeek_session_istimeout(session)) {
				tcpeek_session_timeout(session);
			}
		}
		lnklist_destroy(keys);
		pthread_mutex_unlock(&g.session.mutex);
	}
	return NULL;
}
