#include "tcpeek.h"

struct tcpeek_stat *
tcpeek_stat_create(void) {
	struct tcpeek_stat *stat;

	stat = malloc(sizeof(struct tcpeek_stat));
	if(stat) {
		memset(stat, 0x00, sizeof(struct tcpeek_stat));
	}
	return stat;
}

void
tcpeek_stat_destroy(struct tcpeek_stat *stat) {
	if(stat) {
		free(stat);
	}
}
