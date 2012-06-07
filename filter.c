#include "tcpeek.h"

static int
tcpeek_filter_parse_rule(struct tcpeek_filter_rule *rule, const char *expression);
static uint32_t
getnwaddr(uint32_t addr, uint8_t prefix);

struct tcpeek_filter *
tcpeek_filter_create(void) {
	struct tcpeek_filter *filter;

	filter = malloc(sizeof(struct tcpeek_filter));
	if(filter) {
		memset(filter, 0x00, sizeof(struct tcpeek_filter));
		filter->rule = lnklist_create();
		if(!filter->rule) {
			free(filter);
			return NULL;
		}
	}
	return filter;
}

void
tcpeek_filter_destroy(struct tcpeek_filter *filter) {
	if(filter) {
		lnklist_destroy_with_destructor(filter->rule, (void (*)(void *))tcpeek_filter_rule_destroy);
		free(filter);
	}
}

struct tcpeek_filter_rule *
tcpeek_filter_rule_create(void) {
	struct tcpeek_filter_rule *rule;

	rule = malloc(sizeof(struct tcpeek_filter_rule));
	if(rule) {
		memset(rule, 0x00, sizeof(struct tcpeek_filter_rule));
		rule->port = lnklist_create();
		if(!rule->port) {
			free(rule);
			return NULL;
		}
	}
	return rule;
}

void
tcpeek_filter_rule_destroy(struct tcpeek_filter_rule *rule) {
	if(rule) {
		lnklist_destroy_with_destructor(rule->port, free);
		free(rule);
	}
}

int
tcpeek_filter_parse(struct tcpeek_filter *filter, const char *expression) {
	char *sp, *ep;
	struct lnklist *list;
	struct tcpeek_filter_rule *rule;

	sp = (char *)expression;
	if(!(ep = strchr(sp, ':')) || ep == sp) {
		return -1;
	}
	strncpy(filter->name, sp, ep - sp);
	sp = ep + 1;
	if(!(ep = strchr(sp, '@')) || ep == sp) {
		return -1;
	}
	if(strncmp(sp, "IN", 2) == 0) {
		filter->dir = TCPEEK_FILTER_DIR_INBOUND;
	}
	else if(strncmp(sp, "OUT", 3) == 0) {
		filter->dir = TCPEEK_FILTER_DIR_OUTBOUND;
	}
	else {
		return -1;
	}
	sp = ep + 1; 
	list = strsplit(sp, ",", 0);
	if(lnklist_size(list) < 1) {
		lnklist_destroy_with_destructor(list, free);
		return -1;
	} 
	lnklist_iter_init(list);
	while(lnklist_iter_hasnext(list)) {
		rule = tcpeek_filter_rule_create();
		if(tcpeek_filter_parse_rule(rule, lnklist_iter_next(list)) == -1) {
			tcpeek_filter_rule_destroy(rule);
			lnklist_destroy_with_destructor(list, free);
			return -1;
		}
		if(!lnklist_add_tail(filter->rule, rule)) {
			tcpeek_filter_rule_destroy(rule);
			lnklist_destroy_with_destructor(list, free);
			return -1;
		}
	}
	lnklist_destroy_with_destructor(list, free);
	return 0;
}

static int
tcpeek_filter_parse_rule(struct tcpeek_filter_rule *rule, const char *expression) {
	struct lnklist *list;
	char *prefix, *addr, *port;
	uint16_t portno;

	list = strsplit(expression, ":", 0);
	if(lnklist_size(list) < 2) {
		lnklist_destroy(list);
		return -1;
	}
	lnklist_iter_init(list);
	addr = lnklist_iter_next(list);
	if(strisequal(addr, "*")) {
		rule->addr.s_addr = htonl(INADDR_ANY);
	}
	else {
		if((prefix = strchr(addr, '/'))) {
			*(prefix++) = '\0';
			if(strisdigit(prefix) == 0) {
				lnklist_destroy_with_destructor(list, free);
				return -1;
			}
			rule->prefix = (uint8_t)strtol(prefix, NULL, 10);
			if(rule->prefix > 32) {
				lnklist_destroy_with_destructor(list, free);
				return -1;
			}
		}
		else {
			rule->prefix = 32;
		}
		if(inet_pton(AF_INET, addr, &rule->addr) != 1) {
			lnklist_destroy_with_destructor(list, free);
			return -1;
		}
fprintf(stderr, "%s/%u\n", inet_ntoa(rule->addr), rule->prefix);
	}
	while(lnklist_iter_hasnext(list)) {
		port = lnklist_iter_next(list);
		if(strisequal(port, "*")) {
			portno = 0;
		}
		else {
			if(strisdigit(port) == 0) {
				lnklist_destroy_with_destructor(list, free);
				return -1;
			}
			portno = htons((uint16_t)strtol(port, NULL, 10));
		}
		if(!lnklist_add_tail(rule->port, memdup(&portno, sizeof(portno)))) {
			lnklist_destroy_with_destructor(list, free);
			return -1;
		}
	}
	lnklist_destroy_with_destructor(list, free);
	return 0;
}

struct tcpeek_filter *
tcpeek_filter_lookup(struct tcpeek_segment *segment) {
	struct tcpeek_filter *filter;
	struct tcpeek_filter_rule *rule;
	uint16_t *port;

	lnklist_iter_init(g.filter);
	while(lnklist_iter_hasnext(g.filter)) {
		filter = lnklist_iter_next(g.filter);
		lnklist_iter_init(filter->rule);
		while(lnklist_iter_hasnext(filter->rule)) {
			rule = lnklist_iter_next(filter->rule);
			if(filter->dir == TCPEEK_FILTER_DIR_INBOUND) {
				if(segment->tcp.ip.hdr.ip_dst.s_addr != g.addr.unicast.s_addr) {
					continue;
				}
				if(rule->addr.s_addr != htonl(INADDR_ANY) && getnwaddr(segment->tcp.ip.hdr.ip_src.s_addr, rule->prefix) != rule->addr.s_addr) {
					continue;
				}
			}
			else {
				if(segment->tcp.ip.hdr.ip_src.s_addr != g.addr.unicast.s_addr) {
					continue;
				}
				if(rule->addr.s_addr != htonl(INADDR_ANY) && getnwaddr(segment->tcp.ip.hdr.ip_dst.s_addr, rule->prefix) != rule->addr.s_addr) {
					continue;
				}
			}
			lnklist_iter_init(rule->port);
			while(lnklist_iter_hasnext(rule->port)) {
				port = lnklist_iter_next(rule->port);
				if(*port == 0 || *port == segment->tcp.hdr.th_dport) {
					return filter;
				}
			}
		}
	}
	return NULL;
}

static uint32_t
getnwaddr(uint32_t addr, uint8_t prefix) {
	return htonl(ntohl(addr) & (uint32_t)0xffffffff << (32 - prefix));
}
