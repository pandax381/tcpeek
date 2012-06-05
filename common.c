#include "tcpeek.h"

int
strisempty(const char *str) {
	return (!str || str[0] == '\0') ? 1 : 0;
}

int
strisequal(const char *str1, const char *str2) {
	return (str1 && str2) ? ((strcmp(str1, str2) == 0) ? 1 : 0) : 0;
}

char *
strtrim(char *str) {
	char *sp, *ep;

	if(!str) {
		return NULL;
	}
	for(sp = str; *sp; sp++) {
		if(!isspace(*sp)) {
			break;
		}
	}
	for(ep = (str + strlen(str)); ep > sp; ep--) {
		if(!isspace(*(ep - 1))) {
			break;
		}
	}
	memmove(str, sp, ep - sp);
	str[ep - sp] = '\0';
	return str;
}

int
strisdigit(const char *str) {
	if(strisempty(str)) {
		return 0;
	}
	while(*str) {
		if(!isdigit(*(str++))) {
			return 0;
		}
	}
	return 1;
}

struct lnklist *
strsplit(const char *str, const char *sep, size_t num) {
	struct lnklist *dst;
	int seplen, count;
	char *sp, *ep, *piece;

	if(strisempty(str) || strisempty(sep)) {
		return NULL;
	}
	dst = lnklist_create();
	if(!dst) {
		return NULL;
	}
	sp = (char *)str;
	seplen = strlen(sep);
	for(count = 0; count < (int)num || num == 0; count++) {
		ep = strstr(sp, sep);
		piece = ep ? strndup(sp, ep - sp) : strdup(sp);
		if(!piece || !lnklist_add_tail(dst, piece)) {
			free(piece);
			lnklist_iter_init(dst);
			while(lnklist_iter_hasnext(dst)) {
				free(lnklist_iter_remove_next(dst));
			}
			lnklist_destroy(dst);
			return NULL;
		}
		if(!ep) {
			break;
		}
		sp = ep + seplen;
	}
	return dst;
}

void *
memdup(const void *s, size_t n) {
	return memcpy(malloc(n), s, n);
}

#ifndef HAVE_STRNDUP
char *
strndup(const char *s1, size_t n) {
	char *dst;

	dst = malloc(n + 1);
	if(dst) {
		strncpy(dst, s1, n);
	}
	return dst;
}
#endif

struct timeval *
tvsub(struct timeval *a, struct timeval *b, struct timeval *res) {
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_usec = a->tv_usec - b->tv_usec;
	if(res->tv_usec < 0) {
		res->tv_sec -= 1;
		res->tv_usec += 1000000;
	}
	return res;
}

struct timeval *
tvadd(struct timeval *a, struct timeval *b) {
	a->tv_sec += b->tv_sec;
	if(a->tv_usec + b->tv_usec >= 1000000) {
		a->tv_sec++;
		a->tv_usec = a->tv_usec + b->tv_usec - 1000000;
	}
	else {
		a->tv_usec = a->tv_usec + b->tv_usec;
	}
	return a;
}
