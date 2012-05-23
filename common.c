#include "tcpeek.h"

void *
__memdup(const void *s, size_t n) {
	return memcpy(malloc(n), s, n);
}

struct timeval *
__tvsub(struct timeval *a, struct timeval *b, struct timeval *res) {
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_usec = a->tv_usec - b->tv_usec;
	if(res->tv_usec < 0) {
		res->tv_sec -= 1;
		res->tv_usec += 1000000;
	}
	return res;
}

struct timeval *
__tvadd(struct timeval *a, struct timeval *b) {
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
