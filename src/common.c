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
			lnklist_destroy_with_destructor(dst, free);
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
	void *dst;

	return (dst = malloc(n)) ? memcpy(dst, s, n) : NULL;
}

#if !defined(__USE_XOPEN2K8) && !defined(__USE_GNU)
char *
strndup(const char *s1, size_t n) {
	char *dst;
	dst = malloc(n + 1);
	if(dst) {
		strncpy(dst, s1, n);
		dst[n] = 0x00;
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

ssize_t
recvsz(int socket, void *buffer, size_t length, int flags, int timeout) {
	struct pollfd pfd[1];
	size_t done = 0;
	int ready, ret;

	pfd[0].fd = socket;
	pfd[0].events = POLLIN;
	while(done < length) {
		ready = poll(pfd, sizeof(pfd) / sizeof(struct pollfd), timeout);
		if(ready == -1) {
			if(errno != EINTR) {
				return -1;
			}
		}
		else if(ready == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		else {
			ret = recv(socket, (caddr_t)buffer + done, length - done, flags);
			if(ret == -1) {
				if(errno != EINTR) {
					return -1;
				}
			}
			else if(ret == 0) {
				break;
			}
			else {
				done += ret;
			}
		}
	}
	return done;
}

ssize_t
recvln(int socket, char *buffer, size_t length, int flags, int *fin, int timeout) {
	size_t done = 0;
	ssize_t ret;

	while(done < length - 1) {
		ret = recvsz(socket, buffer + done, sizeof(char), flags, timeout);
		if(ret == -1) {
			if(errno != EINTR) {
				return -1;
			}
		}
		else if(ret == 0) {   
			if(fin) {
				*fin = 1;
			}
			break;
		}
		else {
			if(++done >= 2 && buffer[done - 1] == 0x0a && buffer[done - 2] == 0x0d) {
				break;
			}
		}
	}
	buffer[done] = 0x00;
	return done;
}
