#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#include <stdio.h>
#include <sys/types.h>
#include "lnklist.h"

struct hashtable;
struct hashtable_key;

extern struct hashtable *
hashtable_create(size_t capacity);
extern void
hashtable_destroy(struct hashtable *obj);
extern void *
hashtable_put(struct hashtable *obj, const void *key, size_t klen, void *value);
extern void *
hashtable_remove(struct hashtable *obj, const void *key, size_t klen);
extern void *
hashtable_get(struct hashtable *obj, const void *key, size_t klen);
extern struct lnklist *
hashtable_get_keys(struct hashtable *obj);
extern int
hashtable_isempty(struct hashtable *obj);
extern ssize_t
hashtable_size(struct hashtable *obj);
extern void
hashtable_debug_print(struct hashtable *obj, FILE *fp);
extern void *
hashtable_key_get_key(struct hashtable_key *obj);
extern ssize_t
hashtable_key_get_len(struct hashtable_key *obj);

#endif
