#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

struct hashtable_key {
        size_t len;
        void *key;
};

struct hashtable_entry {
        struct hashtable_key key;
        void *value;
};

struct hashtable {
        size_t capacity;
        size_t num;
        struct lnklist **rows;
};

static struct hashtable_entry *
hashtable_entry_create(void);
static void *
hashtable_entry_destroy(struct hashtable_entry *obj);
static void *
hashtable_entry_set(struct hashtable_entry *obj, const void *key, size_t klen, void *value);
static void *
hashtable_entry_get_value(struct hashtable_entry *obj);
static int
hashtable_entry_isequal_key(struct hashtable_entry *obj, const void *key, size_t klen);
static unsigned int
hash(const void *key, size_t klen, size_t threshold);

extern void *
memdup(const void *s, size_t n);

#ifdef __HASHTABLE_DEBUG__
int
main(int argc, char *argv[]) {
	struct hashtable *ht;
	int count;
	char buf[128];
	struct lnklist *keys;
	struct lnklist_key *key;

	ht = hashtable_create(1000);
	if(!ht) {
		fprintf(stderr, "hashtable_create(): error.\n");
		return -1;
	}
	for(count = 0; count < 100000; count++) {
		snprintf(buf, sizeof(buf), "%d", count);
		hashtable_put(ht, &count, sizeof(count), strdup(buf));
	}
	fprintf(stderr, "### hashtable_size(): %d\n", hashtable_size(ht));
	hashtable_debug_print(ht, stderr);
	keys = hashtable_get_keys(ht);
	lnklist_iter_init(keys);
	while(lnklist_iter_hasnext(keys)) {
		key = lnklist_iter_next(keys);
		free(hashtable_remove(ht, hashtable_key_get_key(key), hashtable_key_get_len(key)));
	}
	lnklist_destroy(keys);
	fprintf(stderr, "### hashtable_size(): %d\n", hashtable_size(ht));
	hashtable_debug_print(ht, stderr);
	hashtable_destroy(ht);
	return  0;
}
#endif

struct hashtable *
hashtable_create(size_t capacity) {
	struct hashtable *obj;
	size_t index;

	obj = (struct hashtable *)malloc(sizeof(struct hashtable));
	if(!obj) {
		return NULL;
	}
	obj->capacity = capacity;
	obj->num = 0;
	obj->rows = (struct lnklist **)malloc(obj->capacity * sizeof(struct lnklist *));
	if(!obj->rows) {
		free(obj);
		return NULL;
	}
	for(index = 0; index < obj->capacity; index++) {
		obj->rows[index] = NULL;
	}
	return obj;
}

void
hashtable_destroy(struct hashtable *obj) {
	size_t index;
	struct lnklist *row;

	if(!obj) {
		return;
	}
	for(index = 0; index < obj->capacity; index++) {
		row = obj->rows[index];
		while(lnklist_size(row) > 0) {
			hashtable_entry_destroy(lnklist_remove(row, 0));
		}
		lnklist_destroy(row);
	}
	free(obj->rows);
	free(obj);
}

void *
hashtable_put(struct hashtable *obj, const void *key, size_t klen, void *value) {
	unsigned int index;
	struct lnklist *row;
	struct hashtable_entry *entry;

	if(!obj || !key || !klen) {
		return NULL;
	}
	index = hash(key, klen, obj->capacity);
	row = obj->rows[index];
	if(!row) {
		row = obj->rows[index] = lnklist_create();
		if(!row) {
			return NULL;
		}
	}
	else {
		lnklist_iter_init(row);
		while(lnklist_iter_hasnext(row)) {
			entry = (struct hashtable_entry *)lnklist_iter_next(row);
			if(hashtable_entry_isequal_key(entry, key, klen)) {
				return NULL;
			}
		}
	}
	entry = hashtable_entry_create();
	if(!entry) {
		return NULL;
	}
	hashtable_entry_set(entry, key, klen, value);
	lnklist_add_tail(row, entry);
	obj->num++;
	return value;
}


void *
hashtable_remove(struct hashtable *obj, const void *key, size_t klen) {
	unsigned int index;
	struct lnklist *row;
	void *value = NULL;
	struct hashtable_entry *entry;

	if(!obj || !key || !klen) {
		return NULL;
	}
	index = hash(key, klen, obj->capacity);
	row = obj->rows[index];
	lnklist_iter_init(row);
	while(lnklist_iter_hasnext(row)) {
		entry = (struct hashtable_entry *)lnklist_iter_next(row);
		if(hashtable_entry_isequal_key(entry, key, klen)) {
			value = hashtable_entry_destroy(lnklist_iter_remove(row));
			obj->num--;
			break;
		}
	}
	return value;
}

void *
hashtable_get(struct hashtable *obj, const void *key, size_t klen) {
	unsigned int index;
	struct lnklist *row;
	void *value = NULL;
	struct hashtable_entry *entry;

	if(!obj || !key || !klen) {
		return NULL;
	}
	index = hash(key, klen, obj->capacity);
	row = obj->rows[index];
	lnklist_iter_init(row);
	while(lnklist_iter_hasnext(row)) {
		entry = (struct hashtable_entry *)lnklist_iter_next(row);
		if(hashtable_entry_isequal_key(entry, key, klen)) {
			value = hashtable_entry_get_value(entry);
			break;
		}
	}
	return value;
}

struct lnklist *
hashtable_get_keys(struct hashtable *obj) {
	struct lnklist *keys, *row;
	size_t index;
	struct hashtable_entry *entry;

	if(!obj) {
		return NULL;
	}
	keys = lnklist_create();
	for(index = 0; index < obj->capacity; index++) {
		row = obj->rows[index];
		lnklist_iter_init(row);
		while(lnklist_iter_hasnext(row)) {
			entry = (struct hashtable_entry *)lnklist_iter_next(row);
			lnklist_add_tail(keys, &entry->key);
		}
	}
	return keys;
}

int
hashtable_isempty(struct hashtable *obj) {
	return obj ? (obj->num > 0 ? 0 : 1) : -1;
}

ssize_t
hashtable_size(struct hashtable *obj) {
	return obj ? (ssize_t)obj->num : -1;
}

void
hashtable_debug_print(struct hashtable *obj, FILE *fp) {
	size_t index;
	struct lnklist *row;

	if(!fp || !obj) {
		return;
	}
	for(index = 0; index < obj->capacity; index++) {
		row = obj->rows[index];
		fprintf(fp, "hashtable[%zd]: %zd\n", index, row ? lnklist_size(row) : 0);
	}
}

static struct hashtable_entry *
hashtable_entry_create(void) {
	struct hashtable_entry *obj;

	obj = (struct hashtable_entry *)malloc(sizeof(struct hashtable_entry));
	if(obj) {
		obj->key.len = 0;
		obj->key.key = NULL;
		obj->value = NULL;
	}
	return obj;
}

static void *
hashtable_entry_destroy(struct hashtable_entry *obj) {
	void *value = NULL;

	if(obj) {
		free(obj->key.key);
		value = obj->value;
		free(obj);
	}
	return value;
}

static void *
hashtable_entry_set(struct hashtable_entry *obj, const void *key, size_t klen, void *value) {
	void *old_value;

	if(!obj || !key || !klen) {
		return NULL;
	}
	obj->key.len = klen;
	free(obj->key.key);
	obj->key.key = memdup(key, klen);
	if(obj->value) {
		old_value = obj->value;
	}
	obj->value = value;
	return old_value;
}

static void *
hashtable_entry_get_value(struct hashtable_entry *obj) {
	return obj ? obj->value : NULL;
}

static int
hashtable_entry_isequal_key(struct hashtable_entry *obj, const void *key, size_t klen) {
	return (obj && obj->key.len == klen && memcmp(obj->key.key, key, klen) == 0) ? 1 : 0;
}

void *
hashtable_key_get_key(struct hashtable_key *obj) {
	return obj ? obj->key : NULL;
}

ssize_t
hashtable_key_get_len(struct hashtable_key *obj) {
	return obj ? (ssize_t)obj->len : -1;
}

static unsigned int
hash(const void *key, size_t klen, size_t threshold) {
	size_t index;
	unsigned int h = 0;

	for(index = 0; index < klen; index++) {
		h = (h * 137) + ((unsigned char *)key)[index];
	}
	return h % threshold;
}
