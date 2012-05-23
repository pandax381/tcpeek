#ifndef __LNKLIST_H__
#define __LNKLIST_H__

#include <stdio.h>
#include <sys/types.h>

struct lnklist;

extern struct lnklist *
lnklist_create(void);
extern void
lnklist_destroy(struct lnklist *obj);
extern ssize_t
lnklist_size(struct lnklist *obj);
extern void *
lnklist_add(struct lnklist *obj, void *data, int index);
extern void *
lnklist_remove(struct lnklist *obj, int index);
extern void *
lnklist_get(struct lnklist *obj, int index);
extern void
lnklist_iter_init(struct lnklist *obj);
extern int
lnklist_iter_hasnext(struct lnklist *obj);
extern void *
lnklist_iter_next(struct lnklist *obj);
extern void *
lnklist_iter_remove(struct lnklist *obj);
extern void *
lnklist_iter_remove_next(struct lnklist *obj);

#endif
