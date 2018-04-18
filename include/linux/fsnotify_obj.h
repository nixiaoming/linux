/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FSNOTIFY_OBJ_H
#define _LINUX_FSNOTIFY_OBJ_H

struct fsnotify_mark_connector;

/* struct to embed in objects, which marks can be attached to */
struct fsnotify_obj {
	struct fsnotify_mark_connector __rcu *marks;
	/* all events this object cares about */
	__u32 mask;
};

#endif
