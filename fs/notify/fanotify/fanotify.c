#include <linux/fanotify.h>
#include <linux/fdtable.h>
#include <linux/fsnotify_backend.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h> /* UINT_MAX */
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "fanotify.h"

static bool should_merge(struct fsnotify_event *old_fsn,
			 struct fsnotify_event *new_fsn)
{
	struct fanotify_event_info *old, *new;

	pr_debug("%s: old=%p new=%p\n", __func__, old_fsn, new_fsn);
	old = FANOTIFY_E(old_fsn);
	new = FANOTIFY_E(new_fsn);

	/*
	 * Don't merge with a filename event
	 */
	if (old_fsn->mask & FAN_FILENAME_EVENTS)
		return 0;

	if (old_fsn->inode == new_fsn->inode && old->tgid == new->tgid &&
	    old->path.mnt == new->path.mnt &&
	    old->path.dentry == new->path.dentry)
		return true;
	return false;
}

/* and the list better be locked by something too! */
static int fanotify_merge(struct list_head *list, struct fsnotify_event *event)
{
	struct fsnotify_event *test_event;
	bool do_merge = false;

	pr_debug("%s: list=%p event=%p\n", __func__, list, event);

#ifdef CONFIG_FANOTIFY_ACCESS_PERMISSIONS
	/*
	 * Don't merge a permission event with any other event so that we know
	 * the event structure we have created in fanotify_handle_event() is the
	 * one we should check for permission response.
	 */
	if (event->mask & FAN_ALL_PERM_EVENTS)
		return 0;
#endif

	/*
	 * Don't merge a filename event with any other event
	 */
	if (event->mask & FAN_FILENAME_EVENTS)
		return 0;

	list_for_each_entry_reverse(test_event, list, list) {
		if (should_merge(test_event, event)) {
			do_merge = true;
			break;
		}
	}

	if (!do_merge)
		return 0;

	test_event->mask |= event->mask;
	return 1;
}

#ifdef CONFIG_FANOTIFY_ACCESS_PERMISSIONS
static int fanotify_get_response(struct fsnotify_group *group,
				 struct fanotify_perm_event_info *event)
{
	int ret;

	pr_debug("%s: group=%p event=%p\n", __func__, group, event);

	wait_event(group->fanotify_data.access_waitq, event->response);

	/* userspace responded, convert to something usable */
	switch (event->response) {
	case FAN_ALLOW:
		ret = 0;
		break;
	case FAN_DENY:
	default:
		ret = -EPERM;
	}
	event->response = 0;

	pr_debug("%s: group=%p event=%p about to return ret=%d\n", __func__,
		 group, event, ret);
	
	return ret;
}
#endif

static bool fanotify_should_send_event(struct fsnotify_mark *inode_mark,
				       struct fsnotify_mark *vfsmnt_mark,
				       u32 event_mask, struct path *path,
				       void *data, int data_type)
{
	__u32 marks_mask, marks_ignored_mask;
	struct vfsmount *mnt;
	struct dentry *dentry;

	mnt = inode_mark ? inode_mark->mnt : vfsmnt_mark->mnt;
	pr_debug("%s: inode_mark=%p vfsmnt_mark=%p mnt=%p mask=%x data=%p"
		 " data_type=%d\n", __func__, inode_mark, vfsmnt_mark,
		 mnt, event_mask, data, data_type);

	if (data_type == FSNOTIFY_EVENT_PATH) {
		if (!mnt)
			mnt = ((struct path *)data)->mnt;
		else if (mnt != ((struct path *)data)->mnt)
			return false;
		dentry = ((struct path *)data)->dentry;
	} else if (data_type == FSNOTIFY_EVENT_DENTRY) {
		dentry = (struct dentry *)data;
	} else
		return false;

	pr_debug("%s: dentry=%p inode=%p d_flags=%x\n", __func__,
		 dentry, dentry->d_inode, dentry->d_flags);

	if (WARN_ON(dentry->d_sb != mnt->mnt_sb))
		return false;

	if (WARN_ON(d_is_negative(dentry) || d_really_is_negative(dentry)))
		return false;

	/* sorry, fanotify only gives a damn about files and dirs */
	if (!d_is_reg(dentry) && !d_can_lookup(dentry))
		return false;

	if (inode_mark && vfsmnt_mark) {
		marks_mask = (vfsmnt_mark->mask | inode_mark->mask);
		marks_ignored_mask = (vfsmnt_mark->ignored_mask | inode_mark->ignored_mask);
	} else if (inode_mark) {
		/*
		 * if the event is for a child and this inode doesn't care about
		 * events on the child, don't send it!
		 */
		if ((event_mask & FS_EVENT_ON_CHILD) &&
		    !(inode_mark->mask & FS_EVENT_ON_CHILD))
			return false;
		marks_mask = inode_mark->mask;
		marks_ignored_mask = inode_mark->ignored_mask;
	} else if (vfsmnt_mark) {
		marks_mask = vfsmnt_mark->mask;
		marks_ignored_mask = vfsmnt_mark->ignored_mask;
	} else {
		BUG();
	}

	if (d_is_dir(dentry) &&
	    !(marks_mask & FS_ISDIR & ~marks_ignored_mask))
		return false;

	if (!(event_mask & FAN_ALL_OUTGOING_EVENTS & marks_mask &
	      ~marks_ignored_mask))
		return false;

	/*
	 * Only interesetd in dentry events visible from the mount
	 * from which the root watch was added
	 */
	if (mnt->mnt_root != dentry &&
	    d_ancestor(mnt->mnt_root, dentry) == NULL)
		return false;

	path->dentry = dentry;
	path->mnt = mnt;
	return true;
}

struct fanotify_event_info *fanotify_alloc_event(struct fsnotify_group *group,
						 struct inode *inode, u32 mask,
						 struct path *path,
						 const char *file_name)
{
	struct fanotify_event_info *event;

#ifdef CONFIG_FANOTIFY_ACCESS_PERMISSIONS
	if (mask & FAN_ALL_PERM_EVENTS) {
		struct fanotify_perm_event_info *pevent;

		pevent = kmem_cache_alloc(fanotify_perm_event_cachep,
					  GFP_KERNEL);
		if (!pevent)
			return NULL;
		event = &pevent->fae;
		pevent->response = 0;
		goto init;
	}
#endif

	/*
	 * For filename events (create,delete,rename) and when reporting
	 * file ids to root sb inode, we need to allocate a variable
	 * length fanotify_file_event_info struct.
	 */
	if (mask & FAN_FILEINFO_EVENTS) {
		struct fanotify_file_event_info *ffe;
		int alloc_len = sizeof(*ffe);
		int name_len = 0;

		/*
		 * We need to report the file name either for filename events
		 * (create,delete,rename) or for events that happen on non
		 * directory inodes when reporting file ids to root sb inode
		 * and only if user has requested to get filename info.
		 */
		if (file_name &&
		    ((mask & FAN_FILENAME_EVENTS) ||
		     !d_is_dir(path->dentry)) &&
		    (group->fanotify_data.flags & FAN_EVENT_INFO_NAME)) {
			name_len = strlen(file_name);
			alloc_len += name_len + 1;
		}

		ffe = kmalloc(alloc_len, GFP_KERNEL);
		if (!ffe)
			return NULL;
		event = &ffe->fae;
		ffe->name_len = name_len;
		if (name_len)
			strcpy(ffe->name, file_name);

		ffe->fh.handle_type = FILEID_INVALID;
		ffe->fh.handle_bytes = 0;
		if ((mask & FAN_EVENT_ON_SB) &&
		    (group->fanotify_data.flags & FAN_EVENT_INFO_FH)) {
			/*
			 * Encode only parent inode for filename events
			 * and events on directories. Encode both parent
			 * and child inodes for other events.
			 * ffe->fid is big enough to encode xfs type 0x82:
			 * 64bit parent+child inodes and 32bit generations
			 */
			int handle_dwords = sizeof(ffe->fid) >> 2;
			int type = exportfs_encode_fh(path->dentry,
					(struct fid *)&ffe->fid,
					&handle_dwords,
					!(mask & FAN_FILENAME_EVENTS));

			if (type > 0 && type < FILEID_INVALID) {
				ffe->fh.handle_type = type;
				ffe->fh.handle_bytes = handle_dwords << 2;
			}
		}
		goto init;
	}

	event = kmem_cache_alloc(fanotify_event_cachep, GFP_KERNEL);
	if (!event)
		return NULL;
init: __maybe_unused
	fsnotify_init_event(&event->fse, inode, mask);
	event->tgid = get_pid(task_tgid(current));
	if (path) {
		event->path = *path;
		path_get(&event->path);
		pr_debug("%s: mnt=%p, dentry=%p parent=%p d_flags=%x\n",
				__func__, event->path.mnt, event->path.dentry,
				event->path.dentry->d_parent,
				event->path.dentry->d_flags);
	} else {
		event->path.mnt = NULL;
		event->path.dentry = NULL;
	}
	return event;
}

static int fanotify_handle_event(struct fsnotify_group *group,
				 struct inode *inode,
				 struct fsnotify_mark *inode_mark,
				 struct fsnotify_mark *vfsmnt_mark,
				 u32 mask, void *data, int data_type,
				 const unsigned char *file_name, u32 cookie)
{
	int ret = 0;
	struct fanotify_event_info *event;
	struct fsnotify_event *fsn_event;
	struct path path;

	BUILD_BUG_ON(FAN_ACCESS != FS_ACCESS);
	BUILD_BUG_ON(FAN_MODIFY != FS_MODIFY);
	BUILD_BUG_ON(FAN_ATTRIB != FS_ATTRIB);
	BUILD_BUG_ON(FAN_CLOSE_NOWRITE != FS_CLOSE_NOWRITE);
	BUILD_BUG_ON(FAN_CLOSE_WRITE != FS_CLOSE_WRITE);
	BUILD_BUG_ON(FAN_OPEN != FS_OPEN);
	BUILD_BUG_ON(FAN_MOVED_TO != FS_MOVED_TO);
	BUILD_BUG_ON(FAN_MOVED_FROM != FS_MOVED_FROM);
	BUILD_BUG_ON(FAN_CREATE != FS_CREATE);
	BUILD_BUG_ON(FAN_DELETE != FS_DELETE);
	BUILD_BUG_ON(FAN_DELETE_SELF != FS_DELETE_SELF);
	BUILD_BUG_ON(FAN_MOVE_SELF != FS_MOVE_SELF);
	BUILD_BUG_ON(FAN_EVENT_ON_CHILD != FS_EVENT_ON_CHILD);
	BUILD_BUG_ON(FAN_EVENT_ON_SB != FS_EVENT_ON_SB);
	BUILD_BUG_ON(FAN_Q_OVERFLOW != FS_Q_OVERFLOW);
	BUILD_BUG_ON(FAN_OPEN_PERM != FS_OPEN_PERM);
	BUILD_BUG_ON(FAN_ACCESS_PERM != FS_ACCESS_PERM);
	BUILD_BUG_ON(FAN_ONDIR != FS_ISDIR);

	if (!fanotify_should_send_event(inode_mark, vfsmnt_mark, mask,
					&path, data, data_type))
		return 0;

	pr_debug("%s: group=%p inode=%p mask=%x\n", __func__, group, inode,
		 mask);

	event = fanotify_alloc_event(group, inode, mask, &path, file_name);
	if (unlikely(!event))
		return -ENOMEM;

	fsn_event = &event->fse;
	ret = fsnotify_add_event(group, fsn_event, fanotify_merge);
	if (ret) {
		/* Permission events shouldn't be merged */
		BUG_ON(ret == 1 && mask & FAN_ALL_PERM_EVENTS);
		/* Our event wasn't used in the end. Free it. */
		fsnotify_destroy_event(group, fsn_event);

		return 0;
	}

#ifdef CONFIG_FANOTIFY_ACCESS_PERMISSIONS
	if (mask & FAN_ALL_PERM_EVENTS) {
		ret = fanotify_get_response(group, FANOTIFY_PE(fsn_event));
		fsnotify_destroy_event(group, fsn_event);
	}
#endif
	return ret;
}

static void fanotify_free_group_priv(struct fsnotify_group *group)
{
	struct user_struct *user;

	user = group->fanotify_data.user;
	atomic_dec(&user->fanotify_listeners);
	free_uid(user);
}

static void fanotify_free_event(struct fsnotify_event *fsn_event)
{
	struct fanotify_event_info *event;

	event = FANOTIFY_E(fsn_event);
	path_put(&event->path);
	put_pid(event->tgid);
#ifdef CONFIG_FANOTIFY_ACCESS_PERMISSIONS
	if (fsn_event->mask & FAN_ALL_PERM_EVENTS) {
		kmem_cache_free(fanotify_perm_event_cachep,
				FANOTIFY_PE(fsn_event));
		return;
	}
#endif
	if (fsn_event->mask & FAN_FILEINFO_EVENTS) {
		kfree(FANOTIFY_FE(fsn_event));
		return;
	}

	kmem_cache_free(fanotify_event_cachep, event);
}

const struct fsnotify_ops fanotify_fsnotify_ops = {
	.handle_event = fanotify_handle_event,
	.free_group_priv = fanotify_free_group_priv,
	.free_event = fanotify_free_event,
};
