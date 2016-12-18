#include <linux/fsnotify_backend.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/exportfs.h>

extern struct kmem_cache *fanotify_event_cachep;
extern struct kmem_cache *fanotify_perm_event_cachep;

/*
 * Structure for normal fanotify events. It gets allocated in
 * fanotify_handle_event() and freed when the information is retrieved by
 * userspace
 */
struct fanotify_event_info {
	struct fsnotify_event fse;
	/*
	 * We hold ref to this path so it may be dereferenced at any point
	 * during this object's lifetime
	 */
	struct path path;
	struct pid *tgid;
};

struct fanotify_fid64 {
	u64 ino;
	u32 gen;
	u64 parent_ino;
	u32 parent_gen;
} __attribute__((packed));

/*
 * Structure for fanotify events with variable length data.
 * It gets allocated in fanotify_handle_event() and freed
 * when the information is retrieved by userspace
 */
struct fanotify_file_event_info {
	struct fanotify_event_info fae;
	/*
	 * For events reported to sb root record the file handle
	 */
	struct file_handle fh;
	struct fanotify_fid64 fid;	/* make this allocated? */
	/*
	 * For filename events (create,delete,rename), path points to the
	 * directory and name holds the entry name
	 */
	int name_len;
	char name[];	/* make this allocated? */
};

#ifdef CONFIG_FANOTIFY_ACCESS_PERMISSIONS
/*
 * Structure for permission fanotify events. It gets allocated and freed in
 * fanotify_handle_event() since we wait there for user response. When the
 * information is retrieved by userspace the structure is moved from
 * group->notification_list to group->fanotify_data.access_list to wait for
 * user response.
 */
struct fanotify_perm_event_info {
	struct fanotify_event_info fae;
	int response;	/* userspace answer to question */
	int fd;		/* fd we passed to userspace for this event */
};

static inline struct fanotify_perm_event_info *
FANOTIFY_PE(struct fsnotify_event *fse)
{
	return container_of(fse, struct fanotify_perm_event_info, fae.fse);
}

/* Should use fanotify_perm_event_info for this event? */
static inline bool FANOTIFY_IS_PE(struct fsnotify_event *fse)
{
	return fse->mask & FAN_ALL_PERM_EVENTS;
}
#else
static inline bool FANOTIFY_IS_PE(struct fsnotify_event *fse)
{
	return false;
}
#endif

/* Should use fanotify_file_event_info for this event? */
static inline bool FANOTIFY_IS_FE(struct fsnotify_event *fse)
{
	if (FANOTIFY_IS_PE(fse))
		return false;

	/* Non permission events reported on root may carry file info */
	return fse->mask & (FAN_FILENAME_EVENTS | FAN_EVENT_ON_SB);
}

static inline struct fanotify_file_event_info *
FANOTIFY_FE(struct fsnotify_event *fse)
{
	return container_of(fse, struct fanotify_file_event_info, fae.fse);
}

static inline struct fanotify_event_info *FANOTIFY_E(struct fsnotify_event *fse)
{
	return container_of(fse, struct fanotify_event_info, fse);
}

struct fanotify_event_info *fanotify_alloc_event(struct fsnotify_group *group,
						 struct inode *inode, u32 mask,
						 struct path *path,
						 const char *file_name);
