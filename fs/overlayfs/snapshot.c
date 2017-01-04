/*
 * File: fs/overlayfs/snapshot.c
 *
 * Overlayfs snapshot core functions.
 *
 * Copyright (C) 2016-2017 CTERA Network by Amir Goldstein <amir73il@gmail.com>
 */

#include <uapi/linux/magic.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/ratelimit.h>
#include "overlayfs.h"
#include "ovl_entry.h"

struct file_system_type ovl_snapshot_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "snapshot",
	.mount		= ovl_mount,
	.kill_sb	= kill_anon_super,
};
MODULE_ALIAS_FS("snapshot");
MODULE_ALIAS("snapshot");

static bool registered;

int ovl_snapshot_fs_register(void)
{
	int err = register_filesystem(&ovl_snapshot_fs_type);

	if (!err)
		registered = true;
	else
		pr_warn("overlayfs: failed to register snapshotfs (%i)\n", err);

	return err;
}

void ovl_snapshot_fs_unregister(void)
{
	if (registered)
		unregister_filesystem(&ovl_snapshot_fs_type);
}

int ovl_snapshot_dir(const char *name, struct path *path,
		     struct ovl_fs *ofs, struct super_block *sb)
{
	int err = -ENOMEM;
	bool remote = false;
	char *tmp;

	tmp = kstrdup(name, GFP_KERNEL);
	if (!tmp)
		goto out;

	ovl_unescape(tmp);
	err = ovl_lower_dir(tmp, path, ofs, &sb->s_stack_depth, &remote);
	if (err)
		goto out;

	/* path has to be the root of an overlayfs mount */
	if (!remote || path->dentry != path->mnt->mnt_root ||
	    path->mnt->mnt_sb->s_magic != OVERLAYFS_SUPER_MAGIC) {
		pr_err("overlayfs: '%s' is not an overlayfs mount\n", tmp);
		path_put(path);
		err = -EINVAL;
	}

out:
	kfree(tmp);
	return err;
}

struct vfsmount *ovl_snapshot_mount(struct path *path, struct ovl_fs *ufs)
{
	struct ovl_fs *snapfs;
	struct vfsmount *snapmnt = clone_private_mount(path);

	if (IS_ERR(snapmnt)) {
		pr_err("overlayfs: failed to clone snapshot path\n");
		return snapmnt;
	}

	snapfs = snapmnt->mnt_sb->s_fs_info;
	if (snapfs->numlower > 1 ||
	    ufs->upper_mnt->mnt_root != snapfs->lower_mnt[0]->mnt_root) {
		pr_err("overlayfs: upperdir and snapshot's lowerdir mismatch\n");
		mntput(snapmnt);
		return ERR_PTR(-EINVAL);
	}

	return snapmnt;
}

int ovl_snapshot_remount(struct super_block *sb, int *flags, char *data)
{
	struct ovl_fs *ufs = sb->s_fs_info;
	struct ovl_entry *roe = sb->s_root->d_fsdata;
	struct path snappath = { };
	struct vfsmount *snapmnt = NULL;
	struct dentry *snaproot = NULL;
	struct ovl_config config = {
		.snapshot = NULL,
		.lowerdir = NULL,
		.upperdir = NULL,
		.workdir = NULL,
	};
	char *nosnapshot = NULL;
	int err;

	if (!data)
		return 0;

	pr_info("%s: -o'%s'\n", __func__, (char *)data);

	/*
	 * Set config.snapshot to an empty string and parse remount options.
	 * If no new snapshot= option nor nosnapshot option was found,
	 * config.snapshot will remain an empty string and nothing will change.
	 * If snapshot= option will set a new config.snapshot value or
	 * nosnapshot option will free the empty string, then we will
	 * change the snapshot overlay to the new one or to NULL.
	 */
	if (ufs->config.snapshot) {
		err = -ENOMEM;
		nosnapshot = kstrdup("", GFP_KERNEL);
		if (!nosnapshot)
			return err;
		config.snapshot = nosnapshot;
	}

	err = ovl_parse_opt((char *)data, &config, true);
	if (err)
		goto out_free_config;

	/*
	 * If parser did not change empty string or if parser found
	 * 'nosnapshot' and there is no snapshot - do nothing
	 */
	if ((config.snapshot && !*config.snapshot) ||
	    (!config.snapshot && !ufs->config.snapshot))
		goto out_free_config;

	pr_debug("%s: old snapshot='%s'\n", __func__, ufs->config.snapshot);

	if (config.snapshot) {
		err = ovl_snapshot_dir(config.snapshot, &snappath,
				       ufs, sb);
		if (err)
			goto out_free_config;

		/* If new snappath is same sb as old snapmnt - do nothing */
		if (ufs->__snapmnt &&
		    ufs->__snapmnt->mnt_sb == snappath.mnt->mnt_sb)
			goto out_put_snappath;

		snapmnt = ovl_snapshot_mount(&snappath, ufs);
		if (IS_ERR(snapmnt)) {
			err = PTR_ERR(snapmnt);
			goto out_put_snappath;
		}

		snaproot = dget(snappath.dentry);
	}

	pr_debug("%s: new snapshot='%s'\n", __func__, config.snapshot);

	kfree(ufs->config.snapshot);
	ufs->config.snapshot = config.snapshot;
	config.snapshot = NULL;

	/* prepare to drop old snapshot overlay */
	path_put(&snappath);
	snappath.mnt = ufs->__snapmnt;
	snappath.dentry = roe->__snapdentry;
	rcu_assign_pointer(ufs->__snapmnt, snapmnt);
	rcu_assign_pointer(roe->__snapdentry, snaproot);
	/* wait grace period before dropping old snapshot overlay */
	synchronize_rcu();

out_put_snappath:
	path_put(&snappath);
out_free_config:
	kfree(config.snapshot);
	kfree(config.lowerdir);
	kfree(config.upperdir);
	kfree(config.workdir);
	return err;
}

static int ovl_snapshot_dentry_is_valid(struct dentry *snapdentry,
					struct vfsmount *snapmnt)
{
	/* No snaphsot overlay (pre snapshot take) */
	if (!snapmnt && !snapdentry)
		return 0;

	/* An uninitialized snapdentry after snapshot take */
	if (!snapdentry)
		return -ENOENT;

	/*
	 * snapmnt is NULL and snapdentry is non-NULL
	 * or snapdentry->d_sb != snapmnt->mnt_sb. This implies
	 * a stale snapdentry from an older snapshot overlay
	 */
	if (unlikely(!snapmnt ||
		     snapmnt->mnt_sb != snapdentry->d_sb))
		return -ESTALE;

	return 0;
}

/*
 * Return snapshot overlay path associated with a snapshot mount dentry
 * with elevated refcount if it is valid or error if snapshot mount dentry
 * should be revalidated.
 */
static int ovl_snapshot_path(struct dentry *dentry, struct path *path)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct ovl_entry *oe = dentry->d_fsdata;
	struct path snappath;
	int err;

	rcu_read_lock();
	snappath.mnt = mntget(rcu_dereference(ofs->__snapmnt));
	snappath.dentry = dget(rcu_dereference(oe->__snapdentry));
	rcu_read_unlock();

	err = ovl_snapshot_dentry_is_valid(snappath.dentry, snappath.mnt);
	if (err)
		goto out_err;

	*path = snappath;
	return 0;

out_err:
	path_put(&snappath);
	return err;
}

/*
 * Return snapshot overlay dentry associated with a snapshot mount dentry
 * with elevated refcount if it is valid or error if snapshot mount dentry
 * should be revalidated.
 * If a snapshot mount dentry is used after snapshot take without being
 * revalidated this function may return ESTALE/ENOENT.
 */
struct dentry *ovl_snapshot_dentry(struct dentry *dentry)
{
	struct path snappath = { };
	int err;

	/* Not a snapshot mount */
	if (!ovl_is_snapshot_fs_type(dentry->d_sb))
		return NULL;

	err = ovl_snapshot_path(dentry, &snappath);
	if (err)
		return ERR_PTR(err);

	/*
	 * If snapentry is root, but dentry is not, that indicates that
	 * snapentry is nested inside an already whited out directory,
	 * so need to do nothing about it.
	 */
	if (snappath.dentry && IS_ROOT(snappath.dentry) && !IS_ROOT(dentry)) {
		path_put(&snappath);
		return NULL;
	}

	mntput(snappath.mnt);
	return snappath.dentry;
}

/*
 * Lookup the overlay snapshot dentry in the same path as the looked up
 * snapshot mount dentry. We need to hold a reference to a negative snapshot
 * dentry for explicit whiteout before create in snapshot mount and we need
 * to hold a reference to positive non-dir snapshot dentry even if snapshot
 * mount dentry is a directory, so we know that we don't need to copy up the
 * snapshot mount directory children.
 */
int ovl_snapshot_lookup(struct dentry *parent, struct ovl_lookup_data *d,
			struct dentry **ret)
{
	struct path snappath;
	struct dentry *snapdentry = NULL;
	int err;

	err = ovl_snapshot_path(parent, &snappath);
	if (unlikely(err))
		return err;

	/* !snapparent means no active snapshot overlay */
	if (!snappath.dentry)
		goto out;

	/*
	 * When snapparent is negative or non-dir or when snapparent's
	 * lower dir is not the snapshot mount parent's upper, point the
	 * snapdentry to the snapshot overlay root. This is needed to
	 * indicate this special case and to access snapshot overlay sb.
	 */
	if (!d_can_lookup(snappath.dentry) ||
	    ovl_dentry_lower(snappath.dentry) != ovl_dentry_upper(parent)) {
		snapdentry = dget(snappath.mnt->mnt_root);
		goto out;
	}

	err = ovl_lookup_layer(snappath.dentry, d, &snapdentry);

out:
	path_put(&snappath);
	*ret = snapdentry;
	return err;
}

static int ovl_snapshot_copy_down(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	int err = 0;

	/*
	 * Snapshot dentry may be positive or negative or NULL.
	 * If positive, it may need to be copied down.
	 * If negative, it should be a whiteout.
	 * If NULL, it may be an uninitialized snapdentry after snapshot take,
	 * or it can also be that the snapshot dentry is nested inside an
	 * already whited out directory. Either way, we do nothing about it.
	 */
	if (!snap)
		return 0;

	if (unlikely(IS_ERR(snap))) {
		err = PTR_ERR(snap);
		snap = NULL;
		goto bug;
	}

	if (d_is_negative(snap)) {
		if (WARN_ON(!ovl_dentry_is_opaque(snap)))
			goto bug;
		goto out;
	}

	if (ovl_dentry_upper(snap))
		goto out;

	/* Trigger 'copy down' to snapshot */
	err = ovl_want_write(snap);
	if (err)
		goto bug;
	err = ovl_copy_up(snap);
	ovl_drop_write(snap);
	if (err)
		goto bug;

out:
	dput(snap);
	return 0;

bug:
	pr_warn_ratelimited("overlayfs: failed copy to snapshot (%pd2, ino=%lu, err=%i)\n",
			    dentry, inode ? inode->i_ino : 0, err);
	dput(snap);
	/* Allowing write would corrupt snapshot so deny */
	return -EROFS;
}

static struct dentry *ovl_snapshot_d_real(struct dentry *dentry,
					  const struct inode *inode,
					  unsigned int open_flags,
					  unsigned int flags)
{
	struct dentry *real;
	int err;

	if (!d_is_reg(dentry)) {
		if (!inode || inode == d_inode(dentry))
			return dentry;
		goto bug;
	}

	if (d_is_negative(dentry))
		return dentry;

	if (open_flags & (O_ACCMODE|O_TRUNC)) {
		err = ovl_snapshot_copy_down(dentry);
		if (err)
			return ERR_PTR(err);
	}

	/* With snapshot, the real inode is always the upper */
	real = ovl_dentry_upper(dentry);
	if (!real)
		goto bug;

	if (inode && inode != d_inode(real))
		goto bug;

	if (!inode) {
		err = ovl_check_append_only(d_inode(real), open_flags);
		if (err)
			return ERR_PTR(err);
	}

	return real;

bug:
	WARN(1, "%s(%pd4, %s:%lu): real dentry not found\n", __func__,
	     dentry, inode ? inode->i_sb->s_id : "NULL",
	     inode ? inode->i_ino : 0);
	return dentry;
}

/*
 * Returns 1 if both snapdentry and snapmnt are NULL or
 * if snapdentry and snapmnt point to the same super block.
 *
 * Returns 0 if snapdentry is NULL and snapmnt is not NULL or
 * if snapdentry and snapmnt point to different super blocks.
 * This will cause vfs lookup to invalidate this dentry and call ovl_lookup()
 * again to re-lookup snapdentry from the current snapmnt.
 */
static int ovl_snapshot_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct path snappath = { };
	int err;

	if (flags & LOOKUP_RCU) {
		struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
		struct ovl_entry *oe = dentry->d_fsdata;

		err = ovl_snapshot_dentry_is_valid(
				rcu_dereference(oe->__snapdentry),
				rcu_dereference(ofs->__snapmnt));
	} else {
		err = ovl_snapshot_path(dentry, &snappath);
		path_put(&snappath);
	}

	if (likely(!err))
		return 1;

	if (err == -ESTALE || err == -ENOENT)
	       return 0;

	return err;
}

const struct dentry_operations ovl_snapshot_dentry_operations = {
	.d_release = ovl_dentry_release,
	.d_real = ovl_snapshot_d_real,
	.d_revalidate = ovl_snapshot_revalidate,
};

/* Explicitly whiteout a negative snapshot mount dentry before create */
static int ovl_snapshot_whiteout(struct dentry *dentry)
{
	struct dentry *parent;
	struct dentry *upperdir;
	struct inode *sdir, *udir;
	struct dentry *whiteout;
	const struct cred *old_cred;
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	int err = 0;

	if (!snap)
		return 0;

	if (unlikely(IS_ERR(snap))) {
		err = PTR_ERR(snap);
		pr_warn_ratelimited("%s(%pd2): err=%i\n", __func__,
				    dentry, err);
		d_drop(dentry);
		return err;
	}

	/* No need to whiteout a positive or whiteout snapshot dentry */
	if (!d_is_negative(snap) || ovl_dentry_is_opaque(snap))
		goto out;

	parent = dget_parent(snap);
	sdir = parent->d_inode;

	inode_lock_nested(sdir, I_MUTEX_PARENT);

	err = ovl_want_write(snap);
	if (err)
		goto out;

	err = ovl_copy_up(parent);
	if (err)
		goto out_drop_write;

	upperdir = ovl_dentry_upper(parent);
	udir = upperdir->d_inode;

	old_cred = ovl_override_creds(snap->d_sb);

	inode_lock_nested(udir, I_MUTEX_PARENT);
	whiteout = lookup_one_len(snap->d_name.name, upperdir,
				  snap->d_name.len);
	if (IS_ERR(whiteout)) {
		err = PTR_ERR(whiteout);
		goto out_unlock;
	}

	/*
	 * We could have raced with another task that tested false
	 * ovl_dentry_is_opaque() before udir lock, so if we find a
	 * whiteout all is good.
	 */
	if (!ovl_is_whiteout(whiteout)) {
		err = ovl_do_whiteout(udir, whiteout);
		if (err)
			goto out_dput_whiteout;
	}

	/*
	 * Setting a negative snapshot dentry opaque to signify that
	 * there is no need for explicit whiteout next time.
	 */
	ovl_dentry_set_opaque(snap);
	ovl_dentry_version_inc(parent, true);
out_dput_whiteout:
	dput(whiteout);
out_unlock:
	inode_unlock(udir);
	revert_creds(old_cred);
out_drop_write:
	ovl_drop_write(snap);
	inode_unlock(sdir);
	dput(parent);
out:
	dput(snap);
	return err;
}

int ovl_snapshot_want_write(struct dentry *dentry)
{
	if (!ovl_is_snapshot_fs_type(dentry->d_sb))
		return 0;

	/* Negative dentry may need to be explicitly whited out */
	if (d_is_negative(dentry))
		return ovl_snapshot_whiteout(dentry);

	return ovl_snapshot_copy_down(dentry);
}

void ovl_snapshot_drop_write(struct dentry *dentry)
{
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	struct inode *inode = d_inode(dentry);

	if (unlikely(IS_ERR(snap))) {
		pr_warn_ratelimited("%s(%pd2): err=%i\n", __func__,
				    dentry, (int)PTR_ERR(snap));
		d_drop(dentry);
		return;
	}

	/*
	 * We may have just dropped this dentry, because it was deleted or
	 * renamed over - then snapshot still thinks it has a lower dentry.
	 * Unhash the snapshot dentry as well in this case.
	 */
	if (snap && d_unhashed(dentry)) {
		pr_debug("ovl_snapshot_d_drop(%pd4, %lu): is_dir=%d, negative=%d, unhashed=%d\n",
			dentry, inode ? inode->i_ino : 0, d_is_dir(dentry),
			d_is_negative(dentry), d_unhashed(dentry));
		d_drop(snap);
	}
	dput(snap);
}
