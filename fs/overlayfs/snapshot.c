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

struct dentry *ovl_snapshot_dentry(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	if (!ovl_is_snapshot_fs_type(dentry->d_sb))
		return NULL;

	return oe->__snapdentry;
}

static int ovl_snapshot_copy_down(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	int err = -ENOENT;

	if (WARN_ON(d_is_negative(dentry)))
		goto bug;

	/*
	 * Snapshot dentry may be positive or negative or NULL.
	 * If positive, it may need to be copied down.
	 * If negative, it should be a whiteout.
	 * Otherwise, the entry is nested inside an already
	 * whited out directory, so need to do nothing about it.
	 */
	if (!snap)
		return 0;

	if (d_is_negative(snap)) {
		if (WARN_ON(!ovl_dentry_is_opaque(snap)))
			goto bug;
		return 0;
	}

	if (ovl_dentry_upper(snap))
		return 0;

	/* Trigger 'copy down' to snapshot */
	err = ovl_want_write(snap);
	if (err)
		goto bug;
	err = ovl_copy_up(snap);
	ovl_drop_write(snap);
	if (err)
		goto bug;

	return 0;
bug:
	pr_warn_ratelimited("overlayfs: failed copy to snapshot (%pd2, ino=%lu, err=%i)\n",
			    dentry, inode ? inode->i_ino : 0, err);
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

const struct dentry_operations ovl_snapshot_dentry_operations = {
	.d_release = ovl_dentry_release,
	.d_real = ovl_snapshot_d_real,
};

/* Explicitly whiteout a negative snapshot mount dentry before create */
static int ovl_snapshot_whiteout(struct dentry *snap)
{
	struct dentry *parent;
	struct dentry *upperdir;
	struct inode *sdir, *udir;
	struct dentry *whiteout;
	const struct cred *old_cred;
	int err;

	/* No need to whiteout a positive or whiteout snapshot dentry */
	if (!d_is_negative(snap) || ovl_dentry_is_opaque(snap))
		return 0;

	parent = dget_parent(snap);
	sdir = parent->d_inode;

	inode_lock_nested(sdir, I_MUTEX_PARENT);

	err = ovl_want_write(snap);
	if (err)
		return err;

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
			goto out_dput;
	}

	/*
	 * Setting a negative snapshot dentry opaque to signify that
	 * there is no need for explicit whiteout next time.
	 */
	ovl_dentry_set_opaque(snap);
	ovl_dentry_version_inc(parent, true);
out_dput:
	dput(whiteout);
out_unlock:
	inode_unlock(udir);
	revert_creds(old_cred);
out_drop_write:
	ovl_drop_write(snap);
	inode_unlock(sdir);
	dput(parent);
	return err;
}

int ovl_snapshot_want_write(struct dentry *dentry)
{
	struct dentry *snap = ovl_snapshot_dentry(dentry);

	if (!snap)
		return 0;

	/* Negative dentry may need to be explicitly whited out */
	if (d_is_negative(dentry))
		return ovl_snapshot_whiteout(snap);

	return ovl_snapshot_copy_down(dentry);
}

void ovl_snapshot_drop_write(struct dentry *dentry)
{
	struct dentry *snap = ovl_snapshot_dentry(dentry);
	struct inode *inode = d_inode(dentry);

	/*
	 * We may have just dropped this dentry, because it was deleted or
	 * renamed over - then snapshot still thinks it has a lower dentry.
	 * Unhash the snapshot dentry as well in this case.
	 */
	if (snap && (d_unhashed(dentry))) {
		pr_debug("ovl_snapshot_d_drop(%pd4, %lu): is_dir=%d, negative=%d, unhashed=%d\n",
			dentry, inode ? inode->i_ino : 0, d_is_dir(dentry),
			d_is_negative(dentry), d_unhashed(dentry));
		d_drop(snap);
	}
}
