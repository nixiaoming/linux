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

int ovl_snapshot_want_write(struct dentry *dentry)
{
	struct dentry *snap = ovl_snapshot_dentry(dentry);

	if (!snap)
		return 0;

	if (d_is_negative(dentry))
		return 0;

	return ovl_snapshot_copy_down(dentry);
}

void ovl_snapshot_drop_write(struct dentry *dentry)
{
}
