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
