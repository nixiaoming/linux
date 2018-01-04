/*
 * File: fs/overlayfs/snapshot.c
 *
 * Overlayfs snapshot core functions.
 *
 * Copyright (C) 2016-2017 CTERA Network by Amir Goldstein <amir73il@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <uapi/linux/magic.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include <linux/ratelimit.h>
#include "overlayfs.h"

static void ovl_snapshot_dentry_release(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	if (oe) {
		dput(oe->__snapdentry);
		kfree_rcu(oe, rcu);
	}
}

static int ovl_snapshot_copy_down(struct dentry *dentry);

static struct dentry *ovl_snapshot_d_real(struct dentry *dentry,
					  const struct inode *inode,
					  unsigned int open_flags,
					  unsigned int flags)
{
	struct dentry *real = ovl_dentry_upper(dentry);
	int err;

	if (flags & D_REAL_UPPER)
		return real;

	if (!d_is_reg(dentry)) {
		if (!inode || inode == d_inode(dentry))
			return dentry;
		goto bug;
	}

	if (!real)
		goto bug;

	if (open_flags & (O_ACCMODE|O_TRUNC)) {
		err = ovl_snapshot_copy_down(dentry);
		if (err)
			return ERR_PTR(err);
	}

	if (inode && inode != d_inode(real))
		goto bug;

	if (!inode) {
		err = ovl_check_append_only(d_inode(real), open_flags);
		if (err)
			return ERR_PTR(err);
	}

	return real;

bug:
	WARN(1, "%s(%pd4, %s:%lu): real dentry not found\n", __func__, dentry,
	     inode ? inode->i_sb->s_id : "NULL", inode ? inode->i_ino : 0);
	return dentry;
}

static const struct dentry_operations ovl_snapshot_dentry_operations = {
	.d_release = ovl_snapshot_dentry_release,
	.d_real = ovl_snapshot_d_real,
};

static int ovl_snapshot_show_options(struct seq_file *m, struct dentry *dentry)
{
	struct super_block *sb = dentry->d_sb;
	struct ovl_fs *ofs = sb->s_fs_info;

	seq_show_option(m, "upperdir", ofs->config.upperdir);
	if (!ofs->config.redirect_dir)
		seq_puts(m, ",redirect_dir=off");
	if (ofs->config.snapshot)
		seq_show_option(m, "snapshot", ofs->config.snapshot);

	return 0;
}

static int ovl_snapshot_remount(struct super_block *sb, int *flags, char *data)
{
	return 0;
}

static const struct super_operations ovl_snapshot_super_operations = {
	.alloc_inode	= ovl_alloc_inode,
	.destroy_inode	= ovl_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.put_super	= ovl_put_super,
	.sync_fs	= ovl_sync_fs,
	.statfs		= ovl_statfs,
	.show_options	= ovl_snapshot_show_options,
	.remount_fs	= ovl_snapshot_remount,
};

enum {
	OPT_UPPERDIR,
	OPT_REDIRECT_DIR_ON,
	OPT_REDIRECT_DIR_OFF,
	OPT_SNAPSHOT,
	OPT_ERR,
};

static const match_table_t ovl_snapshot_tokens = {
	{OPT_UPPERDIR,			"upperdir=%s"},
	{OPT_REDIRECT_DIR_ON,		"redirect_dir=on"},
	{OPT_REDIRECT_DIR_OFF,		"redirect_dir=off"},
	{OPT_SNAPSHOT,			"snapshot=%s"},
	{OPT_ERR,			NULL}
};

static int ovl_snapshot_parse_opt(char *opt, struct ovl_config *config)
{
	char *p;

	while ((p = ovl_next_opt(&opt)) != NULL) {
		int token;
		substring_t args[MAX_OPT_ARGS];

		if (!*p)
			continue;

		token = match_token(p, ovl_snapshot_tokens, args);
		switch (token) {
		case OPT_UPPERDIR:
			kfree(config->upperdir);
			config->upperdir = match_strdup(&args[0]);
			if (!config->upperdir)
				return -ENOMEM;
			break;

		case OPT_REDIRECT_DIR_ON:
			config->redirect_dir = true;
			config->redirect_follow = true;
			break;

		case OPT_REDIRECT_DIR_OFF:
			config->redirect_dir = false;
			config->redirect_follow = false;
			break;

		case OPT_SNAPSHOT:
			kfree(config->snapshot);
			config->snapshot = match_strdup(&args[0]);
			if (!config->snapshot)
				return -ENOMEM;
			break;

		default:
			pr_err("overlayfs: unrecognized snapshot mount option \"%s\" or missing value\n", p);
			return -EINVAL;
		}
	}

	return 0;
}

static int ovl_snapshot_dir(struct super_block *sb, struct ovl_fs *ofs,
			    const char *name, struct path *snappath)
{
	struct vfsmount *snapmnt;
	char *tmp;
	int err;

	err = -ENOMEM;
	tmp = kstrdup(name, GFP_KERNEL);
	if (!tmp)
		goto out;

	ovl_unescape(tmp);
	err = ovl_mount_dir_noesc(name, snappath);
	if (err)
		goto out;

	snapmnt = snappath->mnt;
	/* snappath has to be the root of a non-nested overlayfs mount */
	err = -EINVAL;
	if (snappath->dentry != snapmnt->mnt_root ||
	    snapmnt->mnt_sb->s_magic != OVERLAYFS_SUPER_MAGIC) {
		pr_err("overlayfs: snapshot='%s' is not an overlayfs mount\n",
		       tmp);
		goto out_put;
	}

	if (snapmnt->mnt_sb->s_stack_depth > 1) {
		pr_err("overlayfs: snapshot='%s' is a nested overlayfs mount\n",
		       tmp);
		goto out_put;
	}

	err = 0;
out:
	kfree(tmp);
	return err;

out_put:
	path_put_init(snappath);
	goto out;
}

static struct vfsmount *ovl_snapshot_clone_mount(struct ovl_fs *ofs,
						 struct path *snappath)
{
	struct ovl_fs *snapfs;
	struct vfsmount *snapmnt;

	snapmnt = clone_private_mount(snappath);
	if (IS_ERR(snapmnt)) {
		pr_err("overlayfs: failed to clone snapshot path\n");
		return snapmnt;
	}

	snapfs = snapmnt->mnt_sb->s_fs_info;
	if (snapfs->numlower > 1 ||
	    ofs->upper_mnt->mnt_root != snapfs->lower_layers[0].mnt->mnt_root) {
		pr_err("overlayfs: upperdir and snapshot's lowerdir mismatch\n");
		mntput(snapmnt);
		return ERR_PTR(-EINVAL);
	}

	return snapmnt;
}
static int ovl_snapshot_fill_super(struct super_block *sb, void *data,
				   int silent)
{
	struct path upperpath = { };
	struct path snappath = { };
	struct vfsmount *snapmnt;
	struct dentry *root_dentry;
	struct ovl_entry *oe = NULL;
	struct ovl_fs *ofs;
	struct cred *cred;
	int err;

	err = -ENOMEM;
	ofs = kzalloc(sizeof(struct ovl_fs), GFP_KERNEL);
	if (!ofs)
		goto out;

	ofs->creator_cred = cred = prepare_creds();
	if (!cred)
		goto out_err;

	ofs->config.redirect_dir = true;
	err = ovl_snapshot_parse_opt((char *) data, &ofs->config);
	if (err)
		goto out_err;

	err = -EINVAL;
	if (!ofs->config.upperdir) {
		if (!silent)
			pr_err("overlayfs: snapshot mount missing 'upperdir'\n");
		goto out_err;
	}

	err = ovl_get_upper(ofs, &upperpath);
	if (err)
		goto out_err;

	sb->s_maxbytes = ofs->upper_mnt->mnt_sb->s_maxbytes;
	sb->s_time_gran = ofs->upper_mnt->mnt_sb->s_time_gran;
	ofs->same_sb = ofs->upper_mnt->mnt_sb;

	/*
	 * snapshot mount may be remounted later with underlying
	 * snapshot overlay. we must leave room in stack below us
	 * for that overlay, even if snapshot= mount option is not
	 * provided on the initial mount.
	 */
	sb->s_stack_depth = max(1, ofs->upper_mnt->mnt_sb->s_stack_depth);

	err = -EINVAL;
	sb->s_stack_depth++;
	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("overlayfs: snapshot fs maximum stacking depth exceeded\n");
		goto out_err;
	}

	if (ofs->config.snapshot) {
		err = ovl_snapshot_dir(sb, ofs, ofs->config.snapshot,
				       &snappath);
		if (err)
			goto out_err;

		snapmnt = ovl_snapshot_clone_mount(ofs, &snappath);
		err = PTR_ERR(snapmnt);
		if (IS_ERR(snapmnt))
			goto out_err;

		ofs->snapshot_mnt = snapmnt;
	}

	err = -ENOMEM;
	oe = ovl_alloc_entry(0);
	if (!oe)
		goto out_err;

	sb->s_d_op = &ovl_snapshot_dentry_operations;
	sb->s_export_op = &ovl_export_operations;

	/* Never override disk quota limits or use reserved space */
	cap_lower(cred->cap_effective, CAP_SYS_RESOURCE);

	sb->s_magic = OVERLAYFS_SUPER_MAGIC;
	sb->s_op = &ovl_snapshot_super_operations;
	sb->s_xattr = ovl_xattr_handlers;
	sb->s_fs_info = ofs;
	sb->s_flags |= MS_POSIXACL | MS_NOREMOTELOCK;

	err = -ENOMEM;
	root_dentry = d_make_root(ovl_new_inode(sb, S_IFDIR, 0));
	if (!root_dentry)
		goto out_err;

	mntput(upperpath.mnt);
	mntput(snappath.mnt);
	oe->__snapdentry = snappath.dentry;
	oe->has_upper = true;

	root_dentry->d_fsdata = oe;

	/* Hash root directory inode for NFS export */
	ovl_inode_update(d_inode(root_dentry), upperpath.dentry);
	ovl_inode_init(d_inode(root_dentry), upperpath.dentry, NULL);

	sb->s_root = root_dentry;

	return 0;

out_err:
	kfree(oe);
	path_put(&upperpath);
	path_put(&snappath);
	ovl_free_fs(ofs);
out:
	return err;
}

static struct dentry *ovl_snapshot_mount(struct file_system_type *fs_type,
					 int flags, const char *dev_name,
					 void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, ovl_snapshot_fill_super);
}

struct file_system_type ovl_snapshot_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "snapshot",
	.mount		= ovl_snapshot_mount,
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

	return err;
}

void ovl_snapshot_fs_unregister(void)
{
	if (registered)
		unregister_filesystem(&ovl_snapshot_fs_type);
}

/*
 * Helpers for overlayfs snapshot that may be called from code that is
 * shared between snapshot mount and overlayfs mount.
 */

struct dentry *ovl_snapshot_dentry(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	if (!ovl_is_snapshot_fs_type(dentry->d_sb))
		return NULL;

	return oe->__snapdentry;
}

/*
 * Verify that found overlay snapshot dentry in sane -
 * If the snapshot overlay dentry is a merge/lower dir, then its lower dentry
 * should be pointing back to the snapshot mount upper dentry.
 * If the snapshot overlay dentry is non-opaque negative (i.e. not a whiteout),
 * then the snapshot mount should be also negative (i.e. no upper).
 * Otherwise, this may be a stray redirect that is pointing the snapshot mount
 * at the wrong path in overlay snapshot.
 *
 * Return 0 for sane, < 0 for inconsitency
 */
int ovl_snapshot_verify(struct ovl_fs *ofs, struct dentry *snapdentry,
			struct dentry *upperdentry, char *redirect)
{
	enum ovl_path_type snaptype;
	int err = 0;

	if (!snapdentry)
		goto no_redirect;

	/* Redirect should not be pointing at negative */
	if (!snapdentry->d_inode) {
		if (!ovl_dentry_is_opaque(snapdentry)) {
			if (!upperdentry)
				return 0;
			/* Either a stale redirect or inconsitency */
			err = -ENOENT;
		}
		goto no_redirect;
	}

	/* Redirect should not be pointing at non-dir */
	if (!upperdentry || !d_is_dir(upperdentry) || !d_is_dir(snapdentry))
		goto no_redirect;

	/* Redirect should not be pointing at non-merge upper */
	snaptype = ovl_path_type(snapdentry);
	if (OVL_TYPE_UPPER(snaptype) && !OVL_TYPE_MERGE(snaptype))
		goto no_redirect;

	/* Lower/merge dir should point back at the redirecting upper */
	if (ovl_dentry_lower(snapdentry) != upperdentry)
		goto no_redirect;

	return 0;

no_redirect:
	/* Clear stale redirect if exists and return ESTALE to retry lookup */
	if (redirect && upperdentry) {
		err = mnt_want_write(ofs->upper_mnt);
		if (!err) {
			err = ovl_do_removexattr(upperdentry,
						 OVL_XATTR_REDIRECT);
			mnt_drop_write(ofs->upper_mnt);
		}
		if (!err)
			err = -ESTALE;
	} else if (err && snapdentry) {
		/* We cannot recover from this lookup error */
		pr_warn_ratelimited("%s(%pd2): is_dir=%d, negative=%d, snap_is_dir=%d, snap_negative=%d, err=%i\n",
				    __func__, snapdentry,
				    upperdentry && d_is_dir(upperdentry),
				    !upperdentry, d_is_dir(snapdentry),
				    d_is_negative(snapdentry), err);
	}
	return err;
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
	struct dentry *snapdir = ovl_snapshot_dentry(parent);

	if (!snapdir || !d_can_lookup(snapdir))
		return 0;

	return ovl_lookup_layer(snapdir, d, ret);
}

/*
 * Copy on write to snapshot if needed before file is modified.
 */
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

	if (ovl_dentry_upper(snap) && ovl_dentry_has_upper_alias(snap))
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
