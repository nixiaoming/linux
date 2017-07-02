/*
 * Copyright (C) 2011 Novell Inc.
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/uuid.h>
#include "overlayfs.h"
#include "ovl_entry.h"

void ovl_unescape(char *s)
{
	char *d = s;

	for (;; s++, d++) {
		if (*s == '\\')
			s++;
		*d = *s;
		if (!*s)
			break;
	}
}

int ovl_want_write(struct dentry *dentry)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	int err = ovl_snapshot_want_write(dentry);

	if (err)
		return err;

	return mnt_want_write(ofs->upper_mnt);
}

void ovl_drop_write(struct dentry *dentry)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;

	ovl_snapshot_drop_write(dentry);
	mnt_drop_write(ofs->upper_mnt);
}

struct dentry *ovl_workdir(struct dentry *dentry)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	return ofs->workdir;
}

const struct cred *ovl_override_creds(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	return override_creds(ofs->creator_cred);
}

struct super_block *ovl_same_sb(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	return ofs->same_sb;
}

bool ovl_can_decode_fh(struct super_block *sb)
{
	return (sb->s_export_op && sb->s_export_op->fh_to_dentry &&
		uuid_be_cmp(*(uuid_be *) &sb->s_uuid, NULL_UUID_BE));
}

struct dentry *ovl_indexdir(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	return ofs->indexdir;
}

struct ovl_entry *ovl_alloc_entry(unsigned int numlower)
{
	size_t size = offsetof(struct ovl_entry, lowerstack[numlower]);
	struct ovl_entry *oe = kzalloc(size, GFP_KERNEL);

	if (oe)
		oe->numlower = numlower;

	return oe;
}

bool ovl_dentry_remote(struct dentry *dentry)
{
	return dentry->d_flags &
		(DCACHE_OP_REVALIDATE | DCACHE_OP_WEAK_REVALIDATE |
		 DCACHE_OP_REAL);
}

bool ovl_dentry_weird(struct dentry *dentry)
{
	return dentry->d_flags & (DCACHE_NEED_AUTOMOUNT |
				  DCACHE_MANAGE_TRANSIT |
				  DCACHE_OP_HASH |
				  DCACHE_OP_COMPARE);
}

enum ovl_path_type ovl_path_type(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	return READ_ONCE(oe->__type);
}

void ovl_update_type(struct dentry *dentry, bool is_dir)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	enum ovl_path_type type = 0;

	spin_lock(&dentry->d_lock);
	if (oe->__upperdentry) {
		type = __OVL_PATH_UPPER;
		/*
		 * Non-dir dentry can hold lower dentry of its copy up origin.
		 */
		if (oe->numlower) {
			type |= __OVL_PATH_ORIGIN;
			if (is_dir)
				type |= __OVL_PATH_MERGE;
		}
	} else if (ovl_dentry_ro_upper(dentry)) {
		type |= __OVL_PATH_RO_UPPER;
	} else {
		if (oe->numlower > 1)
			type |= __OVL_PATH_MERGE;
	}

	/*
	 * The [RO]UPPER/MERGE/ORIGIN flags can never be cleared during the
	 * lifetime of a dentry, so don't bother masking them out first.
	 */
	oe->__type |= type;
	spin_unlock(&dentry->d_lock);
}

void ovl_path_upper(struct dentry *dentry, struct path *path)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct ovl_entry *oe = dentry->d_fsdata;

	path->mnt = ofs->upper_mnt;
	path->dentry = ovl_upperdentry_dereference(oe);
}

void ovl_path_lower(struct dentry *dentry, struct path *path)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	*path = oe->numlower ? oe->lowerstack[0] : (struct path) { };
}

enum ovl_path_type ovl_path_real(struct dentry *dentry, struct path *path)
{
	enum ovl_path_type type = ovl_path_type(dentry);

	if (!OVL_TYPE_UPPER(type))
		ovl_path_lower(dentry, path);
	else
		ovl_path_upper(dentry, path);

	return type;
}

struct dentry *ovl_dentry_upper(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	return ovl_upperdentry_dereference(oe);
}

struct dentry *ovl_dentry_ro_upper(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	if (d_is_dir(dentry) || ovl_is_snapshot_fs_type(dentry->d_sb))
		return NULL;

	return ovl_roupperdentry_dereference(oe);
}

static struct dentry *__ovl_dentry_lower(struct ovl_entry *oe)
{
	return oe->numlower ? oe->lowerstack[0].dentry : NULL;
}

struct dentry *ovl_dentry_lower(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	return __ovl_dentry_lower(oe);
}

struct dentry *ovl_dentry_real(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	struct dentry *realdentry;

	realdentry = ovl_upperdentry_dereference(oe);
	if (!realdentry)
		realdentry = __ovl_dentry_lower(oe);

	return realdentry;
}

struct ovl_dir_cache *ovl_dir_cache(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	return oe->cache;
}

void ovl_set_dir_cache(struct dentry *dentry, struct ovl_dir_cache *cache)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	oe->cache = cache;
}

bool ovl_dentry_is_opaque(struct dentry *dentry)
{
	return OVL_TYPE_OPAQUE(ovl_path_type(dentry));
}

bool ovl_dentry_is_impure(struct dentry *dentry)
{
	return OVL_TYPE_IMPURE(ovl_path_type(dentry));
}

bool ovl_dentry_is_whiteout(struct dentry *dentry)
{
	return !dentry->d_inode && ovl_dentry_is_opaque(dentry);
}

void ovl_dentry_set_opaque(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	spin_lock(&dentry->d_lock);
	oe->__type |= __OVL_PATH_OPAQUE;
	spin_unlock(&dentry->d_lock);
}

static void ovl_dentry_set_impure(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	spin_lock(&dentry->d_lock);
	oe->__type |= __OVL_PATH_IMPURE;
	spin_unlock(&dentry->d_lock);
}

void ovl_dentry_set_indexed(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	spin_lock(&dentry->d_lock);
	oe->__type |= __OVL_PATH_INDEX;
	spin_unlock(&dentry->d_lock);
}

bool ovl_redirect_dir(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	return ofs->config.redirect_dir && !ofs->noxattr;
}

bool ovl_consistent_fd(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	return ofs->config.consistent_fd;
}

const char *ovl_dentry_get_redirect(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	return oe->redirect;
}

void ovl_dentry_set_redirect(struct dentry *dentry, const char *redirect)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	kfree(oe->redirect);
	oe->redirect = redirect;
}

/*
 * May be called up to twice in the lifetime of an overlay dentry -
 * the first time when updating a ro upper dentry with an orphan index
 * and the second time when updating a linked upper dentry.
 * Linked upper must have the same inode as the index.
 */
void ovl_dentry_update(struct dentry *dentry, struct dentry *upperdentry,
		       bool rocopyup)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	struct inode *inode = upperdentry->d_inode;

	WARN_ON(!inode_is_locked(upperdentry->d_parent->d_inode) &&
		!mutex_is_locked(&OVL_I(d_inode(dentry))->oi_lock));
	WARN_ON(oe->__upperdentry);
	/*
	 * Make sure upperdentry is consistent before making it visible to
	 * ovl_[ro]upperdentry_dereference()
	 */
	smp_wmb();
	if (rocopyup) {
		WARN_ON(oe->__roupperdentry);
		oe->__roupperdentry = upperdentry;
	} else {
		WARN_ON(ovl_dentry_ro_upper(dentry) &&
			oe->__roupperdentry->d_inode != inode);
		oe->__upperdentry = upperdentry;
	}
	ovl_update_type(dentry, d_is_dir(dentry));
}

static void ovl_insert_inode_hash(struct inode *inode, struct inode *realinode)
{
	WARN_ON(!inode_unhashed(inode));
	__insert_inode_hash(inode, (unsigned long) realinode);
}

void ovl_inode_init(struct inode *inode, struct inode *realinode, bool is_upper)
{
	struct ovl_inode_info *oi = OVL_I_INFO(inode);

	if (is_upper) {
		oi->__upperinode = realinode;
		oi->lowerinode = NULL;
		if (!S_ISDIR(realinode->i_mode))
			ovl_insert_inode_hash(inode, realinode);
	} else {
		oi->__upperinode = NULL;
		oi->lowerinode = realinode;
	}
	ovl_copyattr(realinode, inode);
}

struct inode *ovl_inode_real(struct inode *inode, bool *is_upper)
{
	struct ovl_inode_info *oi = OVL_I_INFO(inode);
	struct inode *realinode;

	realinode = READ_ONCE(oi->__upperinode);
	if (is_upper)
		*is_upper = !!realinode;
	if (!realinode)
		realinode = oi->lowerinode;

	return realinode;
}

/*
 * When inodes index is enabled, we hash all non-dir inodes by the address
 * of the lower origin inode. We need to take care on concurrent copy up of
 * different lower hardlinks, that only one alias can set the upper real inode.
 * Copy up of an alias that lost the ovl_inode_update() race will get -EEXIST
 * and needs to d_drop() the overlay dentry of that alias, so the next
 * ovl_lookup() will initialize a new overlay inode for the broken hardlink.
 */
int ovl_inode_update(struct inode *inode, struct inode *upperinode)
{
	struct ovl_inode_info *oi = OVL_I_INFO(inode);
	struct inode *realinode;
	bool indexed = ovl_indexdir(inode->i_sb);

	WARN_ON(!upperinode);

	spin_lock(&inode->i_lock);
	realinode = oi->__upperinode;
	if (!realinode)
		oi->__upperinode = upperinode;
	spin_unlock(&inode->i_lock);

	if (realinode && realinode != upperinode) {
		WARN_ON(!indexed);
		return -EEXIST;
	}

	/* When inodes index is enabled, inode is hashed before copy up */
	if (!S_ISDIR(upperinode->i_mode) && !indexed)
		ovl_insert_inode_hash(inode, upperinode);

	return 0;
}

void ovl_dentry_version_inc(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	WARN_ON(!inode_is_locked(dentry->d_inode));
	oe->version++;
}

u64 ovl_dentry_version_get(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	WARN_ON(!inode_is_locked(dentry->d_inode));
	return oe->version;
}

bool ovl_is_whiteout(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	return inode && IS_WHITEOUT(inode);
}

struct file *ovl_path_open(struct path *path, int flags)
{
	return dentry_open(path, flags | O_NOATIME, current_cred());
}

int ovl_copy_up_start(struct dentry *dentry)
{
	int err;

	err = mutex_lock_interruptible(&OVL_I(d_inode(dentry))->oi_lock);
	if (!err && ovl_dentry_upper(dentry)) {
		err = 1; /* Already copied up */
		mutex_unlock(&OVL_I(d_inode(dentry))->oi_lock);
	}

	return err;
}

void ovl_copy_up_end(struct dentry *dentry)
{
	mutex_unlock(&OVL_I(d_inode(dentry))->oi_lock);
}

bool ovl_check_origin_xattr(struct dentry *dentry)
{
	int res;

	res = vfs_getxattr(dentry, OVL_XATTR_ORIGIN, NULL, 0);

	/* Zero size value means "copied up but origin unknown" */
	if (res >= 0)
		return true;

	return false;
}

bool ovl_check_dir_xattr(struct dentry *dentry, const char *name)
{
	int res;
	char val;

	if (!d_is_dir(dentry))
		return false;

	res = vfs_getxattr(dentry, name, &val, 1);
	if (res == 1 && val == 'y')
		return true;

	return false;
}

int ovl_check_setxattr(struct dentry *dentry, struct dentry *upperdentry,
		       const char *name, const void *value, size_t size,
		       int xerr)
{
	int err;
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;

	if (ofs->noxattr)
		return xerr;

	err = ovl_do_setxattr(upperdentry, name, value, size, 0);

	if (err == -EOPNOTSUPP) {
		pr_warn("overlayfs: cannot set %s xattr on upper\n", name);
		ofs->noxattr = true;
		return xerr;
	}

	return err;
}

int ovl_set_impure(struct dentry *dentry, struct dentry *upperdentry)
{
	int err;

	if (ovl_dentry_is_impure(dentry))
		return 0;

	/*
	 * Do not fail when upper doesn't support xattrs.
	 * Upper inodes won't have origin nor redirect xattr anyway.
	 */
	err = ovl_check_setxattr(dentry, upperdentry, OVL_XATTR_IMPURE,
				 "y", 1, 0);
	if (!err)
		ovl_dentry_set_impure(dentry);

	return err;
}
