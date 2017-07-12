/*
 * Overlayfs NFS export support.
 *
 * Amir Goldstein <amir73il@gmail.com>
 *
 * Copyright (C) 2017 CTERA Networks. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include "overlayfs.h"
#include "ovl_entry.h"

/* TODO: add export_operations method dentry_to_fh() ??? */
static int ovl_dentry_to_fh(struct dentry *dentry, struct fid *fid,
			    int *max_len, int connectable)
{
	struct dentry *lower = ovl_dentry_lower(dentry);
	int type;

	/* TODO: handle encoding of non pure upper */
	if (lower)
		return FILEID_INVALID;

	/*
	 * Ask real fs to encode the inode of the real upper dentry.
	 * When decoding we ask real fs for the upper dentry and use
	 * the real inode to get the overlay inode.
	 */
	type = exportfs_encode_fh(ovl_dentry_upper(dentry), fid, max_len,
				  connectable);

	/* TODO: encode an ovl_fh struct and return OVL file handle type */
	return type;
}

static int ovl_encode_inode_fh(struct inode *inode, u32 *fh, int *max_len,
			       struct inode *parent)
{
	struct dentry *dentry = d_find_alias(inode);
	int type;

	if (!dentry)
		return FILEID_INVALID;

	/* TODO: handle encoding of non-dir connectable file handle */
	if (parent)
		return FILEID_INVALID;

	type = ovl_dentry_to_fh(dentry, (struct fid *)fh, max_len, 0);

	dput(dentry);
	return type;
}

/*
 * Find or instantiate an overlay dentry from real dentries.
 * Like d_obtain_alias(inode), ovl_obtain_alias() either
 * takes ownership on the upper dentry reference or puts it
 * before returning an error.
 */
static struct dentry *ovl_obtain_alias(struct super_block *sb,
				       struct dentry *upper,
				       struct dentry *lower)
{
	struct inode *inode;
	struct dentry *dentry;
	struct ovl_entry *oe;

	/* TODO: handle decoding of non pure upper */
	if (lower) {
		dput(upper);
		return ERR_PTR(-EINVAL);
	}

	inode = ovl_get_inode(sb, upper, NULL, NULL);
	if (IS_ERR(inode)) {
		dput(upper);
		return ERR_CAST(inode);
	}

	dentry = d_obtain_alias(inode);
	if (IS_ERR(dentry))
		return dentry;

	if (dentry->d_fsdata) {
		if (WARN_ON(ovl_dentry_lower(dentry) ||
			    ovl_dentry_upper(dentry)->d_inode !=
			    upper->d_inode)) {
			dput(dentry);
			return ERR_PTR(-ESTALE);
		}
		return dentry;
	}

	oe = ovl_alloc_entry(0);
	if (!oe) {
		dput(dentry);
		return ERR_PTR(-ENOMEM);
	}

	dentry->d_fsdata = oe;
	ovl_dentry_set_upper_alias(dentry);

	return dentry;

}

static struct dentry *ovl_fh_to_dentry(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct vfsmount *mnt = ofs->upper_mnt;
	const struct export_operations *real_op;
	struct dentry *upper;

	/* TODO: handle decoding of non pure upper */
	if (!mnt)
		return NULL;

	real_op = mnt->mnt_sb->s_export_op;
	/* TODO: decode ovl_fh format file handle */
	upper = real_op->fh_to_dentry(mnt->mnt_sb, fid, fh_len, fh_type);
	if (IS_ERR_OR_NULL(upper))
		return upper;

	/* Find or instantiate a pure upper dentry */
	return ovl_obtain_alias(sb, upper, NULL);
}

const struct export_operations ovl_export_operations = {
	.encode_fh      = ovl_encode_inode_fh,
	.fh_to_dentry	= ovl_fh_to_dentry,
};
