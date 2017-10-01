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

/* Check if dentry is pure upper ancestry up to root */
static bool ovl_is_pure_upper_or_root(struct dentry *dentry)
{
	struct dentry *parent = NULL;

	dget(dentry);
	while (!IS_ROOT(dentry) && !ovl_dentry_lower(dentry)) {
		parent = dget_parent(dentry);
		dput(dentry);
		dentry = parent;
	}
	dput(dentry);

	return dentry == dentry->d_sb->s_root;
}

/* TODO: add export_operations method dentry_to_fh() ??? */
static int ovl_dentry_to_fh(struct dentry *dentry, struct fid *fid,
			    int *max_len, int connectable)
{
	struct dentry *origin = ovl_dentry_lower(dentry);
	struct dentry *upper = ovl_dentry_upper(dentry);
	const struct ovl_fh *fh;
	int len = *max_len << 2;

	/*
	 * Overlay root dir inode is hashed and encoded as pure upper, because
	 * root dir dentry is born upper and not indexed. It is not a problem
	 * that root dir is not indexed, because root dentry is pinned to cache.
	 */
	if (dentry == dentry->d_sb->s_root)
		origin = NULL;

	/*
	 * TODO: handle encoding of non pure upper connectable file handle.
	 *       Parent and child may not be on the same layer, so encode
	 *       connectable file handle as an array of self ovl_fh and
	 *       parent ovl_fh (type OVL_FILEID_WITH_PARENT).
	 */
	if (connectable && !ovl_is_pure_upper_or_root(dentry))
		return FILEID_INVALID;

	/*
	 * We can only encode upper with origin if it is indexed, so NFS export
	 * will work only if overlay was mounted with index=all from the start.
	 *
	 * TODO: Either create index from origin information at encode time
	 *       or encode non-indexed origin inode. The latter option requires
	 *       that both non-dir and dir inodes will be indexed on encode
	 *       time if upper has been renamed/redirected and that on decode,
	 *       when index is not found for decoded lower, lookup upper by name
	 *       with same path as decoded lower, while looking for indexed
	 *       renamed parent directories along the path.
	 */
	if (upper && origin && !ovl_test_flag(OVL_INDEX, d_inode(dentry)))
		return FILEID_INVALID;

	/*
	 * Copy up directory on encode to create an index. We need the index
	 * to decode a connected upper dir dentry, which we will use to
	 * reconnect a disconnected overlay dir dentry.
	 *
	 * TODO: walk back lower parent chain on decode to reconnect overlay
	 *       dir dentry until an indexed dir is found, then continue to
	 *       walk back upper parrent chain.
	 */
	if (d_is_dir(dentry) && !upper) {
		int err;

		if (ovl_want_write(dentry))
			return FILEID_INVALID;

		err = ovl_copy_up(dentry);

		ovl_drop_write(dentry);
		if (err)
			return FILEID_INVALID;

		upper = ovl_dentry_upper(dentry);
	}

	/*
	 * The real encoded inode is the same real inode that is used to hash
	 * the overlay inode, so we can find overlay inode when decoding the
	 * real file handle. For merge dir and non-dir with origin, encode the
	 * origin inode. For root dir and pure upper, encode the upper inode.
	 */
	fh = ovl_encode_fh(origin ?: upper, !origin, connectable);
	if (IS_ERR(fh))
		return FILEID_INVALID;

	if (fh->len > len) {
		kfree(fh);
		return FILEID_INVALID;
	}

	memcpy((char *)fid, (char *)fh, len);
	*max_len = len >> 2;
	kfree(fh);

	return OVL_FILEID_WITHOUT_PARENT;
}

/* Find an alias of inode. If @dir is non NULL, find a child alias */
static struct dentry *ovl_find_alias(struct inode *inode, struct inode *dir)
{
	struct dentry *parent, *child;
	struct dentry *alias = NULL;

	/* Parent inode is never provided when encoding a directory */
	if (!dir || WARN_ON(!S_ISDIR(dir->i_mode) || S_ISDIR(inode->i_mode)))
		return d_find_alias(inode);

	/*
	 * Run all of the dentries associated with this parent. Since this is
	 * a directory, there damn well better only be one item on this list.
	 */
	spin_lock(&dir->i_lock);
	hlist_for_each_entry(parent, &dir->i_dentry, d_u.d_alias) {
		/* Find an alias of inode who is a child of parent */
		spin_lock(&parent->d_lock);
		list_for_each_entry(child, &parent->d_subdirs, d_child) {
			if (child->d_inode == inode) {
				alias = dget(child);
				break;
			}
		}
		spin_unlock(&parent->d_lock);
	}
	spin_unlock(&dir->i_lock);

	return alias;
}

static int ovl_encode_inode_fh(struct inode *inode, u32 *fh, int *max_len,
			       struct inode *parent)
{
	struct dentry *dentry = ovl_find_alias(inode, parent);
	int type;

	if (!dentry)
		return FILEID_INVALID;

	type = ovl_dentry_to_fh(dentry, (struct fid *)fh, max_len, !!parent);

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
	struct ovl_fs *ofs = sb->s_fs_info;
	struct inode *inode;
	struct dentry *dentry;
	struct dentry *index = lower ? upper : NULL;
	struct ovl_entry *oe;

	inode = ovl_get_inode(sb, upper, lower, index);
	if (IS_ERR(inode)) {
		dput(upper);
		return ERR_CAST(inode);
	}

	dentry = d_obtain_alias(inode);
	if (IS_ERR(dentry) || dentry == dentry->d_sb->s_root)
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

	/*
	 * This implementation is currently limited to non-dir and merge dirs
	 * with single lower dir. For this reason, NFS export support currently
	 * requires overlay with single lower layer.
	 *
	 * TODO: use ovl_lookup or derivative to populate lowerstack with more
	 *       lower dirs to support NFS export with multi lower layers.
	 */
	oe = ovl_alloc_entry(lower ? 1 : 0);
	if (!oe) {
		dput(dentry);
		return ERR_PTR(-ENOMEM);
	}
	if (lower) {
		oe->lowerstack->dentry = dget(lower);
		oe->lowerstack->mnt = ofs->lower_mnt[0];
	}
	dentry->d_fsdata = oe;

	if (upper) {
		ovl_dentry_set_upper_alias(dentry);
		if (d_is_dir(upper)) {
			size_t len = 0;
			char *redirect = ovl_get_redirect_xattr(upper, &len);

			if (redirect)
				ovl_dentry_set_redirect(dentry, redirect);
			if (ovl_is_opaquedir(upper))
				ovl_dentry_set_opaque(dentry);
		}
	}

	if (index)
		ovl_set_flag(OVL_INDEX, inode);

	return dentry;

}

static struct dentry *ovl_upper_fh_to_d(struct super_block *sb,
					struct ovl_fh *fh, bool to_parent)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct vfsmount *mnt = ofs->upper_mnt;
	struct dentry *upper;

	if (!mnt)
		return NULL;

	upper = ovl_decode_fh(fh, mnt);
	if (IS_ERR_OR_NULL(upper))
		return upper;

	/*
	 * ovl_decode_fh() will return a connected dentry if the encoded real
	 * file handle was connectable (the case of pure upper ancestry).
	 * fh_to_parent() needs to instantiate an overlay dentry from real
	 * upper parent in that case.
	 */
	if (to_parent) {
		struct dentry *parent;

		if (upper->d_flags & DCACHE_DISCONNECTED) {
			dput(upper);
			return NULL;
		}
		parent = dget_parent(upper);
		dput(upper);
		upper = parent;
	}

	/* Find or instantiate a pure upper dentry */
	return ovl_obtain_alias(sb, upper, NULL);
}

static struct dentry *ovl_fh_to_d(struct super_block *sb, struct fid *fid,
				  int fh_len, int fh_type, bool to_parent)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct dentry *upper = NULL;
	struct dentry *index = NULL;
	struct dentry *origin = NULL;
	struct dentry *dentry = NULL;
	struct ovl_fh *fh = (struct ovl_fh *) fid;
	int err, i;

	/* TODO: handle file handle with parent from different layer */
	if (fh_type != OVL_FILEID_WITHOUT_PARENT)
		return ERR_PTR(-EINVAL);

	err = ovl_check_fh_len(fh, fh_len << 2);
	if (err)
		return ERR_PTR(err);

	if (fh->flags & OVL_FH_FLAG_PATH_UPPER)
		return ovl_upper_fh_to_d(sb, fh, to_parent);

	/* TODO: decode parent from fh_type OVL_FILEID_WITH_PARENT */
	if (to_parent)
		return ERR_PTR(-EINVAL);

	/* Find lower layer by UUID and decode */
	for (i = 0; i < ofs->numlower; i++) {
		origin = ovl_decode_fh(fh, ofs->lower_mnt[i]);
		if (origin)
			break;
	}

	if (IS_ERR_OR_NULL(origin))
		return origin;

	/* Lookup index by decoded origin */
	index = ovl_lookup_index(ofs->indexdir, NULL, origin);
	if (IS_ERR(index)) {
		dput(origin);
		return index;
	}
	if (index) {
		/* Get upper dentry from index */
		upper = ovl_index_upper(index, ofs->upper_mnt);
		err = PTR_ERR(upper);
		if (IS_ERR(upper))
			goto out_err;

		err = ovl_verify_origin(upper, origin, false, false);
		if (err)
			goto out_err;
	}

	dentry = ovl_obtain_alias(sb, upper, origin);

out:
	dput(index);
	dput(origin);
	return dentry;

out_err:
	dentry = ERR_PTR(err);
	goto out;
}

static struct dentry *ovl_fh_to_dentry(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	return ovl_fh_to_d(sb, fid, fh_len, fh_type, false);
}

static struct dentry *ovl_fh_to_parent(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	return ovl_fh_to_d(sb, fid, fh_len, fh_type, true);
}

static struct dentry *ovl_get_parent(struct dentry *dentry)
{
	struct dentry *upper;

	/* TODO: handle connecting of non pure upper */
	if (ovl_dentry_lower(dentry))
		return ERR_PTR(-EACCES);

	/*
	 * When ovl_fh_to_d() returns an overlay dentry, its real upper
	 * dentry should be positive and connected. The reconnecting of
	 * the upper dentry is done by ovl_decode_fh() when decoding the
	 * real upper file handle, so here we have the upper dentry parent
	 * and we need to instantiate an overlay dentry with upper dentry
	 * parent.
	 */
	upper = ovl_dentry_upper(dentry);
	if (!upper || (upper->d_flags & DCACHE_DISCONNECTED))
		return ERR_PTR(-ESTALE);

	upper = dget_parent(upper);

	/* Find or instantiate a pure upper dentry */
	return ovl_obtain_alias(dentry->d_sb, upper, NULL);
}

const struct export_operations ovl_export_operations = {
	.encode_fh      = ovl_encode_inode_fh,
	.fh_to_dentry	= ovl_fh_to_dentry,
	.fh_to_parent	= ovl_fh_to_parent,
	.get_parent	= ovl_get_parent,
};
