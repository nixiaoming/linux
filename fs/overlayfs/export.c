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
#include <linux/ratelimit.h>
#include "overlayfs.h"

int ovl_d_to_fh(struct dentry *dentry, char *buf, int buflen)
{
	struct dentry *origin = ovl_dentry_lower(dentry);
	struct dentry *upper = ovl_dentry_upper(dentry);
	struct ovl_fh *fh = NULL;
	int err;

	/*
	 * Overlay root dir inode is hashed and encoded as pure upper, because
	 * root dir dentry is born upper and not indexed. It is not a problem
	 * that root dir is not indexed, because root dentry is pinned to cache.
	 */
	if (dentry == dentry->d_sb->s_root)
		origin = NULL;

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
	err = -EIO;
	if (upper && origin && !ovl_test_flag(OVL_INDEX, d_inode(dentry)))
		goto fail;

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
		err = ovl_want_write(dentry);
		if (err)
			goto fail;

		err = ovl_copy_up(dentry);

		ovl_drop_write(dentry);
		if (err)
			goto fail;

		upper = ovl_dentry_upper(dentry);
	}

	/*
	 * The real encoded inode is the same real inode that is used to hash
	 * the overlay inode, so we can find overlay inode when decoding the
	 * real file handle. For merge dir and non-dir with origin, encode the
	 * origin inode. For root dir and pure upper, encode the upper inode.
	 */
	fh = ovl_encode_fh(origin ?: upper, !origin, false);

	/*
	 * Set the nested flag on the if encoding file handle from nested lower
	 * overlay. Nesting depth cannot be larger than 1, so one bit is enough.
	 */
	if (origin && origin->d_sb->s_type == &ovl_fs_type)
		fh->flags |= OVL_FH_FLAG_PATH_NESTED;

	err = -EOVERFLOW;
	if (fh->len > buflen)
		goto fail;

	memcpy(buf, (char *)fh, fh->len);
	err = fh->len;

out:
	kfree(fh);
	return err;

fail:
	pr_warn_ratelimited("overlayfs: failed to encode file handle (%pd2, err=%i, buflen=%d, len=%d, type=%d)\n",
			    dentry, err, buflen, fh ? (int)fh->len : 0,
			    fh ? fh->type : 0);
	goto out;
}

/* TODO: add export_operations method dentry_to_fh() ??? */
static int ovl_dentry_to_fh(struct dentry *dentry, u32 *fid, int *max_len,
			    int connectable)
{
	struct dentry *parent;
	char *p = (char *)fid;
	int res, len, rem = *max_len << 2;
	int type = OVL_FILEID_WITHOUT_PARENT;

	if (WARN_ON(connectable && d_is_dir(dentry)))
		connectable = 0;

	res = ovl_d_to_fh(dentry, p, rem);
	if (res <= 0)
		return FILEID_INVALID;

	len = res;

	if (connectable) {
		/* Encode parent fh after child fh */
		parent = dget_parent(dentry);
		p += res;
		rem -= res;
		res = ovl_d_to_fh(parent, p, rem);
		dput(parent);
		if (res <= 0)
			return FILEID_INVALID;

		len += res;
		type = OVL_FILEID_WITH_PARENT;
	}

	/* Round up to dwords */
	*max_len = (len + 3) >> 2;
	return type;
}

/* Find an alias of inode. If @dir is non NULL, find a child alias */
static struct dentry *ovl_find_alias(struct inode *inode, struct inode *dir)
{
	struct dentry *dentry, *parent;
	struct dentry *toput = NULL;

	/* Parent inode is never provided when encoding a directory */
	if (!dir || WARN_ON(!S_ISDIR(dir->i_mode) || S_ISDIR(inode->i_mode)))
		return d_find_alias(inode);

	/* Find an alias of inode who is a child of parent dir */
	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_u.d_alias) {
		dget(dentry);
		spin_unlock(&inode->i_lock);
		if (toput)
			dput(toput);
		parent = dget_parent(dentry);
		if (parent && parent->d_inode == dir) {
			dput(parent);
			return dentry;
		}
		dput(parent);
		spin_lock(&inode->i_lock);
		toput = dentry;
	}
	spin_unlock(&inode->i_lock);

	if (toput)
		dput(toput);

	return NULL;
}

static int ovl_encode_inode_fh(struct inode *inode, u32 *fid, int *max_len,
			       struct inode *parent)
{
	struct dentry *dentry = ovl_find_alias(inode, parent);
	int type;

	/*
	 * This is called from exportfs_encode_inode_fh(), which is called from
	 * exportfs_encode_fh() that hold a reference on both inode and parent
	 * dentries.
	 *
	 * TODO: add export_operations method dentry_to_fh() so we get the
	 *       file and parent dentries instead of having to find them.
	 */
	if (WARN_ON(!dentry))
		return FILEID_INVALID;

	type = ovl_dentry_to_fh(dentry, fid, max_len, !!parent);

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

	/* NFS export requires single lower, so numlower = !!lower */
	inode = ovl_get_inode(sb, upper, lower, index, !!lower);
	if (IS_ERR(inode)) {
		dput(upper);
		return ERR_CAST(inode);
	}

	dentry = d_obtain_alias(inode);
	if (IS_ERR(dentry) || dentry->d_fsdata)
		return dentry;

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
		oe->lowerstack->layer = &ofs->lower_layers[0];
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

static struct dentry *ovl_fh_to_d(struct super_block *sb, struct fid *fid,
				  int fh_len, int fh_type, bool to_parent)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct dentry *upper = NULL;
	struct dentry *origin = NULL;
	struct dentry *dentry = NULL;
	struct inode *inode;
	struct ovl_fh *fh = (struct ovl_fh *) fid;
	int len = fh_len << 2;
	int err, i;
	bool nested;

	err = -EINVAL;
	switch(fh_type) {
		case OVL_FILEID_WITHOUT_PARENT:
			if (to_parent)
				goto out_err;
			break;
		case OVL_FILEID_WITH_PARENT:
			break;
		default:
			goto out_err;
	}

	err = ovl_check_fh_len(fh, len);
	if (err)
		goto out_err;

	if (to_parent) {
		/* Seek to parent fh after child fh */
		len -= fh->len;
		fh = ((void *) fid) + fh->len;
		err = ovl_check_fh_len(fh, len);
		if (err)
			goto out_err;
	}

	/*
	 * Do not try to decode nested upper from upper_mnt.
	 * Clear the 'nested' flag before decoding from lower overlayfs.
	 */
	nested = (fh->flags & OVL_FH_FLAG_PATH_NESTED);
	fh->flags &= ~OVL_FH_FLAG_PATH_NESTED;
	if (!nested && (fh->flags & OVL_FH_FLAG_PATH_UPPER)) {
		err = -ENOENT;
		if (!ofs->upper_mnt)
			goto out_err;

		upper = ovl_decode_fh(fh, ofs->upper_mnt);
		if (IS_ERR_OR_NULL(upper)) {
			err = PTR_ERR(upper);
			if (err && err != -ESTALE)
				goto out_err;
			goto notfound;
		}

		goto obtain_alias;
	}

	/*
	 * Find lower layer by UUID and decode. Find nested file handle in
	 * nested lower overlayfs. Nested overlay will match UUID to its own
	 * lower/upper layers.
	 */
	for (i = 0; i < ofs->numlower; i++) {
		struct vfsmount *mnt = ofs->lower_layers[i].mnt;

		if (nested && mnt->mnt_sb->s_type != &ovl_fs_type)
			continue;

		origin = ovl_decode_fh(fh, mnt);
		if (origin)
			break;
	}

	if (IS_ERR(origin)) {
		err = PTR_ERR(origin);
		if (err != -ESTALE)
			goto out_err;
		goto notfound;
	}

	/* Lookup overlay inode in inode cache by decoded origin inode */
	if (origin) {
		inode = ovl_lookup_inode(sb, origin);
		if (inode) {
			upper = dget(ovl_i_dentry_upper(inode));
			iput(inode);
			goto obtain_alias;
		}
	}

	/*
	 * Lookup indexed upper by origin fh. Even if we failed to decode
	 * origin, we want to find an upper inode by index if it exists.
	 */
	upper = ovl_lookup_upper(ofs->indexdir, fh, ofs->upper_mnt);
	if (IS_ERR_OR_NULL(upper)) {
		err = PTR_ERR(upper);
		if (err && err != -ESTALE)
			goto out_err;
		goto notfound;
	}

	if (upper && origin) {
		err = ovl_verify_origin(upper, origin, false, false);
		if (err)
			goto out_err;
	}

obtain_alias:
	dentry = ovl_obtain_alias(sb, upper, origin);

out:
	if (!IS_ERR(origin))
		dput(origin);
	return dentry;

out_err:
	pr_warn_ratelimited("overlayfs: failed to decode file handle (len=%d, type=%d, err=%i, upper=%ld, origin=%ld)\n",
			    len, fh_type, err,
			    IS_ERR(upper) ? PTR_ERR(upper) : !!upper,
			    IS_ERR(origin) ? PTR_ERR(origin) : !!origin);
	if (!IS_ERR(upper))
		dput(upper);
notfound:
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
	struct dentry *root = dentry->d_sb->s_root;
	struct ovl_entry *roe = root->d_fsdata;
	struct dentry *parent;
	struct dentry *upper;
	struct ovl_path *stack = NULL;
	unsigned int ctr = 0;
	int err;

	/*
	 * When ovl_fh_to_d() returns an overlay dentry, its real upper
	 * dentry should be positive and connected. The reconnecting of
	 * the upper dentry is done by ovl_decode_fh() when decoding the
	 * real upper file handle, so here we have the upper dentry parent
	 * and we need to instantiate an overlay dentry with upper dentry
	 * parent and the lower dir pointed to by origin xattr.
	 *
	 * TODO: handle reconnecting of non upper overlay dentry.
	 */
	upper = ovl_dentry_upper(dentry);
	err = -EIO;
	if (!upper || (upper->d_flags & DCACHE_DISCONNECTED))
		goto out_err;

	upper = dget_parent(upper);
	if (upper == ovl_dentry_upper(root)) {
		dput(upper);
		return dget(root);
	}

	/* Check if parent is merge dir or pure upper */
	err = ovl_check_origin(upper, roe->lowerstack, roe->numlower,
			       &stack, &ctr);
	if (err)
		goto out_err;

	/* Find or instantiate an upper dentry */
	parent = ovl_obtain_alias(dentry->d_sb, upper, stack[0].dentry);
	dput(stack[0].dentry);

out:
	kfree(stack);
	return parent;

out_err:
	pr_warn_ratelimited("overlayfs: failed to decode parent (%pd2, err=%i)\n",
			    dentry, err);
	dput(upper);
	parent = ERR_PTR(err);
	goto out;
}

const struct export_operations ovl_export_operations = {
	.encode_fh      = ovl_encode_inode_fh,
	.fh_to_dentry	= ovl_fh_to_dentry,
	.fh_to_parent	= ovl_fh_to_parent,
	.get_parent	= ovl_get_parent,
};
