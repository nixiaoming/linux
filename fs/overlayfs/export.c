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
#include <linux/cred.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/ratelimit.h>
#include "overlayfs.h"

/*
 * We only need to encode origin if there is a chance that the same object was
 * encoded pre copy up and then we need to stay consistent with the same
 * encoding also after copy up. If non-pure upper is not indexed, then it was
 * copied up before NFS export was enabled. In that case we don't need to worry
 * about staying consistent with pre copy up encoding and we encode an upper
 * file handle.
 *
 * The following table summarizes the different file handle encodings used for
 * different overlay object types with overlay configuration of single and
 * multiple lower layers:
 *
 *  Object type		| Single lower	| Multiple lower
 * --------------------------------------------------------
 *  Pure upper		|	U	|	U
 *  Non-indexed upper	|	U	|	U
 *  Indexed non-dir	|	L	|	L
 *  Lower non-dir	|	L	|	L
 *  Indexed directory	|	L	|	U
 *  Lower directory	|	L	|	U (*)
 *
 * U = upper file handle
 * L = lower file handle
 *
 * The important thing to note is that within the same overlay configuration
 * an overlay object encoding is invariant to copy up (i.e. Lower->Indexed).
 *
 * (*) If decoding an overlay dir from origin is not implemented, we do not
 * encode by lower inode, because if file gets copied up after we encoded it,
 * we won't be able to decode the file handle. To mitigate this case, we copy
 * up the lower dir first and then encode an upper dir file handle.
 */
static bool ovl_should_encode_origin(struct dentry *dentry)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;

	/* Root dentry was born upper */
	if (dentry == dentry->d_sb->s_root)
		return false;

	/*
	 * Decoding a merge dir, whose origin's parent may be on a different
	 * lower layer then the overlay parent's origin is not implemented.
	 * As a simple aproximation, we do not encode lower dir file handles
	 * when overlay has multiple lower layers.
	 */
	if (d_is_dir(dentry) && ofs->numlower > 1)
		return false;

	/* Decoding a non-indexed upper from origin is not implemented */
	if (ovl_dentry_upper(dentry) &&
	    !ovl_test_flag(OVL_INDEX, d_inode(dentry)))
		return false;

	return true;
}

static int ovl_encode_maybe_copy_up(struct dentry *dentry)
{
	int err;

	if (ovl_dentry_upper(dentry))
		return 0;

	err = ovl_want_write(dentry);
	if (err)
		return err;
	err = ovl_copy_up(dentry);

	ovl_drop_write(dentry);
	return err;
}

int ovl_d_to_fh(struct dentry *dentry, char *buf, int buflen)
{
	struct dentry *origin = ovl_dentry_lower(dentry);
	struct ovl_fh *fh = NULL;
	int err;

	/*
	 * If we should not encode a lower dir file handle, copy up and encode
	 * an upper dir file handle.
	 */
	if (!ovl_should_encode_origin(dentry)) {
		err = ovl_encode_maybe_copy_up(dentry);
		if (err)
			goto fail;

		origin = NULL;
	}

	/* Encode an upper or origin file handle */
	fh = ovl_encode_fh(origin ?: ovl_dentry_upper(dentry), !origin);

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

static int ovl_dentry_to_fh(struct dentry *dentry, u32 *fid, int *max_len)
{
	int res, len = *max_len << 2;

	res = ovl_d_to_fh(dentry, (char *)fid, len);
	if (res <= 0)
		return FILEID_INVALID;

	len = res;

	/* Round up to dwords */
	*max_len = (len + 3) >> 2;
	return OVL_FILEID;
}

static int ovl_encode_inode_fh(struct inode *inode, u32 *fid, int *max_len,
			       struct inode *parent)
{
	struct dentry *dentry;
	int type;

	/* TODO: encode connectable file handles */
	if (parent)
		return FILEID_INVALID;

	dentry = d_find_any_alias(inode);
	if (WARN_ON(!dentry))
		return FILEID_INVALID;

	type = ovl_dentry_to_fh(dentry, fid, max_len);

	dput(dentry);
	return type;
}

/*
 * Find or instantiate an overlay dentry from real dentries and index.
 */
static struct dentry *ovl_obtain_alias(struct super_block *sb,
				       struct dentry *upper_alias,
				       struct ovl_path *lowerpath,
				       struct dentry *index)
{
	struct dentry *lower = lowerpath ? lowerpath->dentry : NULL;
	struct dentry *upper = upper_alias ?: index;
	struct dentry *dentry;
	struct inode *inode;
	struct ovl_entry *oe;

	/* We get overlay directory dentries with ovl_lookup_real() */
	if (d_is_dir(upper ?: lower))
		return ERR_PTR(-EIO);

	inode = ovl_get_inode(sb, dget(upper), lower, index, !!lower);
	if (IS_ERR(inode)) {
		dput(upper);
		return ERR_CAST(inode);
	}

	dentry = d_obtain_alias(inode);
	if (IS_ERR(dentry) || dentry->d_fsdata)
		return dentry;

	oe = ovl_alloc_entry(!!lower);
	if (!oe) {
		dput(dentry);
		return ERR_PTR(-ENOMEM);
	}

	dentry->d_fsdata = oe;
	if (upper_alias)
		ovl_dentry_set_upper_alias(dentry);
	if (lower) {
		oe->lowerstack->dentry = dget(lower);
		oe->lowerstack->layer = lowerpath->layer;
	}

	if (index)
		ovl_set_flag(OVL_INDEX, inode);

	return dentry;
}

static struct dentry *ovl_dentry_real_at(struct dentry *dentry, bool is_upper)
{
	return is_upper ? ovl_dentry_upper(dentry) : ovl_dentry_lower(dentry);
}

/*
 * Lookup a child overlay dentry whose real dentry is @real.
 * If @is_upper is true then we lookup a child overlay dentry with the same
 * name as the real dentry. Otherwise, we need to consult index for lookup.
 */
static struct dentry *ovl_lookup_real_one(struct dentry *parent,
					  struct dentry *real, bool is_upper)
{
	struct dentry *this;
	struct qstr *name = &real->d_name;
	int err;

	/* TODO: use index when looking up by lower real dentry */

	/* Lookup overlay dentry by real name */
	this = lookup_one_len_unlocked(name->name, parent, name->len);
	err = PTR_ERR(this);
	if (IS_ERR(this)) {
		goto fail;
	} else if (!this || !this->d_inode) {
		dput(this);
		err = -ENOENT;
		goto fail;
	} else if (ovl_dentry_real_at(this, is_upper) != real) {
		dput(this);
		err = -ESTALE;
		goto fail;
	}

	return this;

fail:
	pr_warn_ratelimited("overlayfs: failed to lookup one by real (%pd2, is_upper=%d, parent=%pd2, err=%i)\n",
			    real, is_upper, parent, err);
	return ERR_PTR(err);
}

static struct dentry *ovl_lookup_real(struct super_block *sb,
				      struct dentry *real, bool is_upper);

/*
 * Lookup an indexed or hashed overlay dentry by real inode.
 */
static struct dentry *ovl_lookup_real_inode(struct super_block *sb,
					    struct dentry *real, bool is_upper)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct dentry *index = NULL;
	struct dentry *this = NULL;
	struct inode *inode;

	/*
	 * Decoding upper dir from index is expensive, so first try to lookup
	 * overlay dentry in inode/dcache.
	 */
	inode = ovl_lookup_inode(sb, real, is_upper);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (inode) {
		this = d_find_any_alias(inode);
		iput(inode);
	}

	/*
	 * For decoded lower dir file handle, lookup index by origin to check
	 * if lower dir was copied up and and/or removed.
	 */
	if (!this && !is_upper && !WARN_ON(!d_is_dir(real))) {
		index = ovl_lookup_index(ofs, NULL, real, false);
		if (IS_ERR(index))
			return index;
	}

	/* Get connected upper overlay dir from index */
	if (index) {
		struct dentry *upper = ovl_index_upper(ofs, index);

		dput(index);
		if (IS_ERR_OR_NULL(upper))
			return upper;

		/*
		 * ovl_lookup_real(is_upper=false) may call recursively once to
		 * ovl_lookup_real(is_upper=true). The first level call walks
		 * back lower parents to the topmost indexed parent. The second
		 * recursive call walks back from indexed upper to the topmost
		 * connected/hashed upper parent (or up to root).
		 */
		this = ovl_lookup_real(sb, upper, true);
		dput(upper);
	}

	if (!this)
		return NULL;

	if (WARN_ON(ovl_dentry_real_at(this, is_upper) != real)) {
		dput(this);
		this = ERR_PTR(-EIO);
	}

	return this;
}

/*
 * Lookup an indexed or hashed overlay dentry, whose real dentry is an
 * ancestor of @real.
 */
static struct dentry *ovl_lookup_real_ancestor(struct super_block *sb,
					       struct dentry *real,
					       bool is_upper)
{
	struct dentry *real_root = ovl_dentry_real_at(sb->s_root, is_upper);
	struct dentry *next, *parent = NULL;
	struct dentry *ancestor;

	if (real_root == real)
		return dget(sb->s_root);

	/* Find the topmost indexed or hashed ancestor */
	next = dget(real);
	for (;;) {
		parent = dget_parent(next);

		/*
		 * Lookup a matching overlay dentry in inode/dentry
		 * cache or in index by real inode.
		 */
		ancestor = ovl_lookup_real_inode(sb, next, is_upper);
		if (ancestor)
			break;

		if (real_root == parent) {
			ancestor = dget(sb->s_root);
			break;
		}

		/*
		 * If @real has been moved out of the layer root directory,
		 * we will eventully hit the real fs root.
		 */
		if (parent == next) {
			ancestor = ERR_PTR(-EXDEV);
			break;
		}

		dput(next);
		next = parent;
	}

	dput(parent);
	dput(next);

	return ancestor;
}

/*
 * Lookup an overlay dentry whose real dentry is @real.
 * If @is_upper is true then we lookup an overlay dentry with the same path
 * as the real dentry. Otherwise, we need to consult index for lookup.
 */
static struct dentry *ovl_lookup_real(struct super_block *sb,
				      struct dentry *real, bool is_upper)
{
	struct dentry *connected;
	int err = 0;

	connected = ovl_lookup_real_ancestor(sb, real, is_upper);
	if (IS_ERR_OR_NULL(connected))
		return connected;

	while (!err) {
		struct dentry *next, *this;
		struct dentry *parent = NULL;
		struct dentry *real_connected = ovl_dentry_real_at(connected,
								   is_upper);

		if (real_connected == real)
			break;

		next = dget(real);
		/* find the topmost dentry not yet connected */
		for (;;) {
			parent = dget_parent(next);

			if (real_connected == parent)
				break;

			/*
			 * If real file has been moved out of the layer root
			 * directory, we will eventully hit the real fs root.
			 */
			if (parent == next) {
				err = -EXDEV;
				break;
			}

			dput(next);
			next = parent;
		}

		if (!err) {
			this = ovl_lookup_real_one(connected, next, is_upper);
			if (!IS_ERR(this)) {
				dput(connected);
				connected = this;
			} else {
				err = PTR_ERR(this);
			}
		}

		dput(parent);
		dput(next);
	}

	if (err)
		goto fail;

	return connected;

fail:
	pr_warn_ratelimited("overlayfs: failed to lookup by real (%pd2, is_upper=%d, connected=%pd2, err=%i)\n",
			    real, is_upper, connected, err);
	dput(connected);
	return ERR_PTR(err);
}

/*
 * Get an overlay dentry from upper/lower real dentries and index.
 */
static struct dentry *ovl_get_dentry(struct super_block *sb,
				     struct dentry *upper,
				     struct ovl_path *lowerpath,
				     struct dentry *index)
{
	struct dentry *real = upper ?: (index ?: lowerpath->dentry);

	/*
	 * Obtain a disconnected overlay dentry from a non-dir real dentry
	 * and index.
	 */
	if (!d_is_dir(real))
		return ovl_obtain_alias(sb, upper, lowerpath, index);

	/* Removed empty directory? */
	if ((real->d_flags & DCACHE_DISCONNECTED) || d_unhashed(real))
		return ERR_PTR(-ENOENT);

	/*
	 * If real dentry is connected and hashed, get a connected overlay
	 * dentry whose real dentry is @real.
	 */
	return ovl_lookup_real(sb, real, !!upper);
}

static struct dentry *ovl_upper_fh_to_d(struct super_block *sb,
					struct ovl_fh *fh)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct ovl_layer layer = { .mnt = ofs->upper_mnt };
	struct dentry *dentry;
	struct dentry *upper;

	if (!ofs->upper_mnt)
		return ERR_PTR(-EACCES);

	upper = ovl_decode_fh(fh, &layer);
	if (IS_ERR_OR_NULL(upper))
		return upper;

	dentry = ovl_get_dentry(sb, upper, NULL, NULL);
	dput(upper);

	return dentry;
}

static struct dentry *ovl_lower_fh_to_d(struct super_block *sb,
					struct ovl_fh *fh)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct ovl_path origin = { };
	struct ovl_path *stack = &origin;
	struct dentry *dentry = NULL;
	struct dentry *index = NULL;
	struct inode *inode = NULL;
	bool is_deleted = false;
	int err;

	/* First lookup indexed upper by fh */
	index = ovl_get_index_fh(ofs, fh);
	err = PTR_ERR(index);
	if (IS_ERR(index)) {
		if (err != -ESTALE)
			return ERR_PTR(err);

		/* Found a whiteout index - treat as deleted inode */
		is_deleted = true;
		index = NULL;
	}

	/* Then try to get upper dir by index */
	if (index && d_is_dir(index)) {
		struct dentry *upper = ovl_index_upper(ofs, index);

		err = PTR_ERR(upper);
		if (IS_ERR_OR_NULL(upper))
			goto out_err;

		dentry = ovl_get_dentry(sb, upper, NULL, NULL);
		dput(upper);
		goto out;
	}

	/* Then lookup origin by fh */
	err = ovl_check_origin_fh(fh, NULL, ofs->lower_layers, ofs->numlower,
				  &stack);
	if (err) {
		goto out_err;
	} else if (!index && !origin.dentry) {
		return NULL;
	} else if (index && origin.dentry) {
		err = ovl_verify_origin(index, origin.dentry, false, false);
		if (err)
			goto out_err;
	} else if (is_deleted && origin.dentry && !d_is_dir(origin.dentry)) {
		/* Lookup deleted overlay inode by origin inode */
		inode = ovl_lookup_inode(sb, origin.dentry, false);
		err = -ESTALE;
		if (!inode || atomic_read(&inode->i_count) == 1)
			goto out_err;

		/* Deleted but still open? */
		index = dget(ovl_i_dentry_upper(inode));
	}

	dentry = ovl_get_dentry(sb, NULL, &origin, index);

out:
	dput(origin.dentry);
	dput(index);
	iput(inode);
	return dentry;

out_err:
	dentry = ERR_PTR(err);
	goto out;
}

static struct dentry *ovl_fh_to_dentry(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	struct dentry *dentry = NULL;
	struct ovl_fh *fh = (struct ovl_fh *) fid;
	int len = fh_len << 2;
	unsigned int flags = 0;
	bool nested;
	int err;

	err = -EINVAL;
	if (fh_type != OVL_FILEID)
		goto out_err;

	err = ovl_check_fh_len(fh, len);
	if (err)
		goto out_err;

	/*
	 * Do not try to decode nested upper from upper_mnt. Decode nested file
	 * handle only from nested lower overlayfs and clear the 'nested' flag
	 * before decoding from lower overlayfs.
	 */
	flags = fh->flags;
	nested = (fh->flags & OVL_FH_FLAG_PATH_NESTED);
	fh->flags &= ~OVL_FH_FLAG_PATH_NESTED;

	err = -ESTALE;
	if (nested && ovl_dentry_lower(sb->s_root)->d_sb->s_type != &ovl_fs_type)
		goto out_err;

	dentry = (flags & OVL_FH_FLAG_PATH_UPPER) && !nested ?
		 ovl_upper_fh_to_d(sb, fh) :
		 ovl_lower_fh_to_d(sb, fh);
	err = PTR_ERR(dentry);
	if (IS_ERR(dentry) && err != -ESTALE)
		goto out_err;

	return dentry;

out_err:
	pr_warn_ratelimited("overlayfs: failed to decode file handle (len=%d, type=%d, flags=%x, err=%i)\n",
			    len, fh_type, flags, err);
	return ERR_PTR(err);
}

static struct dentry *ovl_fh_to_parent(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	pr_warn_ratelimited("overlayfs: connectable file handles not supported; use 'no_subtree_check' exportfs option.\n");
	return ERR_PTR(-EACCES);
}

static int ovl_get_name(struct dentry *parent, char *name,
			struct dentry *child)
{
	/*
	 * ovl_fh_to_dentry() returns connected dir overlay dentries and
	 * ovl_fh_to_parent() is not implemented, so we should not get here.
	 */
	WARN_ON_ONCE(1);
	return -EIO;
}

static struct dentry *ovl_get_parent(struct dentry *dentry)
{
	/*
	 * ovl_fh_to_dentry() returns connected dir overlay dentries, so we
	 * should not get here.
	 */
	WARN_ON_ONCE(1);
	return ERR_PTR(-EIO);
}

const struct export_operations ovl_export_operations = {
	.encode_fh      = ovl_encode_inode_fh,
	.fh_to_dentry	= ovl_fh_to_dentry,
	.fh_to_parent	= ovl_fh_to_parent,
	.get_name	= ovl_get_name,
	.get_parent	= ovl_get_parent,
};
