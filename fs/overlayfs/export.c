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
 * different overlay object types with the subtree_check (i.e. connectable) and
 * no_subtree_check NFS exports variants:
 *
 *  Object type		| subtree_check	| no_subtree_check
 * --------------------------------------------------------
 *  Pure upper		|	U	|	U
 *  Non-indexed upper	|	U	|	U
 *  Indexed non-dir	|	U	|	L
 *  Lower non-dir	|	U (*)	|	L
 *  Indexed/lower dir:	|		|
 *   ofs->numlower == 1	|	L	|	L
 *   ofs->numlower >= 2	|	U (*)	|	U (*)
 *
 * U = upper file handle
 * L = lower file handle
 *
 * The important thing to note is that within the same NFS export variant
 * an overlay object encoding is invariant to copy up (i.e. Lower->Indexed).
 *
 * (*) If decoding an overlay dentry from origin is not implemented, we do not
 * encode by lower inode, because if file gets copied up after we encoded it,
 * we won't be able to decode the file handle. To mitigate those cases, we
 * copy up the lower file first and then encode an upper file handle.
 */
static bool ovl_should_encode_origin(struct dentry *dentry, int connectable)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;

	/* Root dentry was born upper */
	if (dentry == dentry->d_sb->s_root)
		return false;

	/* Decoding a connectable non-dir from origin is not implemented */
	if (connectable)
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

	if (ovl_dentry_upper(dentry) && ovl_dentry_has_upper_alias(dentry))
		return 0;

	err = ovl_want_write(dentry);
	if (err)
		return err;

	err = ovl_copy_up(dentry);

	ovl_drop_write(dentry);
	return err;
}

int ovl_d_to_fh(struct dentry *dentry, char *buf, int buflen, int connectable)
{
	struct dentry *upper;
	struct dentry *origin = ovl_dentry_lower(dentry);
	struct ovl_fh *fh = NULL;
	int err;

	/*
	 * If we should not encode a lower file handle, copy up and encode an
	 * upper file handle.
	 */
	if (!ovl_should_encode_origin(dentry, connectable)) {
		err = ovl_encode_maybe_copy_up(dentry);
		if (err)
			goto fail;

		origin = NULL;
	}

	upper = connectable ? ovl_dentry_upper_alias(dentry) :
			      ovl_dentry_upper(dentry);

	/* Encode an upper or origin file handle */
	fh = ovl_encode_fh(origin ?: upper, !origin, connectable);

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

static int ovl_dentry_to_fh(struct dentry *dentry, u32 *fid, int *max_len,
			    int connectable)
{
	int res, len = *max_len << 2;

	if (WARN_ON(connectable && d_is_dir(dentry)))
		connectable = 0;

	res = ovl_d_to_fh(dentry, (char *)fid, len, connectable);
	if (res <= 0)
		return FILEID_INVALID;

	len = res;

	/* Round up to dwords */
	*max_len = (len + 3) >> 2;
	return OVL_FILEID;
}

/* Find an alias of inode. If @dir is non NULL, find a child alias */
static struct dentry *ovl_find_alias(struct inode *inode, struct inode *dir)
{
	struct dentry *dentry, *parent;
	struct dentry *toput = NULL;

	/* Parent inode is never provided when encoding a directory */
	if (!dir || WARN_ON(!S_ISDIR(dir->i_mode) || S_ISDIR(inode->i_mode)))
		return d_find_any_alias(inode);

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
	 *       dentry instead of having to find it.
	 */
	if (WARN_ON(!dentry))
		return FILEID_INVALID;

	type = ovl_dentry_to_fh(dentry, fid, max_len, !!parent);

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
		ovl_dentry_set_upper_alias(dentry, dget(upper_alias));
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

	connected = dget(sb->s_root);
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
	 * Obtain a disconnected overlay dentry from a disconnected non-dir
	 * real lower dentry and index.
	 */
	if (!upper && !d_is_dir(real))
		return ovl_obtain_alias(sb, NULL, lowerpath, index);

	/*
	 * If real dentry is connected and hashed, get a connected overlay
	 * dentry whose real dentry is @real.
	 */
	if (!(real->d_flags & DCACHE_DISCONNECTED) && !d_unhashed(real)) {
		return ovl_lookup_real(sb, real, !!upper);
	} else if (d_is_dir(real)) {
		/* Removed empty directory? */
		return ERR_PTR(-ENOENT);
	}

	/*
	 * Obtain a disconnected overlay dentry from a disconnected non-dir
	 * real upper dentry.
	 */
	return ovl_obtain_alias(sb, upper, NULL, NULL);
}

static struct dentry *ovl_upper_fh_to_d(struct super_block *sb,
					struct ovl_fh *fh, bool to_parent)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct ovl_layer layer = { .mnt = ofs->upper_mnt };
	struct dentry *dentry;
	struct dentry *tmp, *upper;

	if (!ofs->upper_mnt)
		return ERR_PTR(-EACCES);

	if (!(fh->flags & OVL_FH_FLAG_WITH_PARENT)) {
		/* Cannot connect a non-connectable file handle */
		if (to_parent)
			return ERR_PTR(-ENOENT);

		/* tell ovl_decode_fh() we accept disconnected */
		layer.idx = -1;
	}

	upper = ovl_decode_fh(fh, &layer);
	if (IS_ERR_OR_NULL(upper))
		return upper;

	if (to_parent) {
		if (IS_ROOT(upper)) {
			dput(upper);
			return ERR_PTR(-ECHILD);
		}

		tmp = upper;
		upper = dget_parent(upper);
		dput(tmp);
	}

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

	/* Non-upper connectable file handles are not supported */
	if (fh->flags & OVL_FH_FLAG_WITH_PARENT)
		return ERR_PTR(-EACCES);

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
		inode = ovl_lookup_inode(sb, origin.dentry);
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

static struct dentry *ovl_fh_to_d(struct super_block *sb, struct fid *fid,
				  int fh_len, int fh_type, bool to_parent)
{
	struct dentry *dentry = NULL;
	struct ovl_fh *fh = (struct ovl_fh *) fid;
	int len = fh_len << 2;
	unsigned int flags = 0;
	int err;

	err = -EINVAL;
	if (fh_type != OVL_FILEID)
		goto out_err;

	err = ovl_check_fh_len(fh, len);
	if (err)
		goto out_err;

	flags = fh->flags;
	dentry = (flags & OVL_FH_FLAG_PATH_UPPER) ?
		 ovl_upper_fh_to_d(sb, fh, to_parent) :
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

static int ovl_get_name(struct dentry *parent, char *name,
			struct dentry *child)
{
	struct dentry *upper = ovl_dentry_upper(child);

	/* ovl_fh_to_d() returns connected dir overlay dentries */
	if (d_is_dir(child) || !upper || (upper->d_flags & DCACHE_DISCONNECTED))
		goto fail;

	spin_lock(&upper->d_lock);
	memcpy(name, upper->d_name.name, upper->d_name.len);
	name[upper->d_name.len] = '\0';
	spin_unlock(&upper->d_lock);

	return 0;

fail:
	pr_warn_ratelimited("overlayfs: failed to get name (%pd2, ino=%lu, is_dir=%d, upper=%pd2)\n",
			    parent, d_inode(child)->i_ino, d_is_dir(child),
			    upper);
	return -EIO;
}

static struct dentry *ovl_get_parent(struct dentry *dentry)
{
	/* ovl_fh_to_d() returns connected dir overlay dentries */
	pr_warn_ratelimited("overlayfs: failed to decode parent (%pd2, upper=%pd2)\n",
			    dentry, ovl_dentry_upper(dentry));
	return ERR_PTR(-EIO);
}

const struct export_operations ovl_export_operations = {
	.encode_fh      = ovl_encode_inode_fh,
	.fh_to_dentry	= ovl_fh_to_dentry,
	.fh_to_parent	= ovl_fh_to_parent,
	.get_name	= ovl_get_name,
	.get_parent	= ovl_get_parent,
};
