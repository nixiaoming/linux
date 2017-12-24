/*
 * Copyright (C) 2011 Novell Inc.
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/ratelimit.h>
#include <linux/mount.h>
#include <linux/exportfs.h>
#include "overlayfs.h"

struct ovl_lookup_data {
	struct qstr name;
	bool is_dir;
	bool opaque;
	bool stop;
	bool last;
	char *redirect;
};

static int ovl_check_redirect(struct dentry *dentry, struct ovl_lookup_data *d,
			      size_t prelen, const char *post)
{
	int res;
	char *s, *next, *buf = NULL;

	res = vfs_getxattr(dentry, OVL_XATTR_REDIRECT, NULL, 0);
	if (res < 0) {
		if (res == -ENODATA || res == -EOPNOTSUPP)
			return 0;
		goto fail;
	}
	buf = kzalloc(prelen + res + strlen(post) + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (res == 0)
		goto invalid;

	res = vfs_getxattr(dentry, OVL_XATTR_REDIRECT, buf, res);
	if (res < 0)
		goto fail;
	if (res == 0)
		goto invalid;
	if (buf[0] == '/') {
		for (s = buf; *s++ == '/'; s = next) {
			next = strchrnul(s, '/');
			if (s == next)
				goto invalid;
		}
	} else {
		if (strchr(buf, '/') != NULL)
			goto invalid;

		memmove(buf + prelen, buf, res);
		memcpy(buf, d->name.name, prelen);
	}

	strcat(buf, post);
	kfree(d->redirect);
	d->redirect = buf;
	d->name.name = d->redirect;
	d->name.len = strlen(d->redirect);

	return 0;

err_free:
	kfree(buf);
	return 0;
fail:
	pr_warn_ratelimited("overlayfs: failed to get redirect (%i)\n", res);
	goto err_free;
invalid:
	pr_warn_ratelimited("overlayfs: invalid redirect (%s)\n", buf);
	goto err_free;
}

static int ovl_acceptable(void *ctx, struct dentry *dentry)
{
	struct ovl_layer *layer = ctx;

	/*
	 * A non-dir origin may be disconnected, which is fine, because
	 * we only need it for its unique inode number. However, if layer->idx
	 * is 0, we need an upper dentry that is connected to upper layer root,
	 * so we can lookup overlay path from real upper path for NFS export.
	 */
	if (layer->idx && !d_is_dir(dentry))
		return 1;

	/* Don't decode a deleted empty directory */
	if (d_is_dir(dentry) && d_unhashed(dentry))
		return 0;

	/* Check if dentry belongs to the layer we are decoding from */
	return is_subdir(dentry, layer->mnt->mnt_root);
}

/*
 * Check validity of an overlay file handle buffer.
 *
 * Return 0 for a valid file handle.
 * Return -ENODATA for "origin unknown".
 * Return <0 for an invalid file handle.
 */
int ovl_check_fh_len(struct ovl_fh *fh, int fh_len)
{
	if (fh_len < sizeof(struct ovl_fh) || fh_len < fh->len)
		return -EINVAL;

	if (fh->magic != OVL_FH_MAGIC)
		return -EINVAL;

	/* Treat larger version and unknown flags as "origin unknown" */
	if (fh->version > OVL_FH_VERSION || fh->flags & ~OVL_FH_FLAG_ALL)
		return -ENODATA;

	/* Treat endianness mismatch as "origin unknown" */
	if (!(fh->flags & OVL_FH_FLAG_ANY_ENDIAN) &&
	    (fh->flags & OVL_FH_FLAG_BIG_ENDIAN) != OVL_FH_FLAG_CPU_ENDIAN)
		return -ENODATA;

	return 0;
}

static struct ovl_fh *ovl_get_origin_fh(struct dentry *dentry)
{
	int res, err;
	struct ovl_fh *fh = NULL;

	res = vfs_getxattr(dentry, OVL_XATTR_ORIGIN, NULL, 0);
	if (res < 0) {
		if (res == -ENODATA || res == -EOPNOTSUPP)
			return NULL;
		goto fail;
	}
	/* Zero size value means "copied up but origin unknown" */
	if (res == 0)
		return NULL;

	fh = kzalloc(res, GFP_KERNEL);
	if (!fh)
		return ERR_PTR(-ENOMEM);

	res = vfs_getxattr(dentry, OVL_XATTR_ORIGIN, fh, res);
	if (res < 0)
		goto fail;

	err = ovl_check_fh_len(fh, res);
	if (err < 0) {
		if (err == -ENODATA)
			goto out;
		goto invalid;
	}

	return fh;

out:
	kfree(fh);
	return NULL;

fail:
	pr_warn_ratelimited("overlayfs: failed to get origin (%i)\n", res);
	goto out;
invalid:
	pr_warn_ratelimited("overlayfs: invalid origin (%*phN)\n", res, fh);
	goto out;
}

struct dentry *ovl_decode_fh(struct ovl_fh *fh, struct ovl_layer *layer)
{
	struct dentry *origin;
	int bytes;

	/*
	 * Make sure that the stored uuid matches the uuid of the lower
	 * layer where file handle will be decoded.
	 */
	if (!uuid_equal(&fh->uuid, &layer->mnt->mnt_sb->s_uuid))
		return NULL;

	bytes = (fh->len - offsetof(struct ovl_fh, fid));
	origin = exportfs_decode_fh(layer->mnt, (struct fid *)fh->fid,
				    bytes >> 2, (int)fh->type,
				    ovl_acceptable, layer);
	if (IS_ERR(origin)) {
		/*
		 * Treat stale file handle to lower file as "origin unknown".
		 * upper file handle could become stale when upper file is
		 * unlinked and this information is needed to handle stale
		 * index entries correctly.
		 */
		if (origin == ERR_PTR(-ESTALE) &&
		    !(fh->flags & OVL_FH_FLAG_PATH_UPPER))
			origin = NULL;
		return origin;
	}

	if (ovl_dentry_weird(origin)) {
		dput(origin);
		return NULL;
	}

	return origin;
}

static bool ovl_is_opaquedir(struct dentry *dentry)
{
	return ovl_check_dir_xattr(dentry, OVL_XATTR_OPAQUE);
}

static int ovl_lookup_single(struct dentry *base, struct ovl_lookup_data *d,
			     const char *name, unsigned int namelen,
			     size_t prelen, const char *post,
			     struct dentry **ret)
{
	struct dentry *this;
	int err;

	this = lookup_one_len_unlocked(name, base, namelen);
	if (IS_ERR(this)) {
		err = PTR_ERR(this);
		this = NULL;
		if (err == -ENOENT || err == -ENAMETOOLONG)
			goto out;
		goto out_err;
	}
	if (!this->d_inode)
		goto put_and_out;

	if (ovl_dentry_weird(this)) {
		/* Don't support traversing automounts and other weirdness */
		err = -EREMOTE;
		goto out_err;
	}
	if (ovl_is_whiteout(this)) {
		d->stop = d->opaque = true;
		goto put_and_out;
	}
	if (!d_can_lookup(this)) {
		d->stop = true;
		if (d->is_dir)
			goto put_and_out;
		goto out;
	}
	d->is_dir = true;
	if (!d->last && ovl_is_opaquedir(this)) {
		d->stop = d->opaque = true;
		goto out;
	}
	err = ovl_check_redirect(this, d, prelen, post);
	if (err)
		goto out_err;
out:
	*ret = this;
	return 0;

put_and_out:
	dput(this);
	this = NULL;
	goto out;

out_err:
	dput(this);
	return err;
}

static int ovl_lookup_layer(struct dentry *base, struct ovl_lookup_data *d,
			    struct dentry **ret)
{
	/* Counting down from the end, since the prefix can change */
	size_t rem = d->name.len - 1;
	struct dentry *dentry = NULL;
	int err;

	if (d->name.name[0] != '/')
		return ovl_lookup_single(base, d, d->name.name, d->name.len,
					 0, "", ret);

	while (!IS_ERR_OR_NULL(base) && d_can_lookup(base)) {
		const char *s = d->name.name + d->name.len - rem;
		const char *next = strchrnul(s, '/');
		size_t thislen = next - s;
		bool end = !next[0];

		/* Verify we did not go off the rails */
		if (WARN_ON(s[-1] != '/'))
			return -EIO;

		err = ovl_lookup_single(base, d, s, thislen,
					d->name.len - rem, next, &base);
		dput(dentry);
		if (err)
			return err;
		dentry = base;
		if (end)
			break;

		rem -= thislen + 1;

		if (WARN_ON(rem >= d->name.len))
			return -EIO;
	}
	*ret = dentry;
	return 0;
}


int ovl_check_origin_fh(struct ovl_fh *fh, struct dentry *upperdentry,
			struct ovl_layer *layers, unsigned int numlayers,
			struct ovl_path **stackp)
{
	struct dentry *origin = NULL;
	int i;

	for (i = 0; i < numlayers; i++) {
		origin = ovl_decode_fh(fh, &layers[i]);
		if (origin)
			break;
	}

	if (!origin)
		return -ESTALE;
	else if (IS_ERR(origin))
		return PTR_ERR(origin);

	if (upperdentry && !ovl_is_whiteout(upperdentry) &&
	    ((d_inode(origin)->i_mode ^ d_inode(upperdentry)->i_mode) & S_IFMT))
		goto invalid;

	if (!*stackp)
		*stackp = kmalloc(sizeof(struct ovl_path), GFP_KERNEL);
	if (!*stackp) {
		dput(origin);
		return -ENOMEM;
	}
	**stackp = (struct ovl_path){.dentry = origin, .layer = &layers[i]};

	return 0;

invalid:
	pr_warn_ratelimited("overlayfs: invalid origin (%pd2, ftype=%x, origin ftype=%x).\n",
			    upperdentry, d_inode(upperdentry)->i_mode & S_IFMT,
			    d_inode(origin)->i_mode & S_IFMT);
	dput(origin);
	return -EIO;
}

static int ovl_check_origin(struct dentry *upperdentry,
			    struct ovl_layer *layers, unsigned int numlayers,
			    struct ovl_path **stackp, unsigned int *ctrp)
{
	struct ovl_fh *fh = ovl_get_origin_fh(upperdentry);
	int err;

	if (IS_ERR_OR_NULL(fh))
		return PTR_ERR(fh);

	err = ovl_check_origin_fh(fh, upperdentry, layers, numlayers, stackp);
	kfree(fh);

	if (err) {
		if (err == -ESTALE)
			return 0;
		return err;
	}

	if (WARN_ON(*ctrp))
		return -EIO;

	*ctrp = 1;
	return 0;
}

/*
 * Verify that @fh matches the origin file handle stored in OVL_XATTR_ORIGIN.
 * Return 0 on match, -ESTALE on mismatch, < 0 on error.
 */
static int ovl_verify_origin_fh(struct dentry *dentry, const struct ovl_fh *fh)
{
	struct ovl_fh *ofh = ovl_get_origin_fh(dentry);
	int err = 0;

	if (!ofh)
		return -ENODATA;

	if (IS_ERR(ofh))
		return PTR_ERR(ofh);

	if (fh->len != ofh->len || memcmp(fh, ofh, fh->len))
		err = -ESTALE;

	kfree(ofh);
	return err;
}

/*
 * Verify that an inode matches the origin file handle stored in upper inode.
 *
 * If @set is true and there is no stored file handle, encode and store origin
 * file handle in OVL_XATTR_ORIGIN.
 *
 * Return 0 on match, -ESTALE on mismatch, < 0 on error.
 */
int ovl_verify_origin(struct dentry *dentry, struct dentry *origin,
		      bool is_upper, bool set)
{
	struct inode *inode;
	struct ovl_fh *fh;
	int err;

	fh = ovl_encode_fh(origin, is_upper, false);
	err = PTR_ERR(fh);
	if (IS_ERR(fh))
		goto fail;

	err = ovl_verify_origin_fh(dentry, fh);
	if (set && err == -ENODATA)
		err = ovl_do_setxattr(dentry, OVL_XATTR_ORIGIN, fh, fh->len, 0);
	if (err)
		goto fail;

out:
	kfree(fh);
	return err;

fail:
	inode = d_inode(origin);
	pr_warn_ratelimited("overlayfs: failed to verify origin (%pd2, ino=%lu, err=%i)\n",
			    origin, inode ? inode->i_ino : 0, err);
	goto out;
}

/* Get upper dentry from index */
static struct dentry *ovl_index_upper(struct ovl_fs *ofs, struct dentry *index)
{
	struct ovl_fh *fh;
	struct ovl_layer layer = { .mnt = ofs->upper_mnt };
	struct ovl_path upper = { .layer = &layer };
	struct ovl_path *stack = &upper;
	int err;

	if (!d_is_dir(index))
		return dget(index);

	fh = ovl_get_origin_fh(index);
	if (IS_ERR_OR_NULL(fh))
		return ERR_CAST(fh);

	err = ovl_check_origin_fh(fh, index, &layer, 1, &stack);
	kfree(fh);
	if (err)
		return ERR_PTR(err);

	return upper.dentry;
}

/* Is this a leftover from create/whiteout of directory index entry? */
static bool ovl_is_temp_index(struct dentry *index)
{
	const char *p = index->d_name.name;
	int len = index->d_name.len;

	if (!d_is_dir(index) && !ovl_is_whiteout(index))
		return false;

	if (*p++ != '#' || len < 2)
		return false;

	while (--len > 0 && isdigit(*p))
		p++;

	return !len;
}

/*
 * Verify that an index entry name matches the origin file handle stored in
 * OVL_XATTR_ORIGIN and that origin file handle can be decoded to lower path.
 * Return 0 on match, -ESTALE on mismatch or stale origin, < 0 on error.
 */
int ovl_verify_index(struct ovl_fs *ofs, struct dentry *index)
{
	struct ovl_fh *fh = NULL;
	size_t len;
	struct ovl_path origin = { };
	struct ovl_path *stack = &origin;
	struct dentry *upper = NULL;
	int err;

	if (!d_inode(index))
		return 0;

	/* Cleanup leftover from index create/cleanup attempt */
	err = -ESTALE;
	if (ovl_is_temp_index(index))
		goto fail;

	err = -EINVAL;
	if (index->d_name.len < sizeof(struct ovl_fh)*2)
		goto fail;

	err = -ENOMEM;
	len = index->d_name.len / 2;
	fh = kzalloc(len, GFP_KERNEL);
	if (!fh)
		goto fail;

	err = -EINVAL;
	if (hex2bin((u8 *)fh, index->d_name.name, len))
		goto fail;

	err = ovl_check_fh_len(fh, len);
	if (err)
		goto fail;

	/*
	 * Whiteout index entries are used as an indication that an exported
	 * overlay file handle should be treated as stale (i.e. after unlink
	 * of the overlay inode). These entries contain no origin xattr.
	 */
	if (ovl_is_whiteout(index))
		goto out;

	/*
	 * verifying directory index entries are not stale is expensive, so
	 * only verify stale dir index if 'verify' feature is enabled.
	 */
	if (d_is_dir(index) && !ofs->config.verify)
		goto out;

	/*
	 * Directory index entries should have origin xattr pointing to the
	 * real upper dir. Non-dir index entries are hardlinks to the upper
	 * real inode. For non-dir index, we can read the copy up origin xattr
	 * directly from the index dentry, but for dir index we first need to
	 * decode the upper directory.
	 */
	upper = ovl_index_upper(ofs, index);
	if (IS_ERR(upper)) {
		err = PTR_ERR(upper);
		/*
		 * Invalid index entries and stale non-dir index entries need
		 * to be removed.  When dir index has a stale origin fh to upper
		 * dir, we assume that upper dir was removed and we treat the
		 * dir index as orphan entry that needs to be whited out.
		 */
		if (err == -ESTALE)
			goto orphan;
		if (err)
			goto fail;
	}

	err = ovl_verify_origin_fh(upper, fh);
	dput(upper);
	if (err)
		goto fail;

	/* Check if non-dir index is orphan and don't warn before cleaning it */
	if (!d_is_dir(index) && d_inode(index)->i_nlink == 1) {
		err = ovl_check_origin_fh(fh, index, ofs->lower_layers,
					  ofs->numlower, &stack);
		if (err)
			goto fail;

		if (ovl_get_nlink(origin.dentry, index, 0) == 0)
			goto orphan;
	}

out:
	dput(origin.dentry);
	kfree(fh);
	return err;

fail:
	pr_warn_ratelimited("overlayfs: failed to verify index (%pd2, ftype=%x, err=%i)\n",
			    index, d_inode(index)->i_mode & S_IFMT, err);
	goto out;

orphan:
	pr_warn_ratelimited("overlayfs: orphan index entry (%pd2, ftype=%x, nlink=%u)\n",
			    index, d_inode(index)->i_mode & S_IFMT,
			    d_inode(index)->i_nlink);
	err = -ENOENT;
	goto out;
}

static int ovl_get_index_name_fh(struct ovl_fh *fh, struct qstr *name)
{
	char *n, *s;

	n = kzalloc(fh->len * 2, GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	s  = bin2hex(n, fh, fh->len);
	*name = (struct qstr) QSTR_INIT(n, s - n);

	return 0;

}

/*
 * Lookup in indexdir for the index entry of a lower real inode or a copy up
 * origin inode. The index entry name is the hex representation of the lower
 * inode file handle.
 *
 * If the index dentry in negative, then either no lower aliases have been
 * copied up yet, or aliases have been copied up in older kernels and are
 * not indexed.
 *
 * If the index dentry for a copy up origin inode is positive, but points
 * to an inode different than the upper inode, then either the upper inode
 * has been copied up and not indexed or it was indexed, but since then
 * index dir was cleared. Either way, that index cannot be used to indentify
 * the overlay inode.
 */
int ovl_get_index_name(struct dentry *origin, struct qstr *name)
{
	struct ovl_fh *fh;
	int err;

	/*
	 * We encode a non-connectable file handle for index, because the index
	 * must be unqiue and invariant of lower hardlink aliases.
	 */
	fh = ovl_encode_fh(origin, false, false);
	if (IS_ERR(fh))
		return PTR_ERR(fh);

	err = ovl_get_index_name_fh(fh, name);

	kfree(fh);
	return err;
}

/* Lookup index by file handle for NFS export */
struct dentry *ovl_get_index_fh(struct ovl_fs *ofs, struct ovl_fh *fh)
{
	struct dentry *index;
	struct qstr name;
	int err;

	err = ovl_get_index_name_fh(fh, &name);
	if (err)
		return ERR_PTR(err);

	index = lookup_one_len_unlocked(name.name, ofs->indexdir, name.len);
	kfree(name.name);
	if (IS_ERR(index)) {
		if (PTR_ERR(index) == -ENOENT)
			index = NULL;
		return index;
	}

	if (d_is_negative(index))
		err = 0;
	else if (ovl_is_whiteout(index))
		err = -ESTALE;
	else if (ovl_dentry_weird(index))
		err = -EIO;
	else
		return index;

	dput(index);
	return ERR_PTR(err);
}

static struct dentry *ovl_lookup_index(struct dentry *dentry,
				       struct dentry *upper,
				       struct dentry *origin)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct dentry *index;
	struct inode *inode;
	struct qstr name;
	bool is_dir = d_is_dir(origin);
	int err;

	err = ovl_get_index_name(origin, &name);
	if (err)
		return ERR_PTR(err);

	index = lookup_one_len_unlocked(name.name, ofs->indexdir, name.len);
	if (IS_ERR(index)) {
		err = PTR_ERR(index);
		if (err == -ENOENT) {
			index = NULL;
			goto out;
		}
		pr_warn_ratelimited("overlayfs: failed inode index lookup (ino=%lu, key=%*s, err=%i);\n"
				    "overlayfs: mount with '-o index=off' to disable inodes index.\n",
				    d_inode(origin)->i_ino, name.len, name.name,
				    err);
		goto out;
	}

	inode = d_inode(index);
	if (d_is_negative(index)) {
		goto out_dput;
	} else if (ovl_dentry_weird(index) || ovl_is_whiteout(index) ||
		   ((inode->i_mode ^ d_inode(origin)->i_mode) & S_IFMT)) {
		/*
		 * Index should always be of the same file type as origin
		 * except for the case of a whiteout index. A whiteout
		 * index should only exist if all lower aliases have been
		 * unlinked, which means that finding a lower origin on lookup
		 * whose index is a whiteout should be treated as an error.
		 */
		pr_warn_ratelimited("overlayfs: bad index found (index=%pd2, ftype=%x, origin ftype=%x).\n",
				    index, d_inode(index)->i_mode & S_IFMT,
				    d_inode(origin)->i_mode & S_IFMT);
		goto fail;
	} else if (is_dir) {
		if (!upper) {
			pr_warn_ratelimited("overlayfs: suspected uncovered redirected dir found (%pd2, index=%pd2).\n",
					    dentry, index);
			goto fail;
		}

		/* Verify that dir index origin points to upper dir */
		err = ovl_verify_origin(index, upper, true, false);
		if (err) {
			if (err == -ESTALE) {
				pr_warn_ratelimited("overlayfs: suspected multiply redirected dir found (%pd2, index=%pd2).\n",
						    dentry, index);
			}
			goto fail;
		}
	} else if (upper && d_inode(upper) != inode) {
		goto out_dput;
	}
out:
	kfree(name.name);
	return index;

out_dput:
	dput(index);
	index = NULL;
	goto out;

fail:
	dput(index);
	index = ERR_PTR(-EIO);
	goto out;
}

/*
 * Returns next layer in stack starting from top.
 * Returns -1 if this is the last layer.
 */
int ovl_path_next(int idx, struct dentry *dentry, struct path *path)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	BUG_ON(idx < 0);
	if (idx == 0) {
		ovl_path_upper(dentry, path);
		if (path->dentry)
			return oe->numlower ? 1 : -1;
		idx++;
	}
	BUG_ON(idx > oe->numlower);
	path->dentry = oe->lowerstack[idx - 1].dentry;
	path->mnt = oe->lowerstack[idx - 1].layer->mnt;

	return (idx < oe->numlower) ? idx + 1 : -1;
}

struct dentry *ovl_lookup(struct inode *dir, struct dentry *dentry,
			  unsigned int flags)
{
	struct ovl_entry *oe;
	const struct cred *old_cred;
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct ovl_entry *poe = dentry->d_parent->d_fsdata;
	struct ovl_entry *roe = dentry->d_sb->s_root->d_fsdata;
	struct ovl_path *stack = NULL;
	struct dentry *upperdir, *upperdentry = NULL;
	struct dentry *origin = NULL;
	struct dentry *index = NULL;
	unsigned int ctr = 0;
	struct inode *inode = NULL;
	bool upperopaque = false;
	char *upperredirect = NULL;
	struct dentry *this;
	unsigned int i;
	int err;
	struct ovl_lookup_data d = {
		.name = dentry->d_name,
		.is_dir = false,
		.opaque = false,
		.stop = false,
		.last = !poe->numlower,
		.redirect = NULL,
	};

	if (dentry->d_name.len > ofs->namelen)
		return ERR_PTR(-ENAMETOOLONG);

	old_cred = ovl_override_creds(dentry->d_sb);
	upperdir = ovl_dentry_upper(dentry->d_parent);
	if (upperdir) {
		err = ovl_lookup_layer(upperdir, &d, &upperdentry);
		if (err)
			goto out;

		if (upperdentry && unlikely(ovl_dentry_remote(upperdentry))) {
			dput(upperdentry);
			err = -EREMOTE;
			goto out;
		}
		if (upperdentry && !d.is_dir) {
			BUG_ON(!d.stop || d.redirect);
			/*
			 * Lookup copy up origin by decoding origin file handle.
			 * We may get a disconnected dentry, which is fine,
			 * because we only need to hold the origin inode in
			 * cache and use its inode number.  We may even get a
			 * connected dentry, that is not under any of the lower
			 * layers root.  That is also fine for using it's inode
			 * number - it's the same as if we held a reference
			 * to a dentry in lower layer that was moved under us.
			 */
			err = ovl_check_origin(upperdentry, ofs->lower_layers,
					       ofs->numlower, &stack, &ctr);
			if (err)
				goto out_put_upper;
		}

		if (d.redirect) {
			err = -ENOMEM;
			upperredirect = kstrdup(d.redirect, GFP_KERNEL);
			if (!upperredirect)
				goto out_put_upper;
			if (d.redirect[0] == '/')
				poe = roe;
		}
		upperopaque = d.opaque;
	}

	if (!d.stop && poe->numlower) {
		err = -ENOMEM;
		stack = kcalloc(ofs->numlower, sizeof(struct ovl_path),
				GFP_KERNEL);
		if (!stack)
			goto out_put_upper;
	}

	for (i = 0; !d.stop && i < poe->numlower; i++) {
		struct ovl_path lower = poe->lowerstack[i];

		d.last = i == poe->numlower - 1;
		err = ovl_lookup_layer(lower.dentry, &d, &this);
		if (err)
			goto out_put;

		if (!this)
			continue;

		/*
		 * When 'verify' feature is enabled, verify that lower dir
		 * matches the stored origin fh. If no origin fh is stored in
		 * upper of a merge dir, store fh of upper most lower dir.
		 * We do not use unverified origin for index lookup.
		 */
		if (upperdentry && !ctr && ovl_verify(dentry->d_sb)) {
			err = ovl_verify_origin(upperdentry, this, false, true);
			if (err) {
				dput(this);
				break;
			}

			/* Bless lower dir as verified origin */
			origin = this;
		}

		stack[ctr].dentry = this;
		stack[ctr].layer = lower.layer;
		ctr++;

		if (d.stop)
			break;

		/*
		 * Following redirects can have security consequences: it's like
		 * a symlink into the lower layer without the permission checks.
		 * This is only a problem if the upper layer is untrusted (e.g
		 * comes from an USB drive).  This can allow a non-readable file
		 * or directory to become readable.
		 *
		 * Only following redirects when redirects are enabled disables
		 * this attack vector when not necessary.
		 */
		err = -EPERM;
		if (d.redirect && !ofs->config.redirect_follow) {
			pr_warn_ratelimited("overlayfs: refusing to follow redirect for (%pd2)\n",
					    dentry);
			goto out_put;
		}

		if (d.redirect && d.redirect[0] == '/' && poe != roe) {
			poe = roe;
			/* Find the current layer on the root dentry */
			i = lower.layer->idx - 1;
		}
	}

	/*
	 * Lookup index by lower inode and verify it matches upper inode.
	 * We only trust dir index if we verified that lower dir matches
	 * origin, otherwise dir index entries may be inconsistent and we
	 * ignore them. Always lookup index of non-dir and non-upper.
	 */
	if (ctr && (!upperdentry || !d.is_dir))
		origin = stack[0].dentry;

	if (origin && ovl_indexdir(dentry->d_sb) &&
	    (!d.is_dir || ovl_verify(dentry->d_sb))) {
		index = ovl_lookup_index(dentry, upperdentry, origin);
		if (IS_ERR(index)) {
			err = PTR_ERR(index);
			index = NULL;
			goto out_put;
		}
	}

	oe = ovl_alloc_entry(ctr);
	err = -ENOMEM;
	if (!oe)
		goto out_put;

	oe->opaque = upperopaque;
	memcpy(oe->lowerstack, stack, sizeof(struct ovl_path) * ctr);
	dentry->d_fsdata = oe;

	if (upperdentry)
		ovl_dentry_set_upper_alias(dentry, dget(upperdentry));
	else if (index)
		upperdentry = dget(index);

	if (upperdentry || ctr) {
		inode = ovl_get_inode(dentry->d_sb, upperdentry, origin, index,
				      ctr);
		err = PTR_ERR(inode);
		if (IS_ERR(inode))
			goto out_free_oe;

		OVL_I(inode)->redirect = upperredirect;
		if (index)
			ovl_set_flag(OVL_INDEX, inode);
	}

	revert_creds(old_cred);
	dput(index);
	kfree(stack);
	kfree(d.redirect);
	return d_splice_alias(inode, dentry);

out_free_oe:
	dentry->d_fsdata = NULL;
	kfree(oe);
out_put:
	dput(index);
	for (i = 0; i < ctr; i++)
		dput(stack[i].dentry);
	kfree(stack);
out_put_upper:
	dput(upperdentry);
	kfree(upperredirect);
out:
	kfree(d.redirect);
	revert_creds(old_cred);
	return ERR_PTR(err);
}

bool ovl_lower_positive(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	struct ovl_entry *poe = dentry->d_parent->d_fsdata;
	const struct qstr *name = &dentry->d_name;
	unsigned int i;
	bool positive = false;
	bool done = false;

	/*
	 * If dentry is negative, then lower is positive iff this is a
	 * whiteout.
	 */
	if (!dentry->d_inode)
		return oe->opaque;

	/* Negative upper -> positive lower */
	if (!ovl_dentry_upper(dentry))
		return true;

	/* Positive upper -> have to look up lower to see whether it exists */
	for (i = 0; !done && !positive && i < poe->numlower; i++) {
		struct dentry *this;
		struct dentry *lowerdir = poe->lowerstack[i].dentry;

		this = lookup_one_len_unlocked(name->name, lowerdir,
					       name->len);
		if (IS_ERR(this)) {
			switch (PTR_ERR(this)) {
			case -ENOENT:
			case -ENAMETOOLONG:
				break;

			default:
				/*
				 * Assume something is there, we just couldn't
				 * access it.
				 */
				positive = true;
				break;
			}
		} else {
			if (this->d_inode) {
				positive = !ovl_is_whiteout(this);
				done = true;
			}
			dput(this);
		}
	}

	return positive;
}
