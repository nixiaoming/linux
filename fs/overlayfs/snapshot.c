/*
 * File: fs/overlayfs/snapshot.c
 *
 * Overlayfs snapshot core functions.
 *
 * Copyright (C) 2016-2017 CTERA Network by Amir Goldstein <amir73il@gmail.com>
 */

#include <linux/fs.h>
#include <linux/module.h>
#include "overlayfs.h"

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
