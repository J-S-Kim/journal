// SPDX-License-Identifier: GPL-2.0
// Per-core journaling part by Jongseok Kim
// SPDX-FileCopyrightText: Copyright (c) 2021 Sungkyunkwan University
/*
 * linux/fs/ext4mj/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/fs.h>
#include "ext4mj_zj.h"
#include "ext4mj.h"
#include "xattr.h"

static bool
ext4mj_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int
ext4mj_xattr_user_get(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, void *buffer, size_t size)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext4mj_xattr_get(inode, EXT4MJ_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
ext4mj_xattr_user_set(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext4mj_xattr_set(inode, EXT4MJ_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler ext4mj_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= ext4mj_xattr_user_list,
	.get	= ext4mj_xattr_user_get,
	.set	= ext4mj_xattr_user_set,
};
