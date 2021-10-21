// SPDX-License-Identifier: GPL-2.0
/*
 * Written based fs/ext4/xattr_security.c
 * Handler for storing security labels as extended attributes.
 * Per-core journaling part by Jongseok Kim
 * SPDX-FileCopyrightText: Copyright (c) 2021 Sungkyunkwan University
 */

#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "ext4mj_zj.h"
#include "ext4mj.h"
#include "xattr.h"

static int
ext4mj_xattr_security_get(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	return ext4mj_xattr_get(inode, EXT4MJ_XATTR_INDEX_SECURITY,
			      name, buffer, size);
}

static int
ext4mj_xattr_security_set(const struct xattr_handler *handler,
			struct dentry *unused, struct inode *inode,
			const char *name, const void *value,
			size_t size, int flags)
{
	return ext4mj_xattr_set(inode, EXT4MJ_XATTR_INDEX_SECURITY,
			      name, value, size, flags);
}

static int
ext4mj_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		void *fs_info)
{
	const struct xattr *xattr;
	handle_t *handle = fs_info;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = ext4mj_xattr_set_handle(handle, inode,
					    EXT4MJ_XATTR_INDEX_SECURITY,
					    xattr->name, xattr->value,
					    xattr->value_len, 0);
		if (err < 0)
			break;
	}
	return err;
}

int
ext4mj_init_security(handle_t *handle, struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &ext4mj_initxattrs, handle);
}

const struct xattr_handler ext4mj_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= ext4mj_xattr_security_get,
	.set	= ext4mj_xattr_security_set,
};
