// SPDX-License-Identifier: GPL-2.0-or-later
// Per-core journaling part by Jongseok Kim
// SPDX-FileCopyrightText: Copyright (c) 2021 Sungkyunkwan University
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 *
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef __EXT4MJ_FSMAP_H__
#define	__EXT4MJ_FSMAP_H__

struct fsmap;

/* internal fsmap representation */
struct ext4mj_fsmap {
	struct list_head	fmr_list;
	dev_t		fmr_device;	/* device id */
	uint32_t	fmr_flags;	/* mapping flags */
	uint64_t	fmr_physical;	/* device offset of segment */
	uint64_t	fmr_owner;	/* owner id */
	uint64_t	fmr_length;	/* length of segment, blocks */
};

struct ext4mj_fsmap_head {
	uint32_t	fmh_iflags;	/* control flags */
	uint32_t	fmh_oflags;	/* output flags */
	unsigned int	fmh_count;	/* # of entries in array incl. input */
	unsigned int	fmh_entries;	/* # of entries filled in (output). */

	struct ext4mj_fsmap fmh_keys[2];	/* low and high keys */
};

void ext4mj_fsmap_from_internal(struct super_block *sb, struct fsmap *dest,
		struct ext4mj_fsmap *src);
void ext4mj_fsmap_to_internal(struct super_block *sb, struct ext4mj_fsmap *dest,
		struct fsmap *src);

/* fsmap to userspace formatter - copy to user & advance pointer */
typedef int (*ext4mj_fsmap_format_t)(struct ext4mj_fsmap *, void *);

int ext4mj_getfsmap(struct super_block *sb, struct ext4mj_fsmap_head *head,
		ext4mj_fsmap_format_t formatter, void *arg);

#define EXT4MJ_QUERY_RANGE_ABORT		1
#define EXT4MJ_QUERY_RANGE_CONTINUE	0

/*	fmr_owner special values for FS_IOC_GETFSMAP; some share w/ XFS */
#define EXT4MJ_FMR_OWN_FREE	FMR_OWN_FREE      /* free space */
#define EXT4MJ_FMR_OWN_UNKNOWN	FMR_OWN_UNKNOWN   /* unknown owner */
#define EXT4MJ_FMR_OWN_FS		FMR_OWNER('X', 1) /* static fs metadata */
#define EXT4MJ_FMR_OWN_LOG	FMR_OWNER('X', 2) /* journalling log */
#define EXT4MJ_FMR_OWN_INODES	FMR_OWNER('X', 5) /* inodes */
#define EXT4MJ_FMR_OWN_GDT	FMR_OWNER('f', 1) /* group descriptors */
#define EXT4MJ_FMR_OWN_RESV_GDT	FMR_OWNER('f', 2) /* reserved gdt blocks */
#define EXT4MJ_FMR_OWN_BLKBM	FMR_OWNER('f', 3) /* inode bitmap */
#define EXT4MJ_FMR_OWN_INOBM	FMR_OWNER('f', 4) /* block bitmap */

#endif /* __EXT4MJ_FSMAP_H__ */
