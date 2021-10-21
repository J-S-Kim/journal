// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext4mj/bitmap.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 * Per-core journaling part by Jongseok Kim
 * SPDX-FileCopyrightText: Copyright (c) 2021 Sungkyunkwan University
 */

#include <linux/buffer_head.h>
#include "ext4mj.h"

unsigned int ext4mj_count_free(char *bitmap, unsigned int numchars)
{
	return numchars * BITS_PER_BYTE - memweight(bitmap, numchars);
}

int ext4mj_inode_bitmap_csum_verify(struct super_block *sb, ext4mj_group_t group,
				  struct ext4mj_group_desc *gdp,
				  struct buffer_head *bh, int sz)
{
	__u32 hi;
	__u32 provided, calculated;
	struct ext4mj_sb_info *sbi = EXT4MJ_SB(sb);

	if (!ext4mj_has_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_inode_bitmap_csum_lo);
	calculated = ext4mj_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= EXT4MJ_BG_INODE_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_inode_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	return provided == calculated;
}

void ext4mj_inode_bitmap_csum_set(struct super_block *sb, ext4mj_group_t group,
				struct ext4mj_group_desc *gdp,
				struct buffer_head *bh, int sz)
{
	__u32 csum;
	struct ext4mj_sb_info *sbi = EXT4MJ_SB(sb);

	if (!ext4mj_has_metadata_csum(sb))
		return;

	csum = ext4mj_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_inode_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= EXT4MJ_BG_INODE_BITMAP_CSUM_HI_END)
		gdp->bg_inode_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}

int ext4mj_block_bitmap_csum_verify(struct super_block *sb, ext4mj_group_t group,
				  struct ext4mj_group_desc *gdp,
				  struct buffer_head *bh)
{
	__u32 hi;
	__u32 provided, calculated;
	struct ext4mj_sb_info *sbi = EXT4MJ_SB(sb);
	int sz = EXT4MJ_CLUSTERS_PER_GROUP(sb) / 8;

	if (!ext4mj_has_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_block_bitmap_csum_lo);
	calculated = ext4mj_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= EXT4MJ_BG_BLOCK_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_block_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	if (provided == calculated)
		return 1;

	return 0;
}

void ext4mj_block_bitmap_csum_set(struct super_block *sb, ext4mj_group_t group,
				struct ext4mj_group_desc *gdp,
				struct buffer_head *bh)
{
	int sz = EXT4MJ_CLUSTERS_PER_GROUP(sb) / 8;
	__u32 csum;
	struct ext4mj_sb_info *sbi = EXT4MJ_SB(sb);

	if (!ext4mj_has_metadata_csum(sb))
		return;

	csum = ext4mj_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_block_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= EXT4MJ_BG_BLOCK_BITMAP_CSUM_HI_END)
		gdp->bg_block_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}
