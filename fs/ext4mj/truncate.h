/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Written based fs/ext4/truncate.h
 * Per-core journaling part by Jongseok Kim
 * SPDX-FileCopyrightText: Copyright (c) 2021 Sungkyunkwan University
 *
 * Common inline functions needed for truncate support
 */

/*
 * Truncate blocks that were not used by write. We have to truncate the
 * pagecache as well so that corresponding buffers get properly unmapped.
 */
static inline void ext4mj_truncate_failed_write(struct inode *inode)
{
	down_write(&EXT4MJ_I(inode)->i_mmap_sem);
	truncate_inode_pages(inode->i_mapping, inode->i_size);
	ext4mj_truncate(inode);
	up_write(&EXT4MJ_I(inode)->i_mmap_sem);
}

/*
 * Work out how many blocks we need to proceed with the next chunk of a
 * truncate transaction.
 */
static inline unsigned long ext4mj_blocks_for_truncate(struct inode *inode)
{
	ext4mj_lblk_t needed;

	needed = inode->i_blocks >> (inode->i_sb->s_blocksize_bits - 9);

	/* Give ourselves just enough room to cope with inodes in which
	 * i_blocks is corrupt: we've seen disk corruptions in the past
	 * which resulted in random data in an inode which looked enough
	 * like a regular file for ext4mj to try to delete it.  Things
	 * will go a bit crazy if that happens, but at least we should
	 * try not to panic the whole kernel. */
	if (needed < 2)
		needed = 2;

	/* But we need to bound the transaction so we don't overflow the
	 * journal. */
	if (needed > EXT4MJ_MAX_TRANS_DATA)
		needed = EXT4MJ_MAX_TRANS_DATA;

	return EXT4MJ_DATA_TRANS_BLOCKS(inode->i_sb) + needed;
}

