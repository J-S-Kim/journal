// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/zj/commit.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * Per-core journaling part by Jongseok Kim
 * SPDX-FileCopyrightText: Copyright (c) 2021 Electronics and Telecommunications Research Institute
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal commit routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.
 */

#include <linux/time.h>
#include <linux/fs.h>
#include "zj.h"
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
#include <linux/crc32.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/bitops.h>
#include <trace/events/zj.h>

/*
 * IO end handler for temporary buffer_heads handling writes to the journal.
 */
static void journal_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	struct zjournal_head *jh = bh2jh(bh);
	struct zjournal_head *orig_jh = NULL;
	struct buffer_head *orig_bh = NULL;

	if (jh)
		orig_jh = jh->b_orig;

	if (orig_jh)
		orig_bh = jh2bh(orig_jh);
	else {
		orig_bh = bh->b_private;
		if (jh)
			printk(KERN_ERR "no orig jh %p\n", bh);
	}

	BUFFER_TRACE(bh, "");
	if (uptodate)
		set_buffer_uptodate(bh);
	else
		clear_buffer_uptodate(bh);
	if (orig_bh) {
		clear_bit_unlock(BH_Shadow, &bh->b_state);
		smp_mb__after_atomic();
	}
	unlock_buffer(bh);
}

/*
 * When an ext4 file is truncated, it is possible that some pages are not
 * successfully freed, because they are attached to a committing transaction.
 * After the transaction commits, these pages are left on the LRU, with no
 * ->mapping, and with attached buffers.  These pages are trivially reclaimable
 * by the VM, but their apparent absence upsets the VM accounting, and it makes
 * the numbers in /proc/meminfo look odd.
 *
 * So here, we have a buffer which has just come off the forget list.  Look to
 * see if we can strip all buffers from the backing page.
 *
 * Called under lock_journal(), and possibly under journal_datalist_lock.  The
 * caller provided us with a ref against the buffer, and we drop that here.
 */
static void release_buffer_page(struct buffer_head *bh)
{
	struct page *page;

	if (buffer_dirty(bh))
		goto nope;
	if (atomic_read(&bh->b_count) != 1)
		goto nope;
	page = bh->b_page;
	if (!page)
		goto nope;
	if (page->mapping)
		goto nope;

	/* OK, it's a truncated page */
	if (!trylock_page(page))
		goto nope;

	get_page(page);
	__brelse(bh);
	try_to_free_buffers(page);
	unlock_page(page);
	put_page(page);
	return;

nope:
	__brelse(bh);
}

static void zj_commit_block_csum_set(zjournal_t *j, struct buffer_head *bh)
{
	struct commit_header *h;
	__u32 csum;

	if (!zj_journal_has_csum_v2or3(j))
		return;

	h = (struct commit_header *)(bh->b_data);
	h->h_chksum_type = 0;
	h->h_chksum_size = 0;
	h->h_chksum[0] = 0;
	csum = zj_chksum(j, j->j_csum_seed, bh->b_data, j->j_blocksize);
	h->h_chksum[0] = cpu_to_be32(csum);
}

/*
 * Done it all: now submit the commit record.  We should have
 * cleaned up our previous buffers by now, so if we are in abort
 * mode we can now just skip the rest of the journal write
 * entirely.
 *
 * Returns 1 if the journal needs to be aborted or 0 on success
 */
static int journal_submit_commit_record(zjournal_t *journal,
					ztransaction_t *commit_transaction,
					struct buffer_head **cbh,
					__u32 crc32_sum)
{
	struct commit_header *tmp;
	struct buffer_head *bh;
	int ret, cpu;
	int tag_bytes = sizeof(commit_block_tag_t);
	struct timespec64 now = current_kernel_time64();
	char *tagp = NULL;
	commit_block_tag_t *tag;

	*cbh = NULL;

	if (is_journal_aborted(journal))
		return 0;

	bh = zj_journal_get_descriptor_buffer(commit_transaction,
						ZJ_COMMIT_BLOCK);
	if (!bh)
		return 1;

	tmp = (struct commit_header *)bh->b_data;
	tmp->h_commit_sec = cpu_to_be64(now.tv_sec);
	tmp->h_commit_nsec = cpu_to_be32(now.tv_nsec);

	if (zj_has_feature_checksum(journal)) {
		tmp->h_chksum_type 	= ZJ_CRC32_CHKSUM;
		tmp->h_chksum_size 	= ZJ_CRC32_CHKSUM_SIZE;
		tmp->h_chksum[0] 	= cpu_to_be32(crc32_sum);
	}

	tagp = &bh->b_data[sizeof(struct commit_header)];

	/*spin_lock(&commit_transaction->t_mark_lock);*/
	for_each_possible_cpu(cpu) {
		struct list_head *rc = &commit_transaction->t_commit_list[cpu];
		commit_entry_t *tc;

		list_for_each_entry(tc, rc, pos) {
			tag = (commit_block_tag_t *) tagp;
			tag->core = cpu_to_be16(tc->core & (u16)~0);
			tag->tid = cpu_to_be32(tc->tid & (u32)~0);
			tagp += tag_bytes;
		}
	}
	/*spin_unlock(&commit_transaction->t_mark_lock);*/
	tag = (commit_block_tag_t *) tagp;
	tag->core = cpu_to_be16(0 & (u16)~0);
	tag->tid = cpu_to_be32(0 & (u32)~0);
	zj_commit_block_csum_set(journal, bh);

	BUFFER_TRACE(bh, "submit commit block");
	lock_buffer(bh);
	clear_buffer_dirty(bh);
	set_buffer_uptodate(bh);
	bh->b_end_io = journal_end_buffer_io_sync;

	if (journal->j_flags & ZJ_BARRIER &&
			!zj_has_feature_async_commit(journal))
		ret = submit_bh(REQ_OP_WRITE,
			REQ_SYNC | REQ_PREFLUSH | REQ_FUA, bh);
	else
		ret = submit_bh(REQ_OP_WRITE, REQ_SYNC, bh);

	*cbh = bh;
	return ret;
}

/*
 * This function along with journal_submit_commit_record
 * allows to write the commit record asynchronously.
 */
static int journal_wait_on_commit_record(zjournal_t *journal,
					 struct buffer_head *bh)
{
	int ret = 0;

	clear_buffer_dirty(bh);
	wait_on_buffer(bh);

	if (unlikely(!buffer_uptodate(bh)))
		ret = -EIO;
	put_bh(bh);            /* One for getblk() */

	return ret;
}

/*
 * write the filemap data using writepage() address_space_operations.
 * We don't do block allocation here even for delalloc. We don't
 * use writepages() because with dealyed allocation we may be doing
 * block allocation in writepages().
 */
static int journal_submit_inode_data_buffers(struct address_space *mapping)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode =  WB_SYNC_ALL,
		.nr_to_write = mapping->nrpages * 2,
		.range_start = 0,
		.range_end = i_size_read(mapping->host),
	};

	ret = generic_writepages(mapping, &wbc);
	return ret;
}

/*
 * Submit all the data buffers of inode associated with the transaction to
 * disk.
 *
 * We are in a committing transaction. Therefore no new inode can be added to
 * our inode list. We use JI_COMMIT_RUNNING flag to protect inode we currently
 * operate on from being released while we write out pages.
 */
static int journal_submit_data_buffers(zjournal_t *journal,
		ztransaction_t *commit_transaction)
{
	struct zj_inode *jinode;
	int err, ret = 0;
	struct address_space *mapping;

	spin_lock(&journal->j_list_lock);
	list_for_each_entry(jinode, &commit_transaction->t_inode_list, i_list) {
		if (!(jinode->i_flags & JI_WRITE_DATA))
			continue;
		mapping = jinode->i_vfs_inode->i_mapping;
		jinode->i_flags |= JI_COMMIT_RUNNING;
		spin_unlock(&journal->j_list_lock);
		/*
		 * submit the inode data buffers. We use writepage
		 * instead of writepages. Because writepages can do
		 * block allocation  with delalloc. We need to write
		 * only allocated blocks here.
		 */
		trace_zj_submit_inode_data(jinode->i_vfs_inode);
		err = journal_submit_inode_data_buffers(mapping);
		if (!ret)
			ret = err;
		spin_lock(&journal->j_list_lock);
		J_ASSERT(jinode->i_transaction == commit_transaction);
		jinode->i_flags &= ~JI_COMMIT_RUNNING;
		smp_mb();
		wake_up_bit(&jinode->i_flags, __JI_COMMIT_RUNNING);
	}
	spin_unlock(&journal->j_list_lock);
	return ret;
}

/*
 * Wait for data submitted for writeout, refile inodes to proper
 * transaction if needed.
 *
 */
static int journal_finish_inode_data_buffers(zjournal_t *journal,
		ztransaction_t *commit_transaction)
{
	struct zj_inode *jinode, *next_i;
	struct list_head *pos;
	int err, ret = 0;
	LIST_HEAD(current_list);
	LIST_HEAD(next_list);

	/* For locking, see the comment in journal_submit_data_buffers() */
restart:
	spin_lock(&journal->j_list_lock);
	list_for_each(pos, &commit_transaction->t_inode_list) {
		jinode = list_entry(pos, struct zj_inode, i_list);
		if (!(jinode->i_flags & JI_WAIT_DATA))
			continue;
		jinode->i_flags |= JI_COMMIT_RUNNING;
		spin_unlock(&journal->j_list_lock);
		err = filemap_fdatawait_keep_errors(
				jinode->i_vfs_inode->i_mapping);
		if (!ret)
			ret = err;
		spin_lock(&journal->j_list_lock);
		jinode->i_flags &= ~JI_COMMIT_RUNNING;
		smp_mb();
		wake_up_bit(&jinode->i_flags, __JI_COMMIT_RUNNING);
	}

	/* Now refile inode to proper lists */
	list_for_each_entry_safe(jinode, next_i,
				 &commit_transaction->t_inode_list, i_list) {
		list_del(&jinode->i_list);
		if (jinode->i_next_transaction) {
			jinode->i_transaction = jinode->i_next_transaction;
			jinode->i_next_transaction = NULL;
			jinode->i_flags |= JI_TEMP_LIST;
			list_add(&jinode->i_list, &next_list);
		} else 
			jinode->i_transaction = NULL;
	}

	spin_unlock(&journal->j_list_lock);

	if (!list_empty(&next_list)) {
		list_for_each_entry_safe(jinode, next_i,
				&next_list, i_list) {
			ztransaction_t *next_transaction = jinode->i_transaction;
			zjournal_t *next_journal;

			list_del(&jinode->i_list);

			if (unlikely(ZERO_OR_NULL_PTR(next_transaction))) {
				zj_free_inode(jinode);
			}
			next_journal = next_transaction->t_journal;

			if (next_transaction->t_state < T_COMMIT) {
				spin_lock(&next_journal->j_list_lock);
				list_add(&jinode->i_list,
						&next_transaction->t_inode_list);
				jinode->i_flags &= ~JI_TEMP_LIST;
				smp_mb();
				wake_up_bit(&jinode->i_flags, __JI_TEMP_LIST);
				spin_unlock(&next_journal->j_list_lock);
			} else {
				spin_lock(&journal->j_list_lock);
				list_add(&jinode->i_list,
						&commit_transaction->t_inode_list);
				jinode->i_flags &= ~JI_TEMP_LIST;
				smp_mb();
				wake_up_bit(&jinode->i_flags, __JI_TEMP_LIST);
				spin_unlock(&journal->j_list_lock);
			}
		}
	}

	if (!list_empty(&commit_transaction->t_inode_list))
		goto restart;

	return ret;
}

static __u32 zj_checksum_data(__u32 crc32_sum, struct buffer_head *bh)
{
	struct page *page = bh->b_page;
	char *addr;
	__u32 checksum;

	addr = kmap_atomic(page);
	checksum = crc32_be(crc32_sum,
		(void *)(addr + offset_in_page(bh->b_data)), bh->b_size);
	kunmap_atomic(addr);

	return checksum;
}

static void write_tag_block(zjournal_t *j, journal_block_tag_t *tag,
				   unsigned long long block)
{
	tag->t_blocknr = cpu_to_be32(block & (u32)~0);
	if (zj_has_feature_64bit(j))
		tag->t_blocknr_high = cpu_to_be32((block >> 31) >> 1);
}

static void zj_block_tag_csum_set(zjournal_t *j, journal_block_tag_t *tag,
				    struct buffer_head *bh, __u32 sequence)
{
	journal_block_tag3_t *tag3 = (journal_block_tag3_t *)tag;
	struct page *page = bh->b_page;
	__u8 *addr;
	__u32 csum32;
	__be32 seq;

	if (!zj_journal_has_csum_v2or3(j))
		return;

	seq = cpu_to_be32(sequence);
	addr = kmap_atomic(page);
	csum32 = zj_chksum(j, j->j_csum_seed, (__u8 *)&seq, sizeof(seq));
	csum32 = zj_chksum(j, csum32, addr + offset_in_page(bh->b_data),
			     bh->b_size);
	kunmap_atomic(addr);

	if (zj_has_feature_csum3(j))
		tag3->t_checksum = cpu_to_be32(csum32);
	else
		tag->t_checksum = cpu_to_be16(csum32);
}
/*
 * zj_journal_commit_transaction
 *
 * The primary function for committing a transaction to the log.  This
 * function is called by the journal thread to begin a complete commit.
 */
void zj_journal_commit_transaction(zjournal_t *journal)
{
	struct transaction_stats_s stats;
	ztransaction_t *commit_transaction;
	struct zjournal_head *jh;
	struct buffer_head *descriptor;
	struct buffer_head **wbuf = journal->j_wbuf;
	int bufs;
	int flags;
	int err;
	unsigned long long blocknr;
	ktime_t start_time;
	u64 commit_time;
	char *tagp = NULL;
	journal_block_tag_t *tag = NULL;
	int space_left = 0;
	int first_tag = 0;
	int tag_flag;
	int i, cpu;
	int tag_bytes = zjournal_tag_bytes(journal);
	struct buffer_head *cbh = NULL; /* For transactional checksums */
	__u32 crc32_sum = ~0;
	struct blk_plug plug;
	/* Tail of the journal */
	unsigned long first_block;
	tid_t first_tid;
	int update_tail;
	int csum_size = 0;
	LIST_HEAD(io_bufs);
	LIST_HEAD(log_bufs);
	int io_bufs_num = 0;

	if (zj_journal_has_csum_v2or3(journal))
		csum_size = sizeof(struct zj_journal_block_tail);

	/*
	 * First job: lock down the current transaction and wait for
	 * all outstanding updates to complete.
	 */

	/* Do we need to erase the effects of a prior zj_journal_flush? */
	if (journal->j_flags & ZJ_FLUSHED) {
		jbd_debug(3, "super block updated\n");
		mutex_lock_io(&journal->j_checkpoint_mutex);
		/*
		 * We hold j_checkpoint_mutex so tail cannot change under us.
		 * We don't need any special data guarantees for writing sb
		 * since journal is empty and it is ok for write to be
		 * flushed only with transaction commit.
		 */
		zj_journal_update_sb_log_tail(journal,
						journal->j_tail_sequence,
						journal->j_tail,
						REQ_SYNC);
		mutex_unlock(&journal->j_checkpoint_mutex);
	} else {
		jbd_debug(3, "superblock not updated\n");
	}

	J_ASSERT(journal->j_running_transaction != NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);

	commit_transaction = journal->j_running_transaction;
	if (commit_transaction->t_real_commit)
		printk(KERN_ERR "(%d, %d) already real commit 0, state: %d\n", commit_transaction->t_journal->j_core_id, commit_transaction->t_tid, commit_transaction->t_real_commit_state);

	trace_zj_start_commit(journal, commit_transaction);
	jbd_debug(1, "ZJ: starting commit of transaction %d\n",
			commit_transaction->t_tid);

	write_lock(&journal->j_state_lock);
	J_ASSERT(commit_transaction->t_state == T_RUNNING);
	commit_transaction->t_state = T_LOCKED;

	trace_zj_commit_locking(journal, commit_transaction);
	stats.run.rs_wait = commit_transaction->t_max_wait;
	stats.run.rs_request_delay = 0;
	stats.run.rs_locked = jiffies;
	if (commit_transaction->t_requested)
		stats.run.rs_request_delay =
			zj_time_diff(commit_transaction->t_requested,
				       stats.run.rs_locked);
	stats.run.rs_running = zj_time_diff(commit_transaction->t_start,
					      stats.run.rs_locked);

	spin_lock(&commit_transaction->t_handle_lock);
	while (atomic_read(&commit_transaction->t_updates)) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_updates, &wait,
					TASK_UNINTERRUPTIBLE);
		if (atomic_read(&commit_transaction->t_updates)) {
			spin_unlock(&commit_transaction->t_handle_lock);
			write_unlock(&journal->j_state_lock);
			schedule();
			write_lock(&journal->j_state_lock);
			spin_lock(&commit_transaction->t_handle_lock);
		}
		finish_wait(&journal->j_wait_updates, &wait);
	}
	spin_unlock(&commit_transaction->t_handle_lock);

	J_ASSERT (atomic_read(&commit_transaction->t_outstanding_credits) <=
			journal->j_max_transaction_buffers);

	/*
	 * First thing we are allowed to do is to discard any remaining
	 * BJ_Reserved buffers.  Note, it is _not_ permissible to assume
	 * that there are no such buffers: if a large filesystem
	 * operation like a truncate needs to split itself over multiple
	 * transactions, then it may try to do a zj_journal_restart() while
	 * there are still BJ_Reserved buffers outstanding.  These must
	 * be released cleanly from the current transaction.
	 *
	 * In this case, the filesystem must still reserve write access
	 * again before modifying the buffer in the new transaction, but
	 * we do not require it to remember exactly which old buffers it
	 * has reserved.  This is consistent with the existing behaviour
	 * that multiple zj_journal_get_write_access() calls to the same
	 * buffer are perfectly permissible.
	 */
	while (commit_transaction->t_reserved_list) {
		jh = commit_transaction->t_reserved_list;
		JBUFFER_TRACE(jh, "reserved, unused: refile");
		/*
		 * A zj_journal_get_undo_access()+zj_journal_release_buffer() may
		 * leave undo-committed data.
		 */
		if (jh->b_committed_data) {
			struct buffer_head *bh = jh2bh(jh);

			jbd_lock_bh_state(bh);
			zj_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			jbd_unlock_bh_state(bh);
		}
		zj_journal_refile_buffer(journal, jh);
	}

	write_unlock(&journal->j_state_lock);

	/*
	 * Now try to drop any written-back buffers from the journal's
	 * checkpoint lists.  We do this *before* commit because it potentially
	 * frees some memory
	 */
	spin_lock(&journal->j_list_lock);
	__zj_journal_clean_checkpoint_list(journal, false);
	spin_unlock(&journal->j_list_lock);

	write_lock(&journal->j_state_lock);
	jbd_debug(3, "ZJ: commit phase 1\n");

	/*
	 * Clear revoked flag to reflect there is no revoked buffers
	 * in the next transaction which is going to be started.
	 */
	zj_clear_buffer_revoked_flags(journal);

	/*
	 * Switch to a new revoke table.
	 */
	zj_journal_switch_revoke_table(journal);

	/*
	 * Reserved credits cannot be claimed anymore, free them
	 */
	atomic_sub(atomic_read(&journal->j_reserved_credits),
		   &commit_transaction->t_outstanding_credits);

	trace_zj_commit_flushing(journal, commit_transaction);
	stats.run.rs_flushing = jiffies;
	stats.run.rs_locked = zj_time_diff(stats.run.rs_locked,
					     stats.run.rs_flushing);

	commit_transaction->t_state = T_FLUSH;
	journal->j_committing_transaction = commit_transaction;
	journal->j_running_transaction = NULL;
	start_time = ktime_get();
	commit_transaction->t_log_start = journal->j_head;

	// one more after T_FLUSH
	spin_lock(&commit_transaction->t_handle_lock);
	while (atomic_read(&commit_transaction->t_updates)) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_updates, &wait,
					TASK_UNINTERRUPTIBLE);
		if (atomic_read(&commit_transaction->t_updates)) {
			spin_unlock(&commit_transaction->t_handle_lock);
			write_unlock(&journal->j_state_lock);
			schedule();
			write_lock(&journal->j_state_lock);
			spin_lock(&commit_transaction->t_handle_lock);
		}
		finish_wait(&journal->j_wait_updates, &wait);
	}
	spin_unlock(&commit_transaction->t_handle_lock);

	wake_up(&journal->j_wait_transaction_locked);
	write_unlock(&journal->j_state_lock);

	jbd_debug(3, "ZJ: commit phase 2a\n");

	/*
	 * Now start flushing things to disk, in the order they appear
	 * on the transaction lists.  Data blocks go first.
	 */
	err = journal_submit_data_buffers(journal, commit_transaction);
	if (err)
		zj_journal_abort(journal, err);

	blk_start_plug(&plug);
	zj_journal_write_revoke_records(commit_transaction, &log_bufs);

	jbd_debug(3, "ZJ: commit phase 2b\n");

	/*
	 * Way to go: we have now written out all of the data for a
	 * transaction!  Now comes the tricky part: we need to write out
	 * metadata.  Loop over the transaction's entire buffer list:
	 */
	write_lock(&journal->j_state_lock);
	commit_transaction->t_state = T_COMMIT;
	write_unlock(&journal->j_state_lock);

	trace_zj_commit_logging(journal, commit_transaction);
	stats.run.rs_logging = jiffies;
	stats.run.rs_flushing = zj_time_diff(stats.run.rs_flushing,
					       stats.run.rs_logging);
	stats.run.rs_blocks =
		atomic_read(&commit_transaction->t_outstanding_credits);
	stats.run.rs_blocks_logged = 0;

	if (commit_transaction->t_nr_buffers >
		 atomic_read(&commit_transaction->t_outstanding_credits)) {
		printk(KERN_ERR "t_nr_buffers: %d, t_outstanding_credits: %d\n",
		commit_transaction->t_nr_buffers, atomic_read(&commit_transaction->t_outstanding_credits));
	}

	err = 0;
	bufs = 0;
	descriptor = NULL;
	while (commit_transaction->t_buffers) {

		/* Find the next buffer to be journaled... */

		jh = commit_transaction->t_buffers;

		/* If we're in abort mode, we just un-journal the buffer and
		   release it. */

		if (is_journal_aborted(journal)) {
			clear_buffer_jbddirty(jh2bh(jh));
			JBUFFER_TRACE(jh, "journal is aborting: refile");
			zj_buffer_abort_trigger(jh,
						  jh->b_frozen_data ?
						  jh->b_frozen_triggers :
						  jh->b_triggers);
			zj_journal_refile_buffer(journal, jh);
			/* If that was the last one, we need to clean up
			 * any descriptor buffers which may have been
			 * already allocated, even if we are now
			 * aborting. */
			if (!commit_transaction->t_buffers)
				goto start_journal_io;
			continue;
		}

		/* Make sure we have a descriptor block in which to
		   record the metadata buffer. */

		if (!descriptor) {
			J_ASSERT (bufs == 0);

			jbd_debug(4, "ZJ: get descriptor\n");

			descriptor = zj_journal_get_descriptor_buffer(
							commit_transaction,
							ZJ_DESCRIPTOR_BLOCK);
			if (!descriptor) {
				zj_journal_abort(journal, -EIO);
				continue;
			}

			jbd_debug(4, "ZJ: got buffer %llu (%p)\n",
				(unsigned long long)descriptor->b_blocknr,
				descriptor->b_data);
			tagp = &descriptor->b_data[sizeof(zjournal_header_t)];
			space_left = descriptor->b_size -
						sizeof(zjournal_header_t);
			first_tag = 1;
			set_buffer_jwrite(descriptor);
			set_buffer_dirty(descriptor);
			wbuf[bufs++] = descriptor;

			/* Record it so that we can wait for IO
                           completion later */
			BUFFER_TRACE(descriptor, "ph3: file as descriptor");
			zj_file_log_bh(&log_bufs, descriptor);
		}

		/* Where is the buffer to be written? */

		err = zj_journal_next_log_block(journal, &blocknr);
		/* If the block mapping failed, just abandon the buffer
		   and repeat this loop: we'll fall into the
		   refile-on-abort condition above. */
		if (err) {
			zj_journal_abort(journal, err);
			continue;
		}

		/*
		 * start_this_handle() uses t_outstanding_credits to determine
		 * the free space in the log, but this counter is changed
		 * by zj_journal_next_log_block() also.
		 */
		atomic_dec(&commit_transaction->t_outstanding_credits);

repeat_meta:
		/* Bump b_count to prevent truncate from stumbling over
                   the shadowed buffer!  @@@ This can go if we ever get
                   rid of the shadow pairing of buffers. */
		atomic_inc(&jh2bh(jh)->b_count);
		/*zj_journal_grab_zjournal_head(jh2bh(jh));*/

		/*
		 * Make a temporary IO buffer with which to write it out
		 * (this will requeue the metadata buffer to BJ_Shadow).
		 */
		set_bit(BH_JWrite, &jh2bh(jh)->b_state);
		JBUFFER_TRACE(jh, "ph3: write metadata");
		flags = zj_journal_write_metadata_buffer(commit_transaction,
						jh, &wbuf[bufs], blocknr);
		if (!jh || !jh2bh(jh)) {
			panic("no jh2bh\n");
		}
		__brelse(jh2bh(jh));
		if (flags < 0) {
			zj_journal_abort(journal, flags);
			continue;
		} else if (flags & 4) {
			clear_bit(BH_JWrite, &jh2bh(jh)->b_state);
			jh = commit_transaction->t_buffers;

			if (!jh) 
				goto check_journal_io;
			goto repeat_meta;
		}

		zj_file_log_bh(&io_bufs, wbuf[bufs]);
		io_bufs_num++;

		if (io_bufs_num != commit_transaction->t_nr_shadows) {
			printk(KERN_ERR "%d, %d\n", io_bufs_num, commit_transaction->t_nr_shadows);
		}

		/* Record the new block's tag in the current descriptor
                   buffer */

		tag_flag = 0;
		if (flags & 1)
			tag_flag |= ZJ_FLAG_ESCAPE;
		if (!first_tag)
			tag_flag |= ZJ_FLAG_SAME_UUID;

		tag = (journal_block_tag_t *) tagp;
		write_tag_block(journal, tag, jh2bh(jh)->b_blocknr);
		tag->t_flags = cpu_to_be16(tag_flag);
		zj_block_tag_csum_set(journal, tag, wbuf[bufs],
					commit_transaction->t_tid);
		tagp += tag_bytes;
		space_left -= tag_bytes;
		bufs++;

		/*zj_journal_put_zjournal_head(jh);*/

		if (first_tag) {
			memcpy (tagp, journal->j_uuid, 16);
			tagp += 16;
			space_left -= 16;
			first_tag = 0;
		}

		/* If there's no more to do, or if the descriptor is full,
		   let the IO rip! */
check_journal_io:
		if (bufs == journal->j_wbufsize ||
		    commit_transaction->t_buffers == NULL ||
		    space_left < tag_bytes + 16 + csum_size) {

			jbd_debug(4, "ZJ: Submit %d IOs\n", bufs);

			if (bufs == 0)
				continue;

			/* Write an end-of-descriptor marker before
                           submitting the IOs.  "tag" still points to
                           the last tag we set up. */

			tag->t_flags |= cpu_to_be16(ZJ_FLAG_LAST_TAG);

			zj_descriptor_block_csum_set(journal, descriptor);
start_journal_io:
			for (i = 0; i < bufs; i++) {
				struct buffer_head *bh = wbuf[i];
				/*
				 * Compute checksum.
				 */
				if (zj_has_feature_checksum(journal)) {
					crc32_sum =
					    zj_checksum_data(crc32_sum, bh);
				}

				lock_buffer(bh);
				clear_buffer_dirty(bh);
				set_buffer_uptodate(bh);
				bh->b_end_io = journal_end_buffer_io_sync;
				submit_bh(REQ_OP_WRITE, REQ_SYNC, bh);
			}
			cond_resched();
			stats.run.rs_blocks_logged += bufs;

			/* Force a new descriptor to be generated next
                           time round the loop. */
			descriptor = NULL;
			bufs = 0;
		}
	}

	err = journal_finish_inode_data_buffers(journal, commit_transaction);
	if (err) {
		printk(KERN_WARNING
			"ZJ: Detected IO errors while flushing file data "
		       "on %s\n", journal->j_devname);
		if (journal->j_flags & ZJ_ABORT_ON_SYNCDATA_ERR)
			zj_journal_abort(journal, err);
		err = 0;
	}

	/*
	 * Get current oldest transaction in the log before we issue flush
	 * to the filesystem device. After the flush we can be sure that
	 * blocks of all older transactions are checkpointed to persistent
	 * storage and we will be safe to update journal start in the
	 * superblock with the numbers we get here.
	 */
	update_tail =
		zj_journal_get_log_tail(journal, &first_tid, &first_block);

	write_lock(&journal->j_state_lock);
	if (update_tail) {
		long freed = first_block - journal->j_tail;

		if (first_block < journal->j_tail)
			freed += journal->j_last - journal->j_first;
		/* Update tail only if we free significant amount of space */
		if (freed < journal->j_maxlen / 4)
			update_tail = 0;
	}
	J_ASSERT(commit_transaction->t_state == T_COMMIT);
	commit_transaction->t_state = T_COMMIT_DFLUSH;
	write_unlock(&journal->j_state_lock);

	/* 
	 * If the journal is not located on the file system device,
	 * then we must flush the file system device before we issue
	 * the commit record
	 */
	if (commit_transaction->t_need_data_flush &&
	    (journal->j_fs_dev != journal->j_dev) &&
	    (journal->j_flags & ZJ_BARRIER))
		blkdev_issue_flush(journal->j_fs_dev, GFP_NOFS, NULL);

	/* Done it all: now write the commit record asynchronously. */
	if (zj_has_feature_async_commit(journal)) {
		err = journal_submit_commit_record(journal, commit_transaction,
						 &cbh, crc32_sum);
		if (err)
			__zj_journal_abort_hard(journal);
	}

	blk_finish_plug(&plug);

	/* Lo and behold: we have just managed to send a transaction to
           the log.  Before we can commit it, wait for the IO so far to
           complete.  Control buffers being written are on the
           transaction's t_log_list queue, and metadata buffers are on
           the io_bufs list.

	   Wait for the buffers in reverse order.  That way we are
	   less likely to be woken up until all IOs have completed, and
	   so we incur less scheduling load.
	*/

	jbd_debug(3, "ZJ: commit phase 3\n");

	while (!list_empty(&io_bufs)) {
		struct buffer_head *bh = list_entry(io_bufs.prev,
						    struct buffer_head,
						    b_assoc_buffers);
		struct buffer_head *orig_bh;
		struct zjournal_head *orig_jh;

		wait_on_buffer(bh);
		cond_resched();

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;
		zj_unfile_log_bh(bh);
		io_bufs_num--;

		/*
		 * The list contains temporary buffer heads created by
		 * zj_journal_write_metadata_buffer().
		 */
		__brelse(bh);

		/* We also have to refile the corresponding shadowed buffer */
		if (!commit_transaction->t_shadow_list) {
			printk(KERN_ERR "%d, %d\n", io_bufs_num, commit_transaction->t_nr_shadows);
			printk(KERN_ERR "shadow list error (%d, %d) bh: %p, jh: %p, jh's orig: %p, jh's TX: %p(state: %d)\n", 
			journal->j_core_id, commit_transaction->t_tid, bh, bh2jh(bh), bh2jh(bh)->b_orig, bh2jh(bh)->b_transaction, bh2jh(bh)->b_transaction->t_state);
			panic("shadow");
		}
		jh = commit_transaction->t_shadow_list->b_tprev;
		bh = jh2bh(jh);

		orig_jh = jh->b_orig;
		orig_bh = jh2bh(orig_jh);

		clear_buffer_jwrite(bh);
		clear_buffer_jwrite(orig_bh);
		J_ASSERT_BH(bh, !buffer_shadow(bh));

		/* The metadata is now released for reuse, but we need
                   to remember it against this transaction so that when
                   we finally commit, we can do any checkpointing
                   required. */
		JBUFFER_TRACE(jh, "file as BJ_Forget");
		zj_journal_file_buffer(jh, commit_transaction, BJ_Forget);
		JBUFFER_TRACE(jh, "brelse shadowed buffer");
	}

	J_ASSERT (commit_transaction->t_shadow_list == NULL);

	jbd_debug(3, "ZJ: commit phase 4\n");

	/* Here we wait for the revoke record and descriptor record buffers */
	while (!list_empty(&log_bufs)) {
		struct buffer_head *bh;

		bh = list_entry(log_bufs.prev, struct buffer_head, b_assoc_buffers);
		wait_on_buffer(bh);
		cond_resched();

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		BUFFER_TRACE(bh, "ph5: control buffer writeout done: unfile");
		clear_buffer_jwrite(bh);
		zj_unfile_log_bh(bh);
		__brelse(bh);		/* One for getblk */
		/* AKPM: bforget here */
	}

	if (err)
		zj_journal_abort(journal, err);

	jbd_debug(3, "ZJ: commit phase 5\n");
	write_lock(&journal->j_state_lock);
	J_ASSERT(commit_transaction->t_state == T_COMMIT_DFLUSH);
	commit_transaction->t_state = T_COMMIT_JFLUSH;
	write_unlock(&journal->j_state_lock);

	if (!zj_has_feature_async_commit(journal)) {
		err = journal_submit_commit_record(journal, commit_transaction,
						&cbh, crc32_sum);
		if (err)
			__zj_journal_abort_hard(journal);
	}

	// per core list에서 mark 들을 중복 제거한 뒤
	// check mark list 로 옮겨준다. 옮겨보니 해당 리스트에 마크가 하나도 없으면
	// real_commit을 체크해준다.
	spin_lock(&commit_transaction->t_mark_lock);
	commit_transaction->t_check_num = 0;
	for_each_possible_cpu(cpu) {
		struct list_head *rc = &commit_transaction->t_commit_list[cpu];

		while (!list_empty(rc)) {
			commit_entry_t *tc = list_entry(rc->prev, commit_entry_t, pos);

			list_del_init(&tc->pos);
			if (zj_check_mark_in_list(&commit_transaction->t_check_mark_list, tc)) {
				zj_free_commit(tc);
				continue;
			}
			tc->state = 0;
			tc->debug = 1;
			list_add(&tc->pos, &commit_transaction->t_check_mark_list); 
			if (commit_transaction->t_real_commit)
				printk(KERN_ERR "(%d, %d) already real commit 1, state: %d\n", commit_transaction->t_journal->j_core_id, commit_transaction->t_tid, commit_transaction->t_real_commit_state);
			commit_transaction->t_check_num++;
		}
	}
	if (commit_transaction->t_check_num_max < commit_transaction->t_check_num)
		commit_transaction->t_check_num_max = commit_transaction->t_check_num;

	spin_unlock(&commit_transaction->t_mark_lock);

	if (cbh)
		err = journal_wait_on_commit_record(journal, cbh);
	if (zj_has_feature_async_commit(journal) &&
	    journal->j_flags & ZJ_BARRIER) {
		blkdev_issue_flush(journal->j_dev, GFP_NOFS, NULL);
	}

	if (err)
		zj_journal_abort(journal, err);

	/*
	 * Now disk caches for filesystem device are flushed so we are safe to
	 * erase checkpointed transactions from the log by updating journal
	 * superblock.
	 */
	if (update_tail)
		zj_update_log_tail(journal, first_tid, first_block);

	/* End of a transaction!  Finally, we can do checkpoint
           processing: any buffers committed as a result of this
           transaction can be removed from any checkpoint list it was on
           before. */

	jbd_debug(3, "ZJ: commit phase 6\n");

	J_ASSERT(commit_transaction->t_buffers == NULL);
	J_ASSERT(commit_transaction->t_checkpoint_list == NULL);
	J_ASSERT(commit_transaction->t_shadow_list == NULL);

restart_loop:
	/*
	 * As there are other places (journal_unmap_buffer()) adding buffers
	 * to this list we have to be careful and hold the j_list_lock.
	 */
	spin_lock(&journal->j_list_lock);
	while (commit_transaction->t_forget) {
		ztransaction_t *cp_transaction;
		zjournal_t *cp_journal;
		struct buffer_head *frozen_bh, *orig_bh;
		struct zjournal_head *orig_jh;
		int try_to_free = 0;

		jh = commit_transaction->t_forget;
		frozen_bh = jh2bh(jh);
		spin_unlock(&journal->j_list_lock);

		if (!buffer_frozen(frozen_bh)) {
			/*
			 *아마 거의 100% forget을 통해 frozne copy가 아닌 orig bh가 바로 온 케이스
			 *거기에 맞춰 처리
			 */
			orig_jh = jh;
			jh = NULL;
			frozen_bh = NULL;
		} else
			orig_jh = jh->b_orig;

		orig_bh = jh2bh(orig_jh);

		/*
		 * Get a reference so that bh cannot be freed before we are
		 * done with it.
		 */
		get_bh(orig_bh);
		jbd_lock_bh_state(orig_bh);
		if (jh)
			J_ASSERT_JH(jh,	jh->b_transaction == commit_transaction);

		/*
		 * If there is undo-protected committed data against
		 * this buffer, then we can remove it now.  If it is a
		 * buffer needing such protection, the old frozen_data
		 * field now points to a committed version of the
		 * buffer, so rotate that field to the new committed
		 * data.
		 *
		 * Otherwise, we can just throw away the frozen data now.
		 *
		 * We also know that the frozen data has already fired
		 * its triggers if they exist, so we can clear that too.
		 */
		if (orig_jh->b_committed_data) {
			zj_free(orig_jh->b_committed_data, orig_bh->b_size);
			orig_jh->b_committed_data = NULL;
			if (orig_jh->b_frozen_data) {
				orig_jh->b_committed_data = orig_jh->b_frozen_data;
				orig_jh->b_frozen_data = NULL;
				orig_jh->b_frozen_triggers = NULL;
			}
		} else if (orig_jh->b_frozen_data) {
			zj_free(orig_jh->b_frozen_data, orig_bh->b_size);
			orig_jh->b_frozen_data = NULL;
			orig_jh->b_frozen_triggers = NULL;
		}

		spin_lock(&journal->j_list_lock);
		cp_transaction = orig_jh->b_cp_transaction;
		if (cp_transaction) {
			cp_journal = cp_transaction->t_journal;
			JBUFFER_TRACE(orig_jh, "remove from old cp transaction");
			cp_transaction->t_chp_stats.cs_dropped++;
			if (journal != cp_journal) {
				spin_unlock(&journal->j_list_lock);
				spin_lock(&cp_journal->j_list_lock);
			}
			__zj_journal_remove_checkpoint(orig_jh);
			if (journal != cp_journal) {
				spin_unlock(&cp_journal->j_list_lock);
				spin_lock(&journal->j_list_lock);
			}
		}

		/*
		* A buffer which has been freed while still being journaled by
		* a previous transaction.
		*/
		if (buffer_freed(orig_bh)) {
			/*
			 * If the running transaction is the one containing
			 * "add to orphan" operation (b_next_transaction !=
			 * NULL), we have to wait for that transaction to
			 * commit before we can really get rid of the buffer.
			 * So just clear b_modified to not confuse transaction
			 * credit accounting and refile the buffer to
			 * BJ_Forget of the running transaction. If the just
			 * committed transaction contains "add to orphan"
			 * operation, we can completely invalidate the buffer
			 * now. We are rather through in that since the
			 * buffer may be still accessible when blocksize <
			 * pagesize and it is attached to the last partial
			 * page.
			 */
			/*
			 * 원래 unmap을 통해 freed가 set되면 항상 이전에 commit중이던게
			 * 이곳에 먼저 도달하게 되고, 여길 통과하고 아래 refile을 통해
			 * 다음 tx의 forget으로 전달.
			 * 그런데 지금은 그렇지 않고 바로 forget에 매달려 있으며, 
			 * 심지어는 forget의 tx가 여기에 먼저 도달할 수 있음
			 * 따라서 두 가지 케이스를 모두 고려하며 코드를 수정해야함
			 */
			orig_jh->b_modified = 0;
			//clear_buffer_freed(orig_bh);
			if (!orig_jh->b_next_transaction) {
				clear_buffer_freed(orig_bh);
				clear_buffer_jbddirty(orig_bh);
				clear_buffer_mapped(orig_bh);
				clear_buffer_new(orig_bh);
				clear_buffer_req(orig_bh);
				orig_bh->b_bdev = NULL;
			}
		}


		if (buffer_jbddirty(orig_bh)) {
			JBUFFER_TRACE(orig_jh, "add to new checkpointing trans");
			set_buffer_checkpoint(orig_bh);
			__zj_journal_insert_checkpoint(orig_jh, commit_transaction);
			if (is_journal_aborted(journal))
				clear_buffer_jbddirty(orig_bh);
		} else {
			J_ASSERT_BH(orig_bh, !buffer_dirty(orig_bh));
			if (buffer_dirty(orig_bh))
				panic("bdirty\n");
			/*
			 * The buffer on BJ_Forget list and not jbddirty means
			 * it has been freed by this transaction and hence it
			 * could not have been reallocated until this
			 * transaction has committed. *BUT* it could be
			 * reallocated once we have written all the data to
			 * disk and before we process the buffer on BJ_Forget
			 * list.
			 */
			if (!orig_jh->b_cpcount)
				try_to_free = 1;
		}

		JBUFFER_TRACE(orig_jh, "refile or unfile buffer");

		if (!jh) {
			J_ASSERT_BH(orig_bh, !buffer_dirty(orig_bh));
			if (!orig_jh->b_cpcount)
				try_to_free = 1;

			__zj_journal_refile_buffer(orig_jh);

		} else {
			//unlink & free shadow jh
			--orig_jh->b_cpcount;

			if (commit_transaction->t_forget == jh) {
				commit_transaction->t_forget = jh->b_tnext;
				if (commit_transaction->t_forget == jh)
					commit_transaction->t_forget = NULL;
			}
			jh->b_tprev->b_tnext = jh->b_tnext;
			jh->b_tnext->b_tprev = jh->b_tprev;

			if (orig_jh->b_orig == jh) {
				orig_jh->b_orig = NULL;
			}

			--jh->b_jcount;
			journal_free_zjournal_head(jh);

			zj_free(frozen_bh->b_data, frozen_bh->b_size);
			if (!list_empty(&frozen_bh->b_assoc_buffers))
				printk(KERN_ERR "%p\n", frozen_bh);
			free_buffer_head(frozen_bh);

			if (!orig_jh->b_cpcount) {
				if (!buffer_jbddirty(orig_bh)) {
					try_to_free = 1;
				} 
				else if (orig_jh->b_transaction == NULL && !orig_jh->b_cpcount && 
						test_clear_buffer_jbddirty(orig_bh)) {
					mark_buffer_dirty(orig_bh);	/* Expose it to the VM */
				}
			}
			zj_journal_put_zjournal_head(orig_jh);
		}

		jbd_unlock_bh_state(orig_bh);

		if (try_to_free)
			release_buffer_page(orig_bh);	/* Drops bh reference */
		else {
			__brelse(orig_bh);
		}
		cond_resched_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);
	/*
	 * This is a bit sleazy.  We use j_list_lock to protect transition
	 * of a transaction into T_FINISHED state and calling
	 * __zj_journal_drop_transaction(). Otherwise we could race with
	 * other checkpointing code processing the transaction...
	 */
	write_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	/*
	 * Now recheck if some buffers did not get attached to the transaction
	 * while the lock was dropped...
	 */
	if (commit_transaction->t_forget) {
		spin_unlock(&journal->j_list_lock);
		write_unlock(&journal->j_state_lock);
		goto restart_loop;
	}

	/* Add the transaction to the checkpoint list
	 * __journal_remove_checkpoint() can not destroy transaction
	 * under us because it is not marked as T_FINISHED yet */
	if (journal->j_checkpoint_transactions == NULL) {
		journal->j_checkpoint_transactions = commit_transaction;
		commit_transaction->t_cpnext = commit_transaction;
		commit_transaction->t_cpprev = commit_transaction;
	} else {
		commit_transaction->t_cpnext =
			journal->j_checkpoint_transactions;
		commit_transaction->t_cpprev =
			commit_transaction->t_cpnext->t_cpprev;
		commit_transaction->t_cpnext->t_cpprev =
			commit_transaction;
		commit_transaction->t_cpprev->t_cpnext =
				commit_transaction;
	}

	radix_tree_insert(&journal->j_checkpoint_txtree, 
		commit_transaction->t_tid, commit_transaction);


	//if (commit_transaction->t_checkpoint_list == NULL &&
	//	commit_transaction->t_checkpoint_io_list == NULL) {
	//	commit_transaction->t_real_commit = 1;
	//	spin_lock(&commit_transaction->t_mark_lock);
	//	while(!list_empty(&commit_transaction->t_check_mark_list)) {
	//		commit_entry_t *tc = list_entry(commit_transaction->t_check_mark_list.next, 
	//						commit_entry_t, pos);
	//		list_del(&tc->pos);
	//		zj_free_commit(tc);
	//		commit_transaction->t_check_num--;
	//	}
	//	spin_unlock(&commit_transaction->t_mark_lock);
	//}
	spin_unlock(&journal->j_list_lock);

	/* Done with this transaction! */

	jbd_debug(3, "ZJ: commit phase 7\n");

	J_ASSERT(commit_transaction->t_state == T_COMMIT_JFLUSH);

	commit_transaction->t_start = jiffies;
	stats.run.rs_logging = zj_time_diff(stats.run.rs_logging,
					      commit_transaction->t_start);

	/*
	 * File the transaction statistics
	 */
	stats.ts_tid = commit_transaction->t_tid;
	stats.run.rs_handle_count =
		atomic_read(&commit_transaction->t_handle_count);
	trace_zj_run_stats(journal->j_fs_dev->bd_dev,
			     commit_transaction->t_tid, &stats.run);
	stats.ts_requested = (commit_transaction->t_requested) ? 1 : 0;

	commit_transaction->t_state = T_COMMIT_CALLBACK;
	J_ASSERT(commit_transaction == journal->j_committing_transaction);
	journal->j_commit_sequence = commit_transaction->t_tid;
	journal->j_committing_transaction = NULL;
	commit_time = ktime_to_ns(ktime_sub(ktime_get(), start_time));

	/*
	 * weight the commit time higher than the average time so we don't
	 * react too strongly to vast changes in the commit time
	 */
	if (likely(journal->j_average_commit_time))
		journal->j_average_commit_time = (commit_time +
				journal->j_average_commit_time*3) / 4;
	else
		journal->j_average_commit_time = commit_time;

	write_unlock(&journal->j_state_lock);

	if (journal->j_commit_callback)
		journal->j_commit_callback(journal, commit_transaction);

	trace_zj_end_commit(journal, commit_transaction);
	jbd_debug(1, "ZJ: commit %d complete, head %d\n",
		  journal->j_commit_sequence, journal->j_tail_sequence);

	write_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	commit_transaction->t_state = T_FINISHED;

	spin_lock(&commit_transaction->t_mark_lock);
	if (list_empty(&commit_transaction->t_check_mark_list)) {
		commit_transaction->t_real_commit = 1;
		commit_transaction->t_real_commit_state = 1;
	}
	spin_unlock(&commit_transaction->t_mark_lock);

	/* Check if the transaction can be dropped now that we are finished */
	if (commit_transaction->t_checkpoint_list == NULL &&
	    commit_transaction->t_checkpoint_io_list == NULL) {
		if (commit_transaction->t_real_commit) {
			__zj_journal_drop_transaction(journal, commit_transaction);
			zj_journal_free_transaction(commit_transaction);
		}
	}
	spin_unlock(&journal->j_list_lock);
	write_unlock(&journal->j_state_lock);
	wake_up(&journal->j_wait_done_commit);

	/*
	 * Calculate overall stats
	 */
	spin_lock(&journal->j_history_lock);
	journal->j_stats.ts_tid++;
	journal->j_stats.ts_requested += stats.ts_requested;
	journal->j_stats.run.rs_wait += stats.run.rs_wait;
	journal->j_stats.run.rs_request_delay += stats.run.rs_request_delay;
	journal->j_stats.run.rs_running += stats.run.rs_running;
	journal->j_stats.run.rs_locked += stats.run.rs_locked;
	journal->j_stats.run.rs_flushing += stats.run.rs_flushing;
	journal->j_stats.run.rs_logging += stats.run.rs_logging;
	journal->j_stats.run.rs_handle_count += stats.run.rs_handle_count;
	journal->j_stats.run.rs_blocks += stats.run.rs_blocks;
	journal->j_stats.run.rs_blocks_logged += stats.run.rs_blocks_logged;
	spin_unlock(&journal->j_history_lock);
}
