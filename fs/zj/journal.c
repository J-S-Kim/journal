// SPDX-License-Identifier: GPL-2.0+
// Per-core journaling part by Jongseok Kim
// SPDX-FileCopyrightText: Copyright (c) 2021 Sungkyunkwan University
/*
 * linux/fs/zj/journal.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Generic filesystem journal-writing code; part of the ext2fs
 * journaling system.
 *
 * This file manages journals: areas of disk reserved for logging
 * transactional updates.  This includes the kernel journaling thread
 * which is responsible for scheduling updates to the log.
 *
 * We do not actually manage the physical storage of the journal in this
 * file: that is left to a per-journal policy function, which allows us
 * to store the journal within a filesystem-specified area for ext2
 * journaling (ext2 can use a reserved inode for storing the log).
 */

#include <linux/module.h>
#include <linux/time.h>
#include <linux/fs.h>
#include "zj.h"
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/freezer.h>
#include <linux/pagemap.h>
#include <linux/kthread.h>
#include <linux/poison.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/math64.h>
#include <linux/hash.h>
#include <linux/log2.h>
#include <linux/vmalloc.h>
#include <linux/backing-dev.h>
#include <linux/bitops.h>
#include <linux/ratelimit.h>
#include <linux/sched/mm.h>

#define CREATE_TRACE_POINTS
#include <trace/events/zj.h>

#include <linux/uaccess.h>
#include <asm/page.h>

#ifdef CONFIG_ZJ_DEBUG
ushort zj_journal_enable_debug __read_mostly;
EXPORT_SYMBOL(zj_journal_enable_debug);

module_param_named(zj_debug, zj_journal_enable_debug, ushort, 0644);
MODULE_PARM_DESC(zj_debug, "Debugging level for zj");
#endif

EXPORT_SYMBOL(zj_journal_extend);
EXPORT_SYMBOL(zj_journal_stop);
EXPORT_SYMBOL(zj_journal_lock_updates);
EXPORT_SYMBOL(zj_journal_unlock_updates);
EXPORT_SYMBOL(zj_journal_get_write_access);
EXPORT_SYMBOL(zj_journal_get_create_access);
EXPORT_SYMBOL(zj_journal_get_undo_access);
EXPORT_SYMBOL(zj_journal_set_triggers);
EXPORT_SYMBOL(zj_journal_dirty_metadata);
EXPORT_SYMBOL(zj_journal_forget);
#if 0
EXPORT_SYMBOL(journal_sync_buffer);
#endif
EXPORT_SYMBOL(zj_journal_flush);
EXPORT_SYMBOL(zj_journal_revoke);

EXPORT_SYMBOL(journal_alloc_zjournal_head);
EXPORT_SYMBOL(journal_free_zjournal_head);
EXPORT_SYMBOL(zj_shadow);

EXPORT_SYMBOL(zj_journal_init_dev);
EXPORT_SYMBOL(zj_journal_init_inode);
EXPORT_SYMBOL(zj_journal_check_used_features);
EXPORT_SYMBOL(zj_journal_check_available_features);
EXPORT_SYMBOL(zj_journal_set_features);
EXPORT_SYMBOL(zj_get_target_transaction);
EXPORT_SYMBOL(zj_journal_load);
EXPORT_SYMBOL(zj_journal_destroy);
EXPORT_SYMBOL(zj_journal_abort);
EXPORT_SYMBOL(zj_journal_errno);
EXPORT_SYMBOL(zj_journal_ack_err);
EXPORT_SYMBOL(zj_journal_clear_err);
EXPORT_SYMBOL(zj_log_wait_commit);
EXPORT_SYMBOL(zj_log_start_commit);
EXPORT_SYMBOL(zj_journal_start_commit);
EXPORT_SYMBOL(zj_journal_force_commit_nested);
EXPORT_SYMBOL(zj_journal_wipe);
EXPORT_SYMBOL(zj_journal_blocks_per_page);
EXPORT_SYMBOL(zj_journal_invalidatepage);
EXPORT_SYMBOL(zj_zjournal_try_to_free_buffers);
EXPORT_SYMBOL(zj_journal_force_commit);
EXPORT_SYMBOL(zj_journal_force_commit_start);
EXPORT_SYMBOL(zj_journal_inode_add_write);
EXPORT_SYMBOL(zj_journal_inode_add_wait);
EXPORT_SYMBOL(zj_journal_init_jbd_inode);
EXPORT_SYMBOL(zj_journal_release_jbd_inode);
EXPORT_SYMBOL(zj_journal_begin_ordered_truncate);
EXPORT_SYMBOL(zj_inode_cache);
EXPORT_SYMBOL(zj_commit_cache);

static void __journal_abort_soft (zjournal_t *journal, int errno);
static int zj_journal_create_slab(size_t slab_size);

int tunmap1, tunmap2, tunmap3, tunmap4, tunmap5, tunmap6, tunmap7, tunmap8, tunmap9;
int tforget_total, tforget1, tforget2, tforget3, tforget4, tforget5, tforget6;

#ifdef CONFIG_ZJ_DEBUG
void __zj_debug(int level, const char *file, const char *func,
		  unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (level > zj_journal_enable_debug)
		return;
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_DEBUG "%s: (%s, %u): %pV\n", file, func, line, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(__zj_debug);
#endif

/* Checksumming functions */
static int zj_verify_csum_type(zjournal_t *j, journal_superblock_t *sb)
{
	if (!zj_journal_has_csum_v2or3_feature(j))
		return 1;

	return sb->s_checksum_type == ZJ_CRC32C_CHKSUM;
}

static __be32 zj_superblock_csum(zjournal_t *j, journal_superblock_t *sb)
{
	__u32 csum;
	__be32 old_csum;

	old_csum = sb->s_checksum;
	sb->s_checksum = 0;
	csum = zj_chksum(j, ~0, (char *)sb, sizeof(journal_superblock_t));
	sb->s_checksum = old_csum;

	return cpu_to_be32(csum);
}

static int zj_superblock_csum_verify(zjournal_t *j, journal_superblock_t *sb)
{
	if (!zj_journal_has_csum_v2or3(j))
		return 1;

	return sb->s_checksum == zj_superblock_csum(j, sb);
}

static void zj_superblock_csum_set(zjournal_t *j, journal_superblock_t *sb)
{
	if (!zj_journal_has_csum_v2or3(j))
		return;

	sb->s_checksum = zj_superblock_csum(j, sb);
}

/*
 * Helper function used to manage commit timeouts
 */

static void commit_timeout(unsigned long __data)
{
	struct task_struct * p = (struct task_struct *) __data;

	wake_up_process(p);
}

/*
 * kjournald2: The main thread function used to manage a logging device
 * journal.
 *
 * This kernel thread is responsible for two things:
 *
 * 1) COMMIT:  Every so often we need to commit the current state of the
 *    filesystem to disk.  The journal thread is responsible for writing
 *    all of the metadata buffers to disk.
 *
 * 2) CHECKPOINT: We cannot reuse a used section of the log file until all
 *    of the data in that part of the log has been rewritten elsewhere on
 *    the disk.  Flushing these old buffers to reclaim space in the log is
 *    known as checkpointing, and this thread is responsible for that job.
 */

static int kjournald2(void *arg)
{
	zjournal_t *journal = arg;
	ztransaction_t *transaction;

	/*
	 * Set up an interval timer which can be used to trigger a commit wakeup
	 * after the commit interval expires
	 */
	setup_timer(&journal->j_commit_timer, commit_timeout,
			(unsigned long)current);

	set_freezable();

	/* Record that the journal thread is running */
	journal->j_task = current;
	wake_up(&journal->j_wait_done_commit);

	/*
	 * Make sure that no allocations from this kernel thread will ever
	 * recurse to the fs layer because we are responsible for the
	 * transaction commit and any fs involvement might get stuck waiting for
	 * the trasn. commit.
	 */
	memalloc_nofs_save();

	/*
	 * And now, wait forever for commit wakeup events.
	 */
	write_lock(&journal->j_state_lock);

loop:
	if (journal->j_flags & ZJ_UNMOUNT)
		goto end_loop;

	jbd_debug(1, "commit_sequence=%d, commit_request=%d\n",
		journal->j_commit_sequence, journal->j_commit_request);

	if (journal->j_commit_sequence != journal->j_commit_request) {
		jbd_debug(1, "OK, requests differ\n");
		write_unlock(&journal->j_state_lock);
		del_timer_sync(&journal->j_commit_timer);
		zj_journal_commit_transaction(journal);
		write_lock(&journal->j_state_lock);
		goto loop;
	}

	wake_up(&journal->j_wait_done_commit);
	if (freezing(current)) {
		/*
		 * The simpler the better. Flushing journal isn't a
		 * good idea, because that depends on threads that may
		 * be already stopped.
		 */
		jbd_debug(1, "Now suspending kjournald2\n");
		write_unlock(&journal->j_state_lock);
		try_to_freeze();
		write_lock(&journal->j_state_lock);
	} else {
		/*
		 * We assume on resume that commits are already there,
		 * so we don't sleep
		 */
		DEFINE_WAIT(wait);
		int should_sleep = 1;

		prepare_to_wait(&journal->j_wait_commit, &wait,
				TASK_INTERRUPTIBLE);
		if (journal->j_commit_sequence != journal->j_commit_request)
			should_sleep = 0;
		transaction = journal->j_running_transaction;
		if (transaction && time_after_eq(jiffies,
						transaction->t_expires))
			should_sleep = 0;
		if (journal->j_flags & ZJ_UNMOUNT)
			should_sleep = 0;
		if (should_sleep) {
			write_unlock(&journal->j_state_lock);
			schedule();
			write_lock(&journal->j_state_lock);
		}
		finish_wait(&journal->j_wait_commit, &wait);
	}

	jbd_debug(1, "kjournald2 wakes\n");

	/*
	 * Were we woken up by a commit wakeup event?
	 */
	transaction = journal->j_running_transaction;
	if (transaction && time_after_eq(jiffies, transaction->t_expires)) {
		journal->j_commit_request = transaction->t_tid;
		jbd_debug(1, "woke because of timeout\n");
	}
	goto loop;

end_loop:
	del_timer_sync(&journal->j_commit_timer);
	journal->j_task = NULL;
	wake_up(&journal->j_wait_done_commit);
	jbd_debug(1, "Journal thread exiting.\n");
	write_unlock(&journal->j_state_lock);
	return 0;
}

static int zj_journal_start_thread(zjournal_t *journal, int core)
{
	struct task_struct *t;

	t = kthread_create(kjournald2, journal, "zj/%s",
			journal->j_devname);

	if (!IS_ERR(t)) {
		kthread_bind(t, core);
		wake_up_process(t);
	} else
		return PTR_ERR(t);

	/* Set journal's core id as core_id for per cored journaling*/
	journal->j_core_id = core;

	wait_event(journal->j_wait_done_commit, journal->j_task != NULL);
	return 0;
}

static void journal_kill_thread(zjournal_t *journal)
{
	write_lock(&journal->j_state_lock);
	journal->j_flags |= ZJ_UNMOUNT;

	while (journal->j_task) {
		write_unlock(&journal->j_state_lock);
		wake_up(&journal->j_wait_commit);
		wait_event(journal->j_wait_done_commit, journal->j_task == NULL);
		write_lock(&journal->j_state_lock);
	}
	write_unlock(&journal->j_state_lock);
}

/*
 * zj_journal_write_metadata_buffer: write a metadata buffer to the journal.
 *
 * Writes a metadata buffer to a given disk block.  The actual IO is not
 * performed but a new buffer_head is constructed which labels the data
 * to be written with the correct destination disk block.
 *
 * Any magic-number escaping which needs to be done will cause a
 * copy-out here.  If the buffer happens to start with the
 * ZJ_MAGIC_NUMBER, then we can't write it to the log directly: the
 * magic number is only written to the log for descripter blocks.  In
 * this case, we copy the data and replace the first word with 0, and we
 * return a result code which indicates that this buffer needs to be
 * marked as an escaped buffer in the corresponding log descriptor
 * block.  The missing word can then be restored when the block is read
 * during recovery.
 *
 * If the source buffer has already been modified by a new transaction
 * since we took the last commit snapshot, we use the frozen copy of
 * that data for IO. If we end up using the existing buffer_head's data
 * for the write, then we have to make sure nobody modifies it while the
 * IO is in progress. do_get_write_access() handles this.
 *
 * The function returns a pointer to the buffer_head to be used for IO.
 * 
 *
 * Return value:
 *  <0: Error
 * >=0: Finished OK
 *
 * On success:
 * Bit 0 set == escape performed on the data
 * Bit 1 set == buffer copy-out performed (kfree the data after IO)
 */

int zj_journal_write_metadata_buffer(ztransaction_t *transaction,
				  struct zjournal_head  *jh_in,
				  struct buffer_head **bh_out,
				  sector_t blocknr)
{
	int need_copy_out = 0, need_free = 0, free_out = 0;
	int done_copy_out = 0;
	int do_escape = 0;
	char *mapped_data, *cold_data;
	struct zjournal_head *cold_jh, *free_jh;
	struct buffer_head *new_bh, *free_bh;
	struct page *new_page;
	unsigned int new_offset;
	struct buffer_head *bh_in = jh2bh(jh_in);
	zjournal_t *journal = transaction->t_journal;
	struct buffer_head *orig_bh;
	struct zjournal_head *orig_jh;
#ifdef ZJ_PROFILE
	unsigned long start_time, end_time;
#endif

	/*
	 * The buffer really shouldn't be locked: only the current committing
	 * transaction is allowed to write it, so nobody else is allowed
	 * to do any IO.
	 *
	 * akpm: except if we're journalling data, and write() output is
	 * also part of a shared mapping, and another thread has
	 * decided to launch a writepage() against this buffer.
	 */
	jbd_lock_bh_state(bh_in);
	smp_mb();

	if (buffer_shadow(bh_in)) {
		//already freezed in do get write acc
		done_copy_out = 1;
		new_bh = bh_in;
		cold_jh = jh_in;
		goto journal_block;
	}
	jbd_unlock_bh_state(bh_in);
#ifdef ZJ_PROFILE
	start_time = jiffies;
#endif

	new_bh = alloc_buffer_head(GFP_NOFS|__GFP_NOFAIL);

	/* keep subsequent assertions sane */
	cold_data = zj_alloc(bh_in->b_size, GFP_NOFS | __GFP_NOFAIL);
	cold_jh = journal_alloc_zjournal_head();

#ifdef ZJ_PROFILE
	end_time = jiffies;
	spin_lock(&journal->j_ov_lock);
	journal->j_ov_stats.zj_copy_time2 += zj_time_diff(start_time, end_time);
	journal->j_ov_stats.zj_copy_page2 ++;
	spin_unlock(&journal->j_ov_lock);
#endif

	jbd_lock_bh_state(bh_in);
repeat:
	/*
	 * If a new transaction has already done a buffer copy-out, then
	 * we use that version of the data for the commit.
	 */

	done_copy_out = 1;
	if (jh_in->b_transaction == NULL ||
	jh_in->b_transaction != transaction) {
		need_free = 1;
		free_bh = new_bh;
		free_jh = cold_jh;

		if (jh_in->b_orig == NULL) {
			free_out = 1;
			jbd_unlock_bh_state(bh_in);
			goto free;
		}
		J_ASSERT_JH(jh_in, jh_in->b_orig != NULL);
		cold_jh = jh_in->b_orig;
		new_bh = jh2bh(cold_jh);

		if (cold_jh->b_transaction != transaction) {
			free_out = 1;
			jbd_unlock_bh_state(bh_in);
			goto free;
		}

		// commit 시 write metadata 직전에 버퍼의 카운트를 하나 늘려주는데,
		// 여기서는 write를 직접 내릴 대상이 orig에서 copy본으로 바꼈으므로
		// count 관리가 필요하다.
		atomic_set(&new_bh->b_count, 1);

		goto journal_block;
	}
	zj_shadow(bh_in, jh_in, cold_jh, new_bh, cold_data, 1);

	// commit 시 write metadata 직전에 버퍼의 카운트를 하나 늘려주는데,
	// 여기서는 write를 직접 내릴 대상이 orig에서 copy본으로 바꼈으므로
	// count 관리가 필요하다.
	atomic_set(&new_bh->b_count, 1);
	jh_in->b_cpcount++;
	jh_in->b_transaction = NULL;
	jh_in->b_jlist = BJ_None;
	zj_journal_put_zjournal_head(jh_in);

	new_page = virt_to_page(cold_data);
	new_offset = offset_in_page(cold_data);

	mapped_data = kmap_atomic(new_page);
	/*
	 * Fire data frozen trigger if data already wasn't frozen.  Do this
	 * before checking for escaping, as the trigger may modify the magic
	 * offset.  If a copy-out happens afterwards, it will have the correct
	 * data in the buffer.
	 */
	if (!done_copy_out)
		zj_buffer_frozen_trigger(jh_in, mapped_data + new_offset,
					   jh_in->b_triggers);

	/*
	 * Check for escaping
	 */
	if (*((__be32 *)(mapped_data + new_offset)) ==
				cpu_to_be32(ZJ_MAGIC_NUMBER)) {
		need_copy_out = 1;
		do_escape = 1;
	}
	kunmap_atomic(mapped_data);

	/*
	 * Do we need to do a data copy?
	 */
	if (need_copy_out && !done_copy_out) {
		char *tmp;

		jbd_unlock_bh_state(bh_in);
		tmp = zj_alloc(bh_in->b_size, GFP_NOFS);
		if (!tmp) {
			brelse(new_bh);
			return -ENOMEM;
		}
		jbd_lock_bh_state(bh_in);
		if (jh_in->b_frozen_data) {
			zj_free(tmp, bh_in->b_size);
			goto repeat;
		}

		jh_in->b_frozen_data = tmp;
		mapped_data = kmap_atomic(new_page);
		memcpy(tmp, mapped_data + new_offset, bh_in->b_size);
		kunmap_atomic(mapped_data);

		new_page = virt_to_page(tmp);
		new_offset = offset_in_page(tmp);
		done_copy_out = 1;

		/*
		 * This isn't strictly necessary, as we're using frozen
		 * data for the escaping, but it keeps consistency with
		 * b_frozen_data usage.
		 */
		jh_in->b_frozen_triggers = jh_in->b_triggers;
	}

	/*
	 * Did we need to do an escaping?  Now we've done all the
	 * copying, we can finally do so.
	 */
	if (do_escape) {
		mapped_data = kmap_atomic(new_page);
		*((unsigned int *)(mapped_data + new_offset)) = 0;
		kunmap_atomic(mapped_data);
	}

	set_bh_page(new_bh, new_page, new_offset);

journal_block:
	new_bh->b_bdev = journal->j_dev;
	new_bh->b_blocknr = blocknr;
	set_buffer_mapped(new_bh);

	*bh_out = new_bh;
	if (!buffer_shadow(new_bh) || !buffer_frozen(new_bh))
		panic("ghi");
	jbd_unlock_bh_state(bh_in);
	jbd_lock_bh_state(new_bh);

	/*set_buffer_shadow(jh2bh(cold_jh->b_orig));*/
	/*
	 * The to-be-written buffer needs to get moved to the io queue,
	 * and the original buffer whose contents we are shadowing or
	 * copying is moved to the transaction's shadow queue.
	 */
	JBUFFER_TRACE(jh_in, "file as BJ_Shadow");
	spin_lock(&journal->j_list_lock);
	__zj_journal_file_buffer(cold_jh, transaction, BJ_Shadow);
	spin_unlock(&journal->j_list_lock);

	set_buffer_dirty(new_bh);
	jbd_unlock_bh_state(new_bh);

	orig_jh = cold_jh->b_orig;
	orig_bh = jh2bh(orig_jh);


	if (need_free) {
free:
		zj_free(cold_data, bh_in->b_size);
		free_buffer_head(free_bh);
		journal_free_zjournal_head(free_jh);
	}

	return do_escape | (done_copy_out << 1) | (free_out << 2);
}

/*
 * Allocation code for the journal file.  Manage the space left in the
 * journal, so that we can begin checkpointing when appropriate.
 */

/*
 * Called with j_state_lock locked for writing.
 * Returns true if a transaction commit was started.
 */
int __zj_log_start_commit(zjournal_t *journal, tid_t target)
{
	/* Return if the txn has already requested to be committed */
	if (journal->j_commit_request == target)
		return 0;

	/*
	 * The only transaction we can possibly wait upon is the
	 * currently running transaction (if it exists).  Otherwise,
	 * the target tid must be an old one.
	 */
	if (journal->j_running_transaction &&
	    journal->j_running_transaction->t_tid == target) {
		/*
		 * We want a new commit: OK, mark the request and wakeup the
		 * commit thread.  We do _not_ do the commit ourselves.
		 */

		journal->j_commit_request = target;
		jbd_debug(1, "ZJ: requesting commit %d/%d\n",
			  journal->j_commit_request,
			  journal->j_commit_sequence);
		journal->j_running_transaction->t_requested = jiffies;
		wake_up(&journal->j_wait_commit);
		return 1;
	} else if (!tid_geq(journal->j_commit_request, target))
		/* This should never happen, but if it does, preserve
		   the evidence before kjournald goes into a loop and
		   increments j_commit_sequence beyond all recognition. */
		WARN_ONCE(1, "ZJ: bad log_start_commit: %u %u %u %u\n",
			  journal->j_commit_request,
			  journal->j_commit_sequence,
			  target, journal->j_running_transaction ? 
			  journal->j_running_transaction->t_tid : 0);
	return 0;
}

int zj_log_start_commit(zjournal_t *journal, tid_t tid)
{
	int ret;

	write_lock(&journal->j_state_lock);
	ret = __zj_log_start_commit(journal, tid);
	write_unlock(&journal->j_state_lock);
	return ret;
}

/*
 * Force and wait any uncommitted transactions.  We can only force the running
 * transaction if we don't have an active handle, otherwise, we will deadlock.
 * Returns: <0 in case of error,
 *           0 if nothing to commit,
 *           1 if transaction was successfully committed.
 */
static int __zj_journal_force_commit(zjournal_t *journal)
{
	ztransaction_t *transaction = NULL;
	tid_t tid;
	int need_to_start = 0, ret = 0;

	read_lock(&journal->j_state_lock);
	if (journal->j_running_transaction && !current->journal_info) {
		transaction = journal->j_running_transaction;
		if (!tid_geq(journal->j_commit_request, transaction->t_tid))
			need_to_start = 1;
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	if (!transaction) {
		/* Nothing to commit */
		read_unlock(&journal->j_state_lock);
		return 0;
	}
	tid = transaction->t_tid;
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		zj_log_start_commit(journal, tid);
	ret = zj_log_wait_commit(journal, tid);
	if (!ret)
		ret = 1;

	return ret;
}

int zj_journal_force_commit_start(zjournal_t *journal)
{
	ztransaction_t *transaction = NULL;
	tid_t tid;
	int need_to_start = 0;
	
	read_lock(&journal->j_state_lock);
	if (journal->j_running_transaction && !current->journal_info) {
		transaction = journal->j_running_transaction;
		if (!tid_geq(journal->j_commit_request, transaction->t_tid))
			need_to_start = 1;
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	if (!transaction) {
		/* Nothing to commit */
		read_unlock(&journal->j_state_lock);
		return 0;
	}
	tid = transaction->t_tid;
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		zj_log_start_commit(journal, tid);

	return tid;
}

/**
 * Force and wait upon a commit if the calling process is not within
 * transaction.  This is used for forcing out undo-protected data which contains
 * bitmaps, when the fs is running out of space.
 *
 * @journal: journal to force
 * Returns true if progress was made.
 */
int zj_journal_force_commit_nested(zjournal_t *journal)
{
	int ret;

	ret = __zj_journal_force_commit(journal);
	return ret > 0;
}

/**
 * int journal_force_commit() - force any uncommitted transactions
 * @journal: journal to force
 *
 * Caller want unconditional commit. We can only force the running transaction
 * if we don't have an active handle, otherwise, we will deadlock.
 */
int zj_journal_force_commit(zjournal_t *journal)
{
	int ret;

	J_ASSERT(!current->journal_info);
	ret = __zj_journal_force_commit(journal);
	if (ret > 0)
		ret = 0;
	return ret;
}

/*
 * Start a commit of the current running transaction (if any).  Returns true
 * if a transaction is going to be committed (or is currently already
 * committing), and fills its tid in at *ptid
 */
int zj_journal_start_commit(zjournal_t *journal, tid_t *ptid)
{
	int ret = 0;

	write_lock(&journal->j_state_lock);
	if (journal->j_running_transaction) {
		tid_t tid = journal->j_running_transaction->t_tid;

		__zj_log_start_commit(journal, tid);
		/* There's a running transaction and we've just made sure
		 * it's commit has been scheduled. */
		if (ptid)
			*ptid = tid;
		ret = 1;
	} else if (journal->j_committing_transaction) {
		/*
		 * If commit has been started, then we have to wait for
		 * completion of that transaction.
		 */
		if (ptid)
			*ptid = journal->j_committing_transaction->t_tid;
		ret = 1;
	}
	write_unlock(&journal->j_state_lock);
	return ret;
}

/*
 * Return 1 if a given transaction has not yet sent barrier request
 * connected with a transaction commit. If 0 is returned, transaction
 * may or may not have sent the barrier. Used to avoid sending barrier
 * twice in common cases.
 */
int zj_trans_will_send_data_barrier(zjournal_t *journal, tid_t tid)
{
	int ret = 0;
	ztransaction_t *commit_trans;

	if (!(journal->j_flags & ZJ_BARRIER))
		return 0;
	read_lock(&journal->j_state_lock);
	/* Transaction already committed? */
	if (tid_geq(journal->j_commit_sequence, tid))
		goto out;
	commit_trans = journal->j_committing_transaction;
	if (!commit_trans || commit_trans->t_tid != tid) {
		ret = 1;
		goto out;
	}
	/*
	 * Transaction is being committed and we already proceeded to
	 * submitting a flush to fs partition?
	 */
	if (journal->j_fs_dev != journal->j_dev) {
		if (!commit_trans->t_need_data_flush ||
		    commit_trans->t_state >= T_COMMIT_DFLUSH)
			goto out;
	} else {
		if (commit_trans->t_state >= T_COMMIT_JFLUSH)
			goto out;
	}
	ret = 1;
out:
	read_unlock(&journal->j_state_lock);
	return ret;
}
EXPORT_SYMBOL(zj_trans_will_send_data_barrier);

/*
 * Wait for a specified commit to complete.
 * The caller may not hold the journal lock.
 */
int zj_log_wait_commit(zjournal_t *journal, tid_t tid)
{
	int err = 0;

	read_lock(&journal->j_state_lock);
#ifdef CONFIG_PROVE_LOCKING
	/*
	 * Some callers make sure transaction is already committing and in that
	 * case we cannot block on open handles anymore. So don't warn in that
	 * case.
	 */
	if (tid_gt(tid, journal->j_commit_sequence) &&
	    (!journal->j_committing_transaction ||
	     journal->j_committing_transaction->t_tid != tid)) {
		read_unlock(&journal->j_state_lock);
		zj_might_wait_for_commit(journal);
		read_lock(&journal->j_state_lock);
	}
#endif
#ifdef CONFIG_ZJ_DEBUG
	if (!tid_geq(journal->j_commit_request, tid)) {
		printk(KERN_ERR
		       "%s: error: j_commit_request=%d, tid=%d\n",
		       __func__, journal->j_commit_request, tid);
	}
#endif
	while (tid_gt(tid, journal->j_commit_sequence)) {
		jbd_debug(1, "ZJ: want %d, j_commit_sequence=%d\n",
				  tid, journal->j_commit_sequence);
		read_unlock(&journal->j_state_lock);
		wake_up(&journal->j_wait_commit);
		wait_event(journal->j_wait_done_commit,
				!tid_gt(tid, journal->j_commit_sequence));
		read_lock(&journal->j_state_lock);
	}
	read_unlock(&journal->j_state_lock);

	if (unlikely(is_journal_aborted(journal)))
		err = -EIO;
	return err;
}

/*
 * When this function returns the transaction corresponding to tid
 * will be completed.  If the transaction has currently running, start
 * committing that transaction before waiting for it to complete.  If
 * the transaction id is stale, it is by definition already completed,
 * so just return SUCCESS.
 */
int zj_complete_transaction(zjournal_t *journal, tid_t tid)
{
	int	need_to_wait = 1;

	read_lock(&journal->j_state_lock);
	if (journal->j_running_transaction &&
	    journal->j_running_transaction->t_tid == tid) {
		if (journal->j_commit_request != tid) {
			/* transaction not yet started, so request it */
			read_unlock(&journal->j_state_lock);
			zj_log_start_commit(journal, tid);
			goto wait_commit;
		}
	} else if (!(journal->j_committing_transaction &&
		     journal->j_committing_transaction->t_tid == tid))
		need_to_wait = 0;
	read_unlock(&journal->j_state_lock);
	if (!need_to_wait)
		return 0;
wait_commit:
	return zj_log_wait_commit(journal, tid);
}
EXPORT_SYMBOL(zj_complete_transaction);

/*
 * Log buffer allocation routines:
 */

int zj_journal_next_log_block(zjournal_t *journal, unsigned long long *retp)
{
	unsigned long blocknr;

	write_lock(&journal->j_state_lock);
	J_ASSERT(journal->j_free > 1);

	blocknr = journal->j_head;
	journal->j_head++;
	journal->j_free--;
	if (journal->j_head == journal->j_last)
		journal->j_head = journal->j_first;
	write_unlock(&journal->j_state_lock);
	return zj_journal_bmap(journal, blocknr, retp);
}

/*
 * Conversion of logical to physical block numbers for the journal
 *
 * On external journals the journal blocks are identity-mapped, so
 * this is a no-op.  If needed, we can use j_blk_offset - everything is
 * ready.
 */
int zj_journal_bmap(zjournal_t *journal, unsigned long blocknr,
		 unsigned long long *retp)
{
	int err = 0;
	unsigned long long ret;

	if (journal->j_inode) {
		ret = bmap(journal->j_inode, blocknr);
		if (ret)
			*retp = ret;
		else {
			printk(KERN_ALERT "%s: journal block not found "
					"at offset %lu on %s\n",
			       __func__, blocknr, journal->j_devname);
			err = -EIO;
			__journal_abort_soft(journal, err);
		}
	} else {
		*retp = blocknr; /* +journal->j_blk_offset */
	}
	return err;
}

/*
 * We play buffer_head aliasing tricks to write data/metadata blocks to
 * the journal without copying their contents, but for journal
 * descriptor blocks we do need to generate bona fide buffers.
 *
 * After the caller of zj_journal_get_descriptor_buffer() has finished modifying
 * the buffer's contents they really should run flush_dcache_page(bh->b_page).
 * But we don't bother doing that, so there will be coherency problems with
 * mmaps of blockdevs which hold live JBD-controlled filesystems.
 */
struct buffer_head *
zj_journal_get_descriptor_buffer(ztransaction_t *transaction, int type)
{
	zjournal_t *journal = transaction->t_journal;
	struct buffer_head *bh;
	unsigned long long blocknr;
	zjournal_header_t *header;
	int err;

	err = zj_journal_next_log_block(journal, &blocknr);

	if (err)
		return NULL;

	bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
	if (!bh)
		return NULL;
	lock_buffer(bh);
	memset(bh->b_data, 0, journal->j_blocksize);
	header = (zjournal_header_t *)bh->b_data;
	header->h_magic = cpu_to_be32(ZJ_MAGIC_NUMBER);
	header->h_blocktype = cpu_to_be32(type);
	header->h_sequence = cpu_to_be32(transaction->t_tid);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);
	BUFFER_TRACE(bh, "return this buffer");
	return bh;
}

void zj_descriptor_block_csum_set(zjournal_t *j, struct buffer_head *bh)
{
	struct zj_journal_block_tail *tail;
	__u32 csum;

	if (!zj_journal_has_csum_v2or3(j))
		return;

	tail = (struct zj_journal_block_tail *)(bh->b_data + j->j_blocksize -
			sizeof(struct zj_journal_block_tail));
	tail->t_checksum = 0;
	csum = zj_chksum(j, j->j_csum_seed, bh->b_data, j->j_blocksize);
	tail->t_checksum = cpu_to_be32(csum);
}

/*
 * Return tid of the oldest transaction in the journal and block in the journal
 * where the transaction starts.
 *
 * If the journal is now empty, return which will be the next transaction ID
 * we will write and where will that transaction start.
 *
 * The return value is 0 if journal tail cannot be pushed any further, 1 if
 * it can.
 */
int zj_journal_get_log_tail(zjournal_t *journal, tid_t *tid,
			      unsigned long *block)
{
	ztransaction_t *transaction;
	int ret;

	read_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	transaction = journal->j_checkpoint_transactions;
	if (transaction) {
		*tid = transaction->t_tid;
		*block = transaction->t_log_start;
	} else if ((transaction = journal->j_committing_transaction) != NULL) {
		*tid = transaction->t_tid;
		*block = transaction->t_log_start;
	} else if ((transaction = journal->j_running_transaction) != NULL) {
		*tid = transaction->t_tid;
		*block = journal->j_head;
	} else {
		*tid = journal->j_transaction_sequence;
		*block = journal->j_head;
	}
	ret = tid_gt(*tid, journal->j_tail_sequence);
	spin_unlock(&journal->j_list_lock);
	read_unlock(&journal->j_state_lock);

	return ret;
}

/*
 * Update information in journal structure and in on disk journal superblock
 * about log tail. This function does not check whether information passed in
 * really pushes log tail further. It's responsibility of the caller to make
 * sure provided log tail information is valid (e.g. by holding
 * j_checkpoint_mutex all the time between computing log tail and calling this
 * function as is the case with zj_cleanup_zjournal_tail()).
 *
 * Requires j_checkpoint_mutex
 */
int __zj_update_log_tail(zjournal_t *journal, tid_t tid, unsigned long block)
{
	unsigned long freed;
	int ret;

	BUG_ON(!mutex_is_locked(&journal->j_checkpoint_mutex));

	/*
	 * We cannot afford for write to remain in drive's caches since as
	 * soon as we update j_tail, next transaction can start reusing journal
	 * space and if we lose sb update during power failure we'd replay
	 * old transaction with possibly newly overwritten data.
	 */
	ret = zj_journal_update_sb_log_tail(journal, tid, block,
					      REQ_SYNC | REQ_FUA);
	if (ret)
		goto out;

	write_lock(&journal->j_state_lock);
	freed = block - journal->j_tail;
	if (block < journal->j_tail)
		freed += journal->j_last - journal->j_first;

	trace_zj_update_log_tail(journal, tid, block, freed);
	jbd_debug(1,
		  "Cleaning journal tail from %d to %d (offset %lu), "
		  "freeing %lu\n",
		  journal->j_tail_sequence, tid, block, freed);

	journal->j_free += freed;
	journal->j_tail_sequence = tid;
	journal->j_tail = block;
	write_unlock(&journal->j_state_lock);

out:
	return ret;
}

/*
 * This is a variation of __zj_update_log_tail which checks for validity of
 * provided log tail and locks j_checkpoint_mutex. So it is safe against races
 * with other threads updating log tail.
 */
void zj_update_log_tail(zjournal_t *journal, tid_t tid, unsigned long block)
{
	mutex_lock_io(&journal->j_checkpoint_mutex);
	if (tid_gt(tid, journal->j_tail_sequence))
		__zj_update_log_tail(journal, tid, block);
	mutex_unlock(&journal->j_checkpoint_mutex);
}

struct zj_stats_proc_session {
	zjournal_t *journal;
	struct transaction_stats_s *stats;
	int start;
	int max;
};

#ifdef ZJ_PROFILE
struct zj_ov_proc_session {
	zjournal_t *journal;
	struct zjournal_overhead *ovs;
	int start;
	int max;
};

static int zj_seq_ov_show(struct seq_file *seq, void *v)
{
	struct zj_ov_proc_session *s = seq->private;

	if (v != SEQ_START_TOKEN)
		return 0;

	seq_printf(seq, "  %u  %d %u %d (copy1, page1, copy2, page2)\n",
			jiffies_to_msecs(s->ovs->zj_copy_time1), s->ovs->zj_copy_page1,
			jiffies_to_msecs(s->ovs->zj_copy_time2), s->ovs->zj_copy_page2);
	seq_printf(seq, "  %u  %d %u %d (wait1, page1, wait2, page2)\n",
			jiffies_to_msecs(s->ovs->zj_wait_time1), s->ovs->zj_wait_page1,
			jiffies_to_msecs(s->ovs->zj_wait_time2), s->ovs->zj_wait_page2);

	return 0;
}
#endif

static void *zj_seq_info_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? NULL : SEQ_START_TOKEN;
}

static void *zj_seq_info_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

static int zj_seq_info_show(struct seq_file *seq, void *v)
{
	struct zj_stats_proc_session *s = seq->private;

	if (v != SEQ_START_TOKEN)
		return 0;
	seq_printf(seq, "%lu transactions (%lu requested), "
		   "each up to %u blocks\n",
		   s->stats->ts_tid, s->stats->ts_requested,
		   s->journal->j_max_transaction_buffers);
	if (s->stats->ts_tid == 0)
		return 0;
	seq_printf(seq, "average: \n  %u ms waiting for transaction\n",
	    jiffies_to_msecs(s->stats->run.rs_wait ));
	seq_printf(seq, "  %u ms request delay\n",
	    (s->stats->ts_requested == 0) ? 0 :
	    jiffies_to_msecs(s->stats->run.rs_request_delay));
	seq_printf(seq, "  %u ms running transaction\n",
	    jiffies_to_msecs(s->stats->run.rs_running ));
	seq_printf(seq, "  %u ms transaction was being locked\n",
	    jiffies_to_msecs(s->stats->run.rs_locked ));
	seq_printf(seq, "  %u ms flushing data (in ordered mode)\n",
	    jiffies_to_msecs(s->stats->run.rs_flushing ));
	seq_printf(seq, "  %u ms logging transaction\n",
	    jiffies_to_msecs(s->stats->run.rs_logging ));
	seq_printf(seq, "  %llu us average transaction commit time\n",
		   s->journal->j_average_commit_time);
	seq_printf(seq, "  %u handles per transaction\n",
	    s->stats->run.rs_handle_count );
	seq_printf(seq, "  %u blocks per transaction\n",
	    s->stats->run.rs_blocks);
	seq_printf(seq, "  %u logged blocks per transaction\n",
	    s->stats->run.rs_blocks_logged );
	return 0;
}

static void zj_seq_info_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations zj_seq_info_ops = {
	.start  = zj_seq_info_start,
	.next   = zj_seq_info_next,
	.stop   = zj_seq_info_stop,
	.show   = zj_seq_info_show,
};

#ifdef ZJ_PROFILE
static const struct seq_operations zj_seq_ov_ops = {
	.start  = zj_seq_info_start,
	.next   = zj_seq_info_next,
	.stop   = zj_seq_info_stop,
	.show   = zj_seq_ov_show,
};

static int zj_seq_ov_open(struct inode *inode, struct file *file)
{
	zjournal_t *journal = PDE_DATA(inode);
	struct zj_ov_proc_session *s;
	int rc, size;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (s == NULL)
		return -ENOMEM;
	size = sizeof(struct zjournal_overhead);
	s->ovs = kmalloc(size, GFP_KERNEL);
	if (s->ovs == NULL) {
		kfree(s);
		return -ENOMEM;
	}
	spin_lock(&journal->j_ov_lock);
	memcpy(s->ovs, &journal->j_ov_stats, size);
	s->journal = journal;
	spin_unlock(&journal->j_ov_lock);

	rc = seq_open(file, &zj_seq_ov_ops);
	if (rc == 0) {
		struct seq_file *m = file->private_data;
		m->private = s;
	} else {
		kfree(s->ovs);
		kfree(s);
	}
	return rc;

}

static int zj_seq_ov_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct zj_ov_proc_session *s = seq->private;
	kfree(s->ovs);
	kfree(s);
	return seq_release(inode, file);
}

static const struct file_operations zj_seq_ov_fops = {
	.owner		= THIS_MODULE,
	.open           = zj_seq_ov_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = zj_seq_ov_release,
};
#endif

static int zj_seq_info_open(struct inode *inode, struct file *file)
{
	zjournal_t *journal = PDE_DATA(inode);
	struct zj_stats_proc_session *s;
	int rc, size;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (s == NULL)
		return -ENOMEM;
	size = sizeof(struct transaction_stats_s);
	s->stats = kmalloc(size, GFP_KERNEL);
	if (s->stats == NULL) {
		kfree(s);
		return -ENOMEM;
	}
	spin_lock(&journal->j_history_lock);
	memcpy(s->stats, &journal->j_stats, size);
	s->journal = journal;
	spin_unlock(&journal->j_history_lock);

	rc = seq_open(file, &zj_seq_info_ops);
	if (rc == 0) {
		struct seq_file *m = file->private_data;
		m->private = s;
	} else {
		kfree(s->stats);
		kfree(s);
	}
	return rc;

}

static int zj_seq_info_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct zj_stats_proc_session *s = seq->private;
	kfree(s->stats);
	kfree(s);
	return seq_release(inode, file);
}

static const struct file_operations zj_seq_info_fops = {
	.owner		= THIS_MODULE,
	.open           = zj_seq_info_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = zj_seq_info_release,
};

static struct proc_dir_entry *proc_zj_stats;

static void zj_stats_proc_init(zjournal_t *journal)
{
	journal->j_proc_entry = proc_mkdir(journal->j_devname, proc_zj_stats);
	if (journal->j_proc_entry) {
		proc_create_data("info", S_IRUGO, journal->j_proc_entry,
				 &zj_seq_info_fops, journal);
#ifdef ZJ_PROFILE
		proc_create_data("overhead", S_IRUGO, journal->j_proc_entry,
				&zj_seq_ov_fops, journal);
#endif
	}
}

static void zj_stats_proc_exit(zjournal_t *journal)
{
	remove_proc_entry("info", journal->j_proc_entry);
	remove_proc_entry(journal->j_devname, proc_zj_stats);
}

/*
 * Management for journal control blocks: functions to create and
 * destroy zjournal_t structures, and to initialise and read existing
 * journal blocks from disk.  */

/* First: create and setup a zjournal_t object in memory.  We initialise
 * very few fields yet: that has to wait until we have created the
 * journal structures from from scratch, or loaded them from disk. */

static zjournal_t *journal_init_common(struct block_device *bdev,
			struct block_device *fs_dev,
			unsigned long long start, int len, int blocksize)
{
	static struct lock_class_key zj_trans_commit_key;
	zjournal_t *journal;
	int err;
	struct buffer_head *bh;
	int n;

	journal = kzalloc(sizeof(*journal), GFP_KERNEL);
	if (!journal)
		return NULL;

	init_waitqueue_head(&journal->j_wait_transaction_locked);
	init_waitqueue_head(&journal->j_wait_done_commit);
	init_waitqueue_head(&journal->j_wait_commit);
	init_waitqueue_head(&journal->j_wait_updates);
	init_waitqueue_head(&journal->j_wait_nexts);
	init_waitqueue_head(&journal->j_wait_reserved);
	mutex_init(&journal->j_barrier);
	mutex_init(&journal->j_checkpoint_mutex);
	spin_lock_init(&journal->j_revoke_lock);
	spin_lock_init(&journal->j_list_lock);
	spin_lock_init(&journal->j_mark_lock);
	rwlock_init(&journal->j_state_lock);
	INIT_RADIX_TREE(&journal->j_checkpoint_txtree, GFP_KERNEL);

	journal->j_commit_interval = (HZ * ZJ_DEFAULT_MAX_COMMIT_AGE);
	journal->j_min_batch_time = 0;
	journal->j_max_batch_time = 15000; /* 15ms */
	atomic_set(&journal->j_reserved_credits, 0);

	tunmap1 = 0;
	tunmap2 = 0;
	tunmap3 = 0;
	tunmap4 = 0;
	tunmap5 = 0;
	tunmap6 = 0;
	tunmap7 = 0;
	tunmap8 = 0;
	tunmap9 = 0;

	tforget_total = 0;
	tforget1 = 0;
	tforget2 = 0;
	tforget3 = 0;
	tforget4 = 0;
	tforget5 = 0;
	tforget6 = 0;

	/* The journal is marked for error until we succeed with recovery! */
	journal->j_flags = ZJ_ABORT;

	/* Set up a default-sized revoke table for the new mount. */
	err = zj_journal_init_revoke(journal, JOURNAL_REVOKE_DEFAULT_HASH);
	if (err)
		goto err_cleanup;

	spin_lock_init(&journal->j_history_lock);
#ifdef ZJ_PROFILE
	spin_lock_init(&journal->j_ov_lock);
#endif

	lockdep_init_map(&journal->j_trans_commit_map, "zj_handle",
			 &zj_trans_commit_key, 0);

	/* journal descriptor can store up to n blocks -bzzz */
	journal->j_blocksize = blocksize;
	journal->j_dev = bdev;
	journal->j_fs_dev = fs_dev;
	journal->j_blk_offset = start;
	journal->j_maxlen = len;
	n = journal->j_blocksize / sizeof(journal_block_tag_t);
	journal->j_wbufsize = n;
	journal->j_wbuf = kmalloc_array(n, sizeof(struct buffer_head *),
					GFP_KERNEL);
	journal->j_cbuf = kmalloc_array(ZJ_NR_COMMIT, sizeof(commit_mark_t),
					GFP_KERNEL);
	journal->j_cbuf_debug = 0;
	if (!journal->j_wbuf)
		goto err_cleanup;
	if (!journal->j_cbuf)
		goto err_cleanup;

	bh = getblk_unmovable(journal->j_dev, start, journal->j_blocksize);
	if (!bh) {
		pr_err("%s: Cannot get buffer for journal superblock\n",
			__func__);
		goto err_cleanup;
	}
	journal->j_sb_buffer = bh;
	journal->j_superblock = (journal_superblock_t *)bh->b_data;

	return journal;

err_cleanup:
	kfree(journal->j_wbuf);
	kfree(journal->j_cbuf);
	zj_journal_destroy_revoke(journal);
	kfree(journal);
	return NULL;
}

/* zj_journal_init_dev and zj_journal_init_inode:
 *
 * Create a journal structure assigned some fixed set of disk blocks to
 * the journal.  We don't actually touch those disk blocks yet, but we
 * need to set up all of the mapping information to tell the journaling
 * system where the journal blocks are.
 *
 */

/**
 *  zjournal_t * zj_journal_init_dev() - creates and initialises a journal structure
 *  @bdev: Block device on which to create the journal
 *  @fs_dev: Device which hold journalled filesystem for this journal.
 *  @start: Block nr Start of journal.
 *  @len:  Length of the journal in blocks.
 *  @blocksize: blocksize of journalling device
 *
 *  Returns: a newly created zjournal_t *
 *
 *  zj_journal_init_dev creates a journal which maps a fixed contiguous
 *  range of blocks on an arbitrary block device.
 *
 */
zjournal_t *zj_journal_init_dev(struct block_device *bdev,
			struct block_device *fs_dev,
			unsigned long long start, int len, int blocksize)
{
	zjournal_t *journal;

	journal = journal_init_common(bdev, fs_dev, start, len, blocksize);
	if (!journal)
		return NULL;

	bdevname(journal->j_dev, journal->j_devname);
	strreplace(journal->j_devname, '/', '!');
	zj_stats_proc_init(journal);

	return journal;
}

/**
 *  zjournal_t * zj_journal_init_inode () - creates a journal which maps to a inode.
 *  @inode: An inode to create the journal in
 *
 * zj_journal_init_inode creates a journal which maps an on-disk inode as
 * the journal.  The inode must exist already, must support bmap() and
 * must have all data blocks preallocated.
 */
zjournal_t *zj_journal_init_inode(struct inode *inode)
{
	zjournal_t *journal;
	char *p;
	unsigned long long blocknr;

	blocknr = bmap(inode, 0);
	if (!blocknr) {
		pr_err("%s: Cannot locate journal superblock\n",
			__func__);
		return NULL;
	}

	jbd_debug(1, "ZJ: inode %s/%ld, size %lld, bits %d, blksize %ld\n",
		  inode->i_sb->s_id, inode->i_ino, (long long) inode->i_size,
		  inode->i_sb->s_blocksize_bits, inode->i_sb->s_blocksize);

	journal = journal_init_common(inode->i_sb->s_bdev, inode->i_sb->s_bdev,
			blocknr, inode->i_size >> inode->i_sb->s_blocksize_bits,
			inode->i_sb->s_blocksize);
	if (!journal)
		return NULL;

	journal->j_inode = inode;
	bdevname(journal->j_dev, journal->j_devname);
	p = strreplace(journal->j_devname, '/', '!');
	sprintf(p, "-%lu", journal->j_inode->i_ino);
	zj_stats_proc_init(journal);

	return journal;
}

/*
 * If the journal init or create aborts, we need to mark the journal
 * superblock as being NULL to prevent the journal destroy from writing
 * back a bogus superblock.
 */
static void journal_fail_superblock (zjournal_t *journal)
{
	struct buffer_head *bh = journal->j_sb_buffer;
	brelse(bh);
	journal->j_sb_buffer = NULL;
}

/*
 * Given a zjournal_t structure, initialise the various fields for
 * startup of a new journaling session.  We use this both when creating
 * a journal, and after recovering an old journal to reset it for
 * subsequent use.
 */

static int journal_reset(zjournal_t *journal, int core)
{
	journal_superblock_t *sb = journal->j_superblock;
	unsigned long long first, last;

	first = be32_to_cpu(sb->s_first);
	last = be32_to_cpu(sb->s_maxlen);
	if (first + ZJ_MIN_JOURNAL_BLOCKS > last + 1) {
		printk(KERN_ERR "ZJ: Journal too short (blocks %llu-%llu).\n",
		       first, last);
		journal_fail_superblock(journal);
		return -EINVAL;
	}

	journal->j_first = first;
	journal->j_last = last;

	journal->j_head = first;
	journal->j_tail = first;
	journal->j_free = last - first;

	journal->j_tail_sequence = journal->j_transaction_sequence;
	journal->j_commit_sequence = journal->j_transaction_sequence - 1;
	journal->j_commit_request = journal->j_commit_sequence;

	journal->j_max_transaction_buffers = journal->j_maxlen / 4;

	/*
	 * As a special case, if the on-disk copy is already marked as needing
	 * no recovery (s_start == 0), then we can safely defer the superblock
	 * update until the next commit by setting ZJ_FLUSHED.  This avoids
	 * attempting a write to a potential-readonly device.
	 */
	if (sb->s_start == 0) {
		jbd_debug(1, "ZJ: Skipping superblock update on recovered sb "
			"(start %ld, seq %d, errno %d)\n",
			journal->j_tail, journal->j_tail_sequence,
			journal->j_errno);
		journal->j_flags |= ZJ_FLUSHED;
	} else {
		/* Lock here to make assertions happy... */
		mutex_lock_io(&journal->j_checkpoint_mutex);
		/*
		 * Update log tail information. We use REQ_FUA since new
		 * transaction will start reusing journal space and so we
		 * must make sure information about current log tail is on
		 * disk before that.
		 */
		zj_journal_update_sb_log_tail(journal,
						journal->j_tail_sequence,
						journal->j_tail,
						REQ_SYNC | REQ_FUA);
		mutex_unlock(&journal->j_checkpoint_mutex);
	}
	return zj_journal_start_thread(journal, core);
}

static int zj_write_superblock(zjournal_t *journal, int write_flags)
{
	struct buffer_head *bh = journal->j_sb_buffer;
	journal_superblock_t *sb = journal->j_superblock;
	int ret;

	trace_zj_write_superblock(journal, write_flags);
	if (!(journal->j_flags & ZJ_BARRIER))
		write_flags &= ~(REQ_FUA | REQ_PREFLUSH);
	lock_buffer(bh);
	if (buffer_write_io_error(bh)) {
		/*
		 * Oh, dear.  A previous attempt to write the journal
		 * superblock failed.  This could happen because the
		 * USB device was yanked out.  Or it could happen to
		 * be a transient write error and maybe the block will
		 * be remapped.  Nothing we can do but to retry the
		 * write and hope for the best.
		 */
		printk(KERN_ERR "ZJ: previous I/O error detected "
		       "for journal superblock update for %s.\n",
		       journal->j_devname);
		clear_buffer_write_io_error(bh);
		set_buffer_uptodate(bh);
	}
	zj_superblock_csum_set(journal, sb);
	get_bh(bh);
	bh->b_end_io = end_buffer_write_sync;
	ret = submit_bh(REQ_OP_WRITE, write_flags, bh);
	wait_on_buffer(bh);
	if (buffer_write_io_error(bh)) {
		clear_buffer_write_io_error(bh);
		set_buffer_uptodate(bh);
		ret = -EIO;
	}
	if (ret) {
		printk(KERN_ERR "ZJ: Error %d detected when updating "
		       "journal superblock for %s.\n", ret,
		       journal->j_devname);
		zj_journal_abort(journal, ret);
	}

	return ret;
}

/**
 * zj_journal_update_sb_log_tail() - Update log tail in journal sb on disk.
 * @journal: The journal to update.
 * @tail_tid: TID of the new transaction at the tail of the log
 * @tail_block: The first block of the transaction at the tail of the log
 * @write_op: With which operation should we write the journal sb
 *
 * Update a journal's superblock information about log tail and write it to
 * disk, waiting for the IO to complete.
 */
int zj_journal_update_sb_log_tail(zjournal_t *journal, tid_t tail_tid,
				     unsigned long tail_block, int write_op)
{
	journal_superblock_t *sb = journal->j_superblock;
	int ret;

	if (is_journal_aborted(journal))
		return -EIO;

	BUG_ON(!mutex_is_locked(&journal->j_checkpoint_mutex));
	jbd_debug(1, "ZJ: updating superblock (start %lu, seq %u)\n",
		  tail_block, tail_tid);

	sb->s_sequence = cpu_to_be32(tail_tid);
	sb->s_start    = cpu_to_be32(tail_block);

	ret = zj_write_superblock(journal, write_op);
	if (ret)
		goto out;

	/* Log is no longer empty */
	write_lock(&journal->j_state_lock);
	WARN_ON(!sb->s_sequence);
	journal->j_flags &= ~ZJ_FLUSHED;
	write_unlock(&journal->j_state_lock);

out:
	return ret;
}

/**
 * zj_mark_journal_empty() - Mark on disk journal as empty.
 * @journal: The journal to update.
 * @write_op: With which operation should we write the journal sb
 *
 * Update a journal's dynamic superblock fields to show that journal is empty.
 * Write updated superblock to disk waiting for IO to complete.
 */
static void zj_mark_journal_empty(zjournal_t *journal, int write_op)
{
	journal_superblock_t *sb = journal->j_superblock;

	BUG_ON(!mutex_is_locked(&journal->j_checkpoint_mutex));
	read_lock(&journal->j_state_lock);
	/* Is it already empty? */
	if (sb->s_start == 0) {
		read_unlock(&journal->j_state_lock);
		return;
	}
	jbd_debug(1, "ZJ: Marking journal as empty (seq %d)\n",
		  journal->j_tail_sequence);

	sb->s_sequence = cpu_to_be32(journal->j_tail_sequence);
	sb->s_start    = cpu_to_be32(0);
	read_unlock(&journal->j_state_lock);

	zj_write_superblock(journal, write_op);

	/* Log is no longer empty */
	write_lock(&journal->j_state_lock);
	journal->j_flags |= ZJ_FLUSHED;
	write_unlock(&journal->j_state_lock);
}


/**
 * zj_journal_update_sb_errno() - Update error in the journal.
 * @journal: The journal to update.
 *
 * Update a journal's errno.  Write updated superblock to disk waiting for IO
 * to complete.
 */
void zj_journal_update_sb_errno(zjournal_t *journal)
{
	journal_superblock_t *sb = journal->j_superblock;
	int errcode;

	read_lock(&journal->j_state_lock);
	errcode = journal->j_errno;
	read_unlock(&journal->j_state_lock);
	if (errcode == -ESHUTDOWN)
		errcode = 0;
	jbd_debug(1, "ZJ: updating superblock error (errno %d)\n", errcode);
	sb->s_errno    = cpu_to_be32(errcode);

	zj_write_superblock(journal, REQ_SYNC | REQ_FUA);
}
EXPORT_SYMBOL(zj_journal_update_sb_errno);

/*
 * Read the superblock for a given journal, performing initial
 * validation of the format.
 */
static int journal_get_superblock(zjournal_t *journal)
{
	struct buffer_head *bh;
	journal_superblock_t *sb;
	int err = -EIO;

	bh = journal->j_sb_buffer;

	J_ASSERT(bh != NULL);
	if (!buffer_uptodate(bh)) {
		ll_rw_block(REQ_OP_READ, 0, 1, &bh);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
			printk(KERN_ERR
				"ZJ: IO error reading journal superblock\n");
			goto out;
		}
	}

	if (buffer_verified(bh))
		return 0;

	sb = journal->j_superblock;

	err = -EINVAL;

	if (sb->s_header.h_magic != cpu_to_be32(ZJ_MAGIC_NUMBER) ||
	    sb->s_blocksize != cpu_to_be32(journal->j_blocksize)) {
		printk(KERN_WARNING "ZJ: no valid journal superblock found\n");
		goto out;
	}

	switch(be32_to_cpu(sb->s_header.h_blocktype)) {
	case ZJ_SUPERBLOCK_V1:
		journal->j_format_version = 1;
		break;
	case ZJ_SUPERBLOCK_V2:
		journal->j_format_version = 2;
		break;
	default:
		printk(KERN_WARNING "ZJ: unrecognised superblock format ID\n");
		goto out;
	}

	if (be32_to_cpu(sb->s_maxlen) < journal->j_maxlen)
		journal->j_maxlen = be32_to_cpu(sb->s_maxlen);
	else if (be32_to_cpu(sb->s_maxlen) > journal->j_maxlen) {
		printk(KERN_WARNING "ZJ: journal file too short\n");
		goto out;
	}

	if (be32_to_cpu(sb->s_first) == 0 ||
	    be32_to_cpu(sb->s_first) >= journal->j_maxlen) {
		printk(KERN_WARNING
			"ZJ: Invalid start block of journal: %u\n",
			be32_to_cpu(sb->s_first));
		goto out;
	}

	if (zj_has_feature_csum2(journal) &&
	    zj_has_feature_csum3(journal)) {
		/* Can't have checksum v2 and v3 at the same time! */
		printk(KERN_ERR "ZJ: Can't enable checksumming v2 and v3 "
		       "at the same time!\n");
		goto out;
	}

	if (zj_journal_has_csum_v2or3_feature(journal) &&
	    zj_has_feature_checksum(journal)) {
		/* Can't have checksum v1 and v2 on at the same time! */
		printk(KERN_ERR "ZJ: Can't enable checksumming v1 and v2/3 "
		       "at the same time!\n");
		goto out;
	}

	if (!zj_verify_csum_type(journal, sb)) {
		printk(KERN_ERR "ZJ: Unknown checksum type\n");
		goto out;
	}

	/* Load the checksum driver */
	if (zj_journal_has_csum_v2or3_feature(journal)) {
		journal->j_chksum_driver = crypto_alloc_shash("crc32c", 0, 0);
		if (IS_ERR(journal->j_chksum_driver)) {
			printk(KERN_ERR "ZJ: Cannot load crc32c driver.\n");
			err = PTR_ERR(journal->j_chksum_driver);
			journal->j_chksum_driver = NULL;
			goto out;
		}
	}

	/* Check superblock checksum */
	if (!zj_superblock_csum_verify(journal, sb)) {
		printk(KERN_ERR "ZJ: journal checksum error\n");
		err = -EFSBADCRC;
		goto out;
	}

	/* Precompute checksum seed for all metadata */
	if (zj_journal_has_csum_v2or3(journal))
		journal->j_csum_seed = zj_chksum(journal, ~0, sb->s_uuid,
						   sizeof(sb->s_uuid));

	set_buffer_verified(bh);

	return 0;

out:
	journal_fail_superblock(journal);
	return err;
}

// core와 tid에 해당하는 transaction을 찾아서 반환해준다.
// running, committing, checkpointing 들 중 하나일 것이며
// 그게 아니면 NULL이 반환된다.
ztransaction_t *zj_get_target_transaction(zjournal_t *journal, int core, tid_t tid)
{
	zjournal_t *target_journal;
	ztransaction_t *target_transaction;
	zjournal_t **journals = (zjournal_t **)journal->j_private_start;

	target_journal = journals[core];

	if (!target_journal)
		return NULL;

	read_lock(&target_journal->j_state_lock);
	spin_lock(&target_journal->j_list_lock);

	if (((target_transaction = 
	      target_journal->j_committing_transaction) != NULL) &&
	      target_transaction->t_tid == tid)
		goto out;

	if ((target_transaction = 
	     target_journal->j_running_transaction) != NULL &&
	     target_transaction->t_tid == tid) 
		goto out;

	target_transaction = radix_tree_lookup(&target_journal->j_checkpoint_txtree, tid);

	if (!target_transaction)
		goto out;

	target_transaction = NULL;
out:
	spin_unlock(&target_journal->j_list_lock);
	read_unlock(&target_journal->j_state_lock);

	return target_transaction;

}

/*
 * Load the on-disk journal superblock and read the key fields into the
 * zjournal_t.
 */

static int load_superblock(zjournal_t *journal)
{
	int err;
	journal_superblock_t *sb;

	err = journal_get_superblock(journal);
	if (err)
		return err;

	sb = journal->j_superblock;

	journal->j_tail_sequence = be32_to_cpu(sb->s_sequence);
	journal->j_tail = be32_to_cpu(sb->s_start);
	journal->j_first = be32_to_cpu(sb->s_first);
	journal->j_last = be32_to_cpu(sb->s_maxlen);
	journal->j_errno = be32_to_cpu(sb->s_errno);

	return 0;
}


/**
 * int zj_journal_load() - Read journal from disk.
 * @journal: Journal to act on.
 *
 * Given a zjournal_t structure which tells us which disk blocks contain
 * a journal, read the journal from disk to initialise the in-memory
 * structures.
 */
int zj_journal_load(zjournal_t *journal, int core)
{
	int err;
	journal_superblock_t *sb;

	err = load_superblock(journal);
	if (err)
		return err;

	sb = journal->j_superblock;
	/* If this is a V2 superblock, then we have to check the
	 * features flags on it. */

	if (journal->j_format_version >= 2) {
		if ((sb->s_feature_ro_compat &
		     ~cpu_to_be32(ZJ_KNOWN_ROCOMPAT_FEATURES)) ||
		    (sb->s_feature_incompat &
		     ~cpu_to_be32(ZJ_KNOWN_INCOMPAT_FEATURES))) {
			printk(KERN_WARNING
				"ZJ: Unrecognised features on journal\n");
			return -EINVAL;
		}
	}

	/*
	 * Create a slab for this blocksize
	 */
	err = zj_journal_create_slab(be32_to_cpu(sb->s_blocksize));
	if (err)
		return err;

	/* Let the recovery code check whether it needs to recover any
	 * data from the journal. */
	if (zj_journal_recover(journal))
		goto recovery_error;

	if (journal->j_failed_commit) {
		printk(KERN_ERR "ZJ: journal transaction %u on %s "
		       "is corrupt.\n", journal->j_failed_commit,
		       journal->j_devname);
		return -EFSCORRUPTED;
	}

	/* OK, we've finished with the dynamic journal bits:
	 * reinitialise the dynamic contents of the superblock in memory
	 * and reset them on disk. */
	if (journal_reset(journal, core))
		goto recovery_error;

	journal->j_flags &= ~ZJ_ABORT;
	journal->j_flags |= ZJ_LOADED;
	return 0;

recovery_error:
	printk(KERN_WARNING "ZJ: recovery failed\n");
	return -EIO;
}

/**
 * void zj_journal_destroy() - Release a zjournal_t structure.
 * @journal: Journal to act on.
 *
 * Release a zjournal_t structure once it is no longer in use by the
 * journaled object.
 * Return <0 if we couldn't clean up the journal.
 */
int zj_journal_destroy(zjournal_t *journal)
{
	int err = 0;

	/* Wait for the commit thread to wake up and die. */
	journal_kill_thread(journal);

	/* Force a final log commit */
	if (journal->j_running_transaction)
		zj_journal_commit_transaction(journal);

	/* Force any old transactions to disk */

	/* Totally anal locking here... */
	spin_lock(&journal->j_list_lock);
	while (journal->j_checkpoint_transactions != NULL) {
		spin_unlock(&journal->j_list_lock);
		mutex_lock_io(&journal->j_checkpoint_mutex);
		err = zj_log_do_checkpoint(journal);
		mutex_unlock(&journal->j_checkpoint_mutex);
		/*
		 * If checkpointing failed, just free the buffers to avoid
		 * looping forever
		 */
		if (err) {
			// real commit이 아닌 경우인데 강제로 destroy 해도 괜찮은가?
			zj_journal_destroy_checkpoint(journal);
			spin_lock(&journal->j_list_lock);
			break;
		}
		spin_lock(&journal->j_list_lock);
	}

	J_ASSERT(journal->j_running_transaction == NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);
	J_ASSERT(journal->j_checkpoint_transactions == NULL);
	spin_unlock(&journal->j_list_lock);

	if (journal->j_sb_buffer) {
		if (!is_journal_aborted(journal)) {
			mutex_lock_io(&journal->j_checkpoint_mutex);

			write_lock(&journal->j_state_lock);
			journal->j_tail_sequence =
				++journal->j_transaction_sequence;
			write_unlock(&journal->j_state_lock);

			zj_mark_journal_empty(journal,
					REQ_SYNC | REQ_PREFLUSH | REQ_FUA);
			mutex_unlock(&journal->j_checkpoint_mutex);
		} else
			err = -EIO;
		brelse(journal->j_sb_buffer);
	}

	printk(KERN_ERR "tunmap: %d, %d, %d, %d, %d, %d, %d, %d, %d\n", tunmap1, tunmap2, tunmap3, tunmap4, tunmap5, tunmap6, tunmap7, tunmap8, tunmap9);
	printk(KERN_ERR "tforget: %d, %d, %d, %d, %d, %d, %d\n", tforget_total, tforget1, tforget2, tforget3, tforget4, tforget5, tforget6);

	if (journal->j_proc_entry)
		zj_stats_proc_exit(journal);
	iput(journal->j_inode);
	if (journal->j_revoke)
		zj_journal_destroy_revoke(journal);
	if (journal->j_chksum_driver)
		crypto_free_shash(journal->j_chksum_driver);
	kfree(journal->j_wbuf);
	kfree(journal->j_cbuf);
	kfree(journal);

	return err;
}


/**
 *int zj_journal_check_used_features () - Check if features specified are used.
 * @journal: Journal to check.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Check whether the journal uses all of a given set of
 * features.  Return true (non-zero) if it does.
 **/

int zj_journal_check_used_features (zjournal_t *journal, unsigned long compat,
				 unsigned long ro, unsigned long incompat)
{
	journal_superblock_t *sb;

	if (!compat && !ro && !incompat)
		return 1;
	/* Load journal superblock if it is not loaded yet. */
	if (journal->j_format_version == 0 &&
	    journal_get_superblock(journal) != 0)
		return 0;
	if (journal->j_format_version == 1)
		return 0;

	sb = journal->j_superblock;

	if (((be32_to_cpu(sb->s_feature_compat) & compat) == compat) &&
	    ((be32_to_cpu(sb->s_feature_ro_compat) & ro) == ro) &&
	    ((be32_to_cpu(sb->s_feature_incompat) & incompat) == incompat))
		return 1;

	return 0;
}

/**
 * int zj_journal_check_available_features() - Check feature set in journalling layer
 * @journal: Journal to check.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Check whether the journaling code supports the use of
 * all of a given set of features on this journal.  Return true
 * (non-zero) if it can. */

int zj_journal_check_available_features (zjournal_t *journal, unsigned long compat,
				      unsigned long ro, unsigned long incompat)
{
	if (!compat && !ro && !incompat)
		return 1;

	/* We can support any known requested features iff the
	 * superblock is in version 2.  Otherwise we fail to support any
	 * extended sb features. */

	if (journal->j_format_version != 2)
		return 0;

	if ((compat   & ZJ_KNOWN_COMPAT_FEATURES) == compat &&
	    (ro       & ZJ_KNOWN_ROCOMPAT_FEATURES) == ro &&
	    (incompat & ZJ_KNOWN_INCOMPAT_FEATURES) == incompat)
		return 1;

	return 0;
}

/**
 * int zj_journal_set_features () - Mark a given journal feature in the superblock
 * @journal: Journal to act on.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Mark a given journal feature as present on the
 * superblock.  Returns true if the requested features could be set.
 *
 */

int zj_journal_set_features (zjournal_t *journal, unsigned long compat,
			  unsigned long ro, unsigned long incompat)
{
#define INCOMPAT_FEATURE_ON(f) \
		((incompat & (f)) && !(sb->s_feature_incompat & cpu_to_be32(f)))
#define COMPAT_FEATURE_ON(f) \
		((compat & (f)) && !(sb->s_feature_compat & cpu_to_be32(f)))
	journal_superblock_t *sb;

	if (zj_journal_check_used_features(journal, compat, ro, incompat))
		return 1;

	if (!zj_journal_check_available_features(journal, compat, ro, incompat))
		return 0;

	/* If enabling v2 checksums, turn on v3 instead */
	if (incompat & ZJ_FEATURE_INCOMPAT_CSUM_V2) {
		incompat &= ~ZJ_FEATURE_INCOMPAT_CSUM_V2;
		incompat |= ZJ_FEATURE_INCOMPAT_CSUM_V3;
	}

	/* Asking for checksumming v3 and v1?  Only give them v3. */
	if (incompat & ZJ_FEATURE_INCOMPAT_CSUM_V3 &&
	    compat & ZJ_FEATURE_COMPAT_CHECKSUM)
		compat &= ~ZJ_FEATURE_COMPAT_CHECKSUM;

	jbd_debug(1, "Setting new features 0x%lx/0x%lx/0x%lx\n",
		  compat, ro, incompat);

	sb = journal->j_superblock;

	/* If enabling v3 checksums, update superblock */
	if (INCOMPAT_FEATURE_ON(ZJ_FEATURE_INCOMPAT_CSUM_V3)) {
		sb->s_checksum_type = ZJ_CRC32C_CHKSUM;
		sb->s_feature_compat &=
			~cpu_to_be32(ZJ_FEATURE_COMPAT_CHECKSUM);

		/* Load the checksum driver */
		if (journal->j_chksum_driver == NULL) {
			journal->j_chksum_driver = crypto_alloc_shash("crc32c",
								      0, 0);
			if (IS_ERR(journal->j_chksum_driver)) {
				printk(KERN_ERR "ZJ: Cannot load crc32c "
				       "driver.\n");
				journal->j_chksum_driver = NULL;
				return 0;
			}

			/* Precompute checksum seed for all metadata */
			journal->j_csum_seed = zj_chksum(journal, ~0,
							   sb->s_uuid,
							   sizeof(sb->s_uuid));
		}
	}

	/* If enabling v1 checksums, downgrade superblock */
	if (COMPAT_FEATURE_ON(ZJ_FEATURE_COMPAT_CHECKSUM))
		sb->s_feature_incompat &=
			~cpu_to_be32(ZJ_FEATURE_INCOMPAT_CSUM_V2 |
				     ZJ_FEATURE_INCOMPAT_CSUM_V3);

	sb->s_feature_compat    |= cpu_to_be32(compat);
	sb->s_feature_ro_compat |= cpu_to_be32(ro);
	sb->s_feature_incompat  |= cpu_to_be32(incompat);

	return 1;
#undef COMPAT_FEATURE_ON
#undef INCOMPAT_FEATURE_ON
}

/*
 * zj_journal_clear_features () - Clear a given journal feature in the
 * 				    superblock
 * @journal: Journal to act on.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Clear a given journal feature as present on the
 * superblock.
 */
void zj_journal_clear_features(zjournal_t *journal, unsigned long compat,
				unsigned long ro, unsigned long incompat)
{
	journal_superblock_t *sb;

	jbd_debug(1, "Clear features 0x%lx/0x%lx/0x%lx\n",
		  compat, ro, incompat);

	sb = journal->j_superblock;

	sb->s_feature_compat    &= ~cpu_to_be32(compat);
	sb->s_feature_ro_compat &= ~cpu_to_be32(ro);
	sb->s_feature_incompat  &= ~cpu_to_be32(incompat);
}
EXPORT_SYMBOL(zj_journal_clear_features);

/**
 * int zj_journal_flush () - Flush journal
 * @journal: Journal to act on.
 *
 * Flush all data for a given journal to disk and empty the journal.
 * Filesystems can use this when remounting readonly to ensure that
 * recovery does not need to happen on remount.
 */

int zj_journal_flush(zjournal_t *journal)
{
	int err = 0;
	ztransaction_t *transaction = NULL;

	write_lock(&journal->j_state_lock);

	/* Force everything buffered to the log... */
	if (journal->j_running_transaction) {
		transaction = journal->j_running_transaction;
		__zj_log_start_commit(journal, transaction->t_tid);
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	/* Wait for the log commit to complete... */
	if (transaction) {
		tid_t tid = transaction->t_tid;

		write_unlock(&journal->j_state_lock);
		zj_log_wait_commit(journal, tid);
	} else {
		write_unlock(&journal->j_state_lock);
	}

	/* ...and flush everything in the log out to disk. */
	spin_lock(&journal->j_list_lock);
	while (!err && journal->j_checkpoint_transactions != NULL) {
		spin_unlock(&journal->j_list_lock);
		mutex_lock_io(&journal->j_checkpoint_mutex);
		err = zj_log_do_checkpoint(journal);
		mutex_unlock(&journal->j_checkpoint_mutex);
		spin_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);

	if (is_journal_aborted(journal))
		return -EIO;

	mutex_lock_io(&journal->j_checkpoint_mutex);
	if (!err) {
		err = zj_cleanup_zjournal_tail(journal);
		if (err < 0) {
			mutex_unlock(&journal->j_checkpoint_mutex);
			goto out;
		}
		err = 0;
	}

	/* Finally, mark the journal as really needing no recovery.
	 * This sets s_start==0 in the underlying superblock, which is
	 * the magic code for a fully-recovered superblock.  Any future
	 * commits of data to the journal will restore the current
	 * s_start value. */
	zj_mark_journal_empty(journal, REQ_SYNC | REQ_FUA);
	mutex_unlock(&journal->j_checkpoint_mutex);
	write_lock(&journal->j_state_lock);
	J_ASSERT(!journal->j_running_transaction);
	J_ASSERT(!journal->j_committing_transaction);
	J_ASSERT(!journal->j_checkpoint_transactions);
	J_ASSERT(journal->j_head == journal->j_tail);
	J_ASSERT(journal->j_tail_sequence == journal->j_transaction_sequence);
	write_unlock(&journal->j_state_lock);
out:
	return err;
}

/**
 * int zj_journal_wipe() - Wipe journal contents
 * @journal: Journal to act on.
 * @write: flag (see below)
 *
 * Wipe out all of the contents of a journal, safely.  This will produce
 * a warning if the journal contains any valid recovery information.
 * Must be called between journal_init_*() and zj_journal_load().
 *
 * If 'write' is non-zero, then we wipe out the journal on disk; otherwise
 * we merely suppress recovery.
 */

int zj_journal_wipe(zjournal_t *journal, int write)
{
	int err = 0;

	J_ASSERT (!(journal->j_flags & ZJ_LOADED));

	err = load_superblock(journal);
	if (err)
		return err;

	if (!journal->j_tail)
		goto no_recovery;

	printk(KERN_WARNING "ZJ: %s recovery information on journal\n",
		write ? "Clearing" : "Ignoring");

	err = zj_journal_skip_recovery(journal);
	if (write) {
		/* Lock to make assertions happy... */
		mutex_lock(&journal->j_checkpoint_mutex);
		zj_mark_journal_empty(journal, REQ_SYNC | REQ_FUA);
		mutex_unlock(&journal->j_checkpoint_mutex);
	}

 no_recovery:
	return err;
}

/*
 * Journal abort has very specific semantics, which we describe
 * for journal abort.
 *
 * Two internal functions, which provide abort to the jbd layer
 * itself are here.
 */

/*
 * Quick version for internal journal use (doesn't lock the journal).
 * Aborts hard --- we mark the abort as occurred, but do _nothing_ else,
 * and don't attempt to make any other journal updates.
 */
void __zj_journal_abort_hard(zjournal_t *journal)
{
	ztransaction_t *transaction;

	if (journal->j_flags & ZJ_ABORT)
		return;

	printk(KERN_ERR "Aborting journal on device %s.\n",
	       journal->j_devname);

	write_lock(&journal->j_state_lock);
	journal->j_flags |= ZJ_ABORT;
	transaction = journal->j_running_transaction;
	if (transaction)
		__zj_log_start_commit(journal, transaction->t_tid);
	write_unlock(&journal->j_state_lock);
}

/* Soft abort: record the abort error status in the journal superblock,
 * but don't do any other IO. */
static void __journal_abort_soft (zjournal_t *journal, int errno)
{
	int old_errno;

	write_lock(&journal->j_state_lock);
	old_errno = journal->j_errno;
	if (!journal->j_errno || errno == -ESHUTDOWN)
		journal->j_errno = errno;

	if (journal->j_flags & ZJ_ABORT) {
		write_unlock(&journal->j_state_lock);
		if (!old_errno && old_errno != -ESHUTDOWN &&
		    errno == -ESHUTDOWN)
			zj_journal_update_sb_errno(journal);
		return;
	}
	write_unlock(&journal->j_state_lock);

	__zj_journal_abort_hard(journal);

	if (errno) {
		zj_journal_update_sb_errno(journal);
		write_lock(&journal->j_state_lock);
		journal->j_flags |= ZJ_REC_ERR;
		write_unlock(&journal->j_state_lock);
	}
}

/**
 * void zj_journal_abort () - Shutdown the journal immediately.
 * @journal: the journal to shutdown.
 * @errno:   an error number to record in the journal indicating
 *           the reason for the shutdown.
 *
 * Perform a complete, immediate shutdown of the ENTIRE
 * journal (not of a single transaction).  This operation cannot be
 * undone without closing and reopening the journal.
 *
 * The zj_journal_abort function is intended to support higher level error
 * recovery mechanisms such as the ext2/ext3 remount-readonly error
 * mode.
 *
 * Journal abort has very specific semantics.  Any existing dirty,
 * unjournaled buffers in the main filesystem will still be written to
 * disk by bdflush, but the journaling mechanism will be suspended
 * immediately and no further transaction commits will be honoured.
 *
 * Any dirty, journaled buffers will be written back to disk without
 * hitting the journal.  Atomicity cannot be guaranteed on an aborted
 * filesystem, but we _do_ attempt to leave as much data as possible
 * behind for fsck to use for cleanup.
 *
 * Any attempt to get a new transaction handle on a journal which is in
 * ABORT state will just result in an -EROFS error return.  A
 * zj_journal_stop on an existing handle will return -EIO if we have
 * entered abort state during the update.
 *
 * Recursive transactions are not disturbed by journal abort until the
 * final zj_journal_stop, which will receive the -EIO error.
 *
 * Finally, the zj_journal_abort call allows the caller to supply an errno
 * which will be recorded (if possible) in the journal superblock.  This
 * allows a client to record failure conditions in the middle of a
 * transaction without having to complete the transaction to record the
 * failure to disk.  ext3_error, for example, now uses this
 * functionality.
 *
 * Errors which originate from within the journaling layer will NOT
 * supply an errno; a null errno implies that absolutely no further
 * writes are done to the journal (unless there are any already in
 * progress).
 *
 */

void zj_journal_abort(zjournal_t *journal, int errno)
{
	__journal_abort_soft(journal, errno);
}

/**
 * int zj_journal_errno () - returns the journal's error state.
 * @journal: journal to examine.
 *
 * This is the errno number set with zj_journal_abort(), the last
 * time the journal was mounted - if the journal was stopped
 * without calling abort this will be 0.
 *
 * If the journal has been aborted on this mount time -EROFS will
 * be returned.
 */
int zj_journal_errno(zjournal_t *journal)
{
	int err;

	read_lock(&journal->j_state_lock);
	if (journal->j_flags & ZJ_ABORT)
		err = -EROFS;
	else
		err = journal->j_errno;
	read_unlock(&journal->j_state_lock);
	return err;
}

/**
 * int zj_journal_clear_err () - clears the journal's error state
 * @journal: journal to act on.
 *
 * An error must be cleared or acked to take a FS out of readonly
 * mode.
 */
int zj_journal_clear_err(zjournal_t *journal)
{
	int err = 0;

	write_lock(&journal->j_state_lock);
	if (journal->j_flags & ZJ_ABORT)
		err = -EROFS;
	else
		journal->j_errno = 0;
	write_unlock(&journal->j_state_lock);
	return err;
}

/**
 * void zj_journal_ack_err() - Ack journal err.
 * @journal: journal to act on.
 *
 * An error must be cleared or acked to take a FS out of readonly
 * mode.
 */
void zj_journal_ack_err(zjournal_t *journal)
{
	write_lock(&journal->j_state_lock);
	if (journal->j_errno)
		journal->j_flags |= ZJ_ACK_ERR;
	write_unlock(&journal->j_state_lock);
}

int zj_journal_blocks_per_page(struct inode *inode)
{
	return 1 << (PAGE_SHIFT - inode->i_sb->s_blocksize_bits);
}

/*
 * helper functions to deal with 32 or 64bit block numbers.
 */
size_t zjournal_tag_bytes(zjournal_t *journal)
{
	size_t sz;

	if (zj_has_feature_csum3(journal))
		return sizeof(journal_block_tag3_t);

	sz = sizeof(journal_block_tag_t);

	if (zj_has_feature_csum2(journal))
		sz += sizeof(__u16);

	if (zj_has_feature_64bit(journal))
		return sz;
	else
		return sz - sizeof(__u32);
}

/*
 * JBD memory management
 *
 * These functions are used to allocate block-sized chunks of memory
 * used for making copies of buffer_head data.  Very often it will be
 * page-sized chunks of data, but sometimes it will be in
 * sub-page-size chunks.  (For example, 16k pages on Power systems
 * with a 4k block file system.)  For blocks smaller than a page, we
 * use a SLAB allocator.  There are slab caches for each block size,
 * which are allocated at mount time, if necessary, and we only free
 * (all of) the slab caches when/if the zj module is unloaded.  For
 * this reason we don't need to a mutex to protect access to
 * zj_slab[] allocating or releasing memory; only in
 * zj_journal_create_slab().
 */
#define ZJ_MAX_SLABS 8
static struct kmem_cache *zj_slab[ZJ_MAX_SLABS];

static const char *zj_slab_names[ZJ_MAX_SLABS] = {
	"zj_1k", "zj_2k", "zj_4k", "zj_8k",
	"zj_16k", "zj_32k", "zj_64k", "zj_128k"
};


static void zj_journal_destroy_slabs(void)
{
	int i;

	for (i = 0; i < ZJ_MAX_SLABS; i++) {
		if (zj_slab[i])
			kmem_cache_destroy(zj_slab[i]);
		zj_slab[i] = NULL;
	}
}

static int zj_journal_create_slab(size_t size)
{
	static DEFINE_MUTEX(zj_slab_create_mutex);
	int i = order_base_2(size) - 10;
	size_t slab_size;

	if (size == PAGE_SIZE)
		return 0;

	if (i >= ZJ_MAX_SLABS)
		return -EINVAL;

	if (unlikely(i < 0))
		i = 0;
	mutex_lock(&zj_slab_create_mutex);
	if (zj_slab[i]) {
		mutex_unlock(&zj_slab_create_mutex);
		return 0;	/* Already created */
	}

	slab_size = 1 << (i+10);
	zj_slab[i] = kmem_cache_create(zj_slab_names[i], slab_size,
					 slab_size, 0, NULL);
	mutex_unlock(&zj_slab_create_mutex);
	if (!zj_slab[i]) {
		printk(KERN_EMERG "ZJ: no memory for zj_slab cache\n");
		return -ENOMEM;
	}
	return 0;
}

static struct kmem_cache *get_slab(size_t size)
{
	int i = order_base_2(size) - 10;

	BUG_ON(i >= ZJ_MAX_SLABS);
	if (unlikely(i < 0))
		i = 0;
	BUG_ON(zj_slab[i] == NULL);
	return zj_slab[i];
}

void *zj_alloc(size_t size, gfp_t flags)
{
	void *ptr;

	BUG_ON(size & (size-1)); /* Must be a power of 2 */

	if (size < PAGE_SIZE)
		ptr = kmem_cache_alloc(get_slab(size), flags);
	else
		ptr = (void *)__get_free_pages(flags, get_order(size));

	/* Check alignment; SLUB has gotten this wrong in the past,
	 * and this can lead to user data corruption! */
	BUG_ON(((unsigned long) ptr) & (size-1));

	return ptr;
}

void zj_free(void *ptr, size_t size)
{
	if (size < PAGE_SIZE)
		kmem_cache_free(get_slab(size), ptr);
	else
		free_pages((unsigned long)ptr, get_order(size));
};

/*
 * Journal_head storage management
 */
static struct kmem_cache *zj_zjournal_head_cache;
#ifdef CONFIG_ZJ_DEBUG
static atomic_t nr_zjournal_heads = ATOMIC_INIT(0);
#endif

static int zj_journal_init_zjournal_head_cache(void)
{
	int retval;

	J_ASSERT(zj_zjournal_head_cache == NULL);
	zj_zjournal_head_cache = kmem_cache_create("zj_zjournal_head",
				sizeof(struct zjournal_head),
				0,		/* offset */
				SLAB_TEMPORARY | SLAB_TYPESAFE_BY_RCU,
				NULL);		/* ctor */
	retval = 0;
	if (!zj_zjournal_head_cache) {
		retval = -ENOMEM;
		printk(KERN_EMERG "ZJ: no memory for zjournal_head cache\n");
	}
	return retval;
}

static void zj_journal_destroy_zjournal_head_cache(void)
{
	if (zj_zjournal_head_cache) {
		kmem_cache_destroy(zj_zjournal_head_cache);
		zj_zjournal_head_cache = NULL;
	}
}

/*
 * zjournal_head splicing and dicing
 */
struct zjournal_head *journal_alloc_zjournal_head(void)
{
	struct zjournal_head *ret;

#ifdef CONFIG_ZJ_DEBUG
	atomic_inc(&nr_zjournal_heads);
#endif
	ret = kmem_cache_zalloc(zj_zjournal_head_cache, GFP_NOFS);
	if (!ret) {
		jbd_debug(1, "out of memory for zjournal_head\n");
		pr_notice_ratelimited("ENOMEM in %s, retrying.\n", __func__);
		ret = kmem_cache_zalloc(zj_zjournal_head_cache,
				GFP_NOFS | __GFP_NOFAIL);
	}
	return ret;
}

void journal_free_zjournal_head(struct zjournal_head *jh)
{
#ifdef CONFIG_ZJ_DEBUG
	atomic_dec(&nr_zjournal_heads);
	//memset(jh, ZJ_POISON_FREE, sizeof(*jh));
#endif
	kmem_cache_free(zj_zjournal_head_cache, jh);
}

/*
 * A zjournal_head is attached to a buffer_head whenever JBD has an
 * interest in the buffer.
 *
 * Whenever a buffer has an attached zjournal_head, its ->b_state:BH_JBD bit
 * is set.  This bit is tested in core kernel code where we need to take
 * JBD-specific actions.  Testing the zeroness of ->b_private is not reliable
 * there.
 *
 * When a buffer has its BH_JBD bit set, its ->b_count is elevated by one.
 *
 * When a buffer has its BH_JBD bit set it is immune from being released by
 * core kernel code, mainly via ->b_count.
 *
 * A zjournal_head is detached from its buffer_head when the zjournal_head's
 * b_jcount reaches zero. Running transaction (b_transaction) and checkpoint
 * transaction (b_cp_transaction) hold their references to b_jcount.
 *
 * Various places in the kernel want to attach a zjournal_head to a buffer_head
 * _before_ attaching the zjournal_head to a transaction.  To protect the
 * zjournal_head in this situation, zj_journal_add_zjournal_head elevates the
 * zjournal_head's b_jcount refcount by one.  The caller must call
 * zj_journal_put_zjournal_head() to undo this.
 *
 * So the typical usage would be:
 *
 *	(Attach a zjournal_head if needed.  Increments b_jcount)
 *	struct zjournal_head *jh = zj_journal_add_zjournal_head(bh);
 *	...
 *      (Get another reference for transaction)
 *	zj_journal_grab_zjournal_head(bh);
 *	jh->b_transaction = xxx;
 *	(Put original reference)
 *	zj_journal_put_zjournal_head(jh);
 */

/*
 * Give a buffer_head a zjournal_head.
 *
 * May sleep.
 */
struct zjournal_head *zj_journal_add_zjournal_head(struct buffer_head *bh)
{
	struct zjournal_head *jh;
	struct zjournal_head *new_jh = NULL;

repeat:
	if (!buffer_jbd(bh))
		new_jh = journal_alloc_zjournal_head();

	jbd_lock_bh_zjournal_head(bh);
	if (buffer_jbd(bh)) {
		jh = bh2jh(bh);
	} else {
		J_ASSERT_BH(bh,
			(atomic_read(&bh->b_count) > 0) ||
			(bh->b_page && bh->b_page->mapping));

		if (!new_jh) {
			jbd_unlock_bh_zjournal_head(bh);
			goto repeat;
		}

		jh = new_jh;
		new_jh = NULL;		/* We consumed it */
		set_buffer_jbd(bh);
		bh->b_private = jh;
		jh->b_bh = bh;
		get_bh(bh);
		BUFFER_TRACE(bh, "added zjournal_head");
	}
	jh->b_jcount++;
	jbd_unlock_bh_zjournal_head(bh);
	if (new_jh)
		journal_free_zjournal_head(new_jh);
	return bh->b_private;
}

/*
 * Grab a ref against this buffer_head's zjournal_head.  If it ended up not
 * having a zjournal_head, return NULL
 */
struct zjournal_head *zj_journal_grab_zjournal_head(struct buffer_head *bh)
{
	struct zjournal_head *jh = NULL;

	jbd_lock_bh_zjournal_head(bh);
	if (buffer_jbd(bh)) {
		jh = bh2jh(bh);
		jh->b_jcount++;
	}
	jbd_unlock_bh_zjournal_head(bh);
	return jh;
}

static void __journal_remove_zjournal_head(struct buffer_head *bh)
{
	struct zjournal_head *jh = bh2jh(bh);

	J_ASSERT_JH(jh, jh->b_jcount >= 0);
	J_ASSERT_JH(jh, jh->b_transaction == NULL);
	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, jh->b_cp_transaction == NULL);
	J_ASSERT_JH(jh, jh->b_jlist == BJ_None);
	if (jh->b_orig) {
		panic("EXIST jh's b_orig");
	}
	J_ASSERT_JH(jh, jh->b_orig == NULL);
	J_ASSERT_JH(jh, jh->b_cpcount == 0);
	J_ASSERT_BH(bh, buffer_jbd(bh));
	J_ASSERT_BH(bh, jh2bh(jh) == bh);
	BUFFER_TRACE(bh, "remove zjournal_head");
	if (jh->b_frozen_data) {
		printk(KERN_WARNING "%s: freeing b_frozen_data\n", __func__);
		zj_free(jh->b_frozen_data, bh->b_size);
	}
	if (jh->b_committed_data) {
		printk(KERN_WARNING "%s: freeing b_committed_data\n", __func__);
		zj_free(jh->b_committed_data, bh->b_size);
	}
	bh->b_private = NULL;
	jh->b_bh = NULL;	/* debug, really */
	clear_buffer_jbd(bh);
	journal_free_zjournal_head(jh);
}

/*
 * Drop a reference on the passed zjournal_head.  If it fell to zero then
 * release the zjournal_head from the buffer_head.
 */
void zj_journal_put_zjournal_head(struct zjournal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	jbd_lock_bh_zjournal_head(bh);
	J_ASSERT_JH(jh, jh->b_jcount > 0);
	--jh->b_jcount;
	if (!jh->b_jcount) {
		__journal_remove_zjournal_head(bh);
		jbd_unlock_bh_zjournal_head(bh);
		__brelse(bh);
	} else
		jbd_unlock_bh_zjournal_head(bh);
}

/*
 * Initialize jbd inode head
 */
void zj_journal_init_jbd_inode(struct zj_inode *jinode, struct inode *inode)
{
	jinode->i_transaction = NULL;
	jinode->i_next_transaction = NULL;
	jinode->i_vfs_inode = inode;
	jinode->i_flags = 0;
	INIT_LIST_HEAD(&jinode->i_list);
}

/*
 * Function to be called before we start removing inode from memory (i.e.,
 * clear_inode() is a fine place to be called from). It removes inode from
 * transaction's lists.
 */
void zj_journal_release_jbd_inode(zjournal_t *journal,
				    struct zj_inode *jinode)
{
	zjournal_t *real_journal = NULL;

	if (!journal)
		return;
restart:
	if (jinode->i_transaction)
		real_journal = jinode->i_transaction->t_journal;
	else
		real_journal = journal;

	spin_lock(&real_journal->j_list_lock);
	/* Is commit writing out inode - we have to wait */
	if (jinode->i_flags & JI_COMMIT_RUNNING) {
		wait_queue_head_t *wq;
		DEFINE_WAIT_BIT(wait, &jinode->i_flags, __JI_COMMIT_RUNNING);
		wq = bit_waitqueue(&jinode->i_flags, __JI_COMMIT_RUNNING);
		prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
		spin_unlock(&real_journal->j_list_lock);
		schedule();
		finish_wait(wq, &wait.wq_entry);
		goto restart;
	}

	if (jinode->i_flags & JI_TEMP_LIST) {
		wait_queue_head_t *wq;
		DEFINE_WAIT_BIT(wait, &jinode->i_flags, __JI_TEMP_LIST);
		wq = bit_waitqueue(&jinode->i_flags, __JI_TEMP_LIST);
		prepare_to_wait(wq, &wait.wq_entry, TASK_UNINTERRUPTIBLE);
		spin_unlock(&real_journal->j_list_lock);
		schedule();
		finish_wait(wq, &wait.wq_entry);
		goto restart;
	}

	if (jinode->i_transaction) {
		list_del(&jinode->i_list);
		jinode->i_transaction = NULL;
	}
	spin_unlock(&real_journal->j_list_lock);

}


#ifdef CONFIG_PROC_FS

#define ZJ_STATS_PROC_NAME "fs/zj"

static void __init zj_create_jbd_stats_proc_entry(void)
{
	proc_zj_stats = proc_mkdir(ZJ_STATS_PROC_NAME, NULL);
}

static void __exit zj_remove_jbd_stats_proc_entry(void)
{
	if (proc_zj_stats)
		remove_proc_entry(ZJ_STATS_PROC_NAME, NULL);
}

#else

#define zj_create_jbd_stats_proc_entry() do {} while (0)
#define zj_remove_jbd_stats_proc_entry() do {} while (0)

#endif

struct kmem_cache *zj_handle_cache, *zj_inode_cache;
struct kmem_cache *zj_commit_cache;

static int __init zj_journal_init_handle_cache(void)
{
	zj_handle_cache = KMEM_CACHE(zj_journal_handle, SLAB_TEMPORARY);
	if (zj_handle_cache == NULL) {
		printk(KERN_EMERG "ZJ: failed to create handle cache\n");
		return -ENOMEM;
	}
	zj_inode_cache = KMEM_CACHE(zj_inode, 0);
	if (zj_inode_cache == NULL) {
		printk(KERN_EMERG "ZJ: failed to create inode cache\n");
		kmem_cache_destroy(zj_handle_cache);
		return -ENOMEM;
	}
	zj_commit_cache = KMEM_CACHE(commit_entry_s, SLAB_TEMPORARY);
	if (zj_commit_cache == NULL) {
		printk(KERN_EMERG "ZJ: failed to create commit cache\n");
		kmem_cache_destroy(zj_handle_cache);
		kmem_cache_destroy(zj_inode_cache);
		return -ENOMEM;
	}
	return 0;
}

static void zj_journal_destroy_handle_cache(void)
{
	if (zj_handle_cache)
		kmem_cache_destroy(zj_handle_cache);
	if (zj_inode_cache)
		kmem_cache_destroy(zj_inode_cache);
	if (zj_commit_cache)
		kmem_cache_destroy(zj_commit_cache);

}

/*
 * Module startup and shutdown
 */

static int __init journal_init_caches(void)
{
	int ret;

	ret = zj_journal_init_revoke_caches();
	if (ret == 0)
		ret = zj_journal_init_zjournal_head_cache();
	if (ret == 0)
		ret = zj_journal_init_handle_cache();
	if (ret == 0)
		ret = zj_journal_init_transaction_cache();
	return ret;
}

static void zj_journal_destroy_caches(void)
{
	zj_journal_destroy_revoke_caches();
	zj_journal_destroy_zjournal_head_cache();
	zj_journal_destroy_handle_cache();
	zj_journal_destroy_transaction_cache();
	zj_journal_destroy_slabs();
}

static int __init journal_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct journal_superblock_s) != 1024);

	ret = journal_init_caches();
	if (ret == 0) {
		zj_create_jbd_stats_proc_entry();
	} else {
		zj_journal_destroy_caches();
	}
	return ret;
}

static void __exit journal_exit(void)
{
#ifdef CONFIG_ZJ_DEBUG
	int n = atomic_read(&nr_zjournal_heads);
	if (n)
		printk(KERN_ERR "ZJ: leaked %d zjournal_heads!\n", n);
#endif
	zj_remove_jbd_stats_proc_entry();
	zj_journal_destroy_caches();
}

MODULE_LICENSE("GPL");
module_init(journal_init);
module_exit(journal_exit);

