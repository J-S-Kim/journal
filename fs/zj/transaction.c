/*
 * linux/fs/zj/transaction.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Generic filesystem transaction handling code; part of the ext2fs
 * journaling system.
 *
 * This file manages transactions (compound commits managed by the
 * journaling code) and handles (individual atomic operations by the
 * filesystem).
 */

#include <linux/time.h>
#include <linux/fs.h>
#include "zj.h"
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/backing-dev.h>
#include <linux/bug.h>
#include <linux/module.h>
#include <linux/sched/mm.h>

#include <trace/events/zj.h>

static void __zj_zjournal_temp_unlink_buffer(struct zjournal_head *jh);
static void __zj_journal_unfile_buffer(struct zjournal_head *jh);

static struct kmem_cache *transaction_cache;
static struct kmem_cache *commit_list_cache;
int __init zj_journal_init_transaction_cache(void)
{
	J_ASSERT(!transaction_cache);
	transaction_cache = kmem_cache_create("zj_transaction_s",
			sizeof(ztransaction_t),
			0,
			SLAB_HWCACHE_ALIGN|SLAB_TEMPORARY,
			NULL);

	J_ASSERT(!commit_list_cache);
	commit_list_cache = kmem_cache_create("zj_commit_list_s",
			sizeof(struct list_head) * 80,
			0,
			SLAB_HWCACHE_ALIGN|SLAB_TEMPORARY,
			NULL);

	if (transaction_cache &&
			commit_list_cache)
		return 0;
	return -ENOMEM;
}

void zj_journal_destroy_transaction_cache(void)
{
	if (commit_list_cache) {
		kmem_cache_destroy(commit_list_cache);
		commit_list_cache = NULL;
	}
	if (transaction_cache) {
		kmem_cache_destroy(transaction_cache);
		transaction_cache = NULL;
	}
}

void zj_journal_free_transaction(ztransaction_t *transaction)
{
	if (unlikely(ZERO_OR_NULL_PTR(transaction)))
		return;
	kmem_cache_free(transaction_cache, transaction);
}

void zj_journal_free_commit_list(struct list_head *commit_list)
{
	if (unlikely(ZERO_OR_NULL_PTR(commit_list)))
		return;
	kmem_cache_free(commit_list_cache, commit_list);
}
/*
 * zj_get_transaction: obtain a new ztransaction_t object.
 *
 * Simply allocate and initialise a new transaction.  Create it in
 * RUNNING state and add it to the current journal (which should not
 * have an existing running transaction: we only make a new transaction
 * once we have started to commit the old one).
 *
 * Preconditions:
 *	The journal MUST be locked.  We don't perform atomic mallocs on the
 *	new transaction	and we can't block without protecting against other
 *	processes trying to touch the journal while it is in transition.
 *
 */

static ztransaction_t *
zj_get_transaction(zjournal_t *journal, ztransaction_t *transaction, struct list_head *percpu_list)
{
	int cpu;
	transaction->t_journal = journal;
	transaction->t_state = T_RUNNING;
	transaction->t_start_time = ktime_get();
	transaction->t_tid = journal->j_transaction_sequence++;
	transaction->t_expires = jiffies + journal->j_commit_interval;
	spin_lock_init(&transaction->t_handle_lock);
	atomic_set(&transaction->t_updates, 0);
	atomic_set(&transaction->t_nexts, 0);
	atomic_set(&transaction->t_outstanding_credits,
		   atomic_read(&journal->j_reserved_credits));
	atomic_set(&transaction->t_handle_count, 0);
	INIT_LIST_HEAD(&transaction->t_inode_list);

	INIT_LIST_HEAD(&transaction->t_check_mark_list);
	INIT_LIST_HEAD(&transaction->t_complete_mark_list);
	spin_lock_init(&transaction->t_mark_lock);

	INIT_LIST_HEAD(&transaction->t_private_list);

	transaction->t_commit_list = percpu_list;

	for (cpu = 0; cpu < 80; cpu++)
		INIT_LIST_HEAD(&transaction->t_commit_list[cpu]);

	/* Set up the commit timer for the new transaction. */
	journal->j_commit_timer.expires = round_jiffies_up(transaction->t_expires);
	add_timer(&journal->j_commit_timer);

	J_ASSERT(journal->j_running_transaction == NULL);
	journal->j_running_transaction = transaction;
	transaction->t_max_wait = 0;
	transaction->t_start = jiffies;
	transaction->t_requested = 0;
	transaction->t_real_commit = 0;

	return transaction;
}

/*
 * Handle management.
 *
 * A handle_t is an object which represents a single atomic update to a
 * filesystem, and which tracks all of the modifications which form part
 * of that one update.
 */

/*
 * Update transaction's maximum wait time, if debugging is enabled.
 *
 * In order for t_max_wait to be reliable, it must be protected by a
 * lock.  But doing so will mean that start_this_handle() can not be
 * run in parallel on SMP systems, which limits our scalability.  So
 * unless debugging is enabled, we no longer update t_max_wait, which
 * means that maximum wait time reported by the zj_run_stats
 * tracepoint will always be zero.
 */
static inline void update_t_max_wait(ztransaction_t *transaction,
				     unsigned long ts)
{
#ifdef CONFIG_ZJ_DEBUG
	if (zj_journal_enable_debug &&
	    time_after(transaction->t_start, ts)) {
		ts = zj_time_diff(ts, transaction->t_start);
		spin_lock(&transaction->t_handle_lock);
		if (ts > transaction->t_max_wait)
			transaction->t_max_wait = ts;
		spin_unlock(&transaction->t_handle_lock);
	}
#endif
}

/*
 * Wait until running transaction passes T_LOCKED state. Also starts the commit
 * if needed. The function expects running transaction to exist and releases
 * j_state_lock.
 */
static void wait_transaction_locked(zjournal_t *journal)
	__releases(journal->j_state_lock)
{
	DEFINE_WAIT(wait);
	int need_to_start;
	tid_t tid = journal->j_running_transaction->t_tid;

	prepare_to_wait(&journal->j_wait_transaction_locked, &wait,
			TASK_UNINTERRUPTIBLE);
	need_to_start = !tid_geq(journal->j_commit_request, tid);
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		zj_log_start_commit(journal, tid);
	zj_might_wait_for_commit(journal);
	schedule();
	finish_wait(&journal->j_wait_transaction_locked, &wait);
}

static void sub_reserved_credits(zjournal_t *journal, int blocks)
{
	atomic_sub(blocks, &journal->j_reserved_credits);
	wake_up(&journal->j_wait_reserved);
}

/*
 * Wait until we can add credits for handle to the running transaction.  Called
 * with j_state_lock held for reading. Returns 0 if handle joined the running
 * transaction. Returns 1 if we had to wait, j_state_lock is dropped, and
 * caller must retry.
 */
static int add_transaction_credits(zjournal_t *journal, int blocks,
				   int rsv_blocks)
{
	ztransaction_t *t = journal->j_running_transaction;
	int needed;
	int total = blocks + rsv_blocks;

	/*
	 * If the current transaction is locked down for commit, wait
	 * for the lock to be released.
	 */
	if (t->t_state == T_LOCKED) {
		wait_transaction_locked(journal);
		return 1;
	}

	/*
	 * If there is not enough space left in the log to write all
	 * potential buffers requested by this operation, we need to
	 * stall pending a log checkpoint to free some more log space.
	 */
	needed = atomic_add_return(total, &t->t_outstanding_credits);
	if (needed > journal->j_max_transaction_buffers) {
		/*
		 * If the current transaction is already too large,
		 * then start to commit it: we can then go back and
		 * attach this handle to a new transaction.
		 */
		atomic_sub(total, &t->t_outstanding_credits);

		/*
		 * Is the number of reserved credits in the current transaction too
		 * big to fit this handle? Wait until reserved credits are freed.
		 */
		if (atomic_read(&journal->j_reserved_credits) + total >
		    journal->j_max_transaction_buffers) {
			read_unlock(&journal->j_state_lock);
			zj_might_wait_for_commit(journal);
			wait_event(journal->j_wait_reserved,
				   atomic_read(&journal->j_reserved_credits) + total <=
				   journal->j_max_transaction_buffers);
			return 1;
		}

		wait_transaction_locked(journal);
		return 1;
	}

	/*
	 * The commit code assumes that it can get enough log space
	 * without forcing a checkpoint.  This is *critical* for
	 * correctness: a checkpoint of a buffer which is also
	 * associated with a committing transaction creates a deadlock,
	 * so commit simply cannot force through checkpoints.
	 *
	 * We must therefore ensure the necessary space in the journal
	 * *before* starting to dirty potentially checkpointed buffers
	 * in the new transaction.
	 */
	if (zj_log_space_left(journal) < zj_space_needed(journal)) {
		atomic_sub(total, &t->t_outstanding_credits);
		read_unlock(&journal->j_state_lock);
		zj_might_wait_for_commit(journal);
		write_lock(&journal->j_state_lock);
		if (zj_log_space_left(journal) < zj_space_needed(journal))
			__zj_log_wait_for_space(journal);
		write_unlock(&journal->j_state_lock);
		return 1;
	}

	/* No reservation? We are done... */
	if (!rsv_blocks)
		return 0;

	needed = atomic_add_return(rsv_blocks, &journal->j_reserved_credits);
	/* We allow at most half of a transaction to be reserved */
	if (needed > journal->j_max_transaction_buffers / 2) {
		sub_reserved_credits(journal, rsv_blocks);
		atomic_sub(total, &t->t_outstanding_credits);
		read_unlock(&journal->j_state_lock);
		zj_might_wait_for_commit(journal);
		wait_event(journal->j_wait_reserved,
			 atomic_read(&journal->j_reserved_credits) + rsv_blocks
			 <= journal->j_max_transaction_buffers / 2);
		return 1;
	}
	return 0;
}

/*
 * start_this_handle: Given a handle, deal with any locking or stalling
 * needed to make sure that there is enough journal space for the handle
 * to begin.  Attach the handle to a transaction and set up the
 * transaction's buffer credits.
 */

static int start_this_handle(zjournal_t *journal, handle_t *handle,
			     gfp_t gfp_mask)
{
	ztransaction_t	*transaction, *new_transaction = NULL;
	struct list_head *new_percpu_list = NULL;
	int		blocks = handle->h_buffer_credits;
	int		rsv_blocks = 0;
	unsigned long ts = jiffies;

	if (handle->h_rsv_handle)
		rsv_blocks = handle->h_rsv_handle->h_buffer_credits;

	/*
	 * Limit the number of reserved credits to 1/2 of maximum transaction
	 * size and limit the number of total credits to not exceed maximum
	 * transaction size per operation.
	 */
	if ((rsv_blocks > journal->j_max_transaction_buffers / 2) ||
	    (rsv_blocks + blocks > journal->j_max_transaction_buffers)) {
		printk(KERN_ERR "ZJ: %s wants too many credits "
		       "credits:%d rsv_credits:%d max:%d\n",
		       current->comm, blocks, rsv_blocks,
		       journal->j_max_transaction_buffers);
		WARN_ON(1);
		return -ENOSPC;
	}

alloc_transaction:
	if (!journal->j_running_transaction) {
		/*
		 * If __GFP_FS is not present, then we may be being called from
		 * inside the fs writeback layer, so we MUST NOT fail.
		 */
		if ((gfp_mask & __GFP_FS) == 0)
			gfp_mask |= __GFP_NOFAIL;
		if (!transaction_cache)
			printk(KERN_ERR "tcache NULL\n");
		new_transaction = kmem_cache_zalloc(transaction_cache,
						    gfp_mask);
		if (!new_transaction)
			return -ENOMEM;

		new_percpu_list = kmem_cache_zalloc(commit_list_cache, gfp_mask);
		if (!new_percpu_list) {
			zj_journal_free_transaction(new_transaction);
			return -ENOMEM;
		}
	}

	jbd_debug(3, "New handle %p going live.\n", handle);

	/*
	 * We need to hold j_state_lock until t_updates has been incremented,
	 * for proper journal barrier handling
	 */
repeat:
	read_lock(&journal->j_state_lock);
	BUG_ON(journal->j_flags & ZJ_UNMOUNT);
	if (is_journal_aborted(journal) ||
	    (journal->j_errno != 0 && !(journal->j_flags & ZJ_ACK_ERR))) {
		read_unlock(&journal->j_state_lock);
		zj_journal_free_transaction(new_transaction);
		if (new_percpu_list)
			zj_journal_free_commit_list(new_percpu_list);
		return -EROFS;
	}

	/*
	 * Wait on the journal's transaction barrier if necessary. Specifically
	 * we allow reserved handles to proceed because otherwise commit could
	 * deadlock on page writeback not being able to complete.
	 */
	if (!handle->h_reserved && journal->j_barrier_count) {
		read_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_transaction_locked,
				journal->j_barrier_count == 0);
		goto repeat;
	}

	if (!journal->j_running_transaction) {
		read_unlock(&journal->j_state_lock);
		if (!new_transaction)
			goto alloc_transaction;
		write_lock(&journal->j_state_lock);
		if (!journal->j_running_transaction &&
		    (handle->h_reserved || !journal->j_barrier_count)) {
			zj_get_transaction(journal, new_transaction, new_percpu_list);
			new_transaction = NULL;
			new_percpu_list = NULL;
		}
		write_unlock(&journal->j_state_lock);
		goto repeat;
	}

	transaction = journal->j_running_transaction;

	if (!handle->h_reserved) {
		/* We may have dropped j_state_lock - restart in that case */
		if (add_transaction_credits(journal, blocks, rsv_blocks))
			goto repeat;
	} else {
		/*
		 * We have handle reserved so we are allowed to join T_LOCKED
		 * transaction and we don't have to check for transaction size
		 * and journal space.
		 */
		sub_reserved_credits(journal, blocks);
		handle->h_reserved = 0;
	}

	/* OK, account for the buffers that this operation expects to
	 * use and add the handle to the running transaction. 
	 */
	update_t_max_wait(transaction, ts);
	handle->h_transaction = transaction;
	handle->h_requested_credits = blocks;
	handle->h_start_jiffies = jiffies;
	atomic_inc(&transaction->t_updates);
	atomic_inc(&transaction->t_handle_count);
	jbd_debug(4, "Handle %p given %d credits (total %d, free %lu)\n",
		  handle, blocks,
		  atomic_read(&transaction->t_outstanding_credits),
		  zj_log_space_left(journal));
	read_unlock(&journal->j_state_lock);
	current->journal_info = handle;

	rwsem_acquire_read(&journal->j_trans_commit_map, 0, 0, _THIS_IP_);
	zj_journal_free_transaction(new_transaction);
	if (new_percpu_list)
		zj_journal_free_commit_list(new_percpu_list);
	/*
	 * Ensure that no allocations done while the transaction is open are
	 * going to recurse back to the fs layer.
	 */
	handle->saved_alloc_context = memalloc_nofs_save();
	return 0;
}

/* Allocate a new handle.  This should probably be in a slab... */
static handle_t *new_handle(int nblocks)
{
	handle_t *handle = zj_alloc_handle(GFP_NOFS);
	if (!handle)
		return NULL;
	handle->h_buffer_credits = nblocks;
	handle->h_ref = 1;

	return handle;
}

handle_t *zj__journal_start(zjournal_t *journal, int nblocks, int rsv_blocks,
			      gfp_t gfp_mask, unsigned int type,
			      unsigned int line_no)
{
	handle_t *handle = journal_current_handle();
	int err;

	if (!journal)
		return ERR_PTR(-EROFS);

	if (handle) {
		/*J_ASSERT(handle->h_transaction->t_journal == journal);*/
		handle->h_ref++;
		return handle;
	}

	handle = new_handle(nblocks);
	if (!handle)
		return ERR_PTR(-ENOMEM);
	if (rsv_blocks) {
		handle_t *rsv_handle;

		rsv_handle = new_handle(rsv_blocks);
		if (!rsv_handle) {
			zj_free_handle(handle);
			return ERR_PTR(-ENOMEM);
		}
		rsv_handle->h_reserved = 1;
		rsv_handle->h_journal = journal;
		handle->h_rsv_handle = rsv_handle;
	}

	err = start_this_handle(journal, handle, gfp_mask);
	if (err < 0) {
		if (handle->h_rsv_handle)
			zj_free_handle(handle->h_rsv_handle);
		zj_free_handle(handle);
		return ERR_PTR(err);
	}
	handle->h_type = type;
	handle->h_line_no = line_no;
	trace_zj_handle_start(journal->j_fs_dev->bd_dev,
				handle->h_transaction->t_tid, type,
				line_no, nblocks);

	return handle;
}
EXPORT_SYMBOL(zj__journal_start);


/**
 * handle_t *zj_journal_start() - Obtain a new handle.
 * @journal: Journal to start transaction on.
 * @nblocks: number of block buffer we might modify
 *
 * We make sure that the transaction can guarantee at least nblocks of
 * modified buffers in the log.  We block until the log can guarantee
 * that much space. Additionally, if rsv_blocks > 0, we also create another
 * handle with rsv_blocks reserved blocks in the journal. This handle is
 * is stored in h_rsv_handle. It is not attached to any particular transaction
 * and thus doesn't block transaction commit. If the caller uses this reserved
 * handle, it has to set h_rsv_handle to NULL as otherwise zj_journal_stop()
 * on the parent handle will dispose the reserved one. Reserved handle has to
 * be converted to a normal handle using zj_journal_start_reserved() before
 * it can be used.
 *
 * Return a pointer to a newly allocated handle, or an ERR_PTR() value
 * on failure.
 */
handle_t *zj_journal_start(zjournal_t *journal, int nblocks)
{
	return zj__journal_start(journal, nblocks, 0, GFP_NOFS, 0, 0);
}
EXPORT_SYMBOL(zj_journal_start);

void zj_journal_free_reserved(handle_t *handle)
{
	zjournal_t *journal = handle->h_journal;

	WARN_ON(!handle->h_reserved);
	sub_reserved_credits(journal, handle->h_buffer_credits);
	zj_free_handle(handle);
}
EXPORT_SYMBOL(zj_journal_free_reserved);

/**
 * int zj_journal_start_reserved() - start reserved handle
 * @handle: handle to start
 * @type: for handle statistics
 * @line_no: for handle statistics
 *
 * Start handle that has been previously reserved with zj_journal_reserve().
 * This attaches @handle to the running transaction (or creates one if there's
 * not transaction running). Unlike zj_journal_start() this function cannot
 * block on journal commit, checkpointing, or similar stuff. It can block on
 * memory allocation or frozen journal though.
 *
 * Return 0 on success, non-zero on error - handle is freed in that case.
 */
int zj_journal_start_reserved(handle_t *handle, unsigned int type,
				unsigned int line_no)
{
	zjournal_t *journal = handle->h_journal;
	int ret = -EIO;

	if (WARN_ON(!handle->h_reserved)) {
		/* Someone passed in normal handle? Just stop it. */
		zj_journal_stop(handle);
		return ret;
	}
	/*
	 * Usefulness of mixing of reserved and unreserved handles is
	 * questionable. So far nobody seems to need it so just error out.
	 */
	if (WARN_ON(current->journal_info)) {
		zj_journal_free_reserved(handle);
		return ret;
	}

	handle->h_journal = NULL;
	/*
	 * GFP_NOFS is here because callers are likely from writeback or
	 * similarly constrained call sites
	 */
	ret = start_this_handle(journal, handle, GFP_NOFS);
	if (ret < 0) {
		handle->h_journal = journal;
		zj_journal_free_reserved(handle);
		return ret;
	}
	handle->h_type = type;
	handle->h_line_no = line_no;
	return 0;
}
EXPORT_SYMBOL(zj_journal_start_reserved);

/**
 * int zj_journal_extend() - extend buffer credits.
 * @handle:  handle to 'extend'
 * @nblocks: nr blocks to try to extend by.
 *
 * Some transactions, such as large extends and truncates, can be done
 * atomically all at once or in several stages.  The operation requests
 * a credit for a number of buffer modifications in advance, but can
 * extend its credit if it needs more.
 *
 * zj_journal_extend tries to give the running handle more buffer credits.
 * It does not guarantee that allocation - this is a best-effort only.
 * The calling process MUST be able to deal cleanly with a failure to
 * extend here.
 *
 * Return 0 on success, non-zero on failure.
 *
 * return code < 0 implies an error
 * return code > 0 implies normal transaction-full status.
 */
int zj_journal_extend(handle_t *handle, int nblocks)
{
	ztransaction_t *transaction = handle->h_transaction;
	zjournal_t *journal;
	int result;
	int wanted;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	result = 1;

	read_lock(&journal->j_state_lock);

	/* Don't extend a locked-down transaction! */
	if (transaction->t_state != T_RUNNING) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "transaction not running\n", handle, nblocks);
		goto error_out;
	}

	spin_lock(&transaction->t_handle_lock);
	wanted = atomic_add_return(nblocks,
				   &transaction->t_outstanding_credits);

	if (wanted > journal->j_max_transaction_buffers) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "transaction too large\n", handle, nblocks);
		atomic_sub(nblocks, &transaction->t_outstanding_credits);
		goto unlock;
	}

	if (wanted + (wanted >> ZJ_CONTROL_BLOCKS_SHIFT) >
	    zj_log_space_left(journal)) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "insufficient log space\n", handle, nblocks);
		atomic_sub(nblocks, &transaction->t_outstanding_credits);
		goto unlock;
	}

	trace_zj_handle_extend(journal->j_fs_dev->bd_dev,
				 transaction->t_tid,
				 handle->h_type, handle->h_line_no,
				 handle->h_buffer_credits,
				 nblocks);

	handle->h_buffer_credits += nblocks;
	handle->h_requested_credits += nblocks;
	result = 0;

	jbd_debug(3, "extended handle %p by %d\n", handle, nblocks);
unlock:
	spin_unlock(&transaction->t_handle_lock);
error_out:
	read_unlock(&journal->j_state_lock);
	return result;
}


/**
 * int zj_journal_restart() - restart a handle .
 * @handle:  handle to restart
 * @nblocks: nr credits requested
 * @gfp_mask: memory allocation flags (for start_this_handle)
 *
 * Restart a handle for a multi-transaction filesystem
 * operation.
 *
 * If the zj_journal_extend() call above fails to grant new buffer credits
 * to a running handle, a call to zj_journal_restart will commit the
 * handle's transaction so far and reattach the handle to a new
 * transaction capable of guaranteeing the requested number of
 * credits. We preserve reserved handle if there's any attached to the
 * passed in handle.
 */
int zj__journal_restart(handle_t *handle, int nblocks, gfp_t gfp_mask)
{
	ztransaction_t *transaction = handle->h_transaction;
	zjournal_t *journal;
	tid_t		tid;
	int		need_to_start, ret;

	/* If we've had an abort of any type, don't even think about
	 * actually doing the restart! */
	if (is_handle_aborted(handle))
		return 0;
	journal = transaction->t_journal;

	/*
	 * First unlink the handle from its current transaction, and start the
	 * commit on that.
	 */
	J_ASSERT(atomic_read(&transaction->t_updates) > 0);
	J_ASSERT(journal_current_handle() == handle);

	read_lock(&journal->j_state_lock);
	spin_lock(&transaction->t_handle_lock);
	atomic_sub(handle->h_buffer_credits,
		   &transaction->t_outstanding_credits);
	if (handle->h_rsv_handle) {
		sub_reserved_credits(journal,
				     handle->h_rsv_handle->h_buffer_credits);
	}
	if (atomic_dec_and_test(&transaction->t_updates))
		wake_up(&journal->j_wait_updates);
	tid = transaction->t_tid;
	spin_unlock(&transaction->t_handle_lock);
	handle->h_transaction = NULL;
	current->journal_info = NULL;

	jbd_debug(2, "restarting handle %p\n", handle);
	need_to_start = !tid_geq(journal->j_commit_request, tid);
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		zj_log_start_commit(journal, tid);

	rwsem_release(&journal->j_trans_commit_map, 1, _THIS_IP_);
	handle->h_buffer_credits = nblocks;
	/*
	 * Restore the original nofs context because the journal restart
	 * is basically the same thing as journal stop and start.
	 * start_this_handle will start a new nofs context.
	 */
	memalloc_nofs_restore(handle->saved_alloc_context);
	ret = start_this_handle(journal, handle, gfp_mask);
	return ret;
}
EXPORT_SYMBOL(zj__journal_restart);


int zj_journal_restart(handle_t *handle, int nblocks)
{
	return zj__journal_restart(handle, nblocks, GFP_NOFS);
}
EXPORT_SYMBOL(zj_journal_restart);

/**
 * void zj_journal_lock_updates () - establish a transaction barrier.
 * @journal:  Journal to establish a barrier on.
 *
 * This locks out any further updates from being started, and blocks
 * until all existing updates have completed, returning only once the
 * journal is in a quiescent state with no updates running.
 *
 * The journal lock should not be held on entry.
 */
void zj_journal_lock_updates(zjournal_t *journal)
{
	DEFINE_WAIT(wait);

	zj_might_wait_for_commit(journal);

	write_lock(&journal->j_state_lock);
	++journal->j_barrier_count;

	/* Wait until there are no reserved handles */
	if (atomic_read(&journal->j_reserved_credits)) {
		write_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_reserved,
			   atomic_read(&journal->j_reserved_credits) == 0);
		write_lock(&journal->j_state_lock);
	}

	/* Wait until there are no running updates */
	while (1) {
		ztransaction_t *transaction = journal->j_running_transaction;

		if (!transaction)
			break;

		spin_lock(&transaction->t_handle_lock);
		prepare_to_wait(&journal->j_wait_updates, &wait,
				TASK_UNINTERRUPTIBLE);
		if (!atomic_read(&transaction->t_updates)) {
			spin_unlock(&transaction->t_handle_lock);
			finish_wait(&journal->j_wait_updates, &wait);
			break;
		}
		spin_unlock(&transaction->t_handle_lock);
		write_unlock(&journal->j_state_lock);
		schedule();
		finish_wait(&journal->j_wait_updates, &wait);
		write_lock(&journal->j_state_lock);
	}
	write_unlock(&journal->j_state_lock);

	/*
	 * We have now established a barrier against other normal updates, but
	 * we also need to barrier against other zj_journal_lock_updates() calls
	 * to make sure that we serialise special journal-locked operations
	 * too.
	 */
	mutex_lock(&journal->j_barrier);
}

/**
 * void zj_journal_unlock_updates (zjournal_t* journal) - release barrier
 * @journal:  Journal to release the barrier on.
 *
 * Release a transaction barrier obtained with zj_journal_lock_updates().
 *
 * Should be called without the journal lock held.
 */
void zj_journal_unlock_updates (zjournal_t *journal)
{
	J_ASSERT(journal->j_barrier_count != 0);

	mutex_unlock(&journal->j_barrier);
	write_lock(&journal->j_state_lock);
	--journal->j_barrier_count;
	write_unlock(&journal->j_state_lock);
	wake_up(&journal->j_wait_transaction_locked);
}

static void warn_dirty_buffer(struct buffer_head *bh)
{
	printk(KERN_WARNING
	       "ZJ: Spotted dirty metadata buffer (dev = %pg, blocknr = %llu). "
	       "There's a risk of filesystem corruption in case of system "
	       "crash.\n",
	       bh->b_bdev, (unsigned long long)bh->b_blocknr);
}

void zj_shadow(struct buffer_head *orig_bh, struct zjournal_head *orig_jh,
		struct zjournal_head *jh, struct buffer_head *bh, char *data, int background) 
{
	struct zjournal_head **list;
	ztransaction_t *transaction = orig_jh->b_transaction;
	zjournal_t *journal = transaction->t_journal;
	struct page *page, *new_page;
	int offset, new_offset;
	char *source;
#ifdef ZJ_PROFILE
	unsigned long start_time, end_time;

	start_time = jiffies;
#endif

	//copy data
	page = orig_bh->b_page;
	offset = offset_in_page(orig_bh->b_data);
	source = kmap_atomic(page);
	memcpy(data, source + offset, orig_bh->b_size);
	kunmap_atomic(source);

	//link data to bh
	new_page = virt_to_page(data);
	new_offset = offset_in_page(data);
	set_bh_page(bh, new_page, new_offset);
	bh->b_size = orig_bh->b_size;

	//link bh to jh
	set_buffer_jbd(bh);
	set_buffer_frozen(bh);
	bh->b_private = jh;
	jh->b_bh = bh;
	get_bh(bh);
	jh->b_jcount++;
	zj_journal_grab_zjournal_head(orig_bh);

	jbd_lock_bh_state(bh);
	set_buffer_shadow(bh);

	//replace Metadata list orig_jh <-> jh
	spin_lock(&journal->j_list_lock);
	list = &orig_jh->b_transaction->t_buffers;
	if (*list == orig_jh) {
		*list = jh;
	}
	jh->b_tnext = orig_jh->b_tnext;
	jh->b_tnext->b_tprev = jh;
	jh->b_tprev = orig_jh->b_tprev;
	jh->b_tprev->b_tnext = jh;
	orig_jh->b_tnext = orig_jh->b_tprev = NULL;
	spin_unlock(&journal->j_list_lock);

	jh->b_jlist = BJ_Metadata;
	jh->b_transaction = transaction;
	jh->b_orig = orig_jh;
	orig_jh->b_orig = jh;
	jbd_unlock_bh_state(bh);

#ifdef ZJ_PROFILE
	end_time = jiffies;
	spin_lock(&journal->j_ov_lock);
	if (background) {
		journal->j_ov_stats.zj_copy_time2 += zj_time_diff(start_time, end_time);
		journal->j_ov_stats.zj_copy_page2++;
	} else {
		journal->j_ov_stats.zj_copy_time1 += zj_time_diff(start_time, end_time);
		journal->j_ov_stats.zj_copy_page1++;
	}
	spin_unlock(&journal->j_ov_lock);
#endif
}

static inline void add_commit_mark_two_side(zjournal_t *journal, ztransaction_t *transaction, 
						zjournal_t *jjournal, ztransaction_t *jtransaction) 
{
	int core = smp_processor_id();
	int my_core = journal->j_core_id, counter_core = jjournal->j_core_id;
	int my_tid = transaction->t_tid, counter_tid = jtransaction->t_tid;
	struct list_head *my_head = &transaction->t_commit_list[core];
	struct list_head *counter_head, *pos;
	commit_entry_t *my_commit, *counter_commit;

	//check exist
	list_for_each(pos, my_head) {
		commit_entry_t *tmp = list_entry(pos, commit_entry_t, pos);
		if (tmp->core == counter_core && tmp->tid == counter_tid)
			return;
	}

	//add local
	my_commit = zj_alloc_commit(GFP_ATOMIC);
	my_commit->core = counter_core;
	my_commit->tid = counter_tid;
	list_add(&my_commit->pos, my_head);

	//add remote
	counter_head = &jtransaction->t_commit_list[core];
	counter_commit = zj_alloc_commit(GFP_ATOMIC);
	counter_commit->core = my_core;
	counter_commit->tid = my_tid;
	list_add(&counter_commit->pos, counter_head);

	return;
}

static inline void add_commit_mark_only_mine(zjournal_t *journal, ztransaction_t *transaction, 
						zjournal_t *jjournal, ztransaction_t *jtransaction)
{
	int core = smp_processor_id();
	int counter_core = jjournal->j_core_id;
	int counter_tid = jtransaction->t_tid;
	struct list_head *my_head = &transaction->t_commit_list[core];
	struct list_head *pos;
	commit_entry_t *my_commit;

	//check exist
	list_for_each(pos, my_head) {
		commit_entry_t *tmp = list_entry(pos, commit_entry_t, pos);
		if (tmp->core == counter_core && tmp->tid == counter_tid)
			return;
	}

	//add local
	my_commit = zj_alloc_commit(GFP_ATOMIC);
	my_commit->core = counter_core;
	my_commit->tid = counter_tid;
	list_add(&my_commit->pos, my_head);

}
/*
 * If the buffer is already part of the current transaction, then there
 * is nothing we need to do.  If it is already part of a prior
 * transaction which we are still committing to disk, then we need to
 * make sure that we do not overwrite the old copy: we do copy-out to
 * preserve the copy going to disk.  We also account the buffer against
 * the handle's metadata buffer credits (unless the buffer is already
 * part of the transaction, that is).
 *
 */
static int
do_get_write_access(handle_t *handle, struct zjournal_head *jh,
			int force_copy)
{
	struct buffer_head *bh, *frozen_bh = NULL;
	struct zjournal_head *frozen_jh = NULL; 
	ztransaction_t *transaction = handle->h_transaction;
	zjournal_t *journal;
	int error;
	char *frozen_buffer = NULL;
	unsigned long start_lock, time_lock;
#ifdef ZJ_PROFILE
	unsigned long start_time, end_time;
#endif

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	jbd_debug(5, "zjournal_head %p, force_copy %d\n", jh, force_copy);

	JBUFFER_TRACE(jh, "entry");
repeat:
	bh = jh2bh(jh);

	/* @@@ Need to check for errors here at some point. */

 	start_lock = jiffies;
	lock_buffer(bh);
	jbd_lock_bh_state(bh);

	/* If it takes too long to lock the buffer, trace it */
	time_lock = zj_time_diff(start_lock, jiffies);
	if (time_lock > HZ/10)
		trace_zj_lock_buffer_stall(bh->b_bdev->bd_dev,
			jiffies_to_msecs(time_lock));

	/* We now hold the buffer lock so it is safe to query the buffer
	 * state.  Is the buffer dirty?
	 *
	 * If so, there are two possibilities.  The buffer may be
	 * non-journaled, and undergoing a quite legitimate writeback.
	 * Otherwise, it is journaled, and we don't expect dirty buffers
	 * in that state (the buffers should be marked JBD_Dirty
	 * instead.)  So either the IO is being done under our own
	 * control and this is a bug, or it's a third party IO such as
	 * dump(8) (which may leave the buffer scheduled for read ---
	 * ie. locked but not dirty) or tune2fs (which may actually have
	 * the buffer dirtied, ugh.)  */

	if (buffer_dirty(bh)) {
		/*
		 * In any case we need to clean the dirty flag and we must
		 * do it under the buffer lock to be sure we don't race
		 * with running write-out.
		 */
		JBUFFER_TRACE(jh, "Journalling dirty buffer");
		clear_buffer_dirty(bh);
		set_buffer_jbddirty(bh);
	}

	unlock_buffer(bh);

	error = -EROFS;
	if (is_handle_aborted(handle)) {
		jbd_unlock_bh_state(bh);
		goto out;
	}
	error = 0;

	/*
	 * The buffer is already part of this transaction if b_transaction or
	 * b_next_transaction points to it
	 */
	if (jh->b_transaction == transaction ||
	    jh->b_next_transaction == transaction)
		goto done;

	/*
	 * If the buffer is not journaled right now, we need to make sure it
	 * doesn't get written to disk before the caller actually commits the
	 * new data
	 */
	if (!jh->b_transaction) {
		JBUFFER_TRACE(jh, "no transaction");
		J_ASSERT_JH(jh, !jh->b_next_transaction);
		JBUFFER_TRACE(jh, "file as BJ_Reserved");
		/*
		 * Make sure all stores to jh (b_modified, b_frozen_data) are
		 * visible before attaching it to the running transaction.
		 * Paired with barrier in zj_write_access_granted()
		 */
		jh->b_modified = 0;
		jh->modified_handle = handle;
		smp_wmb();
		spin_lock(&journal->j_list_lock);
		__zj_journal_file_buffer(jh, transaction, BJ_Reserved);
		spin_unlock(&journal->j_list_lock);
		goto done;
	} else {
		ztransaction_t *jtransaction = jh->b_transaction;
		zjournal_t *jjournal = jtransaction->t_journal;

		read_lock(&jjournal->j_state_lock);
		if (jtransaction->t_state <= T_LOCKED) {
			read_unlock(&jjournal->j_state_lock);
			//add two side
			add_commit_mark_two_side(journal, transaction, jjournal, jtransaction);
			goto done;
		} else {
			read_unlock(&jjournal->j_state_lock);
			add_commit_mark_only_mine(journal, transaction, jjournal, jtransaction);
		}
	}

	/*
	 * If there is already a copy-out version of this buffer, then we don't
	 * need to make another one
	 */
	if (jh->b_frozen_data) {
		JBUFFER_TRACE(jh, "has frozen data");
		goto attach_next;
	}

	JBUFFER_TRACE(jh, "owned by older transaction");


	if (jh->b_jlist == BJ_Metadata || force_copy) {
		JBUFFER_TRACE(jh, "generate frozen data");
		if (!frozen_buffer) {
			JBUFFER_TRACE(jh, "allocate memory for buffer");
			jbd_unlock_bh_state(bh);
#ifdef ZJ_PROFILE
			start_time = jiffies;
#endif
			frozen_buffer = zj_alloc(jh2bh(jh)->b_size,
						   GFP_NOFS | __GFP_NOFAIL);
			frozen_jh = journal_alloc_zjournal_head();
			frozen_bh = alloc_buffer_head(GFP_NOFS|__GFP_NOFAIL);
#ifdef ZJ_PROFILE
			end_time = jiffies;
			spin_lock(&journal->j_ov_lock);
			journal->j_ov_stats.zj_copy_time1 += zj_time_diff(start_time, end_time);
			journal->j_ov_stats.zj_copy_page1++;
			spin_unlock(&journal->j_ov_lock);
#endif

			goto repeat;
		}

		zj_shadow(bh, jh, frozen_jh, frozen_bh, frozen_buffer, 0);

		J_ASSERT_BH(bh, buffer_jbddirty(bh));
		set_buffer_jbddirty(frozen_bh);

		frozen_buffer = NULL;
		frozen_bh = NULL;
		frozen_jh = NULL;
	}

attach_next:
	/*
	 * Make sure all stores to jh (b_modified, b_frozen_data) are visible
	 * before attaching it to the running transaction. Paired with barrier
	 * in zj_write_access_granted()
	 */
	smp_wmb();
	jh->b_modified = 0;
	jh->modified_handle = handle;

	jh->b_cpcount++;
	jh->b_transaction = NULL;
	jh->b_jlist = BJ_None;
	zj_journal_put_zjournal_head(jh);

	spin_lock(&journal->j_list_lock);
	__zj_journal_file_buffer(jh, transaction, BJ_Reserved);
	spin_unlock(&journal->j_list_lock);

done:
	jbd_unlock_bh_state(bh);

	/*
	 * If we are about to journal a buffer, then any revoke pending on it is
	 * no longer valid
	 */
	zj_journal_cancel_revoke(handle, jh);

out:
	if (unlikely(frozen_buffer))	/* It's usually NULL */
		zj_free(frozen_buffer, bh->b_size);
	if (unlikely(frozen_bh)) {
		/*__brelse(frozen_bh);*/
		free_buffer_head(frozen_bh);
	}
	if (unlikely(frozen_jh)) 
		journal_free_zjournal_head(frozen_jh);

	JBUFFER_TRACE(jh, "exit");
	return error;
}

/* Fast check whether buffer is already attached to the required transaction */
static bool zj_write_access_granted(handle_t *handle, struct buffer_head *bh,
							bool undo)
{
	struct zjournal_head *jh;
	bool ret = false;

	/* Dirty buffers require special handling... */
	if (buffer_dirty(bh))
		return false;

	/*
	 * RCU protects us from dereferencing freed pages. So the checks we do
	 * are guaranteed not to oops. However the jh slab object can get freed
	 * & reallocated while we work with it. So we have to be careful. When
	 * we see jh attached to the running transaction, we know it must stay
	 * so until the transaction is committed. Thus jh won't be freed and
	 * will be attached to the same bh while we run.  However it can
	 * happen jh gets freed, reallocated, and attached to the transaction
	 * just after we get pointer to it from bh. So we have to be careful
	 * and recheck jh still belongs to our bh before we return success.
	 */
	rcu_read_lock();
	if (!buffer_jbd(bh))
		goto out;
	/* This should be bh2jh() but that doesn't work with inline functions */
	jh = READ_ONCE(bh->b_private);
	if (!jh)
		goto out;
	/* For undo access buffer must have data copied */
	if (undo && !jh->b_committed_data)
		goto out;
	if (jh->b_transaction != handle->h_transaction &&
	    jh->b_next_transaction != handle->h_transaction)
		goto out;
	/*
	 * There are two reasons for the barrier here:
	 * 1) Make sure to fetch b_bh after we did previous checks so that we
	 * detect when jh went through free, realloc, attach to transaction
	 * while we were checking. Paired with implicit barrier in that path.
	 * 2) So that access to bh done after zj_write_access_granted()
	 * doesn't get reordered and see inconsistent state of concurrent
	 * do_get_write_access().
	 */
	smp_mb();
	if (unlikely(jh->b_bh != bh))
		goto out;
	ret = true;
out:
	rcu_read_unlock();
	return ret;
}

/**
 * int zj_journal_get_write_access() - notify intent to modify a buffer for metadata (not data) update.
 * @handle: transaction to add buffer modifications to
 * @bh:     bh to be used for metadata writes
 *
 * Returns: error code or 0 on success.
 *
 * In full data journalling mode the buffer may be of type BJ_AsyncData,
 * because we're ``write()ing`` a buffer which is also part of a shared mapping.
 */

int zj_journal_get_write_access(handle_t *handle, struct buffer_head *bh)
{
	struct zjournal_head *jh;
	int rc;

	if (zj_write_access_granted(handle, bh, false))
		return 0;

	jh = zj_journal_add_zjournal_head(bh);
	/* We do not want to get caught playing with fields which the
	 * log thread also manipulates.  Make sure that the buffer
	 * completes any outstanding IO before proceeding. */
	rc = do_get_write_access(handle, jh, 0);
	zj_journal_put_zjournal_head(jh);
	return rc;
}


/*
 * When the user wants to journal a newly created buffer_head
 * (ie. getblk() returned a new buffer and we are going to populate it
 * manually rather than reading off disk), then we need to keep the
 * buffer_head locked until it has been completely filled with new
 * data.  In this case, we should be able to make the assertion that
 * the bh is not already part of an existing transaction.
 *
 * The buffer should already be locked by the caller by this point.
 * There is no lock ranking violation: it was a newly created,
 * unlocked buffer beforehand. */

/**
 * int zj_journal_get_create_access () - notify intent to use newly created bh
 * @handle: transaction to new buffer to
 * @bh: new buffer.
 *
 * Call this if you create a new bh.
 */
int zj_journal_get_create_access(handle_t *handle, struct buffer_head *bh)
{
	ztransaction_t *transaction = handle->h_transaction;
	zjournal_t *journal;
	struct zjournal_head *jh = zj_journal_add_zjournal_head(bh);
	int err;

	jbd_debug(5, "zjournal_head %p\n", jh);
	err = -EROFS;
	if (is_handle_aborted(handle))
		goto out;
	journal = transaction->t_journal;
	err = 0;

	JBUFFER_TRACE(jh, "entry");
	/*
	 * The buffer may already belong to this transaction due to pre-zeroing
	 * in the filesystem's new_block code.  It may also be on the previous,
	 * committing transaction's lists, but it HAS to be in Forget state in
	 * that case: the transaction must have deleted the buffer for it to be
	 * reused here.
	 */
	jbd_lock_bh_state(bh);
	J_ASSERT_JH(jh, (jh->b_transaction == transaction ||
		jh->b_transaction == NULL ||
		(jh->b_transaction == journal->j_committing_transaction &&
			  jh->b_jlist == BJ_Forget)));

	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, buffer_locked(jh2bh(jh)));

	if (jh->b_transaction == NULL) {
		/*
		 * Previous zj_journal_forget() could have left the buffer
		 * with jbddirty bit set because it was being committed. When
		 * the commit finished, we've filed the buffer for
		 * checkpointing and marked it dirty. Now we are reallocating
		 * the buffer so the transaction freeing it must have
		 * committed and so it's safe to clear the dirty bit.
		 */
		clear_buffer_dirty(jh2bh(jh));
		/* first access by this transaction */
		jh->b_modified = 0;
		jh->modified_handle = handle;

		JBUFFER_TRACE(jh, "file as BJ_Reserved");
		spin_lock(&journal->j_list_lock);
		__zj_journal_file_buffer(jh, transaction, BJ_Reserved);
		spin_unlock(&journal->j_list_lock);
	} else if (jh->b_transaction->t_state > T_LOCKED) {
		/* first access by this transaction */
		jh->b_modified = 0;
		jh->modified_handle = handle;
	}
	jbd_unlock_bh_state(bh);

	/*
	 * akpm: I added this.  ext3_alloc_branch can pick up new indirect
	 * blocks which contain freed but then revoked metadata.  We need
	 * to cancel the revoke in case we end up freeing it yet again
	 * and the reallocating as data - this would cause a second revoke,
	 * which hits an assertion error.
	 */
	JBUFFER_TRACE(jh, "cancelling revoke");
	zj_journal_cancel_revoke(handle, jh);
out:
	zj_journal_put_zjournal_head(jh);
	return err;
}

/**
 * int zj_journal_get_undo_access() -  Notify intent to modify metadata with
 *     non-rewindable consequences
 * @handle: transaction
 * @bh: buffer to undo
 *
 * Sometimes there is a need to distinguish between metadata which has
 * been committed to disk and that which has not.  The ext3fs code uses
 * this for freeing and allocating space, we have to make sure that we
 * do not reuse freed space until the deallocation has been committed,
 * since if we overwrote that space we would make the delete
 * un-rewindable in case of a crash.
 *
 * To deal with that, zj_journal_get_undo_access requests write access to a
 * buffer for parts of non-rewindable operations such as delete
 * operations on the bitmaps.  The journaling code must keep a copy of
 * the buffer's contents prior to the undo_access call until such time
 * as we know that the buffer has definitely been committed to disk.
 *
 * We never need to know which transaction the committed data is part
 * of, buffers touched here are guaranteed to be dirtied later and so
 * will be committed to a new transaction in due course, at which point
 * we can discard the old committed data pointer.
 *
 * Returns error number or 0 on success.
 */
int zj_journal_get_undo_access(handle_t *handle, struct buffer_head *bh)
{
	int err;
	struct zjournal_head *jh;
	char *committed_data = NULL;

	JBUFFER_TRACE(jh, "entry");
	if (zj_write_access_granted(handle, bh, true))
		return 0;

	jh = zj_journal_add_zjournal_head(bh);
	/*
	 * Do this first --- it can drop the journal lock, so we want to
	 * make sure that obtaining the committed_data is done
	 * atomically wrt. completion of any outstanding commits.
	 */
	err = do_get_write_access(handle, jh, 1);
	if (err)
		goto out;

repeat:
	if (!jh->b_committed_data)
		committed_data = zj_alloc(jh2bh(jh)->b_size,
					    GFP_NOFS|__GFP_NOFAIL);

	jbd_lock_bh_state(bh);
	if (!jh->b_committed_data) {
		/* Copy out the current buffer contents into the
		 * preserved, committed copy. */
		JBUFFER_TRACE(jh, "generate b_committed data");
		if (!committed_data) {
			jbd_unlock_bh_state(bh);
			goto repeat;
		}

		jh->b_committed_data = committed_data;
		committed_data = NULL;
		memcpy(jh->b_committed_data, bh->b_data, bh->b_size);
	}
	jbd_unlock_bh_state(bh);
out:
	zj_journal_put_zjournal_head(jh);
	if (unlikely(committed_data))
		zj_free(committed_data, bh->b_size);
	return err;
}

/**
 * void zj_journal_set_triggers() - Add triggers for commit writeout
 * @bh: buffer to trigger on
 * @type: struct zj_buffer_trigger_type containing the trigger(s).
 *
 * Set any triggers on this zjournal_head.  This is always safe, because
 * triggers for a committing buffer will be saved off, and triggers for
 * a running transaction will match the buffer in that transaction.
 *
 * Call with NULL to clear the triggers.
 */
void zj_journal_set_triggers(struct buffer_head *bh,
			       struct zj_buffer_trigger_type *type)
{
	struct zjournal_head *jh = zj_journal_grab_zjournal_head(bh);

	if (WARN_ON(!jh))
		return;
	jh->b_triggers = type;
	zj_journal_put_zjournal_head(jh);
}

void zj_buffer_frozen_trigger(struct zjournal_head *jh, void *mapped_data,
				struct zj_buffer_trigger_type *triggers)
{
	struct buffer_head *bh = jh2bh(jh);

	if (!triggers || !triggers->t_frozen)
		return;

	triggers->t_frozen(triggers, bh, mapped_data, bh->b_size);
}

void zj_buffer_abort_trigger(struct zjournal_head *jh,
			       struct zj_buffer_trigger_type *triggers)
{
	if (!triggers || !triggers->t_abort)
		return;

	triggers->t_abort(triggers, jh2bh(jh));
}

/**
 * int zj_journal_dirty_metadata() -  mark a buffer as containing dirty metadata
 * @handle: transaction to add buffer to.
 * @bh: buffer to mark
 *
 * mark dirty metadata which needs to be journaled as part of the current
 * transaction.
 *
 * The buffer must have previously had zj_journal_get_write_access()
 * called so that it has a valid zjournal_head attached to the buffer
 * head.
 *
 * The buffer is placed on the transaction's metadata list and is marked
 * as belonging to the transaction.
 *
 * Returns error number or 0 on success.
 *
 * Special care needs to be taken if the buffer already belongs to the
 * current committing transaction (in which case we should have frozen
 * data present for that commit).  In that case, we don't relink the
 * buffer: that only gets done when the old transaction finally
 * completes its commit.
 */
int zj_journal_dirty_metadata(handle_t *handle, struct buffer_head *bh)
{
	ztransaction_t *transaction = handle->h_transaction;
	zjournal_t *journal;
	struct zjournal_head *jh;
	int ret = 0;

	if (is_handle_aborted(handle))
		return -EROFS;

	jbd_lock_bh_state(bh);

	if (!buffer_jbd(bh)) {
		ret = -EUCLEAN;
		goto out_unlock_bh;
	}
	/*
	 * We don't grab jh reference here since the buffer must be part
	 * of the running transaction.
	 */
	jh = bh2jh(bh);
	/*
	 * This and the following assertions are unreliable since we may see jh
	 * in inconsistent state unless we grab bh_state lock. But this is
	 * crucial to catch bugs so let's do a reliable check until the
	 * lockless handling is fully proven.
	 */

	if (jh->b_modified == 1) {
		goto out_unlock_bh;
	}

	journal = transaction->t_journal;
	jbd_debug(5, "zjournal_head %p\n", jh);
	JBUFFER_TRACE(jh, "entry");

	if (jh->b_modified == 0
		&& handle == jh->modified_handle) {
		/*
		 * This buffer's got modified and becoming part
		 * of the transaction. This needs to be done
		 * once a transaction -bzzz
		 */
		if (handle->h_buffer_credits <= 0) {
			ret = -ENOSPC;
			goto out_unlock_bh;
		}
		jh->b_modified = 1;
		handle->h_buffer_credits--;
	}

	/*
	 * fastpath, to avoid expensive locking.  If this buffer is already
	 * on the running transaction's metadata list there is nothing to do.
	 * Nobody can take it off again because there is a handle open.
	 * I _think_ we're OK here with SMP barriers - a mistaken decision will
	 * result in this test being false, so we go in and take the locks.
	 */
	if (jh->b_jlist == BJ_Metadata) {
		JBUFFER_TRACE(jh, "fastpath");
		goto out_unlock_bh;
	}

	set_buffer_jbddirty(bh);

	/*
	 * Metadata already on the current transaction list doesn't
	 * need to be filed.  Metadata on another transaction's list must
	 * be committing, and will be refiled once the commit completes:
	 * leave it alone for now.
	 */
	if (jh->b_transaction != transaction) {
		/* And this case is illegal: we can't reuse another
		 * transaction's data buffer, ever. */
		goto out_unlock_bh;
	}

	/* That test should have eliminated the following case: */
	J_ASSERT_JH(jh, jh->b_frozen_data == NULL);

	JBUFFER_TRACE(jh, "file as BJ_Metadata");
	spin_lock(&journal->j_list_lock);
	__zj_journal_file_buffer(jh, transaction, BJ_Metadata);
	spin_unlock(&journal->j_list_lock);
out_unlock_bh:
	jbd_unlock_bh_state(bh);
	JBUFFER_TRACE(jh, "exit");
	return ret;
}

/**
 * void zj_journal_forget() - bforget() for potentially-journaled buffers.
 * @handle: transaction handle
 * @bh:     bh to 'forget'
 *
 * We can only do the bforget if there are no commits pending against the
 * buffer.  If the buffer is dirty in the current running transaction we
 * can safely unlink it.
 *
 * bh may not be a journalled buffer at all - it may be a non-JBD
 * buffer which came off the hashtable.  Check for this.
 *
 * Decrements bh->b_count by one.
 *
 * Allow this call even if the handle has aborted --- it may be part of
 * the caller's cleanup after an abort.
 */
int zj_journal_forget (handle_t *handle, struct buffer_head *bh)
{
	ztransaction_t *transaction = handle->h_transaction;
	ztransaction_t *jtransaction;
	zjournal_t *journal, *jjournal;
	struct zjournal_head *jh;
	int drop_reserve = 0;
	int err = 0;
	int was_modified = 0;
	int was_dirty = 0;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	BUFFER_TRACE(bh, "entry");

	jbd_lock_bh_state(bh);

	if (!buffer_jbd(bh))
		goto not_jbd;
	jh = bh2jh(bh);

	/* Critical error: attempting to delete a bitmap buffer, maybe?
	 * Don't do any jbd operations, and return an error. */
	if (!J_EXPECT_JH(jh, !jh->b_committed_data,
			 "inconsistent data on disk")) {
		err = -EIO;
		goto not_jbd;
	}

	/* keep track of whether or not this transaction modified us */
	was_modified = jh->b_modified;

	/*
	 * The buffer's going from the transaction, we must drop
	 * all references -bzzz
	 */
	jh->b_modified = 0;

	if (!jh->b_cpcount && jh->b_transaction) {
		jtransaction = jh->b_transaction;
		jjournal = jtransaction->t_journal;

		read_lock(&jjournal->j_state_lock);
		if (jtransaction->t_state > T_LOCKED) {
			// 이제 처음 commit에 진입해서 처리 중
			// 기존 jbd2와 비교하자면, b_transaction은 있고
			// committing인데 next는 없는 상태
			read_unlock(&jjournal->j_state_lock);
			goto not_jbd;
		}
		read_unlock(&jjournal->j_state_lock);

		J_ASSERT_JH(jh, !jh->b_frozen_data);

		/* If we are forgetting a buffer which is already part
		 * of this transaction, then we can just drop it from
		 * the transaction immediately. */
		clear_buffer_dirty(bh);
		clear_buffer_jbddirty(bh);

		JBUFFER_TRACE(jh, "belongs to current transaction: unfile");

		/*
		 * we only want to drop a reference if this transaction
		 * modified the buffer
		 */
		if (was_modified)
			drop_reserve = 1;

		/*
		 * We are no longer going to journal this buffer.
		 * However, the commit of this transaction is still
		 * important to the buffer: the delete that we are now
		 * processing might obsolete an old log entry, so by
		 * committing, we can satisfy the buffer's checkpoint.
		 *
		 * So, if we have a checkpoint on the buffer, we should
		 * now refile the buffer on our BJ_Forget list so that
		 * we know to remove the checkpoint after we commit.
		 */

		spin_lock(&jjournal->j_list_lock);
		if (jh->b_cp_transaction) {
			__zj_journal_file_buffer(jh, jtransaction, BJ_Forget);
		} else {
			__zj_journal_unfile_buffer(jh);
			if (!buffer_jbd(bh)) {
				spin_unlock(&jjournal->j_list_lock);
				jbd_unlock_bh_state(bh);
				__bforget(bh);
				goto drop;
			}
		}
		spin_unlock(&jjournal->j_list_lock);
	} else if (jh->b_cpcount) {
		JBUFFER_TRACE(jh, "belongs to older transaction");

		if (jh->b_transaction) {
			jtransaction = jh->b_transaction;
			jjournal = jtransaction->t_journal;

			read_lock(&jjournal->j_state_lock);
			if (jtransaction->t_state > T_LOCKED) {
				read_unlock(&jjournal->j_state_lock);
				goto not_jbd;
			}
			read_unlock(&jjournal->j_state_lock);

			spin_lock(&jjournal->j_list_lock);
			if (test_clear_buffer_dirty(bh) ||
					test_clear_buffer_jbddirty(bh))
				was_dirty = 1;
			__zj_journal_unfile_buffer(jh);
			if (was_dirty)
				set_buffer_jbddirty(bh);
			spin_unlock(&jjournal->j_list_lock);

			/*
			 * only drop a reference if this transaction modified
			 * the buffer
			 */
			if (was_modified)
				drop_reserve = 1;
		}
	}

not_jbd:
	jbd_unlock_bh_state(bh);
	__brelse(bh);
drop:
	return err;
}

/**
 * int zj_journal_stop() - complete a transaction
 * @handle: transaction to complete.
 *
 * All done for a particular handle.
 *
 * There is not much action needed here.  We just return any remaining
 * buffer credits to the transaction and remove the handle.  The only
 * complication is that we need to start a commit operation if the
 * filesystem is marked for synchronous update.
 *
 * zj_journal_stop itself will not usually return an error, but it may
 * do so in unusual circumstances.  In particular, expect it to
 * return -EIO if a zj_journal_abort has been executed since the
 * transaction began.
 */
int zj_journal_stop(handle_t *handle)
{
	ztransaction_t *transaction = handle->h_transaction;
	zjournal_t *journal;
	int err = 0, wait_for_commit = 0;
	tid_t tid;
	pid_t pid;

	if (!transaction) {
		/*
		 * Handle is already detached from the transaction so
		 * there is nothing to do other than decrease a refcount,
		 * or free the handle if refcount drops to zero
		 */
		if (--handle->h_ref > 0) {
			jbd_debug(4, "h_ref %d -> %d\n", handle->h_ref + 1,
							 handle->h_ref);
			return err;
		} else {
			if (handle->h_rsv_handle)
				zj_free_handle(handle->h_rsv_handle);
			goto free_and_exit;
		}
	}
	journal = transaction->t_journal;

	J_ASSERT(journal_current_handle() == handle);

	if (is_handle_aborted(handle))
		err = -EIO;
	else
		J_ASSERT(atomic_read(&transaction->t_updates) > 0);

	if (--handle->h_ref > 0) {
		jbd_debug(4, "h_ref %d -> %d\n", handle->h_ref + 1,
			  handle->h_ref);
		return err;
	}

	jbd_debug(4, "Handle %p going down\n", handle);
	trace_zj_handle_stats(journal->j_fs_dev->bd_dev,
				transaction->t_tid,
				handle->h_type, handle->h_line_no,
				jiffies - handle->h_start_jiffies,
				handle->h_sync, handle->h_requested_credits,
				(handle->h_requested_credits -
				 handle->h_buffer_credits));

	/*
	 * Implement synchronous transaction batching.  If the handle
	 * was synchronous, don't force a commit immediately.  Let's
	 * yield and let another thread piggyback onto this
	 * transaction.  Keep doing that while new threads continue to
	 * arrive.  It doesn't cost much - we're about to run a commit
	 * and sleep on IO anyway.  Speeds up many-threaded, many-dir
	 * operations by 30x or more...
	 *
	 * We try and optimize the sleep time against what the
	 * underlying disk can do, instead of having a static sleep
	 * time.  This is useful for the case where our storage is so
	 * fast that it is more optimal to go ahead and force a flush
	 * and wait for the transaction to be committed than it is to
	 * wait for an arbitrary amount of time for new writers to
	 * join the transaction.  We achieve this by measuring how
	 * long it takes to commit a transaction, and compare it with
	 * how long this transaction has been running, and if run time
	 * < commit time then we sleep for the delta and commit.  This
	 * greatly helps super fast disks that would see slowdowns as
	 * more threads started doing fsyncs.
	 *
	 * But don't do this if this process was the most recent one
	 * to perform a synchronous write.  We do this to detect the
	 * case where a single process is doing a stream of sync
	 * writes.  No point in waiting for joiners in that case.
	 *
	 * Setting max_batch_time to 0 disables this completely.
	 */
	pid = current->pid;
	if (handle->h_sync && journal->j_last_sync_writer != pid &&
	    journal->j_max_batch_time) {
		u64 commit_time, trans_time;

		journal->j_last_sync_writer = pid;

		read_lock(&journal->j_state_lock);
		commit_time = journal->j_average_commit_time;
		read_unlock(&journal->j_state_lock);

		trans_time = ktime_to_ns(ktime_sub(ktime_get(),
						   transaction->t_start_time));

		commit_time = max_t(u64, commit_time,
				    1000*journal->j_min_batch_time);
		commit_time = min_t(u64, commit_time,
				    1000*journal->j_max_batch_time);

		if (trans_time < commit_time) {
			ktime_t expires = ktime_add_ns(ktime_get(),
						       commit_time);
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_hrtimeout(&expires, HRTIMER_MODE_ABS);
		}
	}

	if (handle->h_sync)
		transaction->t_synchronous_commit = 1;
	current->journal_info = NULL;
	atomic_sub(handle->h_buffer_credits,
		   &transaction->t_outstanding_credits);

	/*
	 * If the handle is marked SYNC, we need to set another commit
	 * going!  We also want to force a commit if the current
	 * transaction is occupying too much of the log, or if the
	 * transaction is too old now.
	 */
	if (handle->h_sync ||
	    (atomic_read(&transaction->t_outstanding_credits) >
	     journal->j_max_transaction_buffers) ||
	    time_after_eq(jiffies, transaction->t_expires)) {
		/* Do this even for aborted journals: an abort still
		 * completes the commit thread, it just doesn't write
		 * anything to disk. */

		jbd_debug(2, "transaction too old, requesting commit for "
					"handle %p\n", handle);
		/* This is non-blocking */
		zj_log_start_commit(journal, transaction->t_tid);

		/*
		 * Special case: ZJ_SYNC synchronous updates require us
		 * to wait for the commit to complete.
		 */
		if (handle->h_sync && !(current->flags & PF_MEMALLOC)) {
			wait_for_commit = 1;
		}
	}

	/*
	 * Once we drop t_updates, if it goes to zero the transaction
	 * could start committing on us and eventually disappear.  So
	 * once we do this, we must not dereference transaction
	 * pointer again.
	 */
	tid = transaction->t_tid;
	if (atomic_dec_and_test(&transaction->t_updates)) {
		wake_up(&journal->j_wait_updates);
		if (journal->j_barrier_count)
			wake_up(&journal->j_wait_transaction_locked);
	}

	rwsem_release(&journal->j_trans_commit_map, 1, _THIS_IP_);

	if (wait_for_commit)
		err = zj_log_wait_commit(journal, tid);

	if (handle->h_rsv_handle)
		zj_journal_free_reserved(handle->h_rsv_handle);
free_and_exit:
	/*
	 * Scope of the GFP_NOFS context is over here and so we can restore the
	 * original alloc context.
	 */
	memalloc_nofs_restore(handle->saved_alloc_context);
	zj_free_handle(handle);
	return err;
}

/*
 *
 * List management code snippets: various functions for manipulating the
 * transaction buffer lists.
 *
 */

/*
 * Append a buffer to a transaction list, given the transaction's list head
 * pointer.
 *
 * j_list_lock is held.
 *
 * jbd_lock_bh_state(jh2bh(jh)) is held.
 */

static inline void
__blist_add_buffer(struct zjournal_head **list, struct zjournal_head *jh)
{
	if (!*list) {
		jh->b_tnext = jh->b_tprev = jh;
		*list = jh;
	} else {
		/* Insert at the tail of the list to preserve order */
		struct zjournal_head *first = *list, *last = first->b_tprev;
		jh->b_tprev = last;
		jh->b_tnext = first;
		last->b_tnext = first->b_tprev = jh;
	}
}

/*
 * Remove a buffer from a transaction list, given the transaction's list
 * head pointer.
 *
 * Called with j_list_lock held, and the journal may not be locked.
 *
 * jbd_lock_bh_state(jh2bh(jh)) is held.
 */

static inline void
__blist_del_buffer(struct zjournal_head **list, struct zjournal_head *jh)
{
	if (*list == jh) {
		*list = jh->b_tnext;
		if (*list == jh)
			*list = NULL;
	}
	jh->b_tprev->b_tnext = jh->b_tnext;
	jh->b_tnext->b_tprev = jh->b_tprev;
}

/*
 * Remove a buffer from the appropriate transaction list.
 *
 * Note that this function can *change* the value of
 * bh->b_transaction->t_buffers, t_forget, t_shadow_list, t_log_list or
 * t_reserved_list.  If the caller is holding onto a copy of one of these
 * pointers, it could go bad.  Generally the caller needs to re-read the
 * pointer from the ztransaction_t.
 *
 * Called under j_list_lock.
 */
static void __zj_zjournal_temp_unlink_buffer(struct zjournal_head *jh)
{
	struct zjournal_head **list = NULL;
	ztransaction_t *transaction;
	struct buffer_head *bh = jh2bh(jh);
	int real_commit = 1;

	J_ASSERT_JH(jh, jbd_is_locked_bh_state(bh));
	transaction = jh->b_transaction;
	if (transaction) {
		assert_spin_locked(&transaction->t_journal->j_list_lock);
		spin_lock(&transaction->t_mark_lock);
		real_commit = transaction->t_real_commit;
		spin_unlock(&transaction->t_mark_lock);
	}

	J_ASSERT_JH(jh, jh->b_jlist < BJ_Types);
	if (jh->b_jlist != BJ_None)
		J_ASSERT_JH(jh, transaction != NULL);

	switch (jh->b_jlist) {
	case BJ_None:
		return;
	case BJ_Metadata:
		transaction->t_nr_buffers--;
		J_ASSERT_JH(jh, transaction->t_nr_buffers >= 0);
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	}

	__blist_del_buffer(list, jh);
	jh->b_jlist = BJ_None;
	if (transaction && is_journal_aborted(transaction->t_journal))
		clear_buffer_jbddirty(bh);
	else if (real_commit && test_clear_buffer_jbddirty(bh))
		mark_buffer_dirty(bh);	/* Expose it to the VM */
}

/*
 * Remove buffer from all transactions.
 *
 * Called with bh_state lock and j_list_lock
 *
 * jh and bh may be already freed when this function returns.
 */
static void __zj_journal_unfile_buffer(struct zjournal_head *jh)
{
	__zj_zjournal_temp_unlink_buffer(jh);
	jh->b_transaction = NULL;
	zj_journal_put_zjournal_head(jh);
}

void zj_journal_unfile_buffer(zjournal_t *journal, struct zjournal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	/* Get reference so that buffer cannot be freed before we unlock it */
	get_bh(bh);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);
	__zj_journal_unfile_buffer(jh);
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh);
	__brelse(bh);
}

/*
 * Called from zj_zjournal_try_to_free_buffers().
 *
 * Called under jbd_lock_bh_state(bh)
 */
static void
__zjournal_try_to_free_buffer(zjournal_t *journal, struct buffer_head *bh)
{
	struct zjournal_head *jh;
	zjournal_t *cp_journal;

	jh = bh2jh(bh);

	if (buffer_locked(bh) || buffer_dirty(bh))
		goto out;

	if (jh->b_next_transaction != NULL || jh->b_transaction != NULL)
		goto out;

	spin_lock(&journal->j_list_lock);
	if (jh->b_cp_transaction != NULL) {
		cp_journal = jh->b_cp_transaction->t_journal;
		/* written-back checkpointed metadata buffer */
		JBUFFER_TRACE(jh, "remove from checkpoint list");
		if (journal != cp_journal) {
			spin_unlock(&journal->j_list_lock);
			spin_lock(&cp_journal->j_list_lock);
		}
		__zj_journal_remove_checkpoint(jh);
		if (journal != cp_journal) {
			spin_unlock(&cp_journal->j_list_lock);
			spin_lock(&journal->j_list_lock);
		}
	}
	spin_unlock(&journal->j_list_lock);
out:
	return;
}

/**
 * int zj_zjournal_try_to_free_buffers() - try to free page buffers.
 * @journal: journal for operation
 * @page: to try and free
 * @gfp_mask: we use the mask to detect how hard should we try to release
 * buffers. If __GFP_DIRECT_RECLAIM and __GFP_FS is set, we wait for commit
 * code to release the buffers.
 *
 *
 * For all the buffers on this page,
 * if they are fully written out ordered data, move them onto BUF_CLEAN
 * so try_to_free_buffers() can reap them.
 *
 * This function returns non-zero if we wish try_to_free_buffers()
 * to be called. We do this if the page is releasable by try_to_free_buffers().
 * We also do it if the page has locked or dirty buffers and the caller wants
 * us to perform sync or async writeout.
 *
 * This complicates JBD locking somewhat.  We aren't protected by the
 * BKL here.  We wish to remove the buffer from its committing or
 * running transaction's ->t_datalist via __zj_journal_unfile_buffer.
 *
 * This may *change* the value of ztransaction_t->t_datalist, so anyone
 * who looks at t_datalist needs to lock against this function.
 *
 * Even worse, someone may be doing a zj_journal_dirty_data on this
 * buffer.  So we need to lock against that.  zj_journal_dirty_data()
 * will come out of the lock with the buffer dirty, which makes it
 * ineligible for release here.
 *
 * Who else is affected by this?  hmm...  Really the only contender
 * is do_get_write_access() - it could be looking at the buffer while
 * zjournal_try_to_free_buffer() is changing its state.  But that
 * cannot happen because we never reallocate freed data as metadata
 * while the data is part of a transaction.  Yes?
 *
 * Return 0 on failure, 1 on success
 */
int zj_zjournal_try_to_free_buffers(zjournal_t *journal,
				struct page *page, gfp_t gfp_mask)
{
	struct buffer_head *head;
	struct buffer_head *bh;
	int ret = 0;

	J_ASSERT(PageLocked(page));

	head = page_buffers(page);
	bh = head;
	do {
		struct zjournal_head *jh;

		/*
		 * We take our own ref against the zjournal_head here to avoid
		 * having to add tons of locking around each instance of
		 * zj_journal_put_zjournal_head().
		 */
		jh = zj_journal_grab_zjournal_head(bh);
		if (!jh)
			continue;

		jbd_lock_bh_state(bh);
		__zjournal_try_to_free_buffer(journal, bh);
		zj_journal_put_zjournal_head(jh);
		jbd_unlock_bh_state(bh);
		if (buffer_jbd(bh))
			goto busy;
	} while ((bh = bh->b_this_page) != head);

	ret = try_to_free_buffers(page);

busy:
	return ret;
}

/*
 * This buffer is no longer needed.  If it is on an older transaction's
 * checkpoint list we need to record it on this transaction's forget list
 * to pin this buffer (and hence its checkpointing transaction) down until
 * this transaction commits.  If the buffer isn't on a checkpoint list, we
 * release it.
 * Returns non-zero if JBD no longer has an interest in the buffer.
 *
 * Called under j_list_lock.
 *
 * Called under jbd_lock_bh_state(bh).
 */
static int __dispose_buffer(struct zjournal_head *jh, ztransaction_t *transaction)
{
	int may_free = 1;
	struct buffer_head *bh = jh2bh(jh);

	if (jh->b_cp_transaction) {
		JBUFFER_TRACE(jh, "on running+cp transaction");
		__zj_zjournal_temp_unlink_buffer(jh);
		/*
		 * We don't want to write the buffer anymore, clear the
		 * bit so that we don't confuse checks in
		 * __journal_file_buffer
		 */
		clear_buffer_jbddirty(bh);
		clear_buffer_dirty(bh);
		__zj_journal_file_buffer(jh, transaction, BJ_Forget);
		may_free = 0;
	} else {
		JBUFFER_TRACE(jh, "on running transaction");
		__zj_journal_unfile_buffer(jh);
		clear_buffer_jbddirty(bh);
	}
	return may_free;
}

/*
 * zj_journal_invalidatepage
 *
 * This code is tricky.  It has a number of cases to deal with.
 *
 * There are two invariants which this code relies on:
 *
 * i_size must be updated on disk before we start calling invalidatepage on the
 * data.
 *
 *  This is done in ext3 by defining an ext3_setattr method which
 *  updates i_size before truncate gets going.  By maintaining this
 *  invariant, we can be sure that it is safe to throw away any buffers
 *  attached to the current transaction: once the transaction commits,
 *  we know that the data will not be needed.
 *
 *  Note however that we can *not* throw away data belonging to the
 *  previous, committing transaction!
 *
 * Any disk blocks which *are* part of the previous, committing
 * transaction (and which therefore cannot be discarded immediately) are
 * not going to be reused in the new running transaction
 *
 *  The bitmap committed_data images guarantee this: any block which is
 *  allocated in one transaction and removed in the next will be marked
 *  as in-use in the committed_data bitmap, so cannot be reused until
 *  the next transaction to delete the block commits.  This means that
 *  leaving committing buffers dirty is quite safe: the disk blocks
 *  cannot be reallocated to a different file and so buffer aliasing is
 *  not possible.
 *
 *
 * The above applies mainly to ordered data mode.  In writeback mode we
 * don't make guarantees about the order in which data hits disk --- in
 * particular we don't guarantee that new dirty data is flushed before
 * transaction commit --- so it is always safe just to discard data
 * immediately in that mode.  --sct
 */

/*
 * The journal_unmap_buffer helper function returns zero if the buffer
 * concerned remains pinned as an anonymous buffer belonging to an older
 * transaction.
 *
 * We're outside-transaction here.  Either or both of j_running_transaction
 * and j_committing_transaction may be NULL.
 */
static int journal_unmap_buffer(zjournal_t *journal, struct buffer_head *bh,
				int partial_page)
{
	ztransaction_t *transaction;
	struct zjournal_head *jh;
	zjournal_t *jjournal = NULL;
	int may_free = 1;

	BUFFER_TRACE(bh, "entry");

	/*
	 * It is safe to proceed here without the j_list_lock because the
	 * buffers cannot be stolen by try_to_free_buffers as long as we are
	 * holding the page lock. --sct
	 */

	if (!buffer_jbd(bh))
		goto zap_buffer_unlocked;

	/* OK, we have data buffer in journaled mode */
	write_lock(&journal->j_state_lock);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);

	jh = zj_journal_grab_zjournal_head(bh);
	if (!jh)
		goto zap_buffer_no_jh;

	/*
	 * We cannot remove the buffer from checkpoint lists until the
	 * transaction adding inode to orphan list (let's call it T)
	 * is committed.  Otherwise if the transaction changing the
	 * buffer would be cleaned from the journal before T is
	 * committed, a crash will cause that the correct contents of
	 * the buffer will be lost.  On the other hand we have to
	 * clear the buffer dirty bit at latest at the moment when the
	 * transaction marking the buffer as freed in the filesystem
	 * structures is committed because from that moment on the
	 * block can be reallocated and used by a different page.
	 * Since the block hasn't been freed yet but the inode has
	 * already been added to orphan list, it is safe for us to add
	 * the buffer to BJ_Forget list of the newest transaction.
	 *
	 * Also we have to clear buffer_mapped flag of a truncated buffer
	 * because the buffer_head may be attached to the page straddling
	 * i_size (can happen only when blocksize < pagesize) and thus the
	 * buffer_head can be reused when the file is extended again. So we end
	 * up keeping around invalidated buffers attached to transactions'
	 * BJ_Forget list just to stop checkpointing code from cleaning up
	 * the transaction this buffer was modified in.
	 */
	if (jh->b_cpcount == 0) {
		/* First case: not on any transaction.  If it
		 * has no checkpoint link, then we can zap it:
		 * it's a writeback-mode buffer so we don't care
		 * if it hits disk safely. */
		transaction = jh->b_transaction;
		if (transaction == NULL) {
			if (!jh->b_cp_transaction) {
				JBUFFER_TRACE(jh, "not on any transaction: zap");
				goto zap_buffer;
			}
			if (jh->b_cp_transaction->t_real_commit && !buffer_dirty(bh)) {
				/* bdflush has written it.  We can drop it now */
				if ((transaction = jh->b_cp_transaction) != NULL) {
					jjournal = transaction->t_journal;
					spin_unlock(&journal->j_list_lock);
					spin_lock(&jjournal->j_list_lock);
				}
				__zj_journal_remove_checkpoint(jh);
				if (jjournal) {
					spin_unlock(&jjournal->j_list_lock);
					spin_lock(&journal->j_list_lock);
				}
				goto zap_buffer;
			}


			/* OK, it must be in the journal but still not
			 * written fully to disk: it's metadata or
			 * journaled data... */
			if (journal->j_running_transaction) {
				/* ... and once the current transaction has
				 * committed, the buffer won't be needed any
				 * longer. */
				JBUFFER_TRACE(jh, "checkpointed: add to BJ_Forget");
				may_free = __dispose_buffer(jh,
						journal->j_running_transaction);
				goto zap_buffer;
			} else {
				/* There is no currently-running transaction. So the
				 * orphan record which we wrote for this file must have
				 * passed into commit.  We must attach this buffer to
				 * the committing transaction, if it exists. */
				if (journal->j_committing_transaction) {
					JBUFFER_TRACE(jh, "give to committing trans");
					/*
					 *어차피 여기서 transaction은 NULL이므로
					 *lock을 바꿔 잡을 필요가 없다.
					 */
					may_free = __dispose_buffer(jh,
							journal->j_committing_transaction);
					goto zap_buffer;
				} else {
					/* The orphan record's transaction has
					 * committed.  We can cleanse this buffer */
					clear_buffer_jbddirty(bh);
					if ((transaction = jh->b_cp_transaction) != NULL) {
						jjournal = transaction->t_journal;
						spin_unlock(&journal->j_list_lock);
						spin_lock(&jjournal->j_list_lock);
					}
					__zj_journal_remove_checkpoint(jh);
					if (jjournal) {
						spin_unlock(&jjournal->j_list_lock);
						spin_lock(&journal->j_list_lock);
					}
					goto zap_buffer;
				}
			}
		} else if (transaction->t_state <= T_LOCKED) {
			/* Good, the buffer belongs to the running transaction.
			 * We are writing our own transaction's data, not any
			 * previous one's, so it is safe to throw it away
			 * (remember that we expect the filesystem to have set
			 * i_size already for this truncate so recovery will not
			 * expose the disk blocks we are discarding here.) */
			/*J_ASSERT_JH(jh, transaction == journal->j_running_transaction);*/
			JBUFFER_TRACE(jh, "on running transaction");

			jjournal = transaction->t_journal;
			if (jjournal) {
				spin_unlock(&journal->j_list_lock);
				spin_lock(&jjournal->j_list_lock);
			}

			may_free = __dispose_buffer(jh, transaction);
			if (jjournal) {
				spin_unlock(&jjournal->j_list_lock);
				spin_lock(&journal->j_list_lock);
			}
		} else {
			goto now_committing;
		}
	} else {
now_committing:
		JBUFFER_TRACE(jh, "on committing transaction");
		/*
		 * The buffer is committing, we simply cannot touch
		 * it. If the page is straddling i_size we have to wait
		 * for commit and try again.
		 */
		if (partial_page) {
			zj_journal_put_zjournal_head(jh);
			spin_unlock(&journal->j_list_lock);
			jbd_unlock_bh_state(bh);
			write_unlock(&journal->j_state_lock);
			return -EBUSY;
		}
		/*
		 * OK, buffer won't be reachable after truncate. We just set
		 * j_next_transaction to the running transaction (if there is
		 * one) and mark buffer as freed so that commit code knows it
		 * should clear dirty bits when it is done with the buffer.
		 */
		set_buffer_freed(bh);
		if (journal->j_running_transaction && buffer_jbddirty(bh)) {
			transaction = jh->b_transaction;
			if (transaction)
				jjournal = transaction->t_journal;
			if (jjournal) {
				spin_unlock(&journal->j_list_lock);
				spin_lock(&jjournal->j_list_lock);
			}

			if (transaction) {
				__zj_zjournal_temp_unlink_buffer(jh);
				jh->b_transaction = journal->j_running_transaction;
			}

			if (jjournal) {
				spin_unlock(&jjournal->j_list_lock);
				spin_lock(&journal->j_list_lock);
			}
			__zj_journal_file_buffer(jh, journal->j_running_transaction, 
						BJ_Forget);
		}
		zj_journal_put_zjournal_head(jh);
		spin_unlock(&journal->j_list_lock);
		jbd_unlock_bh_state(bh);
		write_unlock(&journal->j_state_lock);
		return 0;
	} 
#if 0
	else {
	}
#endif

zap_buffer:
	/*
	 * This is tricky. Although the buffer is truncated, it may be reused
	 * if blocksize < pagesize and it is attached to the page straddling
	 * EOF. Since the buffer might have been added to BJ_Forget list of the
	 * running transaction, journal_get_write_access() won't clear
	 * b_modified and credit accounting gets confused. So clear b_modified
	 * here.
	 */
	jh->b_modified = 0;
	zj_journal_put_zjournal_head(jh);
zap_buffer_no_jh:
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh);
	write_unlock(&journal->j_state_lock);
zap_buffer_unlocked:
	clear_buffer_dirty(bh);
	J_ASSERT_BH(bh, !buffer_jbddirty(bh));
	clear_buffer_mapped(bh);
	clear_buffer_req(bh);
	clear_buffer_new(bh);
	clear_buffer_delay(bh);
	clear_buffer_unwritten(bh);
	bh->b_bdev = NULL;
	return may_free;
}

/**
 * void zj_journal_invalidatepage()
 * @journal: journal to use for flush...
 * @page:    page to flush
 * @offset:  start of the range to invalidate
 * @length:  length of the range to invalidate
 *
 * Reap page buffers containing data after in the specified range in page.
 * Can return -EBUSY if buffers are part of the committing transaction and
 * the page is straddling i_size. Caller then has to wait for current commit
 * and try again.
 */
int zj_journal_invalidatepage(zjournal_t *journal,
				struct page *page,
				unsigned int offset,
				unsigned int length)
{
	struct buffer_head *head, *bh, *next;
	unsigned int stop = offset + length;
	unsigned int curr_off = 0;
	int partial_page = (offset || length < PAGE_SIZE);
	int may_free = 1;
	int ret = 0;

	if (!PageLocked(page))
		BUG();
	if (!page_has_buffers(page))
		return 0;

	BUG_ON(stop > PAGE_SIZE || stop < length);

	/* We will potentially be playing with lists other than just the
	 * data lists (especially for journaled data mode), so be
	 * cautious in our locking. */

	head = bh = page_buffers(page);
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		if (next_off > stop)
			return 0;

		if (offset <= curr_off) {
			/* This block is wholly outside the truncation point */
			lock_buffer(bh);
			ret = journal_unmap_buffer(journal, bh, partial_page);
			unlock_buffer(bh);
			if (ret < 0)
				return ret;
			may_free &= ret;
		}
		curr_off = next_off;
		bh = next;

	} while (bh != head);

	if (!partial_page) {
		if (may_free && try_to_free_buffers(page))
			J_ASSERT(!page_has_buffers(page));
	}
	return 0;
}

/*
 * File a buffer on the given transaction list.
 */
void __zj_journal_file_buffer(struct zjournal_head *jh,
			ztransaction_t *transaction, int jlist)
{
	struct zjournal_head **list = NULL;
	int was_dirty = 0;
	struct buffer_head *bh = jh2bh(jh);

	J_ASSERT_JH(jh, jbd_is_locked_bh_state(bh));
	assert_spin_locked(&transaction->t_journal->j_list_lock);

	J_ASSERT_JH(jh, jh->b_jlist < BJ_Types);
	J_ASSERT_JH(jh, jh->b_transaction == transaction ||
				jh->b_transaction == NULL);

	if (jh->b_transaction && jh->b_jlist == jlist)
		return;

	if (jlist == BJ_Metadata || jlist == BJ_Reserved ||
	    jlist == BJ_Shadow || jlist == BJ_Forget) {
		/*
		 * For metadata buffers, we track dirty bit in buffer_jbddirty
		 * instead of buffer_dirty. We should not see a dirty bit set
		 * here because we clear it in do_get_write_access but e.g.
		 * tune2fs can modify the sb and set the dirty bit at any time
		 * so we try to gracefully handle that.
		 */
		if (buffer_dirty(bh))
			warn_dirty_buffer(bh);
		if (test_clear_buffer_dirty(bh) ||
		    test_clear_buffer_jbddirty(bh))
			was_dirty = 1;
	}

	if (jh->b_transaction)
		__zj_zjournal_temp_unlink_buffer(jh);
	else
		zj_journal_grab_zjournal_head(bh);
	jh->b_transaction = transaction;

	switch (jlist) {
	case BJ_None:
		J_ASSERT_JH(jh, !jh->b_committed_data);
		J_ASSERT_JH(jh, !jh->b_frozen_data);
		return;
	case BJ_Metadata:
		transaction->t_nr_buffers++;
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	}

	__blist_add_buffer(list, jh);
	jh->b_jlist = jlist;

	if (was_dirty)
		set_buffer_jbddirty(bh);
}

void zj_journal_file_buffer(struct zjournal_head *jh,
				ztransaction_t *transaction, int jlist)
{
	jbd_lock_bh_state(jh2bh(jh));
	spin_lock(&transaction->t_journal->j_list_lock);
	__zj_journal_file_buffer(jh, transaction, jlist);
	spin_unlock(&transaction->t_journal->j_list_lock);
	jbd_unlock_bh_state(jh2bh(jh));
}

/*
 * Remove a buffer from its current buffer list in preparation for
 * dropping it from its current transaction entirely.  If the buffer has
 * already started to be used by a subsequent transaction, refile the
 * buffer on that transaction's metadata list.
 *
 * Called under j_list_lock
 * Called under jbd_lock_bh_state(jh2bh(jh))
 *
 * jh and bh may be already free when this function returns
 */
void __zj_journal_refile_buffer(struct zjournal_head *jh)
{
	int was_dirty, jlist;
	struct buffer_head *bh = jh2bh(jh);
	ztransaction_t *old_transaction;

	J_ASSERT_JH(jh, jbd_is_locked_bh_state(bh));
	if (jh->b_transaction)
		assert_spin_locked(&jh->b_transaction->t_journal->j_list_lock);

	/* If the buffer is now unused, just drop it. */
	if (jh->b_next_transaction == NULL) {
		__zj_journal_unfile_buffer(jh);
		return;
	}

	/*
	 * It has been modified by a later transaction: add it to the new
	 * transaction's metadata list.
	 */

	was_dirty = test_clear_buffer_jbddirty(bh);
	__zj_zjournal_temp_unlink_buffer(jh);
	/*
	 * We set b_transaction here because b_next_transaction will inherit
	 * our jh reference and thus __zj_journal_file_buffer() must not
	 * take a new one.
	 */
	old_transaction = jh->b_transaction;
	jh->b_transaction = jh->b_next_transaction;
	jh->b_next_transaction = NULL;
	if (buffer_freed(bh))
		jlist = BJ_Forget;
	else if (jh->b_modified)
		jlist = BJ_Metadata;
	else
		jlist = BJ_Reserved;

	if (old_transaction && old_transaction->t_journal != jh->b_transaction->t_journal) {
		spin_unlock(&old_transaction->t_journal->j_list_lock);
		spin_lock(&jh->b_transaction->t_journal->j_list_lock);
	}

	__zj_journal_file_buffer(jh, jh->b_transaction, jlist);

	if (old_transaction && old_transaction->t_journal != jh->b_transaction->t_journal) {
		spin_unlock(&jh->b_transaction->t_journal->j_list_lock);
		spin_lock(&old_transaction->t_journal->j_list_lock);
	}

	if (was_dirty)
		set_buffer_jbddirty(bh);
}

/*
 * __zj_journal_refile_buffer() with necessary locking added. We take our
 * bh reference so that we can safely unlock bh.
 *
 * The jh and bh may be freed by this call.
 */
void zj_journal_refile_buffer(zjournal_t *journal, struct zjournal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	/* Get reference so that buffer cannot be freed before we unlock it */
	get_bh(bh);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);
	__zj_journal_refile_buffer(jh);
	jbd_unlock_bh_state(bh);
	spin_unlock(&journal->j_list_lock);
	__brelse(bh);
}

/*
 * File inode in the inode list of the handle's transaction
 */
static int zj_journal_file_inode(handle_t *handle, struct zj_inode *jinode,
				   unsigned long flags)
{
	ztransaction_t *transaction = handle->h_transaction;
	zjournal_t *journal;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	jbd_debug(4, "Adding inode %lu, tid:%d\n", jinode->i_vfs_inode->i_ino,
			transaction->t_tid);

	/*
	 * First check whether inode isn't already on the transaction's
	 * lists without taking the lock. Note that this check is safe
	 * without the lock as we cannot race with somebody removing inode
	 * from the transaction. The reason is that we remove inode from the
	 * transaction only in journal_release_jbd_inode() and when we commit
	 * the transaction. We are guarded from the first case by holding
	 * a reference to the inode. We are safe against the second case
	 * because if jinode->i_transaction == transaction, commit code
	 * cannot touch the transaction because we hold reference to it,
	 * and if jinode->i_next_transaction == transaction, commit code
	 * will only file the inode where we want it.
	 */
	if ((jinode->i_transaction == transaction ||
	    jinode->i_next_transaction == transaction) &&
	    (jinode->i_flags & flags) == flags)
		return 0;

	spin_lock(&journal->j_list_lock);
	jinode->i_flags |= flags;
	/* Is inode already attached where we need it? */
	if (jinode->i_transaction == transaction ||
	    jinode->i_next_transaction == transaction)
		goto done;

	/*
	 * We only ever set this variable to 1 so the test is safe. Since
	 * t_need_data_flush is likely to be set, we do the test to save some
	 * cacheline bouncing
	 */
	if (!transaction->t_need_data_flush)
		transaction->t_need_data_flush = 1;
	/* On some different transaction's list - should be
	 * the committing one */
	if (jinode->i_transaction) {
		jinode->i_next_transaction = transaction;
		goto done;
	}
	/* Not on any transaction list... */
	J_ASSERT(!jinode->i_next_transaction);
	jinode->i_transaction = transaction;
	list_add(&jinode->i_list, &transaction->t_inode_list);
done:
	spin_unlock(&journal->j_list_lock);

	return 0;
}

int zj_journal_inode_add_write(handle_t *handle, struct zj_inode *jinode)
{
	return zj_journal_file_inode(handle, jinode,
				       JI_WRITE_DATA | JI_WAIT_DATA);
}

int zj_journal_inode_add_wait(handle_t *handle, struct zj_inode *jinode)
{
	return zj_journal_file_inode(handle, jinode, JI_WAIT_DATA);
}

/*
 * File truncate and transaction commit interact with each other in a
 * non-trivial way.  If a transaction writing data block A is
 * committing, we cannot discard the data by truncate until we have
 * written them.  Otherwise if we crashed after the transaction with
 * write has committed but before the transaction with truncate has
 * committed, we could see stale data in block A.  This function is a
 * helper to solve this problem.  It starts writeout of the truncated
 * part in case it is in the committing transaction.
 *
 * Filesystem code must call this function when inode is journaled in
 * ordered mode before truncation happens and after the inode has been
 * placed on orphan list with the new inode size. The second condition
 * avoids the race that someone writes new data and we start
 * committing the transaction after this function has been called but
 * before a transaction for truncate is started (and furthermore it
 * allows us to optimize the case where the addition to orphan list
 * happens in the same transaction as write --- we don't have to write
 * any data in such case).
 */
int zj_journal_begin_ordered_truncate(zjournal_t *journal,
					struct zj_inode *jinode,
					loff_t new_size)
{
	ztransaction_t *inode_trans, *commit_trans;
	int ret = 0;

	/* This is a quick check to avoid locking if not necessary */
	if (!jinode->i_transaction)
		goto out;
	/* Locks are here just to force reading of recent values, it is
	 * enough that the transaction was not committing before we started
	 * a transaction adding the inode to orphan list */
	read_lock(&journal->j_state_lock);
	commit_trans = journal->j_committing_transaction;
	read_unlock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	inode_trans = jinode->i_transaction;
	spin_unlock(&journal->j_list_lock);
	if (inode_trans->t_tid >= T_COMMIT) {
		ret = filemap_fdatawrite_range(jinode->i_vfs_inode->i_mapping,
			new_size, LLONG_MAX);
		if (ret)
			zj_journal_abort(journal, ret);
	}
out:
	return ret;
}
