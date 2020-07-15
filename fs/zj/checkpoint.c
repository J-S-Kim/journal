/*
 * linux/fs/zj/checkpoint.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1999 Red Hat Software --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Checkpoint routines for the generic filesystem journaling code.
 * Part of the ext2fs journaling system.
 *
 * Checkpointing is the process of ensuring that a section of the log is
 * committed fully to disk, so that that portion of the log can be
 * reused.
 */

#include <linux/time.h>
#include <linux/fs.h>
#include "zj.h"
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include "zj_trace.h"

/*
 * Unlink a buffer from a transaction checkpoint list.
 *
 * Called with j_list_lock held.
 */
static inline void __buffer_unlink_first(struct zjournal_head *jh)
{
	ztransaction_t *transaction = jh->b_cp_transaction;

	jh->b_cpnext->b_cpprev = jh->b_cpprev;
	jh->b_cpprev->b_cpnext = jh->b_cpnext;
	if (transaction->t_checkpoint_list == jh) {
		transaction->t_checkpoint_list = jh->b_cpnext;
		if (transaction->t_checkpoint_list == jh)
			transaction->t_checkpoint_list = NULL;
	}
}

/*
 * Unlink a buffer from a transaction checkpoint(io) list.
 *
 * Called with j_list_lock held.
 */
static inline void __buffer_unlink(struct zjournal_head *jh)
{
	ztransaction_t *transaction = jh->b_cp_transaction;

	__buffer_unlink_first(jh);
	if (transaction->t_checkpoint_io_list == jh) {
		transaction->t_checkpoint_io_list = jh->b_cpnext;
		if (transaction->t_checkpoint_io_list == jh)
			transaction->t_checkpoint_io_list = NULL;
	}
}

/*
 * Move a buffer from the checkpoint list to the checkpoint io list
 *
 * Called with j_list_lock held
 */
static inline void __buffer_relink_io(struct zjournal_head *jh)
{
	ztransaction_t *transaction = jh->b_cp_transaction;

	__buffer_unlink_first(jh);

	if (!transaction->t_checkpoint_io_list) {
		jh->b_cpnext = jh->b_cpprev = jh;
	} else {
		jh->b_cpnext = transaction->t_checkpoint_io_list;
		jh->b_cpprev = transaction->t_checkpoint_io_list->b_cpprev;
		jh->b_cpprev->b_cpnext = jh;
		jh->b_cpnext->b_cpprev = jh;
	}
	transaction->t_checkpoint_io_list = jh;
}

static inline void __zj_mark_enqueue(ztransaction_t *transaction, 
					ztransaction_t *rel_transaction)
{
	commit_entry_t *tc;
	int repeat, checkpoint = 0, checkpointing;
	int i, index = 0, jid;
	tid_t tid;
	LIST_HEAD(mark_list);
	commit_mark_t *buf = transaction->t_journal->j_cbuf;

	J_ASSERT(rel_transaction->t_state == T_FINISHED);

	if (transaction->t_journal->j_cbuf_debug)
		printk(KERN_ERR "Using cbuf another place, need lock?\n");

	transaction->t_journal->j_cbuf_debug = 1;
	
repeat_search:
	repeat = 0;
	checkpointing = checkpoint;
	// mark 임시 저장을 위한 어레이 하나 만들어서
	// 거기에 한번에 rel_transaction 관련 쭉 넣고
	// 그 어레이를 이용하여 체크 및 할당과 insertion 수행하는 것이 좋겠다.
	spin_lock(&rel_transaction->t_mark_lock);
	list_for_each_entry(tc, &rel_transaction->t_check_mark_list, pos) {
		if (index == ZJ_NR_COMMIT) {
			spin_unlock(&rel_transaction->t_mark_lock);
			repeat = 1;
			checkpoint += index;
			goto list_add;
		}
		while (checkpointing) {
			list_next_entry(tc, pos);
			checkpointing--;
		}
		buf[index].core = tc->core;
		buf[index].tid = tc->tid;
		index++;
	}
	spin_unlock(&rel_transaction->t_mark_lock);

	if (!index) {
		transaction->t_journal->j_cbuf_debug = 0;
		return;
	}

list_add:
	jid = transaction->t_journal->j_core_id;
	tid = transaction->t_tid;

	// 일단 미리 할당해서 만들어놓고 임시 리스트에 걸어놓는다.
	spin_lock(&transaction->t_mark_lock);
	for (i = 0; i < index; i++) {
		int mark_core = buf[i].core;
		int mark_tid = buf[i].tid;
		// 해당 mark가 현재 처리 중인 TX에 해당하는 것이면
		// 넣지 않고 넘어간다.
		/*printk(KERN_ERR "index %d/%d     %d/%d", jid,tid,mark_core,mark_tid);*/
		if ((tid == mark_tid && jid == mark_core) ||
		// trasaction의 check나 complete list에 있는가?
			zj_check_mark_value_in_list(&transaction->t_complete_mark_list, 
						mark_core, mark_tid) ||
			zj_check_mark_value_in_list(&transaction->t_check_mark_list, 
					mark_core, mark_tid)) {
			buf[i].tid = 0;
		}
	}
	spin_unlock(&transaction->t_mark_lock);
		
	while (index--) {
		commit_entry_t *new_mark;
		int mark_core = buf[index].core;
		int mark_tid = buf[index].tid;
		
		if (mark_tid == 0)
			continue;
		//새로 넣어야 한다.
		// mark 할당 후 transaction의 check list에 삽입
		new_mark = zj_alloc_commit(GFP_KERNEL);
		new_mark->core = mark_core;
		new_mark->tid = mark_tid;
		list_add(&new_mark->pos, &mark_list);
	}

	spin_lock(&transaction->t_mark_lock);
	// temp list의 mark 들을 transaction의 check mark list로 이동
	list_splice_tail(&mark_list, &transaction->t_check_mark_list);
	spin_unlock(&transaction->t_mark_lock);

	if (repeat)
		goto repeat_search;

	/*printk(KERN_ERR "end enqueu\n");*/
	transaction->t_journal->j_cbuf_debug = 0;
	return;
}

static int __zj_cp_real_commit(ztransaction_t *transaction, int force)
{
	ztransaction_t *rel_transaction;
	zjournal_t *rel_journal;

	
	spin_lock(&transaction->t_mark_lock);
	while (!list_empty(&transaction->t_check_mark_list)) {
		commit_entry_t *cur_mark = list_entry(transaction->t_check_mark_list.next, 
							commit_entry_t, pos);

		/*printk(KERN_ERR "start %d/%d\n", transaction->t_journal->j_core_id, transaction->t_tid);*/
		/*printk(KERN_ERR "mark %d, %d\n",cur_mark->core, cur_mark->tid);*/
		if (cur_mark->state)
			continue;

		cur_mark->state = 1;
		spin_unlock(&transaction->t_mark_lock);

		rel_transaction = zj_get_target_transaction(transaction->t_journal, 
				cur_mark->core, cur_mark->tid);
		if (!rel_transaction)
			// 어떤 케이스가 있을지는 모르겠지만 우선 당장에 생각나는 것은
			// 하나인데, 그냥 real commit되어서 사라졌다라는것
			goto mark_complete;

		spin_lock(&rel_transaction->t_mark_lock);
		if (rel_transaction->t_real_commit) {
			spin_unlock(&rel_transaction->t_mark_lock);
			goto mark_complete;
		}
		spin_unlock(&rel_transaction->t_mark_lock);

		rel_journal = rel_transaction->t_journal;

		read_lock(&rel_journal->j_state_lock);
		if (rel_transaction->t_state < T_FINISHED) {
			read_unlock(&rel_journal->j_state_lock);

			if (!force) {
				/*printk(KERN_ERR "force close\n");*/
				cur_mark->state = 0;
				return 1;
			}

			/*printk(KERN_ERR "wait TX\n");*/
			zj_log_start_commit(rel_journal, rel_transaction->t_tid);
			zj_log_wait_commit(rel_journal, rel_transaction->t_tid);
			read_lock(&rel_journal->j_state_lock);
		}
		read_unlock(&rel_journal->j_state_lock);

		// rel_transaction의 check list에 있는 mark들을 enqueue
		__zj_mark_enqueue(transaction, rel_transaction);

mark_complete:
		spin_lock(&transaction->t_mark_lock);
		// complete list로 이동
		cur_mark->state = 0;
		list_del(&cur_mark->pos);
		list_add(&cur_mark->pos, &transaction->t_complete_mark_list);
	}

	if (!transaction->t_real_commit)
		transaction->t_real_commit = 1;

	spin_unlock(&transaction->t_mark_lock);
	/*printk(KERN_ERR "real commit TX %d\n", transaction->t_tid);*/

	return 0;
}

/*
 * Try to release a checkpointed buffer from its transaction.
 * Returns 1 if we released it and 2 if we also released the
 * whole transaction.
 *
 * Requires j_list_lock
 */
static int __try_to_free_cp_buf(struct zjournal_head *jh)
{
	int ret = 0;
	struct buffer_head *bh = jh2bh(jh);

	if (jh->b_transaction == NULL && jh->b_cpcount == 0 && !buffer_locked(bh) &&
	    !buffer_dirty(bh) && !buffer_write_io_error(bh)) {
		JBUFFER_TRACE(jh, "remove from checkpoint list");
		ret = __zj_journal_remove_checkpoint(jh) + 1;
	}
	return ret;
}

/*
 * __zj_log_wait_for_space: wait until there is space in the journal.
 *
 * Called under j-state_lock *only*.  It will be unlocked if we have to wait
 * for a checkpoint to free up some space in the log.
 */
void __zj_log_wait_for_space(zjournal_t *journal)
{
	int nblocks, space_left;
	/* assert_spin_locked(&journal->j_state_lock); */

	nblocks = zj_space_needed(journal);
	while (zj_log_space_left(journal) < nblocks) {
		write_unlock(&journal->j_state_lock);
		mutex_lock(&journal->j_checkpoint_mutex);

		/*
		 * Test again, another process may have checkpointed while we
		 * were waiting for the checkpoint lock. If there are no
		 * transactions ready to be checkpointed, try to recover
		 * journal space by calling cleanup_zjournal_tail(), and if
		 * that doesn't work, by waiting for the currently committing
		 * transaction to complete.  If there is absolutely no way
		 * to make progress, this is either a BUG or corrupted
		 * filesystem, so abort the journal and leave a stack
		 * trace for forensic evidence.
		 */
		write_lock(&journal->j_state_lock);
		if (journal->j_flags & ZJ_ABORT) {
			mutex_unlock(&journal->j_checkpoint_mutex);
			return;
		}
		spin_lock(&journal->j_list_lock);
		nblocks = zj_space_needed(journal);
		space_left = zj_log_space_left(journal);
		if (space_left < nblocks) {
			int chkpt = journal->j_checkpoint_transactions != NULL;
			tid_t tid = 0;

			if (journal->j_committing_transaction)
				tid = journal->j_committing_transaction->t_tid;
			spin_unlock(&journal->j_list_lock);
			write_unlock(&journal->j_state_lock);
			if (chkpt) {
				zj_log_do_checkpoint(journal);
			} else if (zj_cleanup_zjournal_tail(journal) == 0) {
				/* We were able to recover space; yay! */
				;
			} else if (tid) {
				/*
				 * zj_journal_commit_transaction() may want
				 * to take the checkpoint_mutex if ZJ_FLUSHED
				 * is set.  So we need to temporarily drop it.
				 */
				mutex_unlock(&journal->j_checkpoint_mutex);
				zj_log_wait_commit(journal, tid);
				write_lock(&journal->j_state_lock);
				continue;
			} else {
				printk(KERN_ERR "%s: needed %d blocks and "
				       "only had %d space available\n",
				       __func__, nblocks, space_left);
				printk(KERN_ERR "%s: no way to get more "
				       "journal space in %s\n", __func__,
				       journal->j_devname);
				WARN_ON(1);
				zj_journal_abort(journal, 0);
			}
			write_lock(&journal->j_state_lock);
		} else {
			spin_unlock(&journal->j_list_lock);
		}
		mutex_unlock(&journal->j_checkpoint_mutex);
	}
}

static void
__flush_batch(zjournal_t *journal, int *batch_count)
{
	int i;
	struct blk_plug plug;

	blk_start_plug(&plug);
	for (i = 0; i < *batch_count; i++)
		write_dirty_buffer(journal->j_chkpt_bhs[i], REQ_SYNC);
	blk_finish_plug(&plug);

	for (i = 0; i < *batch_count; i++) {
		struct buffer_head *bh = journal->j_chkpt_bhs[i];
		BUFFER_TRACE(bh, "brelse");
		__brelse(bh);
	}
	*batch_count = 0;
}

/*
 * Perform an actual checkpoint. We take the first transaction on the
 * list of transactions to be checkpointed and send all its buffers
 * to disk. We submit larger chunks of data at once.
 *
 * The journal should be locked before calling this function.
 * Called with j_checkpoint_mutex held.
 */
int zj_log_do_checkpoint(zjournal_t *journal)
{
	struct zjournal_head	*jh;
	struct buffer_head	*bh;
	ztransaction_t		*transaction;
	tid_t			this_tid;
	int			result, batch_count = 0;
	int			force_cp = 0;

	jbd_debug(1, "Start checkpoint\n");

	/*
	 * First thing: if there are any transactions in the log which
	 * don't need checkpointing, just eliminate them from the
	 * journal straight away.
	 */
	result = zj_cleanup_zjournal_tail(journal);
	trace_zj_checkpoint(journal, result);
	jbd_debug(1, "cleanup_zjournal_tail returned %d\n", result);
	if (result <= 0)
		return result;

	/*
	 * OK, we need to start writing disk blocks.  Take one transaction
	 * and write it.
	 */
	result = 0;
	spin_lock(&journal->j_list_lock);
	if (!journal->j_checkpoint_transactions)
		goto out;
	transaction = journal->j_checkpoint_transactions;
	if (transaction->t_chp_stats.cs_chp_time == 0)
		transaction->t_chp_stats.cs_chp_time = jiffies;
	this_tid = transaction->t_tid;
restart:
	/*
	 * If someone cleaned up this transaction while we slept, we're
	 * done (maybe it's a new transaction, but it fell at the same
	 * address).
	 */
	if (journal->j_checkpoint_transactions != transaction ||
	    transaction->t_tid != this_tid)
		goto out;


	// real commit이 아니면 real commit이 될 때까지BFS 진행
	spin_lock(&transaction->t_mark_lock);
	if (!transaction->t_real_commit) {
		spin_unlock(&transaction->t_mark_lock);
		spin_unlock(&journal->j_list_lock);
		__zj_cp_real_commit(transaction, 1);

		// 처음부터 real commit인 TX가 아니라 위의 작업을 통해서 real commit이 된
		// TX라면dirty mark를 찍는게 손해다. 어차피 여기에서 io를 직접 내리는게 빠를듯
		force_cp = 1;
		spin_lock(&journal->j_list_lock);
		spin_lock(&transaction->t_mark_lock);
	}

	// 여기서 real commit 시키지도 않았는데 real commit 되어 있는 상태였다면
	// 해당 TX의 buffer들은 전부(해줘야 하는 것들) dirty mark되어 있었어야 한다.
	// 그렇게 구현.
	J_ASSERT(transaction->t_real_commit == 1);
	spin_unlock(&transaction->t_mark_lock);

	/* checkpoint all of the transaction's buffers */
	while (transaction->t_checkpoint_list) {
		jh = transaction->t_checkpoint_list;
		bh = jh2bh(jh);

		if (buffer_locked(bh)) {
			spin_unlock(&journal->j_list_lock);
			get_bh(bh);
			wait_on_buffer(bh);
			/* the zjournal_head may have gone by now */
			BUFFER_TRACE(bh, "brelse");
			__brelse(bh);
			goto retry;
		}
		if (jh->b_transaction != NULL) {
			ztransaction_t *t = jh->b_transaction;
			zjournal_t *jjournal = t->t_journal;
			tid_t tid = t->t_tid;

			transaction->t_chp_stats.cs_forced_to_close++;
			spin_unlock(&journal->j_list_lock);
			if (unlikely(journal->j_flags & ZJ_UNMOUNT))
				/*
				 * The journal thread is dead; so
				 * starting and waiting for a commit
				 * to finish will cause us to wait for
				 * a _very_ long time.
				 */
				printk(KERN_ERR
		"ZJ: %s: Waiting for Godot: block %llu\n",
		journal->j_devname, (unsigned long long) bh->b_blocknr);

			zj_log_start_commit(jjournal, tid);
			zj_log_wait_commit(jjournal, tid);
			goto retry;
		}
		if (jh->b_cpcount) {
			struct zjournal_head *commit_jh = jh->b_orig;
			ztransaction_t *jtransaction = commit_jh->b_transaction;
			if (!jtransaction)
				printk(KERN_ERR "!jtransaction %d\n",jh->b_cpcount);
			zjournal_t *jjournal = jtransaction->t_journal;
			tid_t tid = jtransaction->t_tid;

			transaction->t_chp_stats.cs_forced_to_close++;
			spin_unlock(&journal->j_list_lock);

			zj_log_start_commit(jjournal, tid);
			zj_log_wait_commit(jjournal, tid);

			goto retry;
		}
		// FIXME(jbddirty가 아니었던 녀석들도 여기 매달려 있는가?)
		// real commit을 여기서 완료 해주었다면 dirty였을 새가 없을 것이고
		// 그러므로 여기서 강제적인 checkpoint가 필요하다.
		if (!force_cp && !buffer_dirty(bh)) {
			if (unlikely(buffer_write_io_error(bh)) && !result)
				result = -EIO;
			BUFFER_TRACE(bh, "remove from checkpoint");
			if (__zj_journal_remove_checkpoint(jh))
				/* The transaction was released; we're done */
				goto out;
			continue;
		}
		/*
		 * Important: we are about to write the buffer, and
		 * possibly block, while still holding the journal
		 * lock.  We cannot afford to let the transaction
		 * logic start messing around with this buffer before
		 * we write it to disk, as that would break
		 * recoverability.
		 */
		BUFFER_TRACE(bh, "queue");
		get_bh(bh);
		J_ASSERT_BH(bh, !buffer_jwrite(bh));
		journal->j_chkpt_bhs[batch_count++] = bh;
		__buffer_relink_io(jh);
		transaction->t_chp_stats.cs_written++;
		if ((batch_count == ZJ_NR_BATCH) ||
		    need_resched() ||
		    spin_needbreak(&journal->j_list_lock))
			goto unlock_and_flush;
	}

	if (batch_count) {
		unlock_and_flush:
			spin_unlock(&journal->j_list_lock);
		retry:
			if (batch_count)
				__flush_batch(journal, &batch_count);
			spin_lock(&journal->j_list_lock);
			goto restart;
	}

	/*
	 * Now we issued all of the transaction's buffers, let's deal
	 * with the buffers that are out for I/O.
	 */
restart2:
	/* Did somebody clean up the transaction in the meanwhile? */
	if (journal->j_checkpoint_transactions != transaction ||
	    transaction->t_tid != this_tid)
		goto out;

	while (transaction->t_checkpoint_io_list) {
		jh = transaction->t_checkpoint_io_list;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) {
			spin_unlock(&journal->j_list_lock);
			get_bh(bh);
			wait_on_buffer(bh);
			/* the zjournal_head may have gone by now */
			BUFFER_TRACE(bh, "brelse");
			__brelse(bh);
			spin_lock(&journal->j_list_lock);
			goto restart2;
		}
		if (unlikely(buffer_write_io_error(bh)) && !result)
			result = -EIO;

		/*
		 * Now in whatever state the buffer currently is, we
		 * know that it has been written out and so we can
		 * drop it from the list
		 */
		if (__zj_journal_remove_checkpoint(jh))
			break;
	}
	if (journal->j_checkpoint_transactions == transaction &&
	    transaction->t_checkpoint_list == NULL &&
	    transaction->t_checkpoint_io_list == NULL) {
		__zj_journal_drop_transaction(journal, transaction);
		zj_journal_free_transaction(transaction);
	}
out:
	spin_unlock(&journal->j_list_lock);
	if (result < 0)
		zj_journal_abort(journal, result);
	else
		result = zj_cleanup_zjournal_tail(journal);

	return (result < 0) ? result : 0;
}

/*
 * Check the list of checkpoint transactions for the journal to see if
 * we have already got rid of any since the last update of the log tail
 * in the journal superblock.  If so, we can instantly roll the
 * superblock forward to remove those transactions from the log.
 *
 * Return <0 on error, 0 on success, 1 if there was nothing to clean up.
 *
 * Called with the journal lock held.
 *
 * This is the only part of the journaling code which really needs to be
 * aware of transaction aborts.  Checkpointing involves writing to the
 * main filesystem area rather than to the journal, so it can proceed
 * even in abort state, but we must not update the super block if
 * checkpointing may have failed.  Otherwise, we would lose some metadata
 * buffers which should be written-back to the filesystem.
 */

int zj_cleanup_zjournal_tail(zjournal_t *journal)
{
	tid_t		first_tid;
	unsigned long	blocknr;

	if (is_journal_aborted(journal))
		return -EIO;

	if (!zj_journal_get_log_tail(journal, &first_tid, &blocknr))
		return 1;
	J_ASSERT(blocknr != 0);

	/*
	 * We need to make sure that any blocks that were recently written out
	 * --- perhaps by zj_log_do_checkpoint() --- are flushed out before
	 * we drop the transactions from the journal. It's unlikely this will
	 * be necessary, especially with an appropriately sized journal, but we
	 * need this to guarantee correctness.  Fortunately
	 * zj_cleanup_zjournal_tail() doesn't get called all that often.
	 */
	if (journal->j_flags & ZJ_BARRIER)
		blkdev_issue_flush(journal->j_fs_dev, GFP_NOFS, NULL);

	return __zj_update_log_tail(journal, first_tid, blocknr);
}


/* Checkpoint list management */

static void journal_dirty_one_cp_list(struct zjournal_head *jh)
{
	struct buffer_head *bh;
	struct zjournal_head *last_jh;
	struct zjournal_head *next_jh = jh;

	if (!jh)
		return;

	last_jh = jh->b_cpprev;
	do {
		jh = next_jh;
		next_jh = jh->b_cpnext;

		if (jh->b_transaction != NULL ||
		    jh->b_next_transaction != NULL ||
		    jh->b_cpcount != 0)
			continue;

		bh = jh2bh(jh);

		if (test_clear_buffer_jbddirty(bh))
			mark_buffer_dirty(bh);	/* Expose it to the VM */
	} while (jh != last_jh);

	return;
}

/*
 * journal_clean_one_cp_list
 *
 * Find all the written-back checkpoint buffers in the given list and
 * release them. If 'destroy' is set, clean all buffers unconditionally.
 *
 * Called with j_list_lock held.
 * Returns 1 if we freed the transaction, 0 otherwise.
 */
static int journal_clean_one_cp_list(struct zjournal_head *jh, bool destroy)
{
	struct zjournal_head *last_jh;
	struct zjournal_head *next_jh = jh;
	int ret;

	if (!jh)
		return 0;

	last_jh = jh->b_cpprev;
	do {
		jh = next_jh;
		next_jh = jh->b_cpnext;
		if (!destroy)
			ret = __try_to_free_cp_buf(jh);
		else
			ret = __zj_journal_remove_checkpoint(jh) + 1;
		if (!ret)
			return 0;
		if (ret == 2)
			return 1;
		/*
		 * This function only frees up some memory
		 * if possible so we dont have an obligation
		 * to finish processing. Bail out if preemption
		 * requested:
		 */
		if (need_resched())
			return 0;
	} while (jh != last_jh);

	return 0;
}

/*
 * journal_clean_checkpoint_list
 *
 * Find all the written-back checkpoint buffers in the journal and release them.
 * If 'destroy' is set, release all buffers unconditionally.
 *
 * Called with j_list_lock held.
 */
void __zj_journal_clean_checkpoint_list(zjournal_t *journal, bool destroy)
{
	ztransaction_t *transaction, *last_transaction, *next_transaction;
	int ret, rt = 0;

	transaction = journal->j_checkpoint_transactions;
	if (!transaction)
		return;

	last_transaction = transaction->t_cpprev;
	next_transaction = transaction;
	do {
		// FIXME list lock을 풀고 real commit 하는데 
		// 그동안 cp TX list가 바뀌면?
		transaction = next_transaction;
		next_transaction = transaction->t_cpnext;

		// transaction이 real commit이 아닌 경우에 대해여
		// 대략 아직 commit이 되지 않은 commit mark를 만날 때까지 BFS를 진행한다.

		spin_lock(&transaction->t_mark_lock);
		if (!transaction->t_real_commit) {
			spin_unlock(&transaction->t_mark_lock);
			spin_unlock(&journal->j_list_lock);
			rt = __zj_cp_real_commit(transaction, 0);

			// real commit이 되었다면 dirty mark를 찍어준다.
			if (!rt) {
				spin_lock(&journal->j_list_lock);
				if (transaction->t_checkpoint_list == NULL &&
				transaction->t_checkpoint_io_list == NULL) {
					__zj_journal_drop_transaction(journal, transaction);
					zj_journal_free_transaction(transaction);
				} else
					journal_dirty_one_cp_list(transaction->t_checkpoint_list);
				continue;
			}
			// real commit에 실패했으므로 걍 여기서 끝
			// 아마 이 뒤의 cp TX도 처리가 덜 되었을 것으로 추측
			spin_lock(&journal->j_list_lock);
			return;
		}
		spin_unlock(&transaction->t_mark_lock);

		// FIXME
		// destroy인 경우는 어떻게 할 것인가?

		// 저널 헤드를 지우는데 실패하거나, 트랜잭션 하나를 지우는데 
		// 완료 하였으면 돌아옴
		// TX를 지웠으면 1 아니면 0
		ret = journal_clean_one_cp_list(transaction->t_checkpoint_list,
						destroy);
		/*
		 * This function only frees up some memory if possible so we
		 * dont have an obligation to finish processing. Bail out if
		 * preemption requested:
		 */
		if (need_resched())
			return;
		if (ret)
			continue;
		/*
		 * It is essential that we are as careful as in the case of
		 * t_checkpoint_list with removing the buffer from the list as
		 * we can possibly see not yet submitted buffers on io_list
		 */
		ret = journal_clean_one_cp_list(transaction->
				t_checkpoint_io_list, destroy);
		if (need_resched())
			return;
		/*
		 * Stop scanning if we couldn't free the transaction. This
		 * avoids pointless scanning of transactions which still
		 * weren't checkpointed.
		 */
		if (!ret)
			return;
	} while (transaction != last_transaction);
}

/*
 * Remove buffers from all checkpoint lists as journal is aborted and we just
 * need to free memory
 */
void zj_journal_destroy_checkpoint(zjournal_t *journal)
{
	/*
	 * We loop because __zj_journal_clean_checkpoint_list() may abort
	 * early due to a need of rescheduling.
	 */
	// FIXME
	// real commit이 아닌 경우인데 강제로 destroy 해도 괜찮은가?
	while (1) {
		spin_lock(&journal->j_list_lock);
		if (!journal->j_checkpoint_transactions) {
			spin_unlock(&journal->j_list_lock);
			break;
		}
		__zj_journal_clean_checkpoint_list(journal, true);
		spin_unlock(&journal->j_list_lock);
		cond_resched();
	}
}

/*
 * journal_remove_checkpoint: called after a buffer has been committed
 * to disk (either by being write-back flushed to disk, or being
 * committed to the log).
 *
 * We cannot safely clean a transaction out of the log until all of the
 * buffer updates committed in that transaction have safely been stored
 * elsewhere on disk.  To achieve this, all of the buffers in a
 * transaction need to be maintained on the transaction's checkpoint
 * lists until they have been rewritten, at which point this function is
 * called to remove the buffer from the existing transaction's
 * checkpoint lists.
 *
 * The function returns 1 if it frees the transaction, 0 otherwise.
 * The function can free jh and bh.
 *
 * This function is called with j_list_lock held.
 */
int __zj_journal_remove_checkpoint(struct zjournal_head *jh)
{
	struct transaction_chp_stats_s *stats;
	ztransaction_t *transaction;
	zjournal_t *journal;
	int ret = 0;

	JBUFFER_TRACE(jh, "entry");

	if ((transaction = jh->b_cp_transaction) == NULL) {
		JBUFFER_TRACE(jh, "not on transaction");
		goto out;
	}
	journal = transaction->t_journal;

	JBUFFER_TRACE(jh, "removing from transaction");
	__buffer_unlink(jh);
	jh->b_cp_transaction = NULL;
	clear_buffer_checkpoint(jh2bh(jh));
	zj_journal_put_zjournal_head(jh);

	if (transaction->t_checkpoint_list != NULL ||
	    transaction->t_checkpoint_io_list != NULL)
		goto out;

	/*
	 * There is one special case to worry about: if we have just pulled the
	 * buffer off a running or committing transaction's checkpoing list,
	 * then even if the checkpoint list is empty, the transaction obviously
	 * cannot be dropped!
	 *
	 * The locking here around t_state is a bit sleazy.
	 * See the comment at the end of zj_journal_commit_transaction().
	 */
	if (transaction->t_state != T_FINISHED ||
	    !transaction->t_real_commit)
		goto out;

	/* OK, that was the last buffer for the transaction: we can now
	   safely remove this transaction from the log */
	stats = &transaction->t_chp_stats;
	if (stats->cs_chp_time)
		stats->cs_chp_time = zj_time_diff(stats->cs_chp_time,
						    jiffies);
	trace_zj_checkpoint_stats(journal->j_fs_dev->bd_dev,
				    transaction->t_tid, stats);

	__zj_journal_drop_transaction(journal, transaction);
	zj_journal_free_transaction(transaction);
	ret = 1;
out:
	return ret;
}

/*
 * journal_insert_checkpoint: put a committed buffer onto a checkpoint
 * list so that we know when it is safe to clean the transaction out of
 * the log.
 *
 * Called with the journal locked.
 * Called with j_list_lock held.
 */
void __zj_journal_insert_checkpoint(struct zjournal_head *jh,
			       ztransaction_t *transaction)
{
	JBUFFER_TRACE(jh, "entry");
	J_ASSERT_JH(jh, buffer_dirty(jh2bh(jh)) || buffer_jbddirty(jh2bh(jh)));
	J_ASSERT_JH(jh, jh->b_cp_transaction == NULL);

	/* Get reference for checkpointing transaction */
	zj_journal_grab_zjournal_head(jh2bh(jh));
	jh->b_cp_transaction = transaction;

	if (!transaction->t_checkpoint_list) {
		jh->b_cpnext = jh->b_cpprev = jh;
	} else {
		jh->b_cpnext = transaction->t_checkpoint_list;
		jh->b_cpprev = transaction->t_checkpoint_list->b_cpprev;
		jh->b_cpprev->b_cpnext = jh;
		jh->b_cpnext->b_cpprev = jh;
	}
	transaction->t_checkpoint_list = jh;
}

/*
 * We've finished with this transaction structure: adios...
 *
 * The transaction must have no links except for the checkpoint by this
 * point.
 *
 * Called with the journal locked.
 * Called with j_list_lock held.
 */

void __zj_journal_drop_transaction(zjournal_t *journal, ztransaction_t *transaction)
{
	assert_spin_locked(&journal->j_list_lock);
	if (transaction->t_cpnext) {
		transaction->t_cpnext->t_cpprev = transaction->t_cpprev;
		transaction->t_cpprev->t_cpnext = transaction->t_cpnext;
		if (journal->j_checkpoint_transactions == transaction)
			journal->j_checkpoint_transactions =
				transaction->t_cpnext;
		if (journal->j_checkpoint_transactions == transaction)
			journal->j_checkpoint_transactions = NULL;
	}

	free_percpu(transaction->t_commit_list);

	J_ASSERT(transaction->t_real_commit == 1);
	J_ASSERT(transaction->t_state == T_FINISHED);
	J_ASSERT(transaction->t_buffers == NULL);
	J_ASSERT(transaction->t_forget == NULL);
	J_ASSERT(transaction->t_shadow_list == NULL);
	J_ASSERT(transaction->t_checkpoint_list == NULL);
	J_ASSERT(transaction->t_checkpoint_io_list == NULL);
	J_ASSERT(atomic_read(&transaction->t_updates) == 0);
	J_ASSERT(journal->j_committing_transaction != transaction);
	J_ASSERT(journal->j_running_transaction != transaction);

	trace_zj_drop_transaction(journal, transaction);

	jbd_debug(1, "Dropping transaction %d, all done\n", transaction->t_tid);
}
