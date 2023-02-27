#ifndef __INODE_H__
#define __INODE_H__

#include <linux/bitfield.h>

#include "spfs.h"
#include "cceh.h"
#include "journal.h"
#include "profiler.h"

#define IS_PM_INODE(inode)		is_inode_flag_set(inode, INODE_PM)
#define IS_TIERED_INODE(inode)		is_inode_flag_set(inode, INODE_TIERED)

#define I_REAL_FLAGS(inode)		\
	((unsigned long *) &I_RAW(inode)->i_flags)

/* inode journal */
#define __ijournal(raw_inode)		((raw_inode)->i_journal)
#define ijournal(inode)			__ijournal(I_RAW(inode))

#define __ijournal_tail(raw_inode)	((raw_inode)->i_journal_tail)
#define ijournal_tail(inode)		__ijournal_tail(I_RAW(inode))

#define IJNL_SIZE	(BLK_SIZE - offsetof(struct spfs_inode, i_journal))
#define IJNL_COUNT	(IJNL_SIZE >> 3)

static inline void __ijournal_init(struct spfs_inode *raw_inode)
{
	__ijournal_tail(raw_inode) = 0;
	memset_l((unsigned long *) __ijournal(raw_inode), 0, IJNL_COUNT);
}

#define ijournal_init(inode)		__ijournal_init(I_RAW(inode))

#define __ijnl_commit(raw_inode, n)	\
	journal_update_tail(&__ijournal_tail(raw_inode), n)
#define ijournal_commit(inode)		__ijnl_commit(I_RAW(inode), 0)
#define ijournal_commit_n(inode, n)	\
	__ijnl_commit(I_RAW(inode), ijournal_tail(inode) - n)

#define __ijournal_log(raw_inode, type, log)				\
({									\
	u32 *tail = &__ijournal_tail(raw_inode);			\
	u32 new_tail = *tail + (sizeof(log) >> 3);			\
	u64 *slot = (u64 *) __ijournal(raw_inode) + *tail;		\
									\
	BUG_ON(new_tail >= IJNL_COUNT);					\
									\
	journal_log(slot, type,	&(log), sizeof(log));			\
	journal_update_tail(tail, new_tail);				\
									\
	slot;								\
})

#define ijournal_log(inode, type, log)	__ijournal_log(I_RAW(inode), type, log)

static inline void __ijournal_log_dir_entry(struct spfs_inode *raw_inode,
		u8 type, spfs_block_t block, cceh_hash_t hash)
{
	struct op_type2 t2 = {block, hash};
	__ijournal_log(raw_inode, type, t2);
}

#define ijournal_log_dir_entry(inode, type, block, hash)		\
	__ijournal_log_dir_entry(I_RAW(inode), type, block, hash)

static inline void __ijnl_log_inode_count(struct spfs_inode *raw_inode)
{
	struct op_type1 t1 = {0};
	__ijournal_log(raw_inode, CHG_INODE_CNT, t1);
}
#define ijournal_log_inode_count(inode)				\
	__ijnl_log_inode_count(I_RAW(inode))

static inline void ijnl_rename(struct inode *inode, u8 type, u64 block)
{
	ijournal_log(inode, type, block);
}

static inline void spfs_set_inode_recovery(struct inode *inode)
{
	__set_bit(INODE_NEED_RECOVERY,
			(unsigned long *) &I_RAW(inode)->i_flags);
	clwb_sfence(I_REAL_FLAGS(inode), sizeof(I_RAW(inode)->i_flags));
}

static inline void spfs_clear_inode_recovery(struct inode *inode)
{
	__clear_bit(INODE_NEED_RECOVERY,
			(unsigned long *) &I_RAW(inode)->i_flags);
	clwb_sfence(I_REAL_FLAGS(inode), sizeof(I_RAW(inode)->i_flags));
}

static inline unsigned long __inode_list_by_ino(struct inode *inode)
{
	return inode->i_ino % INODE_LIST_COUNT;
}

static inline struct blist_head *inode_list_by_ino(struct spfs_sb_info *sbi,
		struct inode *inode)
{
	return &sbi->s_psb->s_inode_list[__inode_list_by_ino(inode)];
}

static inline spinlock_t *inode_list_lock_by_ino(struct spfs_sb_info *sbi,
		struct inode *inode)
{
	return &sbi->s_inode_list_lock[__inode_list_by_ino(inode)];
}

static inline void spfs_add_inode_list(struct inode *inode)
{
#ifdef SPFS_INODE_LIST
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	spinlock_t *lock = inode_list_lock_by_ino(sbi, inode);

	spin_lock(lock);
	blist_add_tail(sbi, &I_RAW(inode)->i_list,
			inode_list_by_ino(sbi, inode));
	spin_unlock(lock);
#endif
}

static inline void spfs_del_inode_list(struct inode *inode)
{
#ifdef SPFS_INODE_LIST
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	spinlock_t *lock = inode_list_lock_by_ino(sbi, inode);

	spin_lock(lock);
	blist_del(sbi, &I_RAW(inode)->i_list);
	spin_unlock(lock);
#endif
}

#define SPFS_INODE_SET_TIME(time, inode, raw_inode)			\
	(raw_inode)->time = cpu_to_le32(clamp_t(int32_t,		\
				(inode)->time.tv_sec, S32_MIN, S32_MAX))

#define SPFS_INODE_GET_TIME(time, inode, raw_inode)			\
do {									\
	(inode)->time.tv_sec = (signed) le32_to_cpu((raw_inode)->time);	\
	(inode)->time.tv_nsec = 0;					\
} while (0)

static inline struct spfs_inode *__spfs_init_new_inode(struct inode *inode,
		spfs_block_t iblk)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	struct spfs_inode *p_inode = blk_addr(sbi, iblk);
	
	init_blist_head(sbi, &p_inode->i_list);
	p_inode->i_uid = cpu_to_le32(i_uid_read(inode));
	p_inode->i_gid = cpu_to_le32(i_gid_read(inode));
	p_inode->i_mode = cpu_to_le16(inode->i_mode);
	p_inode->i_links_count = cpu_to_le16(inode->i_nlink);
	p_inode->i_flags = 0; // TODO
	p_inode->i_size = 0;
	p_inode->i_blocks = 0;
	p_inode->i_version = cpu_to_le64(inode_peek_iversion(inode));
	p_inode->i_eof = -1;
	SPFS_INODE_SET_TIME(i_atime, inode, p_inode);
	SPFS_INODE_SET_TIME(i_mtime, inode, p_inode);
	SPFS_INODE_SET_TIME(i_ctime, inode, p_inode);
    
	p_inode->i_sync_factor = SF_SCALE;

	__ijournal_init(p_inode);

	return p_inode;
}

#define spfs_init_new_inode(i)	__spfs_init_new_inode(i, (i)->i_ino)

static inline void spfs_inode_persist_blocks(struct inode *inode,
		spfs_cluster_t nclusters, bool add)
{
	unsigned int *blocks = &I_RAW(inode)->i_blocks;
	unsigned int nsectors = nclusters << (CLUSTER_SHIFT - 9);

	if (add)
		*blocks += nsectors;
	else
		*blocks -= nsectors;
	clwb_sfence(blocks, sizeof(unsigned int));
}

/*
 * TODO: We don't have clear limitation now, but it should be set by other
 * parameters such as hash segment size.
 */
static inline loff_t spfs_max_inode_size(struct inode *inode)
{
	return (loff_t) 100 << 30; /* 100GB */
}

/* TODO: check whether we violate __mnt_want_write_file or not */
static inline int spfs_inode_update_time(struct inode *inode, int flags)
{
	struct timespec64 now = current_time(inode);

	if (spfs_should_bypass(inode)) {
		struct inode *lower_inode = spfs_inode_to_lower(inode);

		if (lower_inode->i_op->update_time)
			return lower_inode->i_op->update_time(lower_inode, &now,
					flags);

		return generic_update_time(lower_inode, &now, flags);
	}

	if (flags & S_MTIME)
		inode->i_mtime = now;
	if (flags & S_CTIME)
		inode->i_ctime = now;

	/* TODO: persisting and logging time */

	return 0;
}

static inline void __spfs_inode_update_sync_factor(struct inode *inode, 
		unsigned int value) 
{
	struct spfs_inode *raw_inode = I_RAW(inode);
	unsigned int old, cur;

	old = raw_inode->i_sync_factor;
	cur = spfs_calc_sync_factor(SB_INFO(inode->i_sb), old, value);
	raw_inode->i_sync_factor = cur;

	spfs_persist(&raw_inode->i_sync_factor, 
			sizeof(raw_inode->i_sync_factor));
}

static inline void spfs_inode_fast_update_sync_factor(struct inode *inode, 
		unsigned int sync_factor) 
{
	struct spfs_inode *raw_inode = I_RAW(inode);
	
	raw_inode->i_sync_factor = sync_factor;
	spfs_persist(&raw_inode->i_sync_factor, 
			sizeof(raw_inode->i_sync_factor));
}

static inline void spfs_inode_update_sync_factor(struct inode *inode, 
		unsigned int value) 
{
	int delayed_rd_cnt = 0;
	
	if (!S_OPTION(SB_INFO(inode->i_sb))->demotion)
		return;
	/* 
	 * For reads, to avoid blocking, sync factor updates are deferred 
	 * to subsequent write
	 */	
	delayed_rd_cnt = atomic_read(&I_INFO(inode)->sf_rd_cnt);
  
	if (delayed_rd_cnt > 0) {
		atomic_set(&I_INFO(inode)->sf_rd_cnt, 0);

		if (delayed_rd_cnt >= SB_INFO(inode->i_sb)->sf_rd_thld) {
			spfs_inode_fast_update_sync_factor(inode, 0);
		} else {
			while (delayed_rd_cnt-- > 0) {
				__spfs_inode_update_sync_factor(inode, 0);
			}
		}
	}

	__spfs_inode_update_sync_factor(inode, value);
}

#endif // __INODE_H__
