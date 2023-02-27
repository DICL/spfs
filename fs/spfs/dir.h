#ifndef __DIR_H__
#define __DIR_H__

#include "journal.h"

//#define RENAME_DEBUG
#ifdef RENAME_DEBUG
#define rename_msg(fmt, ...)						\
	pr_err("%s: "fmt, __func__, ##__VA_ARGS__)
#define rename_msg_tree(dentry)						\
	rename_msg("%s/%s/%s", dentry->d_parent->d_parent->d_name.name,	\
			dentry->d_parent->d_name.name,			\
			dentry->d_name.name)
#else
#define rename_msg(fmt, ...)		do {} while (0)
#define rename_msg_tree(fmt, ...)	do {} while (0)
#endif

//#define READDIR_DEBUG
#ifdef READDIR_DEBUG
#define readdir_msg(fmt, ...)	pr_err("%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define readdir_msg(fmt, ...)	do {} while (0)
#endif


static inline bool spfs_should_make_dirent(struct dentry *dentry)
{
	struct inode *dir = d_inode(dentry);

	BUG_ON(!S_ISDIR(dir->i_mode));
}

static inline void spfs_swap_dirent(struct dentry *d1, struct dentry *d2)
{
	struct spfs_dentry_info *dinfo = d1->d_fsdata;

	d1->d_fsdata = d2->d_fsdata;
	d2->d_fsdata = dinfo;
}

static inline bool spfs_may_rename(struct inode *s, struct inode *t)
{
	BUG_ON(!t);
	return spfs_should_bypass(s) == spfs_should_bypass(t);
}

static inline bool spfs_should_rename_both(struct inode *inode)
{
	/* It has dirent in PM */
	if (S_ISDIR(inode->i_mode) &&
			is_inode_flag_set(inode, INODE_HAS_PM_CHILDREN))
		return true;
	else if (is_inode_flag_set(inode, INODE_TIERED))
		return true;

	return false;
}

#define djnl(inode)							\
	(&SB_INFO((inode)->i_sb)->s_psb->s_rename_jnl)			\

#define djnl_tail(inode)						\
	(djnl(inode)->jnl_tail)						\

#define djnl_commit(inode) do {						\
	djnl_tail(inode) = 0;						\
	clwb_sfence(&djnl_tail(inode), sizeof(u32));			\
} while (0)


#define __djnl_log(rename_jnl, type, data) ({				\
	u32 *tail = &(rename_jnl)->jnl_tail;				\
	u32 new_tail = *tail + (sizeof(data) >> 3);			\
	u64 *slot = (u64 *) (rename_jnl)->jnl + *tail;			\
									\
	journal_log(slot, type, &(data), sizeof(data));			\
	journal_update_tail(tail, new_tail);				\
									\
	slot;								\
})

/* inode will be flush with tail */
#define djnl_log(inode, type, data) do {				\
	struct spfs_rename_jnl *jnl = djnl(inode);			\
	jnl->jnl_inode = inode->i_ino;					\
	__djnl_log(jnl, type, data);					\
} while (0)

static inline void jnl_rename_replace(struct inode *source,
		spfs_block_t dirent_pbn)
{
	struct op_type2 t2 = { source->i_ino, dirent_pbn };

	djnl_log(source, RENAME_REPLACE, t2);
}

static inline void jnl_rename_undo(struct inode *source,
		spfs_block_t dirent_undo_blk)
{
	djnl_log(source, RENAME_UNDO_BLK, dirent_undo_blk);
}

static inline void __jnl_rename_hash_delete(struct inode *inode, u8 code,
		struct dentry *dentry)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	struct op_type2 t2 = { SPFS_DE_BLK(sbi, dentry), dentry->d_name.hash };

	djnl_log(inode, code, t2);
}

static inline void jnl_rename_hash_delete(struct inode *inode,
		struct dentry *dentry, bool move_dir)
{
	if (move_dir && is_inode_flag_set(d_inode(dentry->d_parent),
				INODE_HAS_PM_CHILDREN) &&
			SPFS_DE_CHILDREN(dentry->d_parent) == 1)
		__jnl_rename_hash_delete(inode, RENAME_DIR_HDEL,
				dentry->d_parent);

	__jnl_rename_hash_delete(inode, RENAME_REG_HDEL, dentry);
}

static inline void jnl_rename_hash_insert(struct inode *inode,
		spfs_block_t dirent_blk, u32 hash)
{
	struct op_type2 t2 = { dirent_blk, hash };
	djnl_log(inode, RENAME_REG_HINS, t2);
}

static inline void jnl_rename_commit(struct inode *inode)
{
	djnl_commit(inode);
}

#endif
