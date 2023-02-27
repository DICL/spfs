#ifndef __NAMEI_H__
#define __NAMEI_H__

#include "spfs.h"
#include "calloc.h"


//#define LOOKUP_DEBUG
#ifdef LOOKUP_DEBUG
#define spfs_lookup_debug(sb, fmt, ...)			\
	spfs_err(sb, "%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define spfs_lookup_debug(sb, fmt, ...)			do {} while (0)
#endif

struct spfs_namei_info {
	struct spfs_cceh_info	*hash;

	struct radix_tree_root		inode_radix;
	spinlock_t			inode_radix_lock;
};

#define NAMEI_INFO(sbi)	((struct spfs_namei_info *) (sbi)->s_namei_info)
#define NAMEI_HASH(sbi)	(NAMEI_INFO(sbi)->hash)


struct spfs_dir_entry {
	struct blist_head	de_sib;
	__le32			de_private;
#define DE_DIR		0x0001
#define DE_LONG_NAME	0x0002
	__le16			de_flags;
	__le16			de_len;
	__le64			de_inode_bno;
	__le64			de_pino;		/* 20 */
	union {
		struct {
#define DE_SHORT_NAME_LEN	(208)
#define MAX_NAME_LEN		DE_SHORT_NAME_LEN // TODO: support long name
			char	de_incomp_name[DE_SHORT_NAME_LEN];
			__le64	de_long_name_bno;
		};
		char		de_name[DE_SHORT_NAME_LEN + 8];
	};
} __attribute((__packed__));

#define SPFS_DE(dentry)		(D_INFO(dentry)->de)
#define SPFS_DE_BLK(sbi, dentry)	(blk_idx(sbi, SPFS_DE(dentry)))
#define SPFS_DE_CHILDREN(dentry)	(SPFS_DE(dentry)->de_private)
#define SPFS_DE_LIST(dentry)		(&SPFS_DE(dentry)->de_sib)

/* for CCEH */
struct cceh_namei_kdata {
	struct inode		*dir;
	struct qstr		name;
	spfs_block_t		fast_del_hint;
	bool			find_dir;
	void			*private;
};

typedef struct cceh_namei_kdata cceh_namei_query_t;

static inline void init_cceh_namei_key(struct cceh_namei_kdata *k,
		struct inode *dir, struct dentry *dentry, bool delete,
		bool find_dir)
{
	struct spfs_sb_info *sbi = SB_INFO(dir->i_sb);

	k->dir = dir;
	k->name = dentry->d_name;
	k->fast_del_hint = delete ? blk_idx(sbi, D_INFO(dentry)->de) : 0;
	k->find_dir = find_dir;
	k->private = NULL;
}

static inline struct spfs_dir_entry *
spfs_namei_cceh_get(struct spfs_sb_info *sbi, struct dentry *dentry,
		bool find_dir)
{
	struct spfs_dir_entry *dirent;
	struct cceh_namei_kdata kdat;

	init_cceh_namei_key(&kdat, d_inode(dentry->d_parent), dentry, false,
			find_dir);
	dirent = spfs_cceh_get(NAMEI_INFO(sbi)->hash, &kdat);
	if (dirent) {
		D_INFO(dentry)->de = dirent;
		D_INFO(dentry)->dirent_slot = kdat.private;
	}

	return dirent;
}

static inline void init_dir_entry_name(struct spfs_dir_entry *de,
		struct dentry *dentry)
{
	size_t len = dentry->d_name.len;

	de->de_len = len;
	memcpy(de->de_name, dentry->d_name.name, MIN(len, DE_SHORT_NAME_LEN));
	if (len > DE_SHORT_NAME_LEN) {
		de->de_flags = DE_LONG_NAME;
		memcpy(de->de_name, dentry->d_name.name + DE_SHORT_NAME_LEN,
				len - DE_SHORT_NAME_LEN);
	} else if (len < DE_SHORT_NAME_LEN)
		de->de_name[de->de_len] = '\0';
	// TODO: long name case
}

static inline struct spfs_dir_entry *
init_dir_entry(struct spfs_dentry_info *info, u64 bno, struct inode *dir,
		struct dentry *dentry, u64 inode_bno, u16 flags)
{
	struct spfs_sb_info *sbi = SB_INFO(dir->i_sb);
	struct spfs_dir_entry *de = blk_addr(sbi, bno);

	info->de = de;

	init_blist_head(sbi, &de->de_sib);
	de->de_inode_bno = inode_bno;
	de->de_pino = dir->i_ino;
	de->de_flags = flags;
	de->de_private = 0;
	init_dir_entry_name(de, dentry);

	return de;
}

static inline void *spfs_add_dirent(struct spfs_sb_info *sbi,
		struct inode *dir, struct dentry *dentry,
		spfs_block_t dirent_loc, u16 flags)
{
	cceh_namei_query_t q;
	init_cceh_namei_key(&q, d_inode(dentry->d_parent), dentry, false,
			(flags & DE_DIR) != 0);
	return spfs_cceh_insert(NAMEI_HASH(sbi), &q, dirent_loc);
}


static inline void *spfs_namei_cceh_insert(struct spfs_sb_info *sbi,
		struct dentry *dentry, spfs_block_t de_blk, u16 flags)
{
	void *retp = spfs_add_dirent(sbi, d_inode(dentry->d_parent), dentry,
			de_blk, flags);
	if (!IS_ERR(retp))
		D_INFO(dentry)->dirent_slot = retp;
	return retp;
}

static inline int spfs_namei_cceh_delete(struct spfs_sb_info *sbi,
		struct inode *dir, struct dentry *dentry, bool find_dir)
{
	cceh_namei_query_t q;
	init_cceh_namei_key(&q, dir, dentry, true, find_dir);
	return __spfs_cceh_delete(NAMEI_HASH(sbi), &q,
			D_INFO(dentry)->dirent_slot);
}

#ifdef CONFIG_SPFS_READDIR_RADIX_TREE
#include "readdir_index.h"
#else
static inline int spfs_dirent_children_count(struct dentry *dentry)
{
	struct spfs_dentry_info *dinfo = D_INFO(dentry);
	struct inode *inode = d_inode(dentry);

	BUG_ON(inode && !S_ISDIR(inode->i_mode));

	if (dinfo->de == NULL) {
		BUG_ON(inode &&
			is_inode_flag_set(inode, INODE_HAS_PM_CHILDREN));
		return 0;
	}

	BUG_ON(!(inode && is_inode_flag_set(inode, INODE_HAS_PM_CHILDREN)));

	return SPFS_DE_CHILDREN(dentry);
}

static inline void __spfs_add_dirent_list(struct spfs_sb_info *sbi,
		struct dentry *dentry, struct dentry *parent)
{
	struct blist_head *list = SPFS_DE_LIST(dentry);
	u32 *parent_child_cnt = &SPFS_DE_CHILDREN(parent);

	BUG_ON(!is_inode_flag_set(d_inode(parent), INODE_HAS_PM_CHILDREN));

	blist_add_tail(sbi, list, SPFS_DE_LIST(parent));
	clwb_sfence(list, sizeof(struct blist_head));

	(*parent_child_cnt)++;
	clwb_sfence(parent_child_cnt, sizeof(u32));

//	pr_err("%s: %s/%s/.. %u", __func__,
//			parent->d_parent->d_name.name,
//			parent->d_name.name,
//			*parent_child_cnt);
}

static inline u32 spfs_del_dirent_list(struct spfs_sb_info *sbi,
		struct dentry *dentry)
{
	struct blist_head *list = SPFS_DE_LIST(dentry);
	u32 *parent_child_cnt = &SPFS_DE_CHILDREN(dentry->d_parent);

	blist_del_init(sbi, list);
	clwb_sfence(list, sizeof(struct blist_head));

	(*parent_child_cnt)--;
	clwb_sfence(parent_child_cnt, sizeof(u32));

//	pr_err("%s: %s/%s/%s %u", __func__,
//			dentry->d_parent->d_parent->d_name.name,
//			dentry->d_parent->d_name.name,
//			dentry->d_name.name,
//			*parent_child_cnt);

	BUG_ON(*parent_child_cnt == 0xffffffff);

	return *parent_child_cnt;
}

#define spfs_init_readdir_index(sbi)	do {} while (0)
#define spfs_exit_readdir_index(sbi)	do {} while (0)

static inline int __init spfs_init_ri_cache(void)
{
	return 0;
}
#define spfs_exit_ri_cache()		do {} while (0)

#endif

static inline void spfs_add_dirent_list(struct spfs_sb_info *sbi,
		struct dentry *dentry)
{
	__spfs_add_dirent_list(sbi, dentry, dentry->d_parent);
}

#endif
