#ifndef __READDIR_INDEX_H__
#define __READDIR_INDEX_H__

typedef struct spfs_readdir_index_data {
	unsigned long		dir;
	struct list_head	children;
} rid_t;

extern struct kmem_cache *spfs_ri_node_cachep;

/* It doesn't count exact number of children */
static inline int spfs_dirent_children_count(struct dentry *dentry)
{
	return !list_empty(D_INFO(dentry)->children);
}

static inline void __spfs_add_dirent_list(struct spfs_sb_info *sbi,
		struct dentry *dentry, struct dentry *parent)
{
	struct spfs_readdir_node *node =
		kmem_cache_alloc(spfs_ri_node_cachep, GFP_ATOMIC);

	if (!D_INFO(parent)->children) {
		rid_t *rid = kmalloc(sizeof(rid_t), GFP_ATOMIC);

		rid->dir = d_inode(parent)->i_ino;
		INIT_LIST_HEAD(&rid->children);

		D_INFO(parent)->children = &rid->children;

		spin_lock(&sbi->s_readdir_index_lock);
		radix_tree_insert(&sbi->s_readdir_index, rid->dir, rid);
		spin_unlock(&sbi->s_readdir_index_lock);
	}

	node->dirent_blk = blk_idx(sbi, D_INFO(dentry)->de);
	list_add(&node->list, D_INFO(parent)->children);

	D_INFO(dentry)->node = node;
}

static inline u32 spfs_del_dirent_list(struct spfs_sb_info *sbi,
		struct dentry *dentry)
{
	list_del(&D_INFO(dentry)->node->list);
	kmem_cache_free(spfs_ri_node_cachep, D_INFO(dentry)->node);

	return !list_empty(D_INFO(dentry->d_parent)->children);
}

extern int spfs_init_readdir_index(struct spfs_sb_info *);
extern int spfs_exit_readdir_index(struct spfs_sb_info *);
extern int __init spfs_init_ri_cache(void);
extern void spfs_exit_ri_cache(void);

#endif
