#include "spfs.h"
#include "readdir_index.h"

struct kmem_cache *spfs_ri_node_cachep;

int spfs_load_readdir_index(struct spfs_sb_info *sbi)
{
	INIT_RADIX_TREE(&sbi->s_readdir_index, GFP_ATOMIC);
	/* TODO: from file */
	return 0;
}

int spfs_init_readdir_index(struct spfs_sb_info *sbi)
{
	spin_lock_init(&sbi->s_readdir_index_lock);
	return spfs_load_readdir_index(sbi);
}

int spfs_store_readdir_index(struct spfs_sb_info *sbi, rid_t *rid)
{
	struct list_head *pos, *tmp;
	struct spfs_readdir_node *node;

	list_for_each_safe(pos, tmp, &rid->children) {
		node = list_entry(pos, struct spfs_readdir_node, list);
		list_del(&node->list);
		/* TODO: file saving */
		kmem_cache_free(spfs_ri_node_cachep, node);
	}
	kfree(rid);

	return 0;
}

int spfs_exit_readdir_index(struct spfs_sb_info *sbi)
{
	rid_t *v[64] = {0, };
	unsigned long i = 0;
	unsigned int found, j;

	while ((found = radix_tree_gang_lookup(&sbi->s_readdir_index,
					(void **) v, i, 64))) {
		pr_err("%s: %ld %u", __func__, i, found);

		for (j = 0; j < found; j++) {
			i = v[j]->dir;
			spfs_store_readdir_index(sbi, v[j]);
		}
		i++;
	}

	return 0;
}

int __init spfs_init_ri_cache()
{
	spfs_ri_node_cachep = kmem_cache_create("spfs_ri_node_cache",
			sizeof(struct spfs_readdir_node), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);
	if (!spfs_ri_node_cachep) {
		pr_err("spfs: failed to create ri node cache");
		return -ENOMEM;
	}

	return 0;
}

void spfs_exit_ri_cache()
{
	kmem_cache_destroy(spfs_ri_node_cachep);
}
