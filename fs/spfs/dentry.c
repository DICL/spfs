#include "spfs.h"
#include "namei.h"
#include "inode.h"

static struct kmem_cache *spfs_dentry_info_cachep;

static int spfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct spfs_sb_info *sbi = SB_INFO(dentry->d_sb);
	struct dentry *lower_dentry = spfs_dentry_to_lower(dentry);
	int ret = 1;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	spin_lock(&dentry->d_lock);
	if (IS_ROOT(dentry)) {
		spin_unlock(&dentry->d_lock);
		return 1;
	}

	if (d_unhashed(dentry)) {
		spin_unlock(&dentry->d_lock);
		return 0;
	}

	/*
	 * Lookup was done for regular file but now we are doing it for dir. or
	 * unknown types: renaming dir. to some type in lower.
	 */
	if (IS_OP_MODE_PM(sbi) && d_really_is_negative(dentry) &&
			(flags & (LOOKUP_DIRECTORY | LOOKUP_PARENT |
				  LOOKUP_RENAME_TARGET))) {
		spin_unlock(&dentry->d_lock);
		return 0;
	}
	spin_unlock(&dentry->d_lock);

	if (!lower_dentry) /* PM only... TODO: flag checking */
		return 1;

	if (lower_dentry->d_flags & DCACHE_OP_REVALIDATE)
		ret = lower_dentry->d_op->d_revalidate(lower_dentry, flags);

	spin_lock(&lower_dentry->d_lock);
	if (d_unhashed(lower_dentry))
		ret = 0;
	spin_unlock(&lower_dentry->d_lock);

	return ret;
}

static int spfs_d_init(struct dentry *dentry)
{
	struct spfs_dentry_info *info = D_INFO(dentry);

	info = kmem_cache_zalloc(spfs_dentry_info_cachep, GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	dentry->d_fsdata = info;

	return 0;
}

static void spfs_d_release(struct dentry *dentry)
{
	/* XXX: can be? */
	if (!dentry || !dentry->d_fsdata)
		return;

	/* NULL dentry and mnt will be ignored */
	path_put(spfs_dentry_to_lower_path(dentry));
	kmem_cache_free(spfs_dentry_info_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

/* done in link_path_walk() */
static int spfs_d_hash(const struct dentry *parent, struct qstr *name)
{
	name->hash = full_name_hash((void *) d_inode(parent)->i_ino,
			name->name, name->len);
	return 0;
}

#define commit_dealloc_dirent(sbi, dentry) do {			\
	pr_err("%s: %s %u", __func__, dentry->d_name.name,	\
			SPFS_DE_BLK(sbi, dentry));		\
	spfs_commit_block_deallocation(sbi,			\
			SPFS_DE_BLK(sbi, dentry), 1);		\
	SPFS_DE(dentry) = NULL;				\
} while (0)

const struct dentry_operations spfs_dops = {
	.d_hash		= spfs_d_hash,
	.d_revalidate	= spfs_d_revalidate,
	.d_init		= spfs_d_init,
	.d_release	= spfs_d_release,
};

int spfs_init_dentry_cache(void)
{
	spfs_dentry_info_cachep = kmem_cache_create("spfs_dentry_cache",
			sizeof(struct spfs_dentry_info), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);
	if (!spfs_dentry_info_cachep) {
		pr_err("spfs: failed to create dentry cache\n");
		return -ENOMEM;
	}

	return 0;
}

void spfs_destory_dentry_cache(void)
{
	kmem_cache_destroy(spfs_dentry_info_cachep);
}

