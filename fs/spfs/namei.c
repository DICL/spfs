#include <linux/namei.h>
#include <linux/mount.h>

#include "spfs.h"
#include "namei.h"
#include "profiler.h"
#include "stats.h"
#include "inode.h"

int spfs_del_dir(struct dentry *dentry)
{
	struct spfs_sb_info *sbi = SB_INFO(dentry->d_sb);
	int ret;

	ret = spfs_namei_cceh_delete(sbi, d_inode(dentry->d_parent), dentry,
			true);
	if (ret)
		BUG();
	spfs_free_blocks(sbi, blk_idx(sbi, SPFS_DE(dentry)), 1);
	clear_inode_flag(d_inode(dentry), INODE_HAS_PM_CHILDREN);
	spfs_commit_block_deallocation(sbi, blk_idx(sbi, SPFS_DE(dentry)), 1);
	SPFS_DE(dentry) = NULL;

	return 0;
}

/* returns # of children of dir. */
int spfs_del_nondir(struct dentry *dentry)
{
	struct inode *dir = d_inode(dentry->d_parent);
	struct spfs_sb_info *sbi = SB_INFO(dir->i_sb);

	BUG_ON(!is_inode_flag_set(dir, INODE_HAS_PM_CHILDREN));
	BUG_ON(spfs_namei_cceh_delete(sbi, dir, dentry, false));

	spfs_del_dirent_list(sbi, dentry);

	spfs_free_blocks(sbi, blk_idx(sbi, SPFS_DE(dentry)), 1);
	spfs_commit_block_deallocation(sbi, blk_idx(sbi, SPFS_DE(dentry)), 1);

	return spfs_dirent_children_count(dentry->d_parent);
}

int __spfs_insert_dir_entries(struct dentry *dentry, spfs_block_t dirent_blk,
		struct dentry *parent, spfs_block_t pdirent_blk)
{
	struct spfs_sb_info *sbi = SB_INFO(dentry->d_sb);
	void *retp;

	if (parent) {
		retp = spfs_namei_cceh_insert(sbi, parent, pdirent_blk, DE_DIR);
		if (IS_ERR(retp)) {
			spfs_debug_err(parent->d_sb,
					"can't insert parent dir. entry of %s",
					dentry->d_name.name);
			return PTR_ERR(retp);
		}
	}

	retp = spfs_namei_cceh_insert(sbi, dentry, dirent_blk, 0);
	if (IS_ERR(retp)) {
		spfs_debug_err(dentry->d_sb, "can't insert dir. entry of %s",
				dentry->d_name.name);
		goto error;
	}

	return 0;
error:
	if (parent) {
		if (spfs_namei_cceh_delete(sbi, d_inode(parent), parent, true))
			spfs_err(dentry->d_sb, "%s: can't delete hash for dir.",
					__func__);
	}

	return PTR_ERR(retp);
}

int spfs_insert_dir_entries(struct dentry *dentry, struct dentry *parent)
{
	struct spfs_sb_info *sbi = SB_INFO(dentry->d_sb);
	return __spfs_insert_dir_entries(dentry, SPFS_DE_BLK(sbi, dentry),
			parent, parent ? SPFS_DE_BLK(sbi, parent) : 0);
}

int spfs_interpose_bp(struct dentry *lower_dentry, struct dentry *dentry,
		struct super_block *sb)
{
	struct inode *inode = spfs_iget_bp(d_inode(lower_dentry), sb);

	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);

	return 0;
}

static struct dentry *spfs_lookup_interpose_bp(struct inode *dir,
		struct dentry *dentry, struct dentry *lower_dentry)
{
	struct spfs_sb_info *sbi = SB_INFO(dentry->d_sb);
	struct path *path = &D_INFO(dentry->d_parent)->lower_path;
	struct inode *inode, *lower_inode;

	fsstack_copy_attr_atime(d_inode(dentry->d_parent),
			d_inode(path->dentry));
	BUG_ON(!d_count(lower_dentry));

	D_INFO(dentry)->lower_path.mnt = mntget(path->mnt);
	D_INFO(dentry)->lower_path.dentry = lower_dentry;

	lower_inode = READ_ONCE(lower_dentry->d_inode);
	if (!lower_inode) {
		/* We want to add because we couldn't find in lower */
		d_add(dentry, NULL);
		return NULL;
	}

	inode = __spfs_iget_bp(lower_inode, dentry->d_sb);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (S_ISDIR(inode->i_mode)) {
		if (spfs_namei_cceh_get(sbi, dentry, true))
			set_inode_flag(inode, INODE_HAS_PM_CHILDREN);

		spfs_interest_dir(dentry, inode);
#ifdef CONFIG_SPFS_READDIR_RADIX_TREE
		D_INFO(dentry)->children =
			radix_tree_lookup(&sbi->s_readdir_index, inode->i_ino);
#endif
	}

	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);
	return d_splice_alias(inode, dentry);
}

/* just attach lower file system objects to upper objects */
static struct dentry *spfs_lookup_interpose_tiered(struct dentry *dentry,
		struct dentry *lower_dentry)
{
	struct path *path = spfs_dentry_to_lower_path(dentry->d_parent);
	struct inode *lower_inode = d_inode(lower_dentry);
	struct inode *inode = d_inode(dentry);

	D_INFO(dentry)->lower_path.mnt = mntget(path->mnt);
	D_INFO(dentry)->lower_path.dentry = lower_dentry;

	if (!igrab(lower_inode))
		return ERR_PTR(-ESTALE);

	spfs_set_inode_lower(inode, lower_inode);

	return NULL;
}

/* lookup in PM */
static struct dentry *
spfs_lookup_internal(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct spfs_sb_info *sbi = SB_INFO(dir->i_sb);
	struct spfs_dir_entry *de;
	struct inode *inode = NULL;
	spfs_block_t inode_blknr;

	/* lookup dir. entry and get inode location */
	de = spfs_namei_cceh_get(sbi, dentry, false);
	/* XXX: are we keeping negative dentry? */
	if (!de)
		return ERR_PTR(-ENOENT);

	inode_blknr = de->de_inode_bno;

	spfs_debug_level(dir->i_sb, 2, "%s: inode %llu for %s", __func__,
			inode_blknr, dentry->d_name.name);

	inode = spfs_iget(dir->i_sb, inode_blknr, flags);
	if (IS_ERR(inode))
		return (struct dentry *) inode;

	return d_splice_alias(inode, dentry);
}

struct dentry *spfs_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct spfs_sb_info *sbi = SB_INFO(dir->i_sb);
	struct dentry *lower_dentry;
	const char *name = dentry->d_name.name;
	size_t len = dentry->d_name.len;
	struct dentry *res;
	bool want_dir = flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY);
	bool want_reg = flags & LOOKUP_CREATE && !(flags & LOOKUP_DIRECTORY);
	bool rename_target = flags & LOOKUP_RENAME_TARGET;

	if (dentry->d_name.len > MAX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	/*
	 *                  | /a/b/c/ | /a/b/c | mkdir /a/b/c |
	 * ----------------------------------------------------
	 * LOOKUP_PARENT    | a, b    | a, b   | -            |
	 * LOOKUP_DIRECTORY | c/      | -      | -            |
	 *
	 * We have modified filename_create() to pass LOOKUP_DIRECTORY
	 * in case of mkdir.
	 */
	if (IS_OP_MODE_DISK(sbi) || want_dir) {
		spfs_lookup_debug(dir->i_sb, "bypass %s/%s/%s for flag 0x%x",
				dentry->d_parent->d_parent->d_name.name,
				dentry->d_parent->d_name.name,
				dentry->d_name.name,
				flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY));
		goto lookup_lower;
	}

	/* OP_MODE_PM or TIERING and finding a regular file */
	res = spfs_lookup_internal(dir, dentry, flags);
	if (!IS_ERR(res) && !IS_TIERED_INODE(d_inode(dentry))) {
		set_inode_flag(d_inode(dentry), INODE_PM);
		goto out; // found in PM and inode is dedicated to PM
	}

	/*
	 * If we are in PM mode, disk lookup for LOOKUP_CREATE without
	 * LOOKUP_DIRECTORY, creation of regular file, can be excluded.
	 *
	 * TODO: already existing files should operate their own mode.
	 */
	if (!rename_target && IS_OP_MODE_PM(sbi) && want_reg) {
		spfs_lookup_debug(dir->i_sb, "skip lower lookup for regular "
				"file creation: %s/%s/%s(0x%px) for 0x%x",
				dentry->d_parent->d_parent->d_name.name,
				dentry->d_parent->d_name.name,
				dentry->d_name.name, dentry, flags);
		res = NULL;
		d_add(dentry, NULL);
		goto out;
	}
lookup_lower:
	/* fallback to bypass and tiered */
	lower_dentry = lookup_one_len_unlocked(name,
			spfs_dentry_to_lower(dentry->d_parent), len);
	if (IS_ERR(lower_dentry)) {
		res = ERR_CAST(lower_dentry);
		goto out;
	}

	/* tiered interpose */
	if (d_really_is_positive(dentry) && IS_TIERED_INODE(d_inode(dentry)))
		res = spfs_lookup_interpose_tiered(dentry, lower_dentry);
	else /* bypass interpose */
		res = spfs_lookup_interpose_bp(dir, dentry, lower_dentry);
out:
	return res;
}

int spfs_namei_init(struct spfs_sb_info *sbi)
{
	struct spfs_namei_info *info;

	info = kmalloc(sizeof(struct spfs_namei_info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	INIT_RADIX_TREE(&info->inode_radix, GFP_NOFS);
	spin_lock_init(&info->inode_radix_lock);

	sbi->s_namei_info = info;

	spfs_init_readdir_index(sbi);

	return 0;
}

int spfs_namei_exit(struct spfs_sb_info *sbi)
{
	spfs_exit_readdir_index(sbi);
	kfree(sbi->s_namei_info);
	return 0;
}
