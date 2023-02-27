#include <linux/iversion.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include <uapi/linux/mount.h>

#include "spfs.h"
#include "namei.h"
#include "extent.h"
#include "inode.h"
#include "profiler.h"
#include "stats.h"

extern const struct dentry_operations spfs_dops;
extern const struct xattr_handler *spfs_xattr_handlers[];

extern int spfs_parse_options(struct spfs_sb_info *, char *, bool);
extern int spfs_truncate(struct inode *, bool);


static struct kmem_cache *spfs_inode_info_cachep;


static struct dentry *spfs_d_make_root(struct spfs_sb_info *sbi,
		struct inode *inode, struct path *lower_path)
{
	struct dentry *dentry;
	struct spfs_dir_entry *de;

	dentry = d_make_root(inode);
	if (!dentry)
		return NULL;

	spfs_set_dentry_lower_path(dentry, lower_path);

	de = spfs_namei_cceh_get(sbi, dentry, true);
	if (de) {
		BUG_ON(!de->de_private);

		spfs_debug(sbi->s_sb, "root has PM children");
		set_inode_flag(inode, INODE_HAS_PM_CHILDREN);
	}

	spfs_interest_dir(dentry, inode);

	return dentry;
}

int spfs_fill_super(struct super_block *sb, const char *dev_name,
		void *data, int silent)
{
	struct spfs_sb_info *sbi = SB_INFO(sb);
	struct inode *inode;
	struct path lower_path;
	int rc;
	bool formatted = false;
	int i;

	spfs_msg(sb, KERN_INFO, "draft");

	sbi->s_dax_device = spfs_get_dax_device(sb);
	if (IS_ERR(sbi->s_dax_device))
		return PTR_ERR(sbi->s_dax_device);

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize_bits = BLK_SHIFT;
	sb->s_op = &spfs_sops;
	sb->s_xattr = spfs_xattr_handlers;
	sb->s_d_op = &spfs_dops;
	sb->s_time_gran = 1;

	rc = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &lower_path);
	if (rc) {
		spfs_msg(sb, KERN_ERR, "failed to lookup %s", dev_name);
		goto out_put_dax;
	}

	sbi->s_sb = sb;
	sbi->s_psb = (struct spfs_super_block *)
		spfs_map_dax_device(sbi, LONG_MAX);
	if (IS_ERR(sbi->s_psb)) {
		rc = PTR_ERR(sbi->s_psb);
		spfs_msg(sb, KERN_ERR, "failed to map dax device: %d", rc);
		goto out_path_put;
	}
again:
	sb->s_magic = le32_to_cpu(sbi->s_psb->s_magic);
	sb->s_blocksize = sbi->s_psb->s_block_size;
	if (sb->s_magic != SPFS_SUPER_MAGIC || S_OPTION(sbi)->format) {
		/* TODO: check backup sb */
		if (!formatted) {
			rc = spfs_format(sbi);
			if (rc)
				goto out_path_put;
			formatted = true;
			S_OPTION(sbi)->format = false;
			goto again;
		}

		spfs_msg(sb, KERN_ERR, "can not find spfs");
		goto out_path_put;
	}

	sb->s_flags = le32_to_cpu(sbi->s_psb->s_flags);
	sb->s_stack_depth = lower_path.dentry->d_sb->s_stack_depth + 1;
	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		spfs_msg(sb, KERN_ERR,
				"maximum fs stacking depth exceeded");
		rc = -EINVAL;
		goto out_path_put;
	}

	atomic_inc(&lower_path.dentry->d_sb->s_active);
	SB_INFO(sb)->s_lower_sb = lower_path.dentry->d_sb;

	inode = spfs_iget_bp(d_inode(lower_path.dentry), sb);
	if (IS_ERR(inode)) {
		spfs_msg(sb, KERN_ERR, "can't get root inode");
		rc = PTR_ERR(inode);
		goto out;
	}

	rc = spfs_namei_init(sbi);
	if (rc) {
		spfs_msg(sb, KERN_ERR, "can't init namei info");
		goto out;
	}

	sbi->s_free_info = kzalloc(sizeof(struct spfs_free_info), GFP_KERNEL);
	if (!FREE_INFO(sbi)) {
		spfs_err(sb, "%s: ENOMEM for free info", __func__);
		goto out;
	}

	rc = spfs_cceh_init(sbi);
	if (rc) {
		spfs_msg(sb, KERN_ERR, "can't init CCEH");
		goto out;
	}

	rc = spfs_init_allocator(sbi);
	if (rc) {
		spfs_msg(sb, KERN_ERR, "can't init block allocator");
		goto out;
	}

	rc = spfs_register_sysfs(sb);
	if (rc) {
		spfs_err(sb, "can't register sysfs");
		goto out;
	}

	for (i = 0; i < INODE_LIST_COUNT; i++)
		spin_lock_init(&sbi->s_inode_list_lock[i]);

	if (IS_OP_MODE_TIERING(sbi) && S_OPTION(sbi)->demotion) {
		rc = spfs_alloc_migr_lists(sbi);
		if (rc) {
			spfs_msg(sb, KERN_ERR, "can't alloc inode migr list");
			goto out;
		}

		rc = spfs_start_usage_thread(sbi);
		if (rc)
			goto out;

		rc = spfs_start_bm_thread(sbi);
		if (rc)
			goto out;
		/* 
		 * alpha 0 is just update sync factor as SF_HIGH 
		 * => no hard limit demotion 
		 */
		if (S_OPTION(sbi)->sf_alp_perc)
			sbi->sf_rd_thld = spfs_calc_sf_rd_thld(sbi);
	}

	/* XXX: should rehash? */
	sb->s_root = spfs_d_make_root(sbi, inode, &lower_path);
	if (!sb->s_root) {
		spfs_msg(sb, KERN_ERR, "can't make root dentry");
		rc = -ENOMEM;
		goto out;
	}

	return 0;
out:
	atomic_dec(&lower_path.dentry->d_sb->s_active);
out_path_put:
	path_put(&lower_path);
out_put_dax:
	fs_put_dax(sbi->s_dax_device);
	return rc;
}

static void spfs_put_super(struct super_block *sb)
{
	struct spfs_sb_info *sbi = SB_INFO(sb);
	struct super_block *lower_sb;

	if (!sbi)
		return;

	flush_cache_all();

	spfs_unregister_sysfs(sb);
	lower_sb = sbi->s_lower_sb;
	sbi->s_lower_sb = NULL;
	atomic_dec(&lower_sb->s_active);

	kfree(sbi->s_options.bdev_path);

	spfs_exit_allocator(sbi);
	spfs_cceh_exit(sbi);
	spfs_namei_exit(sbi);

	fs_put_dax(sbi->s_dax_device);

	kfree(sbi);
	sb->s_fs_info = NULL;
}

static void inode_info_init_once(void *p)
{
	struct spfs_inode_info *info = p;
	inode_init_once(&info->vfs_inode);
}

int spfs_init_inode_cache(void)
{
	spfs_inode_info_cachep = kmem_cache_create("spfs_inode_cache",
			sizeof(struct spfs_inode_info), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD,
			inode_info_init_once);
	if (!spfs_inode_info_cachep) {
		pr_err("spfs: failed to create inode cache\n");
		return -ENOMEM;
	}

	return 0;
}

void spfs_destory_inode_cache(void)
{
	kmem_cache_destroy(spfs_inode_info_cachep);
}

void __spfs_msg(struct super_block *sb,
		const char *level, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk("%sspfs (%s): %pV\n", level, sb->s_id, &vaf);
	va_end(args);
}

static struct inode *spfs_alloc_inode(struct super_block *sb)
{
	struct spfs_inode_info *info;

	info = kmem_cache_alloc(spfs_inode_info_cachep, GFP_NOFS);
	if (!info)
		goto out;

	inode_set_iversion(&info->vfs_inode, 1);
	info->lower_inode = NULL;
	info->raw_inode = NULL;

	info->i_flags = 0;

	spin_lock_init(&info->i_raw_lock);

	info->i_extent_tree = RB_ROOT;
	rwlock_init(&info->i_extent_lock);

	info->i_profiler = NULL;
	if (IS_OP_MODE_TIERING(SB_INFO(sb))) {
		/* TODO: use own slub */
		info->i_profiler =
			kzalloc(sizeof(struct spfs_profiler), GFP_ATOMIC);
		if (!I_PROFILER(&info->vfs_inode)) {
			kmem_cache_free(spfs_inode_info_cachep, info);
			info = NULL;
			goto out;
		}
		spin_lock_init(&I_PROFILER(&info->vfs_inode)->lock);
#ifdef CONFIG_SPFS_BW_PROFILER
		I_PROFILER(&info->vfs_inode)->created_when = jiffies;
#endif
	}

	info->i_file_doing_rw = NULL;

	info->migr_info = NULL;
	spin_lock_init(&info->migr_lock);
	atomic_set(&info->sf_rd_cnt, 0);
	atomic_set(&info->wq_doing, 0);
out:
	return info ? &info->vfs_inode : NULL;
}

static void spfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(spfs_inode_info_cachep, I_INFO(inode));
}

/*
 * iput_final -> drop_inode
 *               evict(I_FREEING) -> destroy(I_FREEING, I_CLEAR) -> free
 */

/* when should we free inode information???? */
static void spfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, spfs_i_callback);
}

static int spfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	//BUG();
	return 0;
}

static void spfs_evict_inode(struct inode *inode)
{
	struct spfs_inode_info *info = I_INFO(inode);
	bool tiered = IS_TIERED_INODE(inode);

	/* BP inode: pm inode may be suspended => may have lower_inode */
	if (info->lower_inode && !tiered) {
		BUG_ON(info->raw_inode); 
		kfree(info->i_profiler); // TODO: sync on where??? xattr?
		info->i_profiler = NULL;
		clear_inode(inode);
		iput(spfs_inode_to_lower(inode));
		return;
	}

	/* alive inode... we don't have page cache */
	if (inode->i_nlink || is_bad_inode(inode))
		goto no_delete;

	/* deleted inode */
	inode->i_size = 0;
	if (inode_get_bytes(inode))
		spfs_truncate(inode, false);

	/* Free inode block.
	 * When deleting file, only hash key and value is deleted.
	 * Name bucket is deleted at final dput and inode is deleted at here.
	 */
	SPFS_BUG_ON(atomic_read(&inode->i_count) > 1);
	SPFS_BUG_ON(inode->i_nlink);

	spfs_free_blocks(SB_INFO(inode->i_sb), inode->i_ino, 1);
	spfs_del_inode_list(inode);

	spfs_commit_block_deallocation(SB_INFO(inode->i_sb), inode->i_ino, 1);
    
no_delete:
	spfs_truncate_extent_info(inode, 0);
	clear_inode(inode);
	if (tiered)
		iput(spfs_inode_to_lower(inode));
}

/* Should we bypass to lower? */
static int spfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct spfs_sb_info *sbi = SB_INFO(sb);
	struct spfs_super_block *psb = sbi->s_psb;

	buf->f_type = SPFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = C2B(psb->s_clusters_count);
	buf->f_bfree = atomic64_read(&FREE_INFO(sbi)->free_blocks_count);
	buf->f_bavail = buf->f_bfree; // now, no reservation
	buf->f_files = psb->s_inodes_count;
	buf->f_ffree = buf->f_bfree; // XXX:
	buf->f_namelen = MAX_NAME_LEN;
	/* TODO: uuid */

	return 0;
}

/* XXX: Should we save and restore old options on error? */
static int spfs_remount(struct super_block *sb, int *flags, char *data)
{
	if ((*flags & ~(MS_RDONLY | MS_SILENT | MS_REMOUNT)) != 0)
		return -EINVAL;

	if (spfs_parse_options(SB_INFO(sb), data, true))
		return -EINVAL;

	return 0;
}

static int spfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct spfs_sb_info *sbi = SB_INFO(root->d_sb);
	struct spfs_mount_options *opts = S_OPTION(sbi);
	int i;

	seq_printf(seq, ",pmem=%s", S_OPTION(sbi)->bdev_path);

	for (i = 0; i < S_OPTION(sbi)->prof_ext_cnt; i++)
		seq_printf(seq, ",extension=%s",
				S_OPTION(sbi)->prof_extensions[i]);

	if (IS_OP_MODE_TIERING(sbi)) {
		seq_printf(seq, ",mode=tiering");
#ifdef CONFIG_SPFS_1SEC_PROFILER
		seq_printf(seq, ",prof_write_1s=%d",
				opts->prof_written_bytes_1sec);
#elif defined(CONFIG_SPFS_BW_PROFILER)
		seq_printf(seq, ",prof_write_bw=%d"
				",prof_fsync_bw=%d",
				opts->prof_write_bandwidth,
				opts->prof_fsync_bandwidth);
#else
		seq_printf(seq, ",migr_fsync_interval=%d"
				",migr_wrt_bytes_btw_fsync=%d"
				",migr_continual_cnt=%d",
				opts->migr_fsync_interval,
				opts->migr_written_bytes_btw_fsync,
				opts->migr_continual_cnt);
		if (opts->migr_dir_boost)
			seq_printf(seq, ",migr_dir_boost");
#endif
		seq_printf(seq, ",demotion=%d,demotion_hard_limit=%d" 
				",demotion_sync_write=%d", 
				opts->demotion, opts->demotion_hard_limit, 
				opts->demotion_sync_write);
		seq_printf(seq, ",sf_alp_perc=%d", opts->sf_alp_perc);
		seq_printf(seq, ",migr_test_num_trigger=%d", 
				opts->migr_test_num_trigger);
	} else if (IS_OP_MODE_PM(sbi))
		seq_printf(seq, ",mode=pm");
	else
		seq_printf(seq, ",mode=disk");

	if (!opts->cceh_fast_path)
		seq_printf(seq, ",cceh_no_fast_path");

	if (opts->pa_cluster_cnt != DEF_PA_CLUSTER_CNT)
		seq_printf(seq, ",prealloc_size_kb=%d",
				opts->pa_cluster_cnt << (CLUSTER_SHIFT - 10));

	if (opts->undo_opt_util != DEF_UNDO_OPT_UTIL)
		seq_printf(seq, ",undo_opt_util=%d", opts->undo_opt_util);

	if (opts->max_extent_len != DEF_MAX_EXTENT_LEN)
		seq_printf(seq, ",max_extent_bits=%d",
				fls(opts->max_extent_len) - 1);

	if (opts->no_gfi)
		seq_printf(seq, ",no_gfi");

	seq_printf(seq, ",consistency=%s", opts->consistency_mode ==
			CONS_MODE_DATA ? "data" : "meta");

	return 0;
}

static void spfs_dirty_inode(struct inode *inode, int flags)
{
	/* TODO: atime */
}

/* generic: destroy, drop */
const struct super_operations spfs_sops = {
	.alloc_inode	= spfs_alloc_inode,
	.destroy_inode	= spfs_destroy_inode,
	.dirty_inode	= spfs_dirty_inode,
	.write_inode	= spfs_write_inode,
	.evict_inode	= spfs_evict_inode,
	.put_super	= spfs_put_super,
	.statfs		= spfs_statfs,
	.remount_fs	= spfs_remount,
	.show_options	= spfs_show_options,
};
