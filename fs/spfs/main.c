#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/backing-dev.h>

#include "spfs.h"
#include "profiler.h"
#include "namei.h"


enum {
	Opt_pmem,
	Opt_format,
	Opt_extension,
	Opt_extent_hash_lp,
	Opt_extent_hash_depth,
	Opt_consistency,
	Opt_mode,
#ifdef CONFIG_SPFS_1SEC_PROFILER
	Opt_prof_write_1s,
#elif defined(CONFIG_SPFS_BW_PROFILER)
	Opt_prof_write_bw,
	Opt_prof_fsync_bw,
#else
	Opt_migr_fsync_interval,
	Opt_migr_wrt_bytes_btw_fsync,
	Opt_migr_continual_cnt,
	Opt_migr_dir_boost,
#endif
	Opt_max_extent_bits,
	Opt_prealloc_kb,
	Opt_undo_opt_util,

	Opt_cceh_no_fast_path,

	Opt_no_gfi,
	
	Opt_demotion,
	Opt_demotion_hard_limit,
	Opt_demotion_sync_write,
	Opt_sf_alp_perc,
	Opt_migr_test_num_trigger,

	Opt_err,
};

static const match_table_t tokens = {
	{Opt_pmem,		"pmem=%s"},
	{Opt_format,		"format"},
	{Opt_extension,		"extension=%s"},
	{Opt_extent_hash_lp,	"ext_hlp=%s"},
	{Opt_extent_hash_depth,	"ext_hdepth=%d"},
	{Opt_consistency,	"consistency=%s"},
	{Opt_mode,		"mode=%s"},
#ifdef CONFIG_SPFS_1SEC_PROFILER
	{Opt_prof_write_1s, "prof_write_1s=%d"},
#elif defined(CONFIG_SPFS_BW_PROFILER)
	{Opt_prof_write_bw, "prof_write_bw=%d"},
	{Opt_prof_fsync_bw, "prof_fsync_bw=%d"},
#else
	{Opt_migr_fsync_interval,	"migr_fsync_interval=%d"},
	{Opt_migr_wrt_bytes_btw_fsync,	"migr_wrt_bytes_btw_fsync=%d"},
	{Opt_migr_continual_cnt,	"migr_continual_cnt=%d"},
	{Opt_migr_dir_boost,		"migr_dir_boost"},
#endif
	{Opt_max_extent_bits, "max_extent_bits=%d"},
	{Opt_prealloc_kb, "prealloc_size_kb=%d"},
	{Opt_undo_opt_util, "undo_opt_util=%d"},

	{Opt_cceh_no_fast_path,		"cceh_no_fast_path"},

	{Opt_no_gfi, "no_gfi"},
	
	{Opt_demotion, "demotion=%d"},
	{Opt_demotion_hard_limit, "demotion_hard_limit=%d"},
	{Opt_demotion_sync_write, "demotion_sync_write=%d"},
	{Opt_sf_alp_perc, "sf_alp_perc=%d"},
	{Opt_migr_test_num_trigger, "migr_test_num_trigger=%d"},
	
	{Opt_err, NULL},
};

void spfs_init_default_options(struct spfs_sb_info *sbi)
{
	struct spfs_mount_options *opts = S_OPTION(sbi);

	/* experimental parameters */
	S_OPTION(sbi)->extent_hash_lp = 8;
	S_OPTION(sbi)->extent_hash_depth = 8;

	S_OPTION(sbi)->consistency_mode = CONS_MODE_DATA;
	S_OPTION(sbi)->operation_mode = OP_MODE_TIERING;

	opts->migr_fsync_interval = 1000; // 1sec
	opts->migr_written_bytes_btw_fsync = 4 << 20; // 4MB
	opts->migr_continual_cnt = 30;
	opts->migr_dir_boost = false;
#ifdef CONFIG_SPFS_1SEC_PROFILER
	opts->prof_written_bytes_1sec = 0; /* disabled */
#elif defined(CONFIG_SPFS_BW_PROFILER)
	opts->prof_write_bandwidth = 0; /* disabled */
	opts->prof_fsync_bandwidth = 0; /* disabled */
#endif
	opts->max_extent_len = DEF_MAX_EXTENT_LEN;
	opts->pa_cluster_cnt = DEF_PA_CLUSTER_CNT;
	opts->undo_opt_util = DEF_UNDO_OPT_UTIL;

	opts->cceh_fast_path = true;

	opts->no_gfi = false;
	
	opts->demotion = true;
	opts->demotion_hard_limit = true;
	opts->demotion_sync_write = true;
	opts->sf_alp_perc = 5;
	opts->migr_test_num_trigger = 0;
}

int spfs_parse_options(struct spfs_sb_info *sbi, char *options,
		bool remount)
{
	struct spfs_mount_options *opts = S_OPTION(sbi);
	char *p, *s;
	int token, ret = 0, len;
	substring_t args[MAX_OPT_ARGS];

	spfs_init_default_options(sbi);

	if (!options)
		return -EINVAL;

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_pmem:
			if (remount) {
				spfs_msg(sbi->s_sb, KERN_ERR,
					"Can not change pmem on remount");
				return -EINVAL;
			}
			opts->bdev_path = match_strdup(&args[0]);
			break;
		case Opt_format:
			S_OPTION(sbi)->format = true;
			break;
		case Opt_extension:
			s = match_strdup(&args[0]);
			if (!s)
				return -ENOMEM;

			if (S_OPTION(sbi)->prof_ext_cnt >= PROF_EXT_CNT ||
					strlen(s) >= PROF_EXT_LEN) {
				spfs_err(sbi->s_sb, "%s: invalid extension "
						"length or number", __func__);
				return -EINVAL;
			}

			strcpy(S_OPTION(sbi)->prof_extensions[
					S_OPTION(sbi)->prof_ext_cnt], s);
			S_OPTION(sbi)->prof_ext_cnt++;

			kfree(s);
			break;
		case Opt_extent_hash_lp:
			s = match_strdup(&args[0]);
			len = strlen(s);

			if (s[len - 1] == '%') {
				int pct;

				s[len - 1] = '\0';
				ret = kstrtouint(s, 0, &pct);
				if (ret == 0)
					opts->extent_hash_lp = BPS * pct / 100;
			} else
				ret = kstrtouint(s, 0, &opts->extent_hash_lp);
			kfree(s);
			break;
		case Opt_extent_hash_depth:
			ret = match_int(&args[0], &opts->extent_hash_depth);
			break;
		case Opt_consistency:
			s = match_strdup(&args[0]);

			if (!strncmp(s, "meta", 4))
				opts->consistency_mode = CONS_MODE_META;
			else if (strncmp(s, "data", 4)) /* default is data */
				ret = -EINVAL;
			kfree(s);
			break;
		case Opt_mode:
			s = match_strdup(&args[0]);

			if (!strncmp(s, "pm", 2))
				opts->operation_mode = OP_MODE_PM;
			else if (!strncmp(s, "disk", 4))
				opts->operation_mode = OP_MODE_DISK;
			else
				ret = -EINVAL;
			break;
#ifdef CONFIG_SPFS_1SEC_PROFILER
		case Opt_prof_write_1s:
			ret = match_int(&args[0],
					&opts->prof_written_bytes_1sec);
			break;
#elif defined(CONFIG_SPFS_BW_PROFILER)
		case Opt_prof_write_bw:
			ret = match_int(&args[0], &opts->prof_write_bandwidth);
			break;
		case Opt_prof_fsync_bw:
			ret = match_int(&args[0], &opts->prof_fsync_bandwidth);
			break;
#else
		case Opt_migr_fsync_interval:
			ret = match_int(&args[0], &opts->migr_fsync_interval);
			break;
		case Opt_migr_wrt_bytes_btw_fsync:
			ret = match_int(&args[0], &len);
			if (!ret)
				opts->migr_written_bytes_btw_fsync = len;
			break;
		case Opt_migr_continual_cnt:
			ret = match_int(&args[0], &opts->migr_continual_cnt);
			break;
		case Opt_migr_dir_boost:
			opts->migr_dir_boost = true;
			break;
#endif
		case Opt_prealloc_kb:
			/* TODO: max. limit */
			ret = match_int(&args[0], &len);
			if (!ret)
				opts->pa_cluster_cnt = len >> (CLUSTER_SHIFT -
						10);
			break;
		case Opt_cceh_no_fast_path:
			opts->cceh_fast_path = false;
			break;
		case Opt_undo_opt_util:
			ret = match_int(&args[0], &opts->undo_opt_util);
			break;
		case Opt_max_extent_bits:
			ret = match_int(&args[0], &len);
			if (!ret && len < 32)
				opts->max_extent_len = 1 << len;
			else
				ret = -EINVAL;
			break;
		case Opt_no_gfi:
			opts->no_gfi = true;
			break;
		case Opt_demotion:
			ret = match_int(&args[0], &opts->demotion);
			if (!opts->demotion)
				opts->demotion_hard_limit = 0;
			break;
		case Opt_demotion_hard_limit:
			ret = match_int(&args[0], &opts->demotion_hard_limit);
			if (!opts->demotion)
				opts->demotion_hard_limit = 0;
			break;
		case Opt_demotion_sync_write:
			ret = match_int(&args[0], &opts->demotion_sync_write);
			break;
		case Opt_sf_alp_perc:
			ret = match_int(&args[0], &opts->sf_alp_perc);
			if (!opts->sf_alp_perc)
				opts->demotion_hard_limit = 0;
			break;
		case Opt_migr_test_num_trigger:
			ret = match_int(&args[0], &opts->migr_test_num_trigger);
			break;
		}

		if (ret) {
			spfs_err(sbi->s_sb, "%s: failed to parse option"
					" for %s", __func__, p);
			return ret;
		}
	}

	return 0;
}

static int spfs_test_super(struct super_block *s, void *data)
{
	return (void *) SB_INFO(s) == data;
}

static int spfs_set_super(struct super_block *s, void *data)
{
	s->s_fs_info = data;
	return 0;
}

static struct dentry *spfs_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	struct block_device *bdev;
	fmode_t mode = FMODE_READ | FMODE_EXCL;
	struct super_block *s;
	struct spfs_sb_info *sbi;
	int rc;

	sbi = kzalloc(sizeof(struct spfs_sb_info), GFP_KERNEL);
	if (!sbi) {
		spfs_msg(s, KERN_ERR, "failed to alloc sbi");
		return ERR_PTR(-ENOMEM);
	}

	rc = spfs_parse_options(sbi, data, false);
	if (rc) {
		spfs_msg(s, KERN_ERR, "failed to parse options");
		goto error_sbi;
	}

	bdev = blkdev_get_by_path(sbi->s_options.bdev_path, mode, fs_type);
	if (IS_ERR(bdev)) {
		spfs_msg(s, KERN_ERR, "failed to open %s: %d",
				sbi->s_options.bdev_path, PTR_ERR(bdev));
		rc = PTR_ERR(bdev);
		goto error_sbi;
	}

	if (!(flags & SB_RDONLY))
		mode |= FMODE_WRITE;

	/*
	 * once the super is inserted into the list by sget, s_umount
	 * will protect the lockfs code from trying to start a snapshot
	 * while we are mounting
	 */
	mutex_lock(&bdev->bd_fsfreeze_mutex);
	if (bdev->bd_fsfreeze_count > 0) {
		mutex_unlock(&bdev->bd_fsfreeze_mutex);
		rc = -EBUSY;
		goto error_bdev;
	}
	s = sget(fs_type, spfs_test_super, spfs_set_super,
			flags | SB_NOSEC, sbi);
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	if (IS_ERR(s))
		goto error_s;

	s->s_bdev = bdev;
	s->s_dev = s->s_bdev->bd_dev;
	s->s_bdi = bdi_get(s->s_bdev->bd_bdi); /* XXX: need? */

	if (s->s_root) {
		/*
		 * s_umount nests inside bd_mutex during
		 * __invalidate_device().  blkdev_put() acquires
		 * bd_mutex and can't be called under s_umount.  Drop
		 * s_umount temporarily.  This is safe as we're
		 * holding an active reference.
		 */
		up_write(&s->s_umount);
		blkdev_put(bdev, mode);
		down_write(&s->s_umount);
	} else {
		s->s_mode = mode;
		snprintf(s->s_id, sizeof(s->s_id), "%pg", bdev);
		sb_set_blocksize(s, block_size(bdev));

		rc = spfs_fill_super(s, dev_name, data, flags & SB_SILENT);
		if (rc) {
			deactivate_locked_super(s);
			goto error;
		}

		s->s_flags |= SB_ACTIVE;
		bdev->bd_super = s;
	}
	
	return dget(s->s_root);

error_s:
	rc = PTR_ERR(s);
error_bdev:
	blkdev_put(bdev, mode);
error_sbi:
	kfree(sbi);
error:
	return ERR_PTR(rc);
}

static void kill_spfs_super(struct super_block *sb)
{
	if (sb->s_root) {
		struct spfs_sb_info *sbi = SB_INFO(sb);

		if (IS_OP_MODE_TIERING(sbi) && S_OPTION(sbi)->demotion) {
			spfs_stop_usage_thread(sbi);
			spfs_stop_bm_thread(sbi);
			
			spfs_destroy_migr_lists(sbi);
		}
	}
	kill_block_super(sb);
}

static struct file_system_type spfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "spfs",
	.mount		= spfs_mount,
	.kill_sb	= kill_spfs_super,
};
MODULE_ALIAS_FS("spfs");

static int __init spfs_init_fs(void)
{
	int err;

	pr_err("spfs: module init\n");

	err = spfs_init_extent();
	if (err)
		goto out;

	err = spfs_init_inode_cache();
	if (err)
		goto out_extent;

	err = spfs_init_dentry_cache();
	if (err)
		goto out_free_icache;

	err = spfs_init_file_cache();
	if (err)
		goto out_free_dcache;

	err = spfs_init_sysfs();
	if (err)
		goto out_free_fcache;
#ifdef SPFS_SMALL_BLOCK
	err = spfs_init_cluster_cache();
	if (err)
		goto out_sysfs;
#endif
	err = register_filesystem(&spfs_fs_type);
	if (err)
		goto out_free_cluster;

	err = spfs_init_ri_cache();
	if (err)
		goto out_unregister_fs;

	return 0;

out_unregister_fs:
	unregister_filesystem(&spfs_fs_type);
out_free_cluster:
#ifdef SPFS_SMALL_BLOCK
	spfs_destroy_cluster_cache();
out_sysfs:
#endif
	spfs_exit_sysfs();
out_free_fcache:
	spfs_destroy_file_cache();
out_free_dcache:
	spfs_destory_dentry_cache();
out_free_icache:
	spfs_destory_inode_cache();
out_extent:
	spfs_exit_extent();
out:
	return err;
}

static void __exit spfs_exit_fs(void)
{
	pr_err("spfs: module exit\n");

	spfs_destory_inode_cache();
	spfs_destory_dentry_cache();
	spfs_destroy_file_cache();
#ifdef SPFS_SMALL_BLOCK
	spfs_destroy_cluster_cache();
#endif
	spfs_exit_sysfs();
	spfs_exit_extent();

	unregister_filesystem(&spfs_fs_type);
	spfs_exit_ri_cache();
}

MODULE_AUTHOR("Hobin Woo SKKU DICL, Samsung Electronics");
MODULE_DESCRIPTION("Absorb File System");
MODULE_LICENSE("GPL");

module_init(spfs_init_fs)
module_exit(spfs_exit_fs)
