#include "spfs.h"
#include "inode.h"
#include "calloc.h"
#include "namei.h"
#include "extent.h"
#include "cceh_extent.h"
#include "profiler.h"

#include <linux/uaccess.h>
#include <linux/mount.h>

//#define MIGR_DEBUG
#ifdef MIGR_DEBUG
#define spfs_migr_debug(fmt, ...)	\
	pr_err("%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define spfs_migr_debug(fmt, ...)	do {} while (0)
#endif

//#define DOWN_MIGR_DEBUG
#ifdef DOWN_MIGR_DEBUG
#define spfs_d_migr_debug(fmt, ...)	\
	pr_err("%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define spfs_d_migr_debug(fmt, ...)	do {} while (0)
#endif

#define MIGR_FORCE_MODE			(FMODE_READ | FMODE_CAN_READ)

#define SPFS_BASIC_DOWNWARD_MIGR

struct spfs_sb_info *spfs_sbi;
struct percpu_counter old_prof_boosted;

extern int spfs_truncate(struct inode *inode, bool);
extern int spfs_create_bp(struct inode *dir, struct dentry *dentry,
		umode_t mode, bool excl);

ssize_t spfs_migr_fill_extent(struct inode *inode, void *buf, size_t count,
		loff_t *pos)
{
	struct file *lower_file = I_INFO(inode)->i_file_doing_rw;
	ssize_t nread;
	fmode_t restore_fmode = 0;

	spfs_migr_debug("inode %lu: fill data to extent lcn=%llu count=%lu",
			inode->i_ino, BYTES2C(*pos), count);

	if (!(lower_file->f_mode & FMODE_READ)) {
		lower_file->f_mode |= FMODE_READ;
		restore_fmode |= FMODE_READ;
	}

	if (!(lower_file->f_mode & FMODE_CAN_READ)) {
		lower_file->f_mode |= FMODE_CAN_READ;
		restore_fmode |= FMODE_CAN_READ;
	}

	nread = kernel_read(lower_file, buf, count, pos);
	if (nread == 0) {
		memset(buf, 0, count);
		nread += count;
	} else if (nread < 0)
		spfs_debug_err(inode->i_sb, "fail to fill migrated extent: %d",
				nread);

	if (restore_fmode)
		lower_file->f_mode &= ~restore_fmode;

	stats_prof_inc_migration_read_on_boosted(inode);
	return nread;
}

int spfs_get_extent_map_lower(struct inode *inode,
		struct fiemap_extent_info *fieinfo)
{
	struct inode *lower_inode = spfs_inode_to_lower(inode);
	int ret;
	mm_segment_t old_fs;

	/* The lower inode is grabbed by inode being lookup */
	if (lower_inode->i_sb->s_magic == EXT4_SUPER_MAGIC)
		inode_lock(lower_inode);

	fieinfo->fi_flags = FIEMAP_FLAG_SYNC;
	fieinfo->fi_extents_mapped = 0;
	fieinfo->fi_extents_max = 0;
	fieinfo->fi_extents_start = NULL;

	/* get the number of extents in lower inode */
	ret = lower_inode->i_op->fiemap(lower_inode, fieinfo, 0,
			FIEMAP_MAX_OFFSET);
	if (ret) {
		spfs_debug_err(inode->i_sb, "failed to fiemap: %d", ret);
		BUG();
	}

	fieinfo->fi_extents_max = fieinfo->fi_extents_mapped;
	fieinfo->fi_extents_mapped = 0;
	fieinfo->fi_extents_start = kvmalloc(sizeof(struct fiemap_extent) *
			fieinfo->fi_extents_max, GFP_KERNEL);
	BUG_ON(!fieinfo->fi_extents_start);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	/* delegate any consistency checks to the lower file system */
	ret = lower_inode->i_op->fiemap(lower_inode, fieinfo, 0,
			FIEMAP_MAX_OFFSET);
	set_fs(old_fs);
	if (ret) {
		spfs_debug_err(inode->i_sb, "failed to fiemap: %d", ret);
		BUG();
	}

	if (lower_inode->i_sb->s_magic == EXT4_SUPER_MAGIC)
		inode_unlock(lower_inode);

	return 0;


}

/* we should check fiemap support on preparation time */
int spfs_migrate_extent_map(struct inode *inode)
{
	struct fiemap_extent_info fieinfo;
	int i, ret;
	spfs_cluster_t pelcn = 0xDEADC0DE;

	ret = spfs_get_extent_map_lower(inode, &fieinfo);
	BUG_ON(ret);
	
	/* TODO: 로깅 */
	for (i = 0; i < fieinfo.fi_extents_mapped; i++) {
		struct fiemap_extent *fe = &fieinfo.fi_extents_start[i];
		unsigned int len = 0;
		spfs_cluster_t lcn = BYTES2C(fe->fe_logical);

		do {
			struct spfs_map_request map;
			cceh_es_t *es;

			/*
			 * The goal of this is to know the extent mapping of
			 * lower, so we don't allocate physical clusters right
			 * now. Read is served from lower, and write allocates
			 * clusters in an on-demand manner.
			 */
			map.pcn = 0;
			map.lcn = lcn + len;
			map.len = __spfs_carve_extent_len(map.lcn,
					BYTES2C(fe->fe_length) - len);
			map.pa_len = 0;

			ijnl_write(inode, WR_NEW, map.lcn, 0, map.len);

			/* link extent chain and update EOF */
			es = spfs_insert_extent(inode, &map, pelcn);
			BUG_ON(es->extent.lcn != map.lcn ||
					es->extent.len != map.len);

			spfs_migr_debug("inode %lu: (%u, %u) es=0x%px",
					inode->i_ino, map.lcn, map.len, es);

			I_EOF(inode) = map_lcn_end(&map);
			clwb_sfence(&I_EOF(inode), sizeof(u32));

			ijournal_commit_n(inode, 2);

			len += map.len;
			pelcn = map.lcn;
		} while (len < BYTES2C(fe->fe_length));

		spfs_migr_debug("inode %lu: %llu %llu %llu %u", inode->i_ino,
				fieinfo.fi_extents_start[i].fe_logical,
				fieinfo.fi_extents_start[i].fe_physical,
				fieinfo.fi_extents_start[i].fe_length,
				fieinfo.fi_extents_start[i].fe_flags);
	}

	kvfree(fieinfo.fi_extents_start);

	return 0;
}

/* assume that dentry is hold by someone */
int spfs_prepare_upward_migration(struct dentry *dentry)
{
	struct spfs_sb_info *sbi = SB_INFO(dentry->d_sb);
	struct dentry *parent = lock_parent(dentry); // lock parent
	struct inode *dir = d_inode(parent);
	struct inode *inode = d_inode(dentry);
	int ret;
	struct spfs_dir_entry *de, *dir_de = NULL;
	struct spfs_inode *spfs_inode;

	DECLARE_PREFETCH(pf, 3, is_inode_flag_set(dir, INODE_HAS_PM_CHILDREN) ?
			2 : 3);
	
	inode_lock(d_inode(dentry));

	spfs_migr_debug("%s(%lu) ++", dentry->d_name.name, inode->i_ino);

	PREFETCH_ALLOC_BLOCKS(sbi, pf, return ret);

	/* Initialize the on-PM inode */
	spfs_inode = __spfs_init_new_inode(inode, pf[0]);
	spfs_inode->i_size = inode->i_size;
	__set_bit(INODE_TIERED, (unsigned long *) &spfs_inode->i_flags);
	__set_bit(INODE_NEED_RECOVERY, (unsigned long *) &spfs_inode->i_flags);

	/* prepare dir. entries to be inserted in hash */
	if (!is_inode_flag_set(dir, INODE_HAS_PM_CHILDREN)) {
		struct dentry *pparent = dget_parent(parent);

		dir_de = init_dir_entry(D_INFO(parent), pf[2], d_inode(pparent),
				parent, (spfs_block_t) -1, DE_DIR);
		dput(pparent);
		set_inode_flag(dir, INODE_HAS_PM_CHILDREN);
	}
	de = init_dir_entry(D_INFO(dentry), pf[1], dir, dentry, pf[0], 0);

	spfs_persist(spfs_inode, sizeof(struct spfs_inode));
	spfs_persist(de, BLK_SIZE);
	if (dir_de)
		spfs_persist(dir_de, BLK_SIZE);
	SPFS_SFENCE();

	if (dir_de)
		__ijournal_log_dir_entry(spfs_inode, CR_DIR_HINS,
				blk_idx(sbi, dir_de), parent->d_name.hash);
	__ijournal_log_dir_entry(spfs_inode, CR_REG_HINS, blk_idx(sbi, de),
			dentry->d_name.hash);

	/* rehash inode */
	remove_inode_hash(inode);
	inode->i_ino = pf[0];
	__insert_inode_hash(inode, pf[0]); /* here? */

	I_INFO(inode)->raw_inode = spfs_inode;
	spfs_add_inode_list(inode);
 
	PREFETCH_COMMIT_ALLOC_BLOCKS(sbi, pf);

	ret = spfs_insert_dir_entries(dentry, dir_de ? parent : NULL);
	if (ret)
		goto error;

	spfs_add_dirent_list(sbi, dentry);

	spfs_inc_inodes_count(dentry->d_sb);
	__ijnl_log_inode_count(spfs_inode);

	ret = spfs_migrate_extent_map(inode);
	BUG_ON(ret);

	__ijnl_commit(spfs_inode, 0);

	set_inode_flag(inode, INODE_TIERED);
	clear_inode_flag(inode, INODE_NEED_TIERING);
#ifdef SPFS_BASIC_DOWNWARD_MIGR
	if (S_OPTION(sbi)->demotion)
		spfs_add_migr_list(inode, dentry);
#endif
	inode_unlock(d_inode(dentry));
	unlock_dir(parent);

	spfs_migr_debug("%s(%lu) --", dentry->d_name.name, inode->i_ino);

	return 0;
error:
	spfs_del_inode_list(inode);
	__ijournal_init(spfs_inode);
	PREFETCH_FREE_BLOCKS(sbi, pf);
	PREFETCH_COMMIT_FREE_BLOCKS(sbi, pf);

	inode_unlock(d_inode(dentry));
	unlock_dir(parent);
	return ret;
}

static inline struct list_head *spfs_get_migr_lists(struct spfs_sb_info *sbi, 
		int ml_id) 
{
	return &sbi->migr_lists[ml_id];
}

static inline struct mutex *spfs_get_migr_list_lock(struct spfs_sb_info *sbi, 
		int ml_id) 
{
	return &sbi->ml_locks[ml_id];
}

static inline bool is_migr_list_empty(struct spfs_sb_info *sbi, int ml_id) 
{
	return list_empty(spfs_get_migr_lists(sbi, ml_id));
}

static inline int spfs_get_migr_list_bin_id(struct spfs_sb_info *sbi, 
		unsigned int sync_factor) 
{
	return sync_factor / SF_BIN_RANGE;
}

static inline int spfs_get_migr_list_id(struct spfs_sb_info *sbi, int cpu_id, 
		int bin_id) 
{
	return cpu_id * SF_NUM_BINS + bin_id;
}

inline void spfs_add_migr_list(struct inode *inode, struct dentry *dentry)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	int cpu_id = hash_64(inode->i_ino, ilog2(FREE_INFO(sbi)->cpus));
	int bin_id = spfs_get_migr_list_bin_id(sbi, 
			I_RAW(inode)->i_sync_factor);
	int ml_id = spfs_get_migr_list_id(sbi, cpu_id, bin_id);
	struct list_head *cur_list = spfs_get_migr_lists(sbi, ml_id);
	struct mutex *lock = spfs_get_migr_list_lock(sbi, ml_id); 
	struct spfs_migr_info *migr_info;

	migr_info = kmalloc(sizeof(struct spfs_migr_info), GFP_KERNEL);
	INIT_LIST_HEAD(&migr_info->migr_list);
	migr_info->inode = inode;
	migr_info->dentry = dget(dentry);
	BUG_ON(I_INFO(inode)->migr_info);
	I_INFO(inode)->migr_info = migr_info;

	spfs_d_migr_debug("list[%d:%d], inode=%lu, dentry=%s", 
			cpu_id, bin_id, inode->i_ino, dentry->d_name.name);

	mutex_lock(lock);
	list_add_tail(&migr_info->migr_list, cur_list);
	mutex_unlock(lock);
}

/* migr info must be added to migr list */
inline void __spfs_calibrate_migr_list(struct inode *inode, unsigned int old_sf)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	int cpu_id;
	int old_bin_id = spfs_get_migr_list_bin_id(sbi, old_sf);
	int cur_bin_id = spfs_get_migr_list_bin_id(sbi, 
			I_RAW(inode)->i_sync_factor);
	int old_ml_id, cur_ml_id;
	struct mutex *old_lock, *cur_lock; 
	struct spfs_migr_info *migr_info = I_INFO(inode)->migr_info;
	struct list_head *cur_list;

	BUG_ON(!migr_info);
	
	cpu_id = hash_64(inode->i_ino, ilog2(FREE_INFO(sbi)->cpus));
	old_ml_id = spfs_get_migr_list_id(sbi, cpu_id, old_bin_id);
	cur_ml_id = spfs_get_migr_list_id(sbi, cpu_id, cur_bin_id);
	
	cur_list = spfs_get_migr_lists(sbi, cur_ml_id);

	old_lock = spfs_get_migr_list_lock(sbi, old_ml_id);
	cur_lock = spfs_get_migr_list_lock(sbi, cur_ml_id);
	
	/* just add migr_info to current migr list */	
	if (is_inode_flag_set(inode, INODE_SUSPENDED)) {
		mutex_lock(cur_lock);
		list_add_tail(&migr_info->migr_list, cur_list);
		clear_inode_flag(inode, INODE_SUSPENDED);
		mutex_unlock(cur_lock);	
	} else { 
		/* replace migr_info from old to current */
		mutex_lock(old_lock);
		list_del(&migr_info->migr_list);
		mutex_unlock(old_lock);
		
		mutex_lock(cur_lock);
		list_add_tail(&migr_info->migr_list, cur_list);
		mutex_unlock(cur_lock);	
	} 
}

inline void spfs_calibrate_migr_list(struct inode *inode, unsigned int old_sf)
{
	// not handle dir boost inode
	if (!IS_TIERED_INODE(inode))
		return;
	__spfs_calibrate_migr_list(inode, old_sf);
}

/* migr info must be removed while unlink and downward migration */
inline void spfs_remove_migr_list(struct inode *inode)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	int cpu_id = hash_64(inode->i_ino, ilog2(FREE_INFO(sbi)->cpus));
	int bin_id = spfs_get_migr_list_bin_id(sbi, 
			I_RAW(inode)->i_sync_factor);
	int ml_id = spfs_get_migr_list_id(sbi, cpu_id, bin_id);
	struct mutex *lock = spfs_get_migr_list_lock(sbi, ml_id); 
	struct spfs_migr_info *migr_info = I_INFO(inode)->migr_info;

	BUG_ON(!migr_info);

	spfs_d_migr_debug("list[%d:%d], inode=%lu, dentry=%s", 
			cpu_id, bin_id,
			inode->i_ino, migr_info->dentry->d_name.name);
	
	if (is_inode_flag_set(inode, INODE_SUSPENDED)) {
		clear_inode_flag(inode, INODE_SUSPENDED);
	} else {
		mutex_lock(lock);
		list_del(&migr_info->migr_list); 
		mutex_unlock(lock);
	}
	
	dput(migr_info->dentry);
	kfree(migr_info);
}

int spfs_alloc_migr_lists(struct spfs_sb_info *sbi) 
{
	int i;
	int cpus = FREE_INFO(sbi)->cpus;
	int num_bins = SF_NUM_BINS;

	sbi->migr_lists = kmalloc(sizeof(struct list_head) * cpus * num_bins, 
			GFP_KERNEL);
	if (!sbi->migr_lists)
		goto err;

	sbi->ml_locks = kmalloc(sizeof(struct mutex) * cpus * num_bins, 
			GFP_KERNEL);
	if (!sbi->ml_locks)
		goto err2;

	for (i = 0; i < cpus * num_bins; i++) {
		INIT_LIST_HEAD(&sbi->migr_lists[i]);
		mutex_init(&sbi->ml_locks[i]);
	}
	
	spfs_sbi = sbi; /* for migr list seqfile */

	return 0;

err2:
	kfree(sbi->migr_lists);
	sbi->migr_lists = NULL;
err:
	return -ENOMEM;
}

int spfs_destroy_migr_lists(struct spfs_sb_info *sbi) 
{
	int i;
	struct spfs_migr_info *migr_info = NULL, *tmp_migr_info;
	struct list_head *list;
	int cpus = FREE_INFO(sbi)->cpus;
	int num_bins = SF_NUM_BINS;

	spfs_d_migr_debug("cpus=%d, num_bins=%d", cpus, num_bins);
	for (i = 0; i < cpus * num_bins; i++) {
		list = &sbi->migr_lists[i];
		list_for_each_entry_safe(migr_info, tmp_migr_info, list,
				migr_list) {
			dput(migr_info->dentry);
			list_del(&migr_info->migr_list);
			kfree(migr_info);
		}
	}

	kfree(sbi->migr_lists);
	kfree(sbi->ml_locks);

	return 0;
}

static inline bool suspend_bm_migr(struct inode *inode)
{
       return rwsem_is_contended(&inode->i_rwsem);
}

ssize_t copy_file_to_lower(struct inode *inode, struct dentry *dentry, 
		struct file *lower_file)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	fmode_t restore_fmode = 0;
	unsigned int restore_f_flags = 0;
	struct spfs_extent_info *ei = NULL;
	spfs_cluster_t pelcn = I_EOF(inode);
	void *buf;
	size_t count;
	loff_t pos = 0;
	ssize_t nwrite, done = 0;
	ssize_t ret = 0;

	BUG_ON(!lower_file);

	if (!(lower_file->f_mode & FMODE_WRITE)) {
		lower_file->f_mode |= FMODE_WRITE;
		restore_fmode |= FMODE_WRITE;
	}

	if (!(lower_file->f_mode & FMODE_CAN_WRITE)) {
		lower_file->f_mode |= FMODE_CAN_WRITE;
		restore_fmode |= FMODE_CAN_WRITE;
	}

	/* XXX: copy is sync write, copy may bother f.g. write */
	if (S_OPTION(sbi)->demotion_sync_write && 
			!(lower_file->f_flags & O_DSYNC)) {
		lower_file->f_flags |= O_DSYNC;
		restore_f_flags |= O_DSYNC;
	}

	/* 1. Iterate file's extent to search extent: from last */
	while (1) {
		/* 2. check if file data is migrated to PM (by lookup extent) */
		if (unlikely(!ei)) {
			ei = spfs_search_extent_info(inode, pelcn);
			if (!ei) {
				spfs_d_migr_debug("Not exist: inode=%lu",
						inode->i_ino);
				ret = -ENOENT;
				break;
			}
		}

		pelcn = ei->prev_extent_lcn; // next extent start
		
		if (!ei->pcn) {
			//spfs_d_migr_debug("Not mapped: inode=%lu, lcn=%u", 
			//		inode->i_ino, ei->lcn);
			goto fallback;
		}
		
		//spfs_d_migr_debug("Mapped: inode=%lu, lcn=%u, len=%u", 
		//		inode->i_ino, ei->lcn, ei->len);

		/* 3. write extent to lower */
		buf = (char *) clu_addr(sbi, ei->pcn); 
		count = C2BYTES(ei->len);
		pos = C2BYTES(ei->lcn);

		nwrite = kernel_write(lower_file, buf, count, &pos);
		if (nwrite < 0) {
			spfs_err(inode->i_sb, "inode=%lu(%lu), count=%lu," 
					"pos=%llu, size=%llu, raw blocks=%u, "
					"nwrite=%ld",
					inode->i_ino,
					spfs_inode_to_lower(inode)->i_ino,
					count, pos, inode->i_size,
					I_RAW(inode)->i_blocks,
					nwrite);
			ret = nwrite;
			BUG();
			break;
		} 

		done += nwrite;
		if (done >= inode->i_size) {
			spfs_d_migr_debug("Full mapped: "
					"inode=%lu(%lu), done=%ld, size=%llu, "
					"raw blocks=%u",
					inode->i_ino, 
					spfs_inode_to_lower(inode)->i_ino,
					done, inode->i_size, 
					I_RAW(inode)->i_blocks); 
			stats_inc_full_mapped_on_demoted();
			break;
		}

		if (suspend_bm_migr(inode)) {
			spfs_d_migr_debug("inode=%lu(%lu) is suspended, "
					"while copying",
					inode->i_ino,
					spfs_inode_to_lower(inode)->i_ino);
			ret = -EAGAIN;

			stats_inc_susp_on_demoted();
			stats_inc_susp_amounts_on_demoted(done);
			break;
		}

fallback:
		ei = spfs_search_extent_info(inode, pelcn);
		if (!ei) {
			spfs_d_migr_debug("%s mapped: "
					"inode=%lu(%lu), done=%ld, size=%llu, "
					"raw blocks=%u",
					done ? "Partial" : "Nothing", 
					inode->i_ino, 
					spfs_inode_to_lower(inode)->i_ino,
					done, inode->i_size, 
					I_RAW(inode)->i_blocks);
			if (done)
				stats_inc_partial_mapped_on_demoted();
			else
				stats_inc_nothing_mapped_on_demoted();

			break;
		}
	}
	
	if (!ret)
		ret = done;
	
	if (restore_fmode) {
		lower_file->f_mode &= ~restore_fmode;
	}
	if (restore_f_flags) {
		lower_file->f_flags &= ~restore_f_flags;
	}

	return ret;
}

/* copy from spfs_unlink */
int clear_tiered_inode_pm_space(struct inode *inode, struct dentry *dentry)
{
	//struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	struct dentry *parent = lock_parent(dentry); /* protect dirent list */
	struct inode *dir = d_inode(dentry->d_parent);
	int n_children;

	BUG_ON(!D_INFO(dentry));
	
	spfs_d_migr_debug("inode=%lu(%lu)", 
			inode->i_ino, spfs_inode_to_lower(inode)->i_ino);
#if 0
	/* XXX: jounaling? */
	if (unlikely(SPFS_DE_CHILDREN(dentry->d_parent) == 1))
		ijournal_log_dir_entry(inode, UL_DIR_HDEL,
				blk_idx(sbi, D_INFO(dentry->d_parent)->de),
				dentry->d_parent->d_name.hash);
	ijournal_log_dir_entry(inode, UL_REG_HDEL,
			blk_idx(sbi, D_INFO(dentry)->de), dentry->d_name.hash);
#endif
	n_children = spfs_del_nondir(dentry);
	if (unlikely(n_children == 0))
		spfs_del_dir(dentry->d_parent);

	/* XXX: should update dir. bypass inode? */
	//clear_nlink(inode);
	inode->i_ctime = current_time(inode);
	dir->i_mtime = dir->i_ctime = current_time(inode);

	//spfs_dec_inodes_count(inode->i_sb);
	//ijournal_log_inode_count(inode);
	
	//d_drop(dentry);

	if (inode_get_bytes(inode))
		spfs_truncate(inode, true);
	inode->i_size = spfs_inode_to_lower(inode)->i_size;

	unlock_dir(parent);

	return 0;
}

/* copy from spfs_alloc_inode */
int reset_tiered_inode_info(struct inode *inode)
{
	struct spfs_inode_info *info = I_INFO(inode);

	spfs_d_migr_debug("inode=%lu(%lu)", 
			inode->i_ino, spfs_inode_to_lower(inode)->i_ino);

	/* Change inode number to lower file and rehash */
	remove_inode_hash(inode);
	inode->i_ino = info->lower_inode->i_ino;
	__insert_inode_hash(inode, inode->i_ino); /* here? */

	/* PM inode was already deallocated */
	info->raw_inode = NULL;
	//spin_lock_init(&info->i_raw_lock);

	/* Deallocate dram extent info */
	spfs_truncate_extent_info(inode, 0);
	info->i_extent_tree = RB_ROOT;
	//rwlock_init(&info->i_extent_lock);

	// XXX: reset profile info?
	memset(I_PROFILER(inode), 0x00, sizeof(struct spfs_profiler));
	spin_lock_init(&I_PROFILER(inode)->lock);

	info->migr_info = NULL;
	atomic_set(&info->sf_rd_cnt, 0);

	clear_inode_flag(inode, INODE_TIERED); /* Tiered => BP */

	return 0;
}

struct file *open_lower_file_for_migration(struct inode *inode, 
		struct dentry *dentry) 
{
	struct dentry *lower_parent, *lower_dentry;
	const char *name;
	struct path lower_path;
	int f_flags = O_RDWR | O_LARGEFILE;
	
	lower_parent = spfs_dentry_to_lower(dentry->d_parent);
	name = dentry->d_name.name;
	lower_dentry = lookup_one_len_unlocked(name, lower_parent, 
			strlen(name)); 

	lower_path.mnt = mntget(spfs_dentry_to_lower_path(dentry)->mnt);
	lower_path.dentry = lower_dentry;
	
	spfs_set_dentry_lower_path(dentry, &lower_path);

	BUG_ON(!spfs_inode_to_lower(inode));

	return dentry_open(&lower_path, f_flags, current_cred());
}

int migrate_file_to_lower(struct inode *inode, struct dentry *dentry)
{
	int ret = 0;
	ssize_t ret2;
	struct file *lower_file = NULL;

	/* check whether file was deleted */
	spin_lock(&dentry->d_lock);
	if (d_unlinked(dentry)) {
		spfs_err(inode->i_sb, "dentry=%s is unlinked", 
				dentry->d_name.name);
		spin_unlock(&dentry->d_lock);
		ret = -ENOENT;
		goto out;
	}
	spin_unlock(&dentry->d_lock);

	if (!(inode->i_state & (I_NEW|I_FREEING))) {
		BUG_ON(!inode_is_locked(inode));
	}

	/* allow only regular files */
	if (!(S_ISREG(inode->i_mode))) {
		spfs_err(inode->i_sb, "inode=%lu, dentry=%s is not reg file", 
				inode->i_ino, dentry->d_name.name);
		ret = -EACCES;
		goto out;
	}
	
	lower_file = open_lower_file_for_migration(inode, dentry);
	if (IS_ERR(lower_file)) {
		ret = -EACCES;
		spfs_err(inode->i_sb, "failed to open lower file: %d", ret);
		goto out2;
	}
	
	if (suspend_bm_migr(inode)) {
		spfs_d_migr_debug("inode=%lu(%lu) is suspended, "
				"after open lower file",
				inode->i_ino,
				spfs_inode_to_lower(inode)->i_ino);
		ret = -EAGAIN;

		stats_inc_susp_on_demoted();
		goto out2;
	}

	ret2 = copy_file_to_lower(inode, dentry, lower_file);
	/* prevent suspending by fg io while free pm space */
	if (ret2 >= 0) {
		spin_lock(&I_INFO(inode)->migr_lock);

		clear_tiered_inode_pm_space(inode, dentry);
		reset_tiered_inode_info(inode);

		spin_unlock(&I_INFO(inode)->migr_lock);
		
		if (ret2 > 0) {
			stats_inc_succ_on_demoted();
			stats_inc_succ_amounts_on_demoted(ret2);
		}
	} else if (ret2 == -EAGAIN)
		ret = ret2;

out2:
	if (ret == -EAGAIN)
		set_inode_flag(inode, INODE_SUSPENDED);

	filp_close(lower_file, NULL);
	path_put(spfs_dentry_to_lower_path(dentry));
out:
	inode_unlock_shared(inode);
	return ret;
}

struct spfs_migr_info *pop_victim_to_migrate(struct spfs_sb_info *sbi, 
		bool by_hard_limit)
{
	int i;
	int cpu = smp_processor_id();
	int num_bins = by_hard_limit ? 1 : SF_NUM_BINS;
	int ml_id;
	struct mutex *lock;
	struct spfs_migr_info *migr_info;
	struct list_head *list;
	struct inode *inode;
	struct spfs_inode *p_inode;
	bool selected = false;	

	for (i = 0; i < num_bins; i++) {
		ml_id = spfs_get_migr_list_id(sbi, cpu, i);
		lock = spfs_get_migr_list_lock(sbi, ml_id);
		list = spfs_get_migr_lists(sbi, ml_id);
		
		mutex_lock(lock);
		list_for_each_entry(migr_info, list, migr_list) {
			inode = migr_info->inode;
			BUG_ON(!inode);
			BUG_ON(is_inode_flag_set(inode, INODE_SUSPENDED));

			p_inode = I_RAW(migr_info->inode);
			BUG_ON(!p_inode);

			if (!i_size_read(inode)) {
				spfs_d_migr_debug("inode=%lu(%lu), size=0",
					inode->i_ino,
					spfs_inode_to_lower(inode)->i_ino);
				continue;
			}
			if (!inode_trylock_shared(inode)) {
				spfs_d_migr_debug("inode=%lu(%lu), was locked",
					inode->i_ino,
					spfs_inode_to_lower(inode)->i_ino);
				continue;
			}

			selected = true;
			list_del(&migr_info->migr_list);
			mutex_unlock(lock);
			goto out;
		}
		mutex_unlock(lock);
	}

out:
	return selected ? migr_info : NULL;
}

int spfs_do_downward_migartion(struct spfs_sb_info *sbi, int cpu)
{
	struct spfs_migr_info *migr_info;
	int ret = 0; 
	bool hard_limit_migr;

again:
	hard_limit_migr = false;
	/* cond 1: by sync factor's hard limit, only check the smallest bin */ 
	if (S_OPTION(sbi)->demotion_hard_limit) {
		migr_info = pop_victim_to_migrate(sbi, true);
		if (migr_info) {
			spfs_d_migr_debug("inode=%lu, sync_factor=%u", 
					migr_info->inode->i_ino, 
					I_RAW(migr_info->inode)->i_sync_factor);
			hard_limit_migr = true;
			goto done_popping;
		}
	}
again2:
	/* cond 2: by usage, free cluster is not enough */
	
	/* XXX: force testing downward migration */
	if (!spfs_is_usage_high(FREE_INFO(sbi))) {
		int num_trigger = S_OPTION(sbi)->migr_test_num_trigger;
		if (num_trigger > 0) {
			/* not exactly correct values */
			uint64_t cur = percpu_counter_sum(&stats_prof_boosted);
			uint64_t old = percpu_counter_sum(&old_prof_boosted);

			if (cur - old > num_trigger) {
				percpu_counter_set(&old_prof_boosted, cur);
				goto do_popping;
			}
		}
		goto out;
	}

do_popping:
	migr_info = pop_victim_to_migrate(sbi, false);
	if (!migr_info) {
		ret = -1;
		spfs_d_migr_debug("[C%2d] PMEM usage is high yet "
				"any inode is found", cpu);
		if (hard_limit_migr)
			goto again2;
		else 
			goto again;
	}

done_popping:
	ret = migrate_file_to_lower(migr_info->inode, migr_info->dentry);
	if (ret != -EAGAIN) {	
		dput(migr_info->dentry);
		kfree(migr_info);
	}

	if (!hard_limit_migr)
		goto again;
out:
	return ret;
}

void wake_up_bm(struct spfs_sb_info *sbi)
{
	int i;

	if (sbi->bm_thread) {
		smp_mb();
		for (i = 0; i < FREE_INFO(sbi)->cpus; i++) {
			wake_up_process(sbi->bm_thread[i].spfs_task);
		}
	}
}

#define BM_THREAD_SLEEP_TIME 1000
static int bm_thread_func(void *data)
{
	struct spfs_sb_info *sbi = data;
	int cpu = 0;

	do {
		schedule_timeout_interruptible(
				msecs_to_jiffies(BM_THREAD_SLEEP_TIME));
		cpu = smp_processor_id();

		//spfs_msg(sbi->s_sb, KERN_INFO,
		//      "---- [Background Migration Thread C%d] ----", cpu);

		spfs_do_downward_migartion(sbi, cpu);
	} while (!kthread_should_stop());

	return 0;
}

// XXX: should be used with gfi, no_gfi => single thread 
int spfs_start_bm_thread(struct spfs_sb_info *sbi)
{
	struct spfs_kthread *bm_thread = NULL;
	int i, err = 0;
	int cpus = FREE_INFO(sbi)->cpus;
	char stmp[100] = {0};
	sbi->bm_thread = NULL;

	/* Initialize background migration kthread */
	bm_thread = kzalloc(sizeof(struct spfs_kthread) * cpus, GFP_KERNEL);
	if (!bm_thread) {
		return -ENOMEM;
	}

	spfs_msg(sbi->s_sb, KERN_INFO, "Start BM threads, cpus=%d", cpus);

	for (i = 0; i < cpus; i++) {
		init_waitqueue_head(&(bm_thread[i].wait_queue_head));
		bm_thread[i].index = i;
		//sprintf(&stmp[0], "SPFS_BM_C%d", i);
		//pr_info("%s", stmp);
		bm_thread[i].spfs_task = kthread_create(bm_thread_func, sbi, 
				stmp);
		kthread_bind(bm_thread[i].spfs_task, i);

		if (IS_ERR(bm_thread[i].spfs_task)) {
			err = PTR_ERR(bm_thread[i].spfs_task);
			goto free;
		}
	}

	sbi->bm_thread = bm_thread;
	wake_up_bm(sbi);

	return 0;

free:
	kfree(bm_thread);
	return err;
}

void spfs_stop_bm_thread(struct spfs_sb_info *sbi)
{
	int i;

	if (sbi->bm_thread) {
		for (i = 0; i < FREE_INFO(sbi)->cpus; i++) {
			kthread_stop(sbi->bm_thread[i].spfs_task);
		}
		kfree(sbi->bm_thread);
		sbi->bm_thread = NULL;
	}
	spfs_msg(sbi->s_sb, KERN_INFO, "%s", __func__);
}

int spfs_update_usage(struct spfs_sb_info *sbi)
{
	int i;
	size_t total_free_cluster_cnt = 0, total_used_cluster_cnt;
	struct spfs_free_info *info = FREE_INFO(sbi);
	int usage_perc;

	/* Monitor cluster/block free info */
	for (i = 0; i < FREE_INFO(sbi)->groups; i++)
		total_free_cluster_cnt += GFI(info, i)->nfree;
	total_used_cluster_cnt = info->clusters_count - total_free_cluster_cnt;

	usage_perc = total_used_cluster_cnt * 100 / info->clusters_count;
	info->cur_usage_perc = usage_perc;

	if (spfs_is_usage_high(info)) {
		/* TODO: make it to seq_printf() */
		//pr_err("clu cnt(used=%lu, free=%lu), util(%%)=%d", 
		spfs_d_migr_debug("clu cnt(used=%lu, free=%lu), util(%%)=%d", 
				total_used_cluster_cnt, 
				total_free_cluster_cnt, usage_perc);
	}

	return 0;
}

void wake_up_usage(struct spfs_sb_info *sbi)
{
	if (sbi->usage_thread) {
		smp_mb();
		wake_up_process(sbi->usage_thread->spfs_task);
	}
}

#define USAGE_THREAD_SLEEP_TIME 250
static int usage_thread_func(void *data)
{
	struct spfs_sb_info *sbi = data;

	do {
		schedule_timeout_interruptible(
				msecs_to_jiffies(USAGE_THREAD_SLEEP_TIME));

		spfs_update_usage(sbi);
	} while (!kthread_should_stop());

	return 0;
}

int spfs_start_usage_thread(struct spfs_sb_info *sbi)
{
	struct spfs_kthread *usage_thread = NULL;
	int err = 0;
	char stmp[100] = "SPFS_USAGE";

	sbi->usage_thread = NULL;
	/* Initialize background usage info kthread */
	usage_thread = kzalloc(sizeof(struct spfs_kthread), GFP_KERNEL);
	if (!usage_thread) {
		return -ENOMEM;
	}

	err = percpu_counter_init(&old_prof_boosted, 0, GFP_KERNEL);
	if (err)
		return err;

	spfs_msg(sbi->s_sb, KERN_INFO, "Start usage thread");

	init_waitqueue_head(&(usage_thread->wait_queue_head));
	usage_thread->spfs_task = kthread_create(usage_thread_func, sbi, stmp);

	if (IS_ERR(usage_thread->spfs_task)) {
		err = PTR_ERR(usage_thread->spfs_task);
		goto free;
	}

	sbi->usage_thread = usage_thread;
	wake_up_usage(sbi);

	return 0;

free:
	kfree(usage_thread);
	return err;
}

void spfs_stop_usage_thread(struct spfs_sb_info *sbi)
{
	if (sbi->usage_thread) {
		kthread_stop(sbi->usage_thread->spfs_task);
		kfree(sbi->usage_thread);
		sbi->usage_thread = NULL;
	}
	percpu_counter_destroy(&old_prof_boosted);
	spfs_msg(sbi->s_sb, KERN_INFO, "%s", __func__);
}


int spfs_seq_migr_lists_show(struct seq_file *seq, void *offset)
{
	int i, cpu;
	int num_cpus;
	int num_bins = SF_NUM_BINS;
	int ml_id;
	struct mutex *lock;
	struct spfs_migr_info *migr_info;
	struct list_head *list;
	struct inode *inode;
	struct spfs_inode *p_inode;
	struct spfs_sb_info *sbi = spfs_sbi;
	int *cnts;
	int total_cnt = 0;

	if (!sbi) {
		seq_printf(seq, "Demotion option doesn't enabled...\n");
		return 0;
	}
	
	num_cpus = FREE_INFO(sbi)->cpus;

	seq_printf(seq, "Migr lists\n"
			"num_cpus=%u, num_bins=%d\n", num_cpus, num_bins);
	
	cnts = kzalloc(sizeof(int) * num_cpus, GFP_KERNEL);
	
	for (cpu = 0; cpu < num_cpus; cpu++) {
		seq_printf(seq, "CPU%2d\n", cpu); 
		for (i = 0; i < num_bins; i++) {
			ml_id = spfs_get_migr_list_id(sbi, cpu, i);
			lock = spfs_get_migr_list_lock(sbi, ml_id);
			mutex_lock(lock);
			list = spfs_get_migr_lists(sbi, ml_id);

			seq_printf(seq, "[%4d]: ", i != (num_bins - 1) ?
					(i + 1) * SF_BIN_RANGE : 
					SF_SCALE + 1);
			list_for_each_entry(migr_info, list, migr_list) {
				p_inode = I_RAW(migr_info->inode);
				BUG_ON(!p_inode);

				inode = migr_info->inode;
				BUG_ON(!inode);

				if (!i_size_read(inode))
					continue;
			 	seq_printf(seq, "(%s, %u) ", 
						migr_info->dentry->d_name.name, 
						I_RAW(inode)->i_sync_factor);
				cnts[cpu]++;
			}
			mutex_unlock(lock);
			seq_printf(seq, "\n"); 
		}
		total_cnt += cnts[cpu];
	}

	seq_printf(seq, "Overall: %d\n", total_cnt); 
	for (i = 0; i < num_cpus; i++) {
		seq_printf(seq, "CPU%2d\t", i); 
	}
	seq_printf(seq, "\n"); 
	for (i = 0; i < num_cpus; i++) {
		seq_printf(seq, "%4d\t", cnts[i]); 
	}
	seq_printf(seq, "\n"); 

	kfree(cnts);
	return 0;
}
