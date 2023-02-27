#include "spfs.h"
#include "inode.h"
#include "calloc.h"
#include "namei.h"
#include "extent.h"
#include "cceh_extent.h"

#include <linux/uaccess.h>


//#define MIGR_DEBUG
#ifdef MIGR_DEBUG
#define spfs_migr_debug(fmt, ...)	\
	pr_err("%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define spfs_migr_debug(fmt, ...)	do {} while (0)
#endif

#define MIGR_FORCE_MODE			(FMODE_READ | FMODE_CAN_READ)

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
