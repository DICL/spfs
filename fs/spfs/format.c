#include "spfs.h"

static unsigned int spfs_format_layout(struct spfs_super_block *sb,
		unsigned long long bdev_size)
{
	spfs_cluster_t cluster_count = BYTES2C(bdev_size);

	sb->s_bitmap_cluster_count = ALIGN(cluster_count,
			CLUSTER_SIZE * BITS_PER_BYTE) >> (3 + CLUSTER_SHIFT);
	sb->s_first_main_clu = SUPER_BLOCK_CLUSTERS +
		sb->s_bitmap_cluster_count;
	sb->s_clusters_count = cluster_count - sb->s_first_main_clu;

	return sb->s_first_main_clu;
}

static unsigned long spfs_format_cceh(struct spfs_sb_info *sbi, void *addr,
		spfs_cluster_t dir_index, unsigned int depth, int lp_bkts)
{
	struct cceh *cceh = addr;
	struct cceh_dir *dir;
	unsigned long dir_cluster_cnt = DIR_CLUSTER_COUNT(depth);
	int i;

	cceh->depth = (unsigned int) -1;
	cceh->dir_c_idx = dir_index;
	cceh->linear_probe_bkts = lp_bkts;

	dir = (struct cceh_dir *) clu_addr(sbi, dir_index);
	memset(dir, 0, CLUSTER_SIZE);
	for (i = 0; i < __cceh_dir_capa(depth); i++)
		dir->s[i] = dir_index + dir_cluster_cnt + i * CPS;

	spfs_msg(sbi->s_sb, KERN_INFO,
			"CCEH format.. dir=%u seg=%u depth=%u lp=%u",
			cceh->dir_c_idx, dir->s[0], cceh->depth,
			cceh->linear_probe_bkts);

	return dir_cluster_cnt + __cceh_dir_capa(depth) * CPS;
}

int spfs_format(struct spfs_sb_info *sbi)
{
	struct spfs_super_block sb;
	size_t xfer;
	spfs_cluster_t fmc;
	unsigned long hash_clu_cnt = 0;
	int i;

	memset(&sb, 0, sizeof(sb));

	/*
	 * TODO: s_magic must be synced alone at the end of format for the
	 * consistency guarantee.
	 */
	sb.s_magic = SPFS_SUPER_MAGIC; // TODO: magic must be last
	sb.s_block_size = BLK_SIZE;
	sb.s_cluster_size = CLUSTER_SIZE;
	sb.s_inode_size = BLK_SIZE;

	fmc = spfs_format_layout(&sb, i_size_read(sbi->s_sb->s_bdev->bd_inode));
	memset(clu_addr(sbi, FIRST_BITMAP_CLU), 0,
			sb.s_bitmap_cluster_count * CLUSTER_SIZE);
	SPFS_SFENCE();
	__bitmap_set(clu_addr(sbi, FIRST_BITMAP_CLU), 0, fmc);

	/* format CCEHs */
#ifdef SPFS_SMALL_BLOCK
	hash_clu_cnt += spfs_format_cceh(sbi, sb.s_cluster_hash, fmc, 0,
			DEF_LINEAR_PROBE_BKT_CNT);
#endif
	hash_clu_cnt += spfs_format_cceh(sbi, &sb.s_namei_hash,
			fmc + hash_clu_cnt, 0, DEF_LINEAR_PROBE_BKT_CNT);
	if (sbi->s_options.extent_hash_lp == 0) {
		spfs_err(sbi->s_sb, "%s: failed to format extent CCEH.. missing"
				" ext_hlp=<..> option", __func__);
		return -EINVAL;
	}
	hash_clu_cnt += spfs_format_cceh(sbi, &sb.s_extent_hash,
			fmc + hash_clu_cnt, sbi->s_options.extent_hash_depth,
			sbi->s_options.extent_hash_lp);
	__bitmap_set(clu_addr(sbi, FIRST_BITMAP_CLU), fmc, hash_clu_cnt);
	SPFS_SFENCE();

	/* TODO: rest of above */

	xfer = spfs_dax_copy_from_addr(sbi,
			sbi->s_psb, &sb, sizeof(sb), true);
	if (!xfer || xfer < sizeof(sb)) {
		spfs_msg(sbi->s_sb, KERN_ERR, "failed to format: %zu",
				xfer);
		return -EFAULT;
	}

	init_blist_head(sbi, &sbi->s_psb->s_migration_list);

	for (i = 0; i < INODE_LIST_COUNT; i++)
		init_blist_head(sbi, &sbi->s_psb->s_inode_list[i]);
	clwb_sfence(sbi->s_psb, C2BYTES(SUPER_BLOCK_CLUSTERS));

	spfs_msg(sbi->s_sb, KERN_INFO, "format done");

	return 0;
}
