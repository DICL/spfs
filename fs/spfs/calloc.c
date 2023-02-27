#include "calloc.h"


int __spfs_init_allocator(struct spfs_free_info *info, int grp)
{
	struct spfs_sb_info *sbi = info->sbi;
	spfs_gfi_t *gfi;
	size_t remain;
	size_t cnt;
#if defined(SPFS_SMALL_BLOCK) && !defined(CONFIG_SPFS_UNIFIED_PCL)
	int i;
#endif
	int ret;
	void *durable_bitmap = clu_addr(sbi, FIRST_BITMAP_CLU +
			(grp * info->bc_per_group));

	gfi = kzalloc(sizeof(spfs_gfi_t), GFP_KERNEL);
	if (!gfi) {
		spfs_err(sbi->s_sb, "%s: can't get GFI memory", __func__);
		return -ENOMEM;
	}

	/* add remain clusters to last rescue group */
	if (!S_OPTION(sbi)->no_gfi && grp == info->groups - 1)
		GFI_NR(gfi) = info->clusters_count - (grp * info->cpc);
	else
		GFI_NR(gfi) = info->cpc;

	cnt = GFI_NR(gfi) / BITS_PER_BYTE;;
	GFI_BITMAP(gfi) = kvmalloc(cnt, GFP_KERNEL);
	if (!GFI_BITMAP(gfi)) {
		spfs_err(sbi->s_sb, "%s: can't get bitmap memory");
		ret = -ENOMEM;
		goto out1;
	}

	remain = memcpy_mcsafe(GFI_BITMAP(gfi), durable_bitmap, cnt);
	if (remain) {
		spfs_err(sbi->s_sb, "%s: can't copy bitmap: %zu %zu",
				__func__, remain, cnt);
		ret = -EFAULT;
		goto out2;
	}

	GFI_DURABLE_BITMAP(gfi) = durable_bitmap;

	GFI_START(gfi) = grp * info->cpc;
	GFI_FREE(gfi) = 0;
	spin_lock_init(GFI_LOCK(gfi));

#ifdef SPFS_SMALL_BLOCK
#ifdef CONFIG_SPFS_UNIFIED_PCL
	INIT_LIST_HEAD(GFI_PCL(gfi, 0));
	spin_lock_init(GFI_PCL_LOCK(gfi, 0));
#else
	for (i = 1; i < BPC; i++) {
		INIT_LIST_HEAD(GFI_PCL(gfi, i));
		spin_lock_init(GFI_PCL_LOCK(gfi, i));
	}
#endif
	GFI_CLUSTERS(gfi) = kvzalloc(GFI_NR(gfi) * sizeof(void *), GFP_KERNEL);
	if (!GFI_CLUSTERS(gfi)) {
		spfs_err(sbi->s_sb, "%s: no memory for cluster array",
				__func__);
		ret = -ENOMEM;
		goto out2;
	}
#endif
	info->gfi[grp] = gfi;
	GFI_FI(gfi) = info;

	return 0;
out2:
	kvfree(GFI_BITMAP(gfi));
out1:
	kfree(gfi);
	return ret;
}

#ifndef SPFS_SMALL_BLOCK
static int spfs_init_group_clusters(struct spfs_free_info *info,
		spfs_gfi_t *gfi)
{
	int i;

	for (i = 0; i < GFI_NR(gfi); i++) {
		if (!test_bit(i, GFI_BITMAP(gfi))) {
			add_free_blocks(BPC, info);
			INC_GFI_FREE(gfi);
		}
	}
	return 0;
}
#endif

static void spfs_show_groups(struct spfs_free_info *info)
{
	struct super_block *sb = info->sbi->s_sb;
	spfs_gfi_t *gfi;
	int i;

	spfs_err(sb, "%s: Total=%u CPUs=%d Groups=%d CPC=%d BCPG=%d\n",
			__func__, info->clusters_count, info->cpus,
			info->groups, info->cpc, info->bc_per_group);

	for (i = 0; i < info->groups; i++) {
		gfi = GFI(info, i);
		spfs_err(sb, "%s: Group%5d start=%lu nr=%lu free=%lu",
				__func__, i, GFI_START(gfi), GFI_NR(gfi),
				GFI_FREE(gfi));
	}
}

int spfs_init_allocator(struct spfs_sb_info *sbi)
{
	struct spfs_super_block *psb = sbi->s_psb;
	struct spfs_free_info *info = FREE_INFO(sbi);
	int i;
	int ret = 0;

	info->sbi = sbi;

	info->clusters_count = sbi->s_psb->s_clusters_count;

	if (S_OPTION(sbi)->no_gfi) {
		info->cpus = 1;
		info->groups = 1;
		info->bc_per_group = psb->s_bitmap_cluster_count;
		goto group_cnt_done;
	}

	info->cpus = num_possible_cpus();
	while (1) {
		info->groups = info->cpus + 1; // for rescue cluster region
		info->bc_per_group = psb->s_bitmap_cluster_count / info->groups;

		if (info->bc_per_group >= MIN_CLUSTER_GROUP_BITMAP_BLOCKS)
			break;

		info->cpus >>= 1;

		spfs_msg(sbi->s_sb, KERN_WARNING, "%s: adjust cpus to %d due to"
				" min. group size", __func__, info->cpus);
	}
group_cnt_done:
	info->cpc = info->bc_per_group * CLUSTER_SIZE * BITS_PER_BYTE;
	// done base layout

	info->gfi = kzalloc(sizeof(spfs_gfi_t *) * info->groups, GFP_KERNEL);
	if (!info->gfi) {
		spfs_err(sbi->s_sb, "%s: can't get memory GFIs", __func__);
		return -ENOMEM;
	}

	/* init. every group layout */
	for (i = 0; i < info->groups; i++) {
		ret = __spfs_init_allocator(info, i);
		if (ret)
			goto out;
	}

#ifdef SPFS_SMALL_BLOCK
	BUG_ON(!info->hash);
#endif
	info->cur_usage_perc = 0;
	info->num_already_full = 0;	
	for (i = 0; i < info->groups; i++) {
		ret = spfs_init_group_clusters(info, info->gfi[i]);
		if (ret) {
			spfs_err(sbi->s_sb, "%s: can't init. clusters",
					__func__);
			goto out;
		}
		if (!GFI_FREE(info->gfi[i]))
			info->num_already_full++;
	}

	spfs_show_groups(info);
out:
	return ret;
}

void spfs_exit_allocator(struct spfs_sb_info *sbi)
{
	struct spfs_free_info *info = FREE_INFO(sbi);
	int i;

	if (!info->gfi)
		return;

	for (i = 0; i < info->groups; i++) {
		if (info->gfi[i]) {
			kvfree(info->gfi[i]->bitmap);
#ifdef SPFS_SMALL_BLOCK
			spfs_exit_group_clusters(info, info->gfi[i]);
#endif
		}
		kfree(info->gfi[i]);
	}
	kfree(info->gfi);
	info->gfi = NULL;

	kfree(info);
}
