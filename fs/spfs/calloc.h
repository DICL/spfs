#ifndef __CALLOC_H__
#define __CALLOC_H__

#include "spfs.h"

#include <linux/delay.h>

#define MIN_CLUSTER_GROUP_BITMAP_BLOCKS	(4)	/* 512MB */

struct spfs_free_info;

typedef struct spfs_group_free_info {
	struct spfs_free_info	*fi;

	unsigned long		*bitmap;
	unsigned long		*durable_bitmap;
	unsigned long		start;
	spfs_cluster_t		nfree;
	spfs_cluster_t		nr;
	unsigned long		next_start;
	/*
	 * 언제 사용? 자신의 클러스터 리스트는 자신만 볼 수 있다?
	 * 그래도 다른 CPU가 클러스터를 빌리러 올 수 있기 떄문에 락을 
	 * 잡아야 한다?
	 */
	spinlock_t		lock;

#ifdef SPFS_SMALL_BLOCK
#ifdef CONFIG_SPFS_UNIFIED_PCL
	struct list_head	pcl;
	spinlock_t		pcl_lock;
#else
	struct list_head	pcl[BPC + 1];
	spinlock_t		pcl_lock[BPC + 1];
#endif

	/* for random indexing... TODO: on-demand loading */
	void **			clusters;
#endif
} spfs_gfi_t;

#ifdef SPFS_GFI_DEBUG
#define gfi_debug(sb, fmt, ...)	pr_debug("%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define gfi_debug(sb, fmt, ...)	do {} while (0)
#endif

struct spfs_free_info {
	struct spfs_sb_info		*sbi;

	/* total number of clusters except sb and bitmap */
	spfs_cluster_t			clusters_count;
	atomic64_t			free_blocks_count; /* TODO: naive */

	int				cpus;
	int				groups;
	int				cpc; /* clusters per cpu */
	/* bitmap clusters per group */
	int				bc_per_group;

#ifdef SPFS_SMALL_BLOCK
	struct spfs_cceh_info		*hash;
#endif
	spfs_gfi_t			**gfi;

	int 				cur_usage_perc;
	int				num_already_full;
};

#define FREE_INFO(sbi)	((struct spfs_free_info *) (sbi)->s_free_info)

#define add_free_blocks(cnt, info)	\
	atomic64_add(cnt, &info->free_blocks_count)
#define sub_free_blocks(cnt, info)	\
	atomic64_sub(cnt, &info->free_blocks_count)
#define get_free_blocks(info)		\
	atomic64_read(&info->free_blocks_count)


/* GFI */
enum { GFI_CPU, GFI_RESCUE, GFI_BRUTE_FORCE };

#define GFI(info, i)		((info)->gfi[i])

#define CPU_GFI(info)		GFI((info), smp_processor_id() % (info)->cpus)
static inline int __RANDOM_GFI_IDX(struct spfs_free_info *info)
{
       int idx = jiffies % info->cpus;

       if (!info->num_already_full) {
               return idx;
       } else {
               if (idx < info->num_already_full) 
		       return jiffies % (info->cpus - info->num_already_full) + 
			       info->num_already_full;
               else
                       return idx;
       }
}
#define RANDOM_GFI(info)        GFI(info, __RANDOM_GFI_IDX(info))
//#define RANDOM_GFI(info)	GFI((info), jiffies % (info)->cpus)
#define RESCUE_GFI(info)	GFI((info), (info)->groups - 1)

#define PCN2GRP(info, pcn)	(MIN((pcn) / (info)->cpc, (info)->groups - 1))
#define PCN_GFI(info, pcn)	GFI((info), PCN2GRP((info), (pcn)))

#define GFI_FI(gfi)		((gfi)->fi)
#define GFI_BITMAP(gfi)		((gfi)->bitmap)
#define GFI_DURABLE_BITMAP(gfi)	((gfi)->durable_bitmap)
#define GFI_START(gfi)		((gfi)->start)
#define GFI_FREE(gfi)		((gfi)->nfree)
#define GFI_NR(gfi)		((gfi)->nr)
#define GFI_LOCK(gfi)		(&(gfi)->lock)
#define GFI_END(gfi)		(GFI_START(gfi) + GFI_NR(gfi) - 1)

#define LOCK_GFI(gfi)		spin_lock(GFI_LOCK((gfi)))
#define UNLOCK_GFI(gfi)		spin_unlock(GFI_LOCK((gfi)))

#define INC_GFI_FREE(gfi)	(GFI_FREE((gfi))++)
#define DEC_GFI_FREE(gfi)	(GFI_FREE((gfi))--)
#define ADD_GFI_FREE(gfi, i)	(GFI_FREE((gfi)) += (i))
#define SUB_GFI_FREE(gfi, i)	(GFI_FREE((gfi)) -= (i))
#define SET_GFI_FREE(gfi, i)	(GFI_FREE((gfi)) = (i))

/* TODO: account rescue group has more clusters than CPC */
#define CIIG(info, i)		((i) % (info)->cpc) /* cluster index in GFI */
/* GFI offset to PCN */
#define GO2P(gfi, offset)	(GFI_START((gfi)) + offset)

enum usage_watermark_t {
	USAGE_WM_HIGH 		= 80,
	USAGE_WM_QUITE_HIGH 	= 90,
	USAGE_WM_VERY_HIGH 	= 95,
};

static inline bool spfs_is_usage_high(struct spfs_free_info *info)
{
	return info->cur_usage_perc > USAGE_WM_HIGH;
}

static inline bool spfs_is_usage_quite_high(struct spfs_free_info *info)
{
	return info->cur_usage_perc > USAGE_WM_QUITE_HIGH;
}

static inline bool spfs_is_usage_very_high(struct spfs_free_info *info)
{
	return info->cur_usage_perc > USAGE_WM_VERY_HIGH;
}

static inline void spfs_set_clusters_durable(struct spfs_sb_info *sbi,
		spfs_cluster_t start, unsigned int len, bool set)
{
	struct spfs_free_info *info = FREE_INFO(sbi);
	spfs_gfi_t *gfi = PCN_GFI(info, start);

	SPFS_BUG_ON(!len || len > GFI_NR(gfi));
	SPFS_BUG_ON(start + len > GFI_START(gfi) + GFI_NR(gfi));

	LOCK_GFI(gfi);
	spfs_persist_bitmap_range(GFI_DURABLE_BITMAP(gfi), CIIG(info, start),
			len, set ? bitmap_set : bitmap_clear);
	UNLOCK_GFI(gfi);
}

#define spfs_has_free_blocks(info, count)		\
	(atomic64_read(&(info)->free_blocks_count) >= (count))

static inline int spfs_claim_free_blocks(struct spfs_sb_info *sbi,
		spfs_block_t count, bool contiguous /* TODO */)
{
	if (spfs_has_free_blocks(FREE_INFO(sbi), count))
		return 0;
	return -ENOSPC;
}

#define spfs_alloc_clusters_durable(sbi, start, len)	\
	spfs_set_clusters_durable(sbi, start, len, true)

#define spfs_free_clusters_durable(sbi, start, len)	\
	spfs_set_clusters_durable(sbi, start, len, false)

#ifdef SPFS_SMALL_BLOCK
#ifdef CONFIG_SPFS_UNIFIED_PCL
#define GFI_PCL(gfi, i)			(&(gfi)->pcl)
#define GFI_PCL_LOCK(gfi, i)		(&(gfi)->pcl_lock)
#else
#define GFI_PCL(gfi, i)			(&(gfi)->pcl[i])
#define GFI_PCL_LOCK(gfi, i)		(&(gfi)->pcl_lock[i])
#endif

#define GFI_CLUSTERS(gfi)		((gfi)->clusters)

#define LOCK_GFI_PCL(gfi, free)		do {	\
	SPFS_BUG_ON(free == 0 || free == BPC);	\
	spin_lock(GFI_PCL_LOCK((gfi), (free)));	\
} while (0)
#define UNLOCK_GFI_PCL(gfi, free)	spin_unlock(GFI_PCL_LOCK((gfi), (free)))

#include "balloc.h"
#else
static inline spfs_cluster_t spfs_alloc_clusters_volatile(struct spfs_sb_info *,
		spfs_cluster_t *, bool, bool, int *);

/* glue functions hiding blocks in cluster */
static inline spfs_block_t spfs_alloc_block(struct spfs_sb_info *sbi,
		bool no_fail, int *errp)
{
	spfs_cluster_t count = 1;
	return spfs_alloc_clusters_volatile(sbi, &count, false, no_fail, errp);
}

static inline spfs_block_t spfs_alloc_blocks(struct spfs_sb_info *sbi,
		unsigned long *count, bool contiguous, bool no_fail, int *errp)
{
	return spfs_alloc_clusters_volatile(sbi, (spfs_cluster_t *) count,
			contiguous, no_fail, errp);
}

static inline int spfs_free_blocks(struct spfs_sb_info *sbi, spfs_block_t start,
		unsigned long len)
{
	spfs_free_clusters_durable(sbi, start, len);
	return 0;
}

static inline int spfs_commit_block_allocation(struct spfs_sb_info *sbi,
		spfs_block_t start, unsigned long len)
{
	spfs_alloc_clusters_durable(sbi, start, len);
	return 0;
}

static void spfs_free_clusters_volatile(struct spfs_sb_info *, spfs_cluster_t,
		unsigned int, bool);

static inline int spfs_commit_block_deallocation(struct spfs_sb_info *sbi,
		spfs_block_t start, unsigned long len)
{
	spfs_free_clusters_volatile(sbi, start, len, true);
	return 0;
}
#endif

static inline void spfs_free_clusters_volatile(struct spfs_sb_info *sbi,
		spfs_cluster_t start, unsigned int len, bool update_count)
{
	struct spfs_free_info *info = FREE_INFO(sbi);
	spfs_gfi_t *gfi = PCN_GFI(info, start);
#ifdef SPFS_SMALL_BLOCK
	unsigned int i;
#endif
#ifdef SPFS_GFI_DEBUG
	unsigned long entries[4];
#endif
	SPFS_BUG_ON_MSG(start == 0, "freeing superblock");
	CHECK_DATA_CORRUPTION(len > GFI_NR(gfi) ||
			(start + len - 1) > GFI_END(gfi),
			"GFI(0x%llx) start %u len %u", (u64) gfi, start, len);

	LOCK_GFI(gfi);

#ifdef SPFS_SMALL_BLOCK
	/* TODO: should we do this????? */
	for (i = 0; i < len; i++) {
		struct spfs_cluster_info *c = cget(info, start + i);

//		if (update_count)
//			clu_lock(c);

		clu_set_free_blocks(c, BPC);
		c->bitmap = BITMAP_IDLE;
#ifdef CLUSTER_COUNT_DEBUG
		c->idle.when = ktime_get();
		stack_trace_save(c->idle.entries, STNR, 0);
#endif
//		if (update_count)
//			clu_unlock(c);
		cput(c);
	}
#endif

	bitmap_clear(GFI_BITMAP(gfi), CIIG(info, start), len);
	if (update_count)
		add_free_blocks(len * BPC, info);
	ADD_GFI_FREE(gfi, len);
#ifdef SPFS_GFI_DEBUG
	stack_trace_save(entries, 4, 1);
	for (i = 0; i < 4; i++)
		printk("%s [%lu %u-%u]%pS\n", __func__, GFI_START(gfi), start,
				len, (void *)entries[i]);
#endif
	UNLOCK_GFI(gfi);
}

static inline spfs_cluster_t
__spfs_alloc_clusters_volatile(struct spfs_sb_info *sbi, spfs_cluster_t *cnt,
		bool contiguous, bool no_fail /* TODO */, bool full, int *errp)
{
	struct spfs_free_info *info = FREE_INFO(sbi);
	spfs_gfi_t *gfi = NULL;
	spfs_cluster_t start;
	int phase = -1; /* 0: random, 1: rescue */
	int i;
	bool no_gfi = S_OPTION(sbi)->no_gfi;
	
	if (!contiguous)
		*cnt = MIN(*cnt, info->cpc / 2);
again:
	*errp = 0;

	if (no_gfi) {
		gfi = info->gfi[0];
		goto group_done;
	}

	if (S_OPTION(sbi)->demotion) {
		if (phase < 2) /* final phase is 2 */
			phase++; 
		/* XXX: what is optimal waiting time? */
		if (spfs_is_usage_quite_high(info))
			usleep_range(500, 1000);
		if (spfs_is_usage_very_high(info))
			msleep(5);
	} else { 
		phase++; /* may be failed to allocate */
	}

	if (phase == 0)
		gfi = RANDOM_GFI(info);
	else if (phase == 1)
		gfi = RESCUE_GFI(info);
	else if (phase == 2) {
		bool found = false;
		int idx;
again2:
		idx = __RANDOM_GFI_IDX(info);
		for (i = 0; i < info->groups - info->num_already_full; i++) {	
			gfi = info->gfi[idx];

			if (GFI_FREE(gfi) >= *cnt) {
				spfs_debug(sbi->s_sb,
						"%s: found GFI(0x%llx) for %u",
						__func__, (u64) gfi, *cnt);
				found = true;
				break;
			}

			if (idx == info->groups - 1) 
				idx = info->num_already_full;
			else 
				idx++;
		}
		if (!found) {
			if (S_OPTION(sbi)->demotion) {
				goto again2;
			} else {
				goto out;
			}
		}
	} else
		goto out;
group_done:
	LOCK_GFI(gfi);
group_lock_done:
	if (GFI_FREE(gfi) < *cnt) {
		spfs_debug(sbi->s_sb, "%s: GFI(0x%llx, %lu) has no blocks for "
				"%u in phase %d. do again", __func__, (u64) gfi,
				GFI_START(gfi), *cnt, phase);
		if (!contiguous && *cnt != 1 && (no_gfi || phase == 1))
			*cnt >>= 1;
		if (no_gfi)
			goto group_lock_done;
		UNLOCK_GFI(gfi);
		goto again;
	}

	BUG_ON(!*cnt);

	start = bitmap_find_next_zero_area_off(GFI_BITMAP(gfi), GFI_NR(gfi),
			gfi->next_start, *cnt, 0, 0);
	if (start >= GFI_NR(gfi)) {
		gfi->next_start = 0;
		spfs_debug(sbi->s_sb, "%s: GFI(0x%llx, %lu)"
				" has no contiguous blocks for %u in"
				" phase %d.. do again", __func__, (u64) gfi,
				GFI_START(gfi), *cnt, phase);
		if (!contiguous && *cnt != 1 && (no_gfi || phase == 1))
			*cnt >>= 1;
		if (no_gfi)
			goto group_lock_done;
		UNLOCK_GFI(gfi);
		goto again;
	}

	bitmap_set(GFI_BITMAP(gfi), start, *cnt);
	SUB_GFI_FREE(gfi, *cnt);

	gfi->next_start = start + *cnt;
	if (gfi->next_start >= GFI_NR(gfi))
		gfi->next_start = 0;

#ifdef SPFS_SMALL_BLOCK
	// TODO: optimization like radix tree gang...
	for (i = 0; i < *cnt; i++) {
		struct spfs_cluster_info *c =
			cget(FREE_INFO(sbi), GO2P(gfi, start + i));

		//clu_lock(c);

		/*
		 * TODO: This situation can be due to two split phases in
		 * deallocation pass. Try to avoid it by locking temporarily.
		 * XXX: required???????
		 *
		 * T1               T2
		 * GFI_LOCK
		 * Bitmap clear
		 * GFI_UNLOCK
		 *                  GFI_LOCK
		 *                  Bitmap set
		 *                  list check!!
		 * list detach
		 */
		if (!list_empty(&c->anchor)) {
			clu_lock(c);
			CHECK_DATA_CORRUPTION(!list_empty(&c->anchor),
					"CLU %u(0x%llx)", c->index, (u64) c);
			clu_unlock(c);
		}

		clu_set_free_blocks(c, full ? 0 : BPC);
		c->bitmap = full ? BITMAP_FULL : BITMAP_IDLE;
#ifdef CLUSTER_COUNT_DEBUG
		if (full) {
			c->full.when = ktime_get();
			stack_trace_save(c->full.entries, STNR, 0);
		} else {
			c->idle.when = ktime_get();
			stack_trace_save(c->idle.entries, STNR, 0);
		}
#endif
		//clu_unlock(c);
		cput(c);
	}
#endif
	UNLOCK_GFI(gfi);

	return GO2P(gfi, start);
out:
	*errp = -ENOSPC;
	pr_err("%s: no available %u clusters in group %lu", __func__, *cnt,
			GFI_START(gfi));
	return 0;
}

/* TODO: finging rescue group in case of ENOSPC */
static inline spfs_cluster_t
spfs_alloc_clusters_volatile(struct spfs_sb_info *sbi, spfs_cluster_t *count,
		bool contiguous, bool no_fail /* TODO */, int *errp)
{
	struct spfs_free_info *info = FREE_INFO(sbi);
	spfs_cluster_t start;

	BUG_ON(!*count);

	start = __spfs_alloc_clusters_volatile(sbi, count, contiguous, no_fail,
			true, errp);
	if (!(*errp))
		sub_free_blocks(*count * BPC, info);

	return start;
}

#define DECLARE_PREFETCH(name, size, cnt)		\
	spfs_block_t name[size] = {0, };		\
	unsigned long name##_len[size] = {0, };		\
	int name##_i = 0;				\
	int name##_cnt = cnt;				\
	int name##_remain

#define PREFETCH_ALLOC_BLOCKS(sbi, name, error_exp)			\
	name##_remain = name##_cnt;					\
	do {								\
		spfs_block_t pbn;					\
		unsigned long len = name##_remain;			\
		int k;							\
									\
		pbn = spfs_alloc_blocks(sbi, &len, true, false, &ret);	\
		if (ret) {						\
			spfs_debug_err(sbi->s_sb,			\
					"can't get %lu blocks",		\
					name##_cnt);			\
			error_exp;					\
		}							\
									\
		for (k = 0; k < len; k++)				\
			name[name##_i + k] = pbn + k;			\
									\
		name##_len[name##_i] = len;				\
		name##_i += len;					\
		name##_remain -= len;					\
	} while (name##_remain)

#define ITERATE_PREFETCH(name, exp)					\
	name##_i = 0;							\
	do {								\
		if (name##_len[name##_i]) {				\
			exp;						\
		}							\
	} while (++name##_i < name##_cnt)


#define PREFETCH_COMMIT_ALLOC_BLOCKS(sbi, name)				\
	ITERATE_PREFETCH(name, spfs_commit_block_allocation(sbi,	\
				name[name##_i], name##_len[name##_i]))

#define PREFETCH_FREE_BLOCKS(sbi, name)					\
	ITERATE_PREFETCH(name, spfs_free_blocks(sbi, name[name##_i],	\
				name##_len[name##_i]))

#define PREFETCH_COMMIT_FREE_BLOCKS(sbi, name)				\
	ITERATE_PREFETCH(name, spfs_commit_block_deallocation(sbi,	\
				name[name##_i], name##_len[name##_i]))

#endif
