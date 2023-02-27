#ifndef _BALLOC_H_
#define _BALLOC_H_

#include <linux/bitops.h>
#include <linux/bitmap.h>

#include "spfs.h"
#include "stats.h"


#define BITMAP_FULL			((1 << BPC) - 1)
#define BITMAP_IDLE			0

#define stack_trace_save(_entries, _max_entries, _skip) do {		\
	struct stack_trace trace = {					\
		.nr_entries = 0,					\
		.entries = _entries,					\
		.max_entries = _max_entries,				\
		.skip = _skip						\
	};								\
	save_stack_trace(&trace);					\
} while (0)


//#define PCL_DEBUG
#ifdef PCL_DEBUG
#define pcl_debug(fmt, ...)		pr_err(fmt, ##__VA_ARGS__)
#define pcl_stack_trace(h, c, f)	do {				\
	unsigned long entries[3];					\
	int i;								\
	stack_trace_save(entries, 3, 1);				\
	for (i = 0; i < 3; i++) {					\
		printk("%s CLU %u(0x%llx) - %d %pS\n", h,		\
				(c)->index, (u64) (c), (f),		\
				(void *)entries[i]);			\
	}								\
} while (0)
#else
#define pcl_debug(fmt, ...)		do {} while (0)
#define pcl_stack_trace(h, c, f)	do {} while (0)
#endif

//#define CLUSTER_COUNT_DEBUG
#ifdef CLUSTER_COUNT_DEBUG
#define STNR 16
struct stack_trace_info {
	ktime_t		when;
	unsigned long	entries[STNR];
};
//#define clu_cnt_debug(fmt, ...)		pr_err(fmt, ##__VA_ARGS__)
#define clu_cnt_debug(fmt, ...)		do {} while (0)
#else
#define clu_cnt_debug(fmt, ...)		do {} while (0)
#endif

/* it keeps block usage information for clusters */
struct spfs_cluster_usage {
	__le32	pcn;
	__le16	bitmap;
	__le16	pad;
} __attribute((__packed__));

#define CLUSTER_IDLE	0
#define CLUSTER_USED	1
#define CLUSTER_FULL	2

#define CLUSTER_FREEING	(1 << 0)

#define CLUSTER_ALIGNED(b)	(!BIIC(b))
#define FREE_LEN(blknr, len)	(MIN(len, BPC - BIIC(blknr)))

struct spfs_cluster_info {
	spfs_gfi_t			*gfi;

	struct list_head		*current_pcl;
	spinlock_t			*current_pcl_lock;
	struct list_head		anchor; /* free_info.free_list */

	int				flags;
	atomic_t			refcount;
	spfs_cluster_t			index;

	/*
	 * Information about free block in cluster. These must not be used for
	 * idle and full clusters.
	 */
	int				free_blocks_count;
	unsigned short			bitmap; // copy of PM bitmap
	struct spfs_cluster_usage	*usage;

	spinlock_t			lock;
#ifdef CLUSTER_COUNT_DEBUG
	struct stack_trace_info		get[5];
	struct stack_trace_info		put[5];
	struct stack_trace_info		full;
	struct stack_trace_info		idle;
#endif
};

#define CINFO_GFI(c)		((c)->gfi)
#define CINFO_PCL(c)		((c)->current_pcl)
#define CINFO_PCL_LOCK(c)	((c)->current_pcl_lock)
#define LOCK_CINFO_PCL(c)	spin_lock(CINFO_PCL_LOCK(c))
#define UNLOCK_CINFO_PCL(c)	spin_unlock(CINFO_PCL_LOCK(c))



#define clu_get_free_blocks(c)		((c)->free_blocks_count)
#define clu_set_free_blocks(c, count)	do {				\
	SPFS_BUG_ON(count > BPC);					\
	clu_cnt_debug("\t%s(%d) [SET] %d in CLU %u(%d)", __func__,	\
			__LINE__, (int) count, c->index,		\
			clu_get_free_blocks(c));			\
	(c)->free_blocks_count = count;					\
} while (0)

#define clu_usage_bitmap(c)		((unsigned long *) &(c)->usage->bitmap)

#define clu_lock(c)		spin_lock(&c->lock)
#ifdef SPFS_DEBUG
#define clu_unlock(c)		do {		\
	assert_spin_locked(&(c)->lock);		\
	spin_unlock(&(c)->lock);		\
} while (0)
#else
#define clu_unlock(c)		spin_unlock(&c->lock)
#endif

#define clu_used(c)		((c)->usage != NULL)
#define clu_idle(c)		(clu_get_free_blocks((c)) == BPC)
#define clu_full(c)		(clu_get_free_blocks(c) == 0)
#define clu_idle_or_full(c)	(clu_idle(c) || clu_full(c))

static inline int spfs_delete_cluster_usage(struct spfs_cceh_info *hash,
		struct spfs_cluster_info *ci)
{
	struct spfs_cluster_usage *cu = ci->usage;

	/*
	 * fast path
	 * TODO: further revalidation.. we may delete stale slot..
	 */
	if (cu->pcn == ci->index) {
		cu->pcn = INVALID;
		/*
		 * make it visible to the other CPUs
		 * spinlock will be implicit barrier(XXX: really?) */
		_clwb(cu, sizeof(struct spfs_cluster_usage));
		return 0;
	}

	return spfs_cceh_delete(hash, VOID_PTR(ci->index));
}

#define FREE_HASH(sbi)	(FREE_INFO(sbi)->hash)

extern void __cput(struct spfs_cluster_info *);

static inline void cput(struct spfs_cluster_info *c)
{
	if (c->flags & CLUSTER_FREEING)
		return;

#ifdef CLUSTER_COUNT_DEBUG
	c->put[atomic_read(&c->refcount)].when = ktime_get();
	stack_trace_save(c->put[atomic_read(&c->refcount)].entries, STNR, 0);
#endif
	if (atomic_dec_and_test(&c->refcount)) {
		pr_err("%s: 0x%llx", __func__, (u64) c);
		/* must be detached when moving free list */
		BUG_ON(!list_empty(&c->anchor));

		c->flags |= CLUSTER_FREEING;
		__cput(c);
	}
}

static struct spfs_cluster_info *__cget(struct spfs_cluster_info *c)
{
#ifdef CLUSTER_COUNT_DEBUG
	c->get[atomic_read(&c->refcount)].when = ktime_get();
	stack_trace_save(c->get[atomic_read(&c->refcount)].entries, STNR, 0);
#endif
	atomic_inc(&c->refcount);

	/* give up to use... TODO: atomic bit operation */
	if (c->flags & CLUSTER_FREEING) {
		cput(c);
		return NULL;
	}

	return c;
}

static inline struct spfs_cluster_info *cget(struct spfs_free_info *info,
		spfs_cluster_t pcn)
{
	struct spfs_cluster_info *c = NULL;
	spfs_gfi_t *gfi = PCN_GFI(info, pcn);

	c = GFI_CLUSTERS(gfi)[pcn - GFI_START(gfi)];
	SPFS_BUG_ON(!c); // TODO: on-demand cacheing...
	
	return __cget(c);
}

extern spfs_block_t spfs_alloc_blocks(struct spfs_sb_info *, unsigned long *,
		bool, bool, int *);

static inline spfs_block_t spfs_alloc_block(struct spfs_sb_info *sbi,
		bool no_fail, int *errp)
{
	unsigned long count = 1;
	return spfs_alloc_blocks(sbi, &count, false, no_fail, errp);
}

extern int spfs_commit_block_allocation(struct spfs_sb_info *, spfs_block_t,
		unsigned long);
extern int spfs_commit_block_deallocation(struct spfs_sb_info *, spfs_block_t,
		unsigned long);

extern int spfs_free_blocks(struct spfs_sb_info *, spfs_block_t, unsigned long);
extern int spfs_clu_update_usage(struct spfs_cceh_info *,
		struct spfs_cluster_info *, spfs_block_t, unsigned long, bool);
extern bool clu_add_free_blocks(struct spfs_free_info *,
		struct spfs_cluster_info *, int);
extern void clu_sub_free_blocks(struct spfs_free_info *,
		struct spfs_cluster_info *, int);
extern int spfs_init_group_clusters(struct spfs_free_info *, spfs_gfi_t *);
extern void spfs_exit_group_clusters(struct spfs_free_info *, spfs_gfi_t *);
extern int clu_get_durable_free(struct spfs_cluster_info *);

#define cluster_aligned_op(sbi, start, len, partial, full) do {		\
	struct spfs_free_info *info = FREE_INFO(sbi);			\
	spfs_cluster_t s = B2C(start), e = B2C(start + len - 1);	\
	unsigned long count = e - s + 1;				\
									\
	if (!CLUSTER_ALIGNED(start)) {					\
		len -= partial(info, start,				\
				MIN(BPC - BIIC(start), len));		\
		start = C2B(++s);					\
		count--;						\
	}								\
									\
	if (!CLUSTER_ALIGNED(start + len)) {				\
		len -= partial(info, C2B(e--), len % BPC);		\
		count--;						\
	}								\
									\
	BUG_ON(!(CLUSTER_ALIGNED(start) &&				\
				CLUSTER_ALIGNED(start + len)));		\
	if (len) {							\
		full;							\
	}								\
} while (0)

#endif
