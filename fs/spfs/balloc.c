#include "calloc.h"
#include "balloc.h"
#include "stats.h"


static struct kmem_cache *spfs_cluster_info_cachep;

static const unsigned char bits_weight_table[256] =
{
#define B2(n) n,	n + 1,		n + 1,		n + 2
#define B4(n) B2(n),	B2(n + 1),	B2(n + 1),	B2(n + 2)
#define B6(n) B4(n),	B4(n + 1),	B4(n + 1),	B4(n + 2)
	B6(0), B6(1), B6(1), B6(2)
};

/* XXX: better than hweight16()? */
int clu_get_durable_free(struct spfs_cluster_info *c)
{
	u16 v = c->usage->bitmap;
	return bits_weight_table[v & 0xff] + bits_weight_table[(v >> 8) & 0xff];
}

void __cput(struct spfs_cluster_info *c)
{
	spfs_gfi_t *gfi = CINFO_GFI(c);

	GFI_CLUSTERS(gfi)[c->index - GFI_START(gfi)] = NULL;
	kmem_cache_free(spfs_cluster_info_cachep, c);
}

/* return true, if it has become idle */
bool clu_add_free_blocks(struct spfs_free_info *info,
		struct spfs_cluster_info *c, int count)
{
	clu_cnt_debug("[ADD] %d in CLU %u(%d)",
			count, c->index, clu_get_free_blocks(c));

	BUG_ON(clu_get_free_blocks(c) >= BPC); // already idle

	if ((c->free_blocks_count += count) == BPC)
		return true;
	return false;
}

void clu_sub_free_blocks(struct spfs_free_info *info,
		struct spfs_cluster_info *c, int count)
{
	clu_cnt_debug("[SUB] %d in CLU %u(%d)",
			count, c->index, clu_get_free_blocks(c));

	BUG_ON(clu_get_free_blocks(c) <= 0);
	c->free_blocks_count -= count;
}

/*
 * return grabbed but not locked cluster info
 * TODO: phase concept for cluster group
 */
static struct spfs_cluster_info *
__spfs_calloc_get_available_cluster(struct spfs_free_info *info,
		unsigned long count)
{
#ifndef CONFIG_SPFS_UNIFIED_PCL
	int i;
#endif
	struct spfs_cluster_info *candidate;
	struct list_head *pos;
	bool found = false;
	spfs_gfi_t *gfi = CPU_GFI(info);

	SPFS_BUG_ON(count >= BPC);
	SPFS_BUG_ON(count == 0);
#ifndef CONFIG_SPFS_UNIFIED_PCL
again:
	/* XXX: starting from high list? */
	for (i = count, found = false; i < BPC && !found; i++) {
		if (list_empty(GFI_PCL(gfi, i)))
			continue;
#endif

		LOCK_GFI_PCL(gfi, i);
		list_for_each(pos, GFI_PCL(gfi, i)) {
			candidate = __cget(list_entry(pos,
						struct spfs_cluster_info,
						anchor));
			if (!candidate)
				continue;

			if (clu_get_free_blocks(candidate) < count) {
				cput(candidate);
				continue;
			}

			found = true;
			break; /* found */
		}
		UNLOCK_GFI_PCL(gfi, i);
#ifndef CONFIG_SPFS_UNIFIED_PCL
	}
#endif

	if (!found)
		goto out;

	clu_lock(candidate);
	if (clu_idle_or_full(candidate) ||
			clu_get_free_blocks(candidate) < count) {
		clu_unlock(candidate);
		cput(candidate);
#ifndef CONFIG_SPFS_UNIFIED_PCL
		/* do again from the list has more free blocks than want */
		if (++count < BPC)
			goto again;
		else
#endif
			found = false;
	}
	// SPFS_BUG_ON(!clu_used(candidate)); // usage is durable data
out:
	return found ? candidate : ERR_PTR(-ENOSPC);
}

/* Return LOCKED and GRABBED cluster info. */
static struct spfs_cluster_info *
spfs_calloc_get_available_cluster(struct spfs_sb_info *sbi, unsigned long count)
{
	struct spfs_free_info *info = FREE_INFO(sbi);
	struct spfs_cluster_info *c;
	int err = 0;
	spfs_cluster_t start;
	spfs_cluster_t n_clu = 1;

	c = __spfs_calloc_get_available_cluster(info, count);
	if (!IS_ERR(c)) /* found */
		goto out;

	/* No available cluster in list. Let's use idle one instead */
	start = __spfs_alloc_clusters_volatile(sbi, &n_clu, false, false, false,
			&err);
	if (err) {
		c = ERR_PTR(-ENOSPC);
		goto out;
	}

	c = cget(info, start); /* GRAB */
	clu_lock(c); /* LOCK */
out:
	return c;
}

/* Memory barrier operation relies on lock, which is implicit barrier */
int spfs_clu_update_usage(struct spfs_cceh_info *info,
		struct spfs_cluster_info *c, spfs_block_t blknr,
		unsigned long len, bool set)
{
	SPFS_BUG_ON(!c->usage);

//	/*
//	 * just point usage to valid PM location...
//	 * we have done all things through dram cached bitmap
//	 */
//	if (!spfs_cceh_revalidate(info, c->usage))
//		c->usage = spfs_cceh_get(info, VOID_PTR(c->index));

	if (set)
		bitmap_set(clu_usage_bitmap(c), BIIC(blknr), len);
	else
		bitmap_clear(clu_usage_bitmap(c), BIIC(blknr), len);
	_clwb(clu_usage_bitmap(c), sizeof(unsigned short));

	return clu_get_durable_free(c);
}

/*
 * Only partial clusters can be here.
 * free count can't be changed because it's protected by rwsem of cluster.
 */
static int __spfs_anchor_cluster_locked(struct spfs_cluster_info *c)
{
#ifndef CONFIG_SPFS_UNIFIED_PCL
	int free = clu_get_free_blocks(c);
#endif
	lockdep_assert_held(&c->lock);

	SPFS_BUG_ON(free == 0 || free == BPC);
	SPFS_BUG_ON(c->current_pcl);
	SPFS_BUG_ON(c->current_pcl_lock);
	SPFS_BUG_ON(!list_empty(&c->anchor));

	CINFO_PCL(c) = GFI_PCL(CINFO_GFI(c), free);
	CINFO_PCL_LOCK(c) = GFI_PCL_LOCK(CINFO_GFI(c), free);

	LOCK_CINFO_PCL(c);

	pcl_debug("\t[LIST ADD] CLU %u(0x%llx) to %d", c->index, (u64) c, free);
	pcl_stack_trace("\t\t[LIST ADD]", c, free);

	list_add_tail(&c->anchor, CINFO_PCL(c));

	UNLOCK_CINFO_PCL(c);

	__cget(c); // grab reference for list

	return 0;
}

static void spfs_detach_cluster(struct spfs_cluster_info *c, int past_free)
{
	if (!list_empty(&c->anchor)) {
		/* TODO: clarify the refcount of cluster. for list and tree */
		SPFS_BUG_ON(atomic_read(&c->refcount) == 1);

		LOCK_CINFO_PCL(c);

		pcl_debug("\t[LIST DEL] CLU %u(0x%llx) to %d", c->index,
				(u64) c, past_free);
		pcl_stack_trace("\t\t[LIST DEL]", c, past_free);

		list_del_init(&c->anchor);

		UNLOCK_CINFO_PCL(c);

		CINFO_PCL(c) = NULL;
		CINFO_PCL_LOCK(c) = NULL;

		cput(c);
	} else {
		SPFS_BUG_ON(past_free != 0 && past_free != BPC);
	}
}

/*
 * free count of cluster is protected by rwsem
 * Note taht extra ref. count must be grabbed for list moving. However, we dont'
 * need to care because of the radix tree.
 */
static int spfs_anchor_cluster_locked(struct spfs_free_info *info,
		struct spfs_cluster_info *c, int past_free)
{
	lockdep_assert_held(&c->lock);
#ifdef CONFIG_SPFS_UNIFIED_PCL
	if (clu_idle_or_full(c))
		spfs_detach_cluster(c, past_free);
	return 0;
#else
	spfs_detach_cluster(c, past_free);

	/* was CLUSTER_USED but is FULL or IDLE */
	if (clu_idle_or_full(c))
		return 0;

	/* anchor to list */
	return __spfs_anchor_cluster_locked(c);
#endif
}

/* protected by .rwsem */
static spfs_block_t spfs_use_free_block_locked(struct spfs_free_info *info,
		struct spfs_cluster_info *c, unsigned long cnt, int *errp)
{
	int start;
	int past_free = clu_get_free_blocks(c);

	lockdep_assert_held(&c->lock);

	start = bitmap_find_next_zero_area_off((unsigned long *) &c->bitmap,
			BPC, 0, cnt, 0, 0);
	if (start >= BPC) {
		*errp = -ENOSPC;
		goto out;
	}

	bitmap_set((unsigned long *) &c->bitmap, start, cnt);

	clu_sub_free_blocks(info, c, cnt);
	CHECK_DATA_CORRUPTION(clu_get_free_blocks(c) !=
			BPC - bitmap_weight((unsigned long *) &c->bitmap, BPC),
			"mismatch of count(%d) and bitmap(0x%x)",
			clu_get_free_blocks(c), c->bitmap);
	sub_free_blocks(cnt, info);
#ifdef CLUSTER_COUNT_DEBUG
	if (clu_full(c)) {
		c->full.when = ktime_get();
		stack_trace_save(c->full.entries, STNR, 0);
	}
#endif
	spfs_anchor_cluster_locked(info, c, past_free);
out:
	return C2B(c->index) + start;
}

static struct spfs_cluster_usage *spfs_insert_cluster_usage(void *hash,
		spfs_block_t blknr, int len, bool idle)
{
	unsigned short bitmap;

	if (idle) {
		bitmap = 0;
		bitmap_set((unsigned long *) &bitmap, BIIC(blknr), len);
	} else {
		bitmap = 0xffff;
		bitmap_clear((unsigned long *) &bitmap, BIIC(blknr), len);
	}
	return spfs_cceh_insert(hash, VOID_PTR(B2C(blknr)), bitmap);
}

/* volatile block allocation */
spfs_block_t spfs_alloc_blocks(struct spfs_sb_info *sbi, unsigned long *count,
		bool contiguous, bool no_fail /* TODO */, int *errp)
{
	struct spfs_free_info *info = FREE_INFO(sbi);
	spfs_block_t start;
	struct spfs_cluster_info *c;

	BUG_ON(!*count);

	if (*count >= BPC) {
		spfs_cluster_t clu_start;
		spfs_cluster_t clu_count;

		do {
			*count = ALIGN_DOWN(*count, BPC);
			clu_count = B2C(*count);
			// must try (1) cpu, (2) rescue and (3) linear search
			clu_start = spfs_alloc_clusters_volatile(sbi,
					&clu_count, contiguous, no_fail, errp);
			if (*errp) {
				*count >>= 1;
				continue;
			}

			if (clu_count != B2C(*count))
				*count = C2B(clu_count);

			start = C2B(clu_start);

			goto out;
		} while (*count >= BPC);

		/* fallback to small allocation */
	}
again:
	*errp = 0;
	while (spfs_claim_free_blocks(sbi, *count, false)) {
		spfs_debug_err(sbi->s_sb, "half %lu blocks", *count);
		if ((*count >>= 1) == 0) {
			*errp = -ENOSPC;
			goto out;
		}
	}

	/*
	 * Find a cluster which can service *count blocks.
	 * spfs_find_available_cluster returns locked cluster info.
	 */
	c = spfs_calloc_get_available_cluster(sbi, *count);
	if (IS_ERR_OR_NULL(c)) {
		spfs_debug_err(sbi->s_sb,
				"can't get cluster can serve %lu blocks: %d",
				*count, PTR_ERR(c));
		*errp = PTR_ERR(c);
		goto out;
	}

	/* Got LOCKED and GRABBED cluster */

	if (clu_idle(c)) {
		CHECK_DATA_CORRUPTION(c->bitmap != BITMAP_IDLE,
				"mismatch of count(%d) and bitmap(0x%x)",
				clu_get_free_blocks(c), c->bitmap);

		start = C2B(c->index);

		bitmap_set((unsigned long *) &c->bitmap, 0, *count);

		clu_sub_free_blocks(info, c, *count);
		sub_free_blocks(*count, info);

		/* link to proper partial list according to its free count */
		__spfs_anchor_cluster_locked(c);

	} else {
		CHECK_DATA_CORRUPTION(clu_full(c) || c->bitmap == BITMAP_FULL ||
				c->bitmap == BITMAP_IDLE,
				"mismatch of count(%d) and bitmap(0x%x)",
				clu_get_free_blocks(c), c->bitmap);

		start = spfs_use_free_block_locked(info, c, *count, errp);
		if (*errp) {
			/*
			 * 11101101, for example, has 2 free blocks but not
			 * contiguous.
			 * TODO: optimization
			 */
			if ((*count >>= 1)) {
				clu_unlock(c);
				cput(c);
				goto again;
			}
		}
	}

	clu_unlock(c);
	cput(c); /* against spfs_calloc_available_cluster() */
out:
	return *errp ? 0 : start;
}


int __spfs_commit_block_deallocation(struct spfs_free_info *info,
		spfs_block_t start, unsigned long len)
{
	struct spfs_cluster_info *c;
	bool was_full, is_idle;
	int past_free;

	c = cget(info, B2C(start));

	clu_lock(c); /* L O C K */

	BUG_ON(clu_idle(c));
	past_free = clu_get_free_blocks(c);

	was_full = clu_full(c);
	is_idle = clu_add_free_blocks(info, c, len);

	if (was_full && is_idle) {
#ifdef CLUSTER_COUNT_DEBUG
		c->idle.when = ktime_get();
		stack_trace_save(c->idle.entries, STNR, 0);
#endif
		spfs_free_clusters_volatile(info->sbi, c->index, 1, false);
		goto out;
	}

	if (is_idle) {
#ifdef CLUSTER_COUNT_DEBUG
		c->idle.when = ktime_get();
		stack_trace_save(c->idle.entries, STNR, 0);
#endif
		spfs_free_clusters_volatile(info->sbi, c->index, 1, false);
	} else {
		bitmap_clear((unsigned long *) &c->bitmap, BIIC(start), len);
		CHECK_DATA_CORRUPTION(c->bitmap == BITMAP_IDLE,
				"inconsistent bitmap 0x%x, %d", c->bitmap,
				clu_get_free_blocks(c));
	}

	spfs_anchor_cluster_locked(info, c, past_free);
out:
	clu_unlock(c);
	add_free_blocks(len, info);
	cput(c);

	return len;
}

int spfs_commit_block_deallocation(struct spfs_sb_info *sbi,
		spfs_block_t start, unsigned long len)
{
	cluster_aligned_op(sbi, start, len, __spfs_commit_block_deallocation,
			spfs_free_clusters_volatile(sbi, s, count, true));
	return 0;
}

/*
 *      | IDLE                      | USED                           | FULL
 * IDLE | x                         | x                              | x
 * USED | usage del., anchoring (1) | usage updating, anchoring  (2) | x
 * FULL | clu. bit clearing     (3) | usage insertion, anchoring (4) | -
 */
static int __spfs_free_blocks(struct spfs_free_info *info,
		spfs_block_t start, unsigned long len)
{
	struct spfs_cluster_info *c;
	bool was_full, is_idle = false;

	c = cget(info, B2C(start));
	clu_lock(c); /* L O C K */

	was_full = !clu_used(c);

	/* USED -> IDLE */
	if (!was_full && spfs_clu_update_usage(info->hash, c, start, len,
				false) == BPC)
		is_idle = true;
	else if (len == BPC)
		is_idle = true;

	if (was_full && is_idle) { // case (3)
		spfs_free_clusters_durable(info->sbi, c->index, 1);
		goto out;
	}

	// 비트맵을 항상 동기화 하는 것으로 변경..
	/* TODO: branch prediction */
	if (was_full) // case (4)
		c->usage = spfs_insert_cluster_usage(info->hash, start, len,
				false);
	else if (is_idle) { // case (1)
		spfs_delete_cluster_usage(info->hash, c);
		c->usage = NULL;
		spfs_free_clusters_durable(info->sbi, c->index, 1);
	} else // case (2)
		spfs_clu_update_usage(info->hash, c, start, len, false);
out:
	clu_unlock(c);
	cput(c);

	return len;
}

int spfs_free_blocks(struct spfs_sb_info *sbi, spfs_block_t start,
		unsigned long len)
{
	cluster_aligned_op(sbi, start, len, __spfs_free_blocks,
			spfs_free_clusters_durable(sbi, s, count));
	return 0;
}

int __spfs_commit_block_allocation(struct spfs_free_info *info,
		spfs_block_t start, unsigned long len)
{
	struct spfs_cluster_info *c;
	bool was_idle, is_full = false;

	c = cget(info, B2C(start));
	clu_lock(c);

	was_idle = !clu_used(c);
	
	if (!was_idle && spfs_clu_update_usage(info->hash, c, start, len,
				true) == 0)
		is_full = true;
	else if (len == BPC)
		is_full = true;

	if (was_idle && is_full) {
		spfs_alloc_clusters_durable(info->sbi, c->index, 1);
		goto out;
	}

	if (was_idle) { // USED
		c->usage = spfs_insert_cluster_usage(info->hash, start, len,
				true);
		spfs_alloc_clusters_durable(info->sbi, c->index, 1);
	} else if (is_full) {
		spfs_delete_cluster_usage(info->hash, c);
		c->usage = NULL;
	} else
		spfs_clu_update_usage(info->hash, c, start, len, true);
out:
	clu_unlock(c);
	cput(c);

	return len;
}

int spfs_commit_block_allocation(struct spfs_sb_info *sbi, spfs_block_t start,
		unsigned long len)
{
	cluster_aligned_op(sbi, start ,len, __spfs_commit_block_allocation,
			spfs_alloc_clusters_durable(sbi, s, count));
	return 0;
}

/*
 *      | radix tree | lnked list | usage info | refcount |
 * IDLE |      O     |      X     |      X     |    1     |
 * USED |      O     |      O     |      O     |    2     |
 * FULL |      O     |      X     |      X     |    1     |
 *
 * This returns the number of free blocks in cluster.
 */
static int __spfs_clu_init(struct spfs_free_info *info,
		struct spfs_cluster_info *c, spfs_cluster_t pcn,
		struct spfs_cluster_usage *u, int type)
{
	memset(c, 0, sizeof(*c));

	INIT_LIST_HEAD(&c->anchor);

	spin_lock_init(&c->lock);

	CINFO_GFI(c) = PCN_GFI(info, pcn);

	/* One for cluster radix tree */
	atomic_set(&c->refcount, 1);
	c->index = pcn;

	if (!u) {
		if (type == CLUSTER_IDLE) {
			clu_set_free_blocks(c, BPC);
			goto out;
		}

		c->bitmap = BITMAP_FULL;
		return 0;
	}

	BUG_ON(pcn != le32_to_cpu(u->pcn));

	c->usage = u;
	c->bitmap = u->bitmap;
	clu_set_free_blocks(c, clu_get_durable_free(c));
out:
	return clu_get_free_blocks(c);
}

static int spfs_balloc_init_cluster(struct spfs_free_info *info,
		struct spfs_cluster_info *c, spfs_cluster_t pcn)
{
	struct spfs_cluster_usage *u = spfs_cceh_get(info->hash, VOID_PTR(pcn));
	return __spfs_clu_init(info, c, pcn, u,
			u ? CLUSTER_USED : CLUSTER_FULL);
}

/* done exclusively at mount time */
int spfs_init_group_clusters(struct spfs_free_info *info, spfs_gfi_t *gfi)
{
	spfs_cluster_t i;
	spfs_cluster_t pcn;
	struct spfs_cluster_info *c;
	int free;

	for (i = 0; i < GFI_NR(gfi); i++) {
		pcn = GO2P(gfi, i);

		c = kmem_cache_alloc(spfs_cluster_info_cachep, GFP_KERNEL);
		if (!c)
			return -ENOMEM;

		/* CLUSTER_IDLE */
		if (!test_bit(i, GFI_BITMAP(gfi))) {
			__spfs_clu_init(info, c, pcn, NULL, CLUSTER_IDLE);
			add_free_blocks(BPC, info);
			INC_GFI_FREE(gfi);
		} else {
			free = spfs_balloc_init_cluster(info, c, pcn);
			add_free_blocks(free, info);

			if (clu_used(c))
				__spfs_anchor_cluster_locked(c);
		}

		/* cache all cluster types */
		GFI_CLUSTERS(gfi)[pcn - GFI_START(gfi)] = c;

		if (!(i % (info->clusters_count / 10)))
			cond_resched();
	}

	return 0;
}

/* should be run exclusively */
void spfs_exit_group_clusters(struct spfs_free_info *info, spfs_gfi_t *gfi)
{
	spfs_cluster_t i = 0;

	for (i = 0; i < GFI_NR(gfi); i++)
		__cput(GFI_CLUSTERS(gfi)[i]);

	kvfree(GFI_CLUSTERS(gfi));
}

int spfs_init_cluster_cache(void)
{
	spfs_cluster_info_cachep = kmem_cache_create("spfs_cluster_cache",
			sizeof(struct spfs_cluster_info), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);
	if (!spfs_cluster_info_cachep) {
		pr_err("%s: can't create cluster cache", __func__);
		return -ENOMEM;
	}

	return 0;
}

void spfs_destroy_cluster_cache(void)
{
	kmem_cache_destroy(spfs_cluster_info_cachep);
}
