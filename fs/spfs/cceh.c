#include "spfs.h"
#include "calloc.h"
#include "stats.h"

struct spfs_cceh_info *(*cceh_init_funcs[])(struct spfs_sb_info *) = {
#ifdef SPFS_SMALL_BLOCK
	spfs_cceh_init_cluster_hash,
#endif
	spfs_cceh_init_namei_hash,
	spfs_cceh_data_init,
};

LIST_HEAD(ccehs);

static void spfs_cceh_init_seg(struct spfs_cceh_info *info,
		struct cceh_seg *seg, unsigned int local_depth,
		unsigned int pattern)
{
	BUG_ON(!seg);
	cceh_debug(info, "init. segment %pK", seg);

	memset(seg, 0xff, SEGMENT_SIZE);

	seg->refcount = 0;
	seg->pad = 0;
	seg->local_depth = local_depth;
	seg->pattern = pattern;
	seg->magic = info->magic;

	clwb_sfence(seg, SEGMENT_SIZE);
}

static struct cceh_seg *spfs_cceh_new_segment(struct spfs_cceh_info *info)
{
	struct cceh_seg *new_seg;
	spfs_cluster_t sc;
	spfs_cluster_t count = CPS;
	int err = 0;

	sc = spfs_alloc_clusters_volatile(info->sbi, &count, true, true, &err);
	if (err) {
		cceh_msg(info, KERN_ERR,
				"can't get %lu cluster for new segment: %d",
				count, err);
		return ERR_PTR(err);
	}
	BUG_ON(count != CPS);
	// TODO: journaling...
	spfs_alloc_clusters_durable(info->sbi, sc, count);

	new_seg = (struct cceh_seg *) clu_addr(info->sbi, sc);

	if (info->sops->s_init)
		info->sops->s_init(info, new_seg, 0, 0);
	else
		spfs_cceh_init_seg(info, new_seg, 0, 0);

	return new_seg;
}

static struct cceh_seg *spfs_cceh_split_seg(struct spfs_cceh_info *info,
		struct cceh_seg *splitting, cceh_hash_t hash)
{
	struct cceh_seg *new_seg;
	cceh_segment_t si = cceh_seg(info, hash, info->cceh->depth);
	spfs_cluster_t calc = info->dir_info.dir->s[si];
	spfs_cluster_t given = clu_idx(info->sbi, splitting);

	if (!cceh_suspend(info, splitting))
		return NULL;

	cceh_debug_split(info, "split segment %lu..%lu(%u)", given, calc, si);

	if (given != calc) {
		cceh_debug_split(info, "somebody did dir. handling between "
				"insertion and split.. again..");
		atomic_set(segment_refcount(splitting), 0);
		return NULL;
	}

	new_seg = spfs_cceh_new_segment(info);
	if (IS_ERR(new_seg))
		return new_seg;

	new_seg->local_depth = splitting->local_depth + 1;

	info->sops->s_insert4split(info, splitting, new_seg);
	clwb_sfence(new_seg, sizeof(*new_seg));

	/* TODO: crash consistency */
	splitting->local_depth++;
	clwb_sfence(&splitting->local_depth, sizeof(splitting->local_depth));

	return new_seg;
}

/*
 * 00xx, 01xx, 10xx, 11xx -> 000x, 001x, 010x, 011x, 100x, 101x, 111x
 * 00xx should be 000x(0) and 001x(1) and 01xx should be 010x(2) and 011x(3)
 */
static struct cceh_dir *spfs_cceh_dir_double(struct spfs_cceh_info *info,
		struct cceh_seg *splitting, struct cceh_seg *new_seg,
		cceh_hash_t hash)
{
	struct cceh_dir *old = info->dir_info.dir;
	struct cceh_dir *new_dir;
	spfs_cluster_t dir_cluster_cnt;
	spfs_cluster_t dc;
	int err = 0;
	struct cceh *cceh = info->cceh;
	cceh_segment_t i, si = cceh_seg(info, hash, cceh->depth);

	cceh_debug_split(info, "dir. doubling due to segment %u(%u)",
			clu_idx(info->sbi, splitting), si);

	CCEH_BUG_ON(old->s[si] != clu_idx(info->sbi, splitting));
	dir_cluster_cnt = DIR_CLUSTER_COUNT(info->cceh->depth + 1);
	CHECK_DATA_CORRUPTION(dir_cluster_cnt == 0,
			"%s: global depth %d", __func__, info->cceh->depth);
	dc = spfs_alloc_clusters_volatile(info->sbi, &dir_cluster_cnt, true,
			true, &err);
	if (err) {
		cceh_dir_print(info, NULL);
		BUG();
	}
	/* TODO: no fail allocation or other workaround */
	BUG_ON(dir_cluster_cnt != DIR_CLUSTER_COUNT(info->cceh->depth + 1));
	spfs_alloc_clusters_durable(info->sbi, dc, dir_cluster_cnt);

	new_dir = (struct cceh_dir *) clu_addr(info->sbi, dc);
	memset(new_dir, 0, CLUSTER_SIZE * dir_cluster_cnt);


	cceh_debug_level(info, 2, "(%s) cnt=%lu si=%x old=%pK new=%pK", __func__,
			dir_cluster_cnt, si, old, new_dir); 
	for (i = 0; i < 1 << cceh->depth; i++) {
		if (i == si) { /* splitted segment */
			new_dir->s[2 * i] = clu_idx(info->sbi, splitting);
			new_dir->s[2 * i + 1] = clu_idx(info->sbi, new_seg);
		} else { /* the others */
			new_dir->s[2 * i] = old->s[i];
			new_dir->s[2 * i + 1] = old->s[i];
		}

		cceh_debug_level(info, 2, "(%s) new_dir.s[%d] = %x",
				__func__, 2 * i, new_dir->s[2 * i]);
		cceh_debug_level(info, 2, "(%s) new_dir.s[%d] = %x",
				__func__, 2 * i + 1, new_dir->s[2 * i + 1]);
	}

	clwb_sfence(new_dir, sizeof(new_dir[0]) * (1UL << (cceh->depth + 1)));
	cceh->depth++;
	cceh->dir_c_idx = dc;

	info->dir_info.dir = new_dir;

	clwb_sfence(cceh, sizeof(*cceh));

	dir_cluster_cnt = DIR_CLUSTER_COUNT(cceh->depth - 1);
	cceh_debug_level(info, 0, "(%s) freeing old dir(%pK) count=%lu",
			__func__, old, dir_cluster_cnt);

	// TODO: journaling...
	spfs_free_clusters_durable(info->sbi, clu_idx(info->sbi, old),
			dir_cluster_cnt);
	spfs_free_clusters_volatile(info->sbi, clu_idx(info->sbi, old), dir_cluster_cnt,
			true);

	cceh_debug_split(info, "dir. doubling done");

	return new_dir;
}

/* refcount will be made at its first getting in both cases
 * TODO: chunk level locking
 */
static void spfs_cceh_dir_update(struct spfs_cceh_info *info,
		struct cceh_seg *splitting, struct cceh_seg *new_seg,
		cceh_hash_t hash)
{
	struct cceh *cceh = info->cceh;
	struct cceh_dir *dir = info->dir_info.dir;
	cceh_segment_t si;
	unsigned int chunk_size, i;

	cceh_debug_split(info, "dir. updating");

	si = cceh_seg(info, hash, cceh->depth);
	CCEH_BUG_ON(dir->s[si] != clu_idx(info->sbi, splitting));

	/* D:S = 1:1 */
	if (!cceh_seg_depth_gap(cceh, splitting)) {
		cceh_segment_t x = si + ((si + 1) % 2);

		dir->s[x] = clu_idx(info->sbi, new_seg);
		clwb_sfence(&dir->s[x], sizeof(dir->s[x]));

		cceh_debug_split(info, "just update s[%u] to %lu",
				x, clu_idx(info->sbi, new_seg));

		goto out;
	}

	/*
	 * depth gap is.. D:S = 1:N
	 * MSB mode
	 * 00_0_, 00_1_, 010, 011, 100, 101, 11j
	 * when segment 00 splits, 000 remains, but 001 should be moved to 001
	 */
	chunk_size = cceh_seg_chunk_size(cceh->depth,
			splitting->local_depth - 1);
	si = cceh_seg_chunk_rep(si, chunk_size);

	cceh_debug_split(info, "depth diff.. chunk_size=%u", chunk_size);
	cceh_debug_split(info, "update s[%u - %u] to %lu",
			si + chunk_size / 2, si + chunk_size - 1,
			clu_idx(info->sbi, new_seg));

	for (i = 0; i < chunk_size / 2; i++)
		dir->s[si + chunk_size / 2 + i] = clu_idx(info->sbi, new_seg);

	clwb_sfence(&dir->s[si + chunk_size / 2],
			sizeof(dir->s[0]) * chunk_size / 2);
out:
	return;
}


void *spfs_cceh_insert(struct spfs_cceh_info *info, cceh_key_t key,
		cceh_value_t value)
{
	cceh_hash_t hash;
	struct cceh_seg *seg, *new_seg;
	void *ret;

again:
	ret = ERR_PTR(-EAGAIN);
	do {
		hash = info->ops->c_hash(key);
		seg = spfs_cceh_get_seg(info, hash);

		BUG_ON(!seg);

		if (cceh_suspended(info, seg, hash))
			continue;

		ret = info->sops->s_insert(info, seg, key, value, hash);
		if (!IS_ERR(ret)) { /* normal insertion done */
			segment_inc_count(seg);
			info->sops->s_persist(info, ret);
			sput(seg);

			return ret;
		}
		sput(seg);
	} while (PTR_ERR(ret) == -EAGAIN);

	BUG_ON(PTR_ERR(ret) != -ENOSPC);

	/* split phase */
	new_seg = spfs_cceh_split_seg(info, seg, hash);
	if (!new_seg)
		goto again; /* someone is doing split */
	else if (IS_ERR(new_seg))
		return new_seg; /* -ENOSPC */

	seg->pattern = cceh_seg_pattern(hash, seg->local_depth - 1) << 1;
	clwb_sfence(&seg->pattern, sizeof(seg->pattern));
	new_seg->pattern = (cceh_seg_pattern(hash, new_seg->local_depth - 1)
		<< 1) + 1;
	clwb_sfence(&new_seg->pattern, sizeof(new_seg->pattern));

	/* exclusive directory locking */
	write_seqlock(&info->dir_info.seqlock);

	/* directory updating phase */
	if (seg->local_depth - 1 < info->cceh->depth)
		spfs_cceh_dir_update(info, seg, new_seg, hash);
	else
		spfs_cceh_dir_double(info, seg, new_seg, hash);

#ifdef CCEH_DEBUG
	cceh_dir_print(info, NULL);
#endif
	/* release suspend */
	atomic_set(segment_refcount(seg), 0);

	write_sequnlock(&info->dir_info.seqlock);

	goto again;

	return NULL; /* not reachable */
}

void *spfs_cceh_get(struct spfs_cceh_info *info, cceh_key_t key)
{
	cceh_hash_t hash;
	void *ret = ERR_PTR(-EAGAIN);
	struct cceh_seg *seg;

	do {
		hash = info->ops->c_hash(key);
		seg = spfs_cceh_get_seg(info, hash);

		if (cceh_suspended(info, seg, hash))
			continue;

		ret = info->sops->s_get(info, seg, key, hash);
		sput(seg);
		if (!IS_ERR(ret))
			return ret;

	} while (PTR_ERR(ret) == -EAGAIN);

	return NULL;
}

bool spfs_cceh_revalidate(struct spfs_cceh_info *info, cceh_query_t query)
{
	BUG_ON(!info->sops->s_revalidate);
	return info->sops->s_revalidate(info, query);
}

/* TODO: shrinking segments and directories */
int __spfs_cceh_delete(struct spfs_cceh_info *info, cceh_query_t q,
		void *cached_slot)
{
	cceh_hash_t hash;
	struct cceh_seg *seg;
	void *ret = ERR_PTR(-EAGAIN);

	do {
		hash = info->ops->c_hash(q);
		seg = spfs_cceh_get_seg(info, hash);

		if (cceh_suspended(info, seg, hash))
			continue;

		if (info->fast_path && cached_slot &&
				info->sops->s_fast_delete &&
				cceh_segment_hold_slot(seg, cached_slot))
			ret = info->sops->s_fast_delete(info, cached_slot);
		else
			ret = info->sops->s_delete(info, seg, q, hash);
	} while (PTR_ERR(ret) == -EAGAIN);

	if (!IS_ERR(ret)) {
		segment_dec_count(seg);
		info->sops->s_persist(info, ret);
	}
	sput(seg);

	return IS_ERR(ret) ? PTR_ERR(ret) : 0;
}

void *spfs_cceh_update(struct spfs_cceh_info *info, cceh_query_t q, void *slot,
		cceh_value_t v)
{
	cceh_hash_t hash;
	struct cceh_seg *seg;
	void *ret = ERR_PTR(-EAGAIN);

	do {
		hash = info->ops->c_hash(q);
		seg = spfs_cceh_get_seg(info, hash);

		if (cceh_suspended(info, seg, hash))
			continue;

		if (info->fast_path && info->sops->s_fast_update &&
				cceh_segment_hold_slot(seg, slot))
			ret = info->sops->s_fast_update(info, q, slot, v);
		else
			ret = info->sops->s_update(info, seg, q, v, hash);
	} while (ret == ERR_PTR(-EAGAIN));

	if (!IS_ERR(ret))
		info->sops->s_persist(info, ret);
	sput(seg);

	return ret;
}

void spfs_cceh_init_segments(struct spfs_cceh_info *info, unsigned int depth)
{
	struct spfs_sb_info *sbi = info->sbi;
	struct cceh_dir *dir;
	struct cceh_seg *seg;
	int i;

	for (i = 0; i < __cceh_dir_capa(depth); i++) {
		dir = clu_addr(sbi, info->cceh->dir_c_idx);
		seg = clu_addr(sbi, dir->s[i]);

		if (info->sops->s_init)
			info->sops->s_init(info, seg, depth, i);
		else
			spfs_cceh_init_seg(info, seg, depth, i);

		cond_resched();
	}

	info->cceh->depth = depth;
}

int spfs_cceh_init(struct spfs_sb_info *sbi)
{
	int i;
	struct spfs_cceh_info *info;

	spfs_msg(sbi->s_sb, KERN_INFO, "init. CCEH");

	for (i = 0; i < sizeof(cceh_init_funcs) / sizeof(cceh_init_funcs[0]);
			i++) {
		info = cceh_init_funcs[i](sbi);

		if (cceh_need_format(info)) {
			if (info->ops->c_init_segments)
				info->ops->c_init_segments();
			else
				spfs_cceh_init_segments(info, 0);
		}
		cceh_debug(info, "CCEH init. done.. %llu %u", info->cceh->depth,
				info->cceh->dir_c_idx);

		info->dir_info.dir = clu_addr(sbi, info->cceh->dir_c_idx);
		seqlock_init(&info->dir_info.seqlock);

		INIT_LIST_HEAD(&info->list);
		list_add_tail(&info->list, &ccehs);

		info->fast_path = S_OPTION(sbi)->cceh_fast_path;
	}
		
	return 0;
}

// TODO: have to deal with uninitialized release
int spfs_cceh_exit(struct spfs_sb_info *sbi)
{
	struct list_head *pos, *n;
	struct spfs_cceh_info *info;

	list_for_each_safe(pos, n, &ccehs) {
		info = list_entry(pos, struct spfs_cceh_info, list);

		kfree(info->name);
		
		list_del_init(&info->list);
	}

	return 0;
}

void spfs_cceh_insert4split(struct spfs_cceh_info *info,
		struct cceh_seg *splitting, struct cceh_seg *new_seg,
		unsigned int index, cceh_slot_t *old)
{
	unsigned int i;
	struct cceh_key_value *kv;

	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		kv = cceh_seg_nth_item(new_seg, lp_slot(info, index, i),
				sizeof(*kv));

		/* empty slot */
		if (kv->k == (u64) INVALID) {
			kv->k = old->k;
			kv->v = old->v;
			segment_mov_count(splitting, new_seg);
			return;
		}
	}

	BUG();
}

void __cceh_msg(struct spfs_cceh_info *info, const char *level, const char *fmt,
		...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk("%sspfs CCEH(%s): %pV\n", level, info->name, &vaf);
	va_end(args);
}
