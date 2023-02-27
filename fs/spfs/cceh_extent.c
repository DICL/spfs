#include "cceh_extent.h"
#include "stats.h"

#include <linux/swab.h>


struct spfs_cceh_info spfs_cceh_data_info;

/*
 * TODO: If the number of extents is large enough to fill the segment due to
 * severe fragmentation, the split becomes no effect. In this case, we should
 * use a method like chaining.
 */
static cceh_hash_t spfs_cceh_data_hash(cceh_key_t key)
{
	struct cceh_extent_query *info = (struct cceh_extent_query *) key;
	return (((u64) info->inode->i_ino * info->inode->i_ino) |
			swab32(info->lcn / info->max_extent_len)) % 0xffffffff;
}

static void spfs_cceh_data_insert4split(struct spfs_cceh_info *info,
		struct cceh_seg *splitting, struct cceh_seg *new_seg)
{
	unsigned int i;
	cceh_es_t *es;

	for (i = 0; i < info->pps; i++) {
		es = cceh_cast_slot(splitting, i, cceh_es_t);

		if (es->key == INVALID)
			continue;

		/* copy slots masked by new pattern */
		if (cceh_seg_hash_mask(es->key, splitting->local_depth + 1)) {
			__spfs_cceh_extent_insert4split(info, new_seg, es);
			segment_mov_count(splitting, new_seg);
		}

		cond_resched();
	}
}

static void *spfs_cceh_data_insert(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t key_info, cceh_value_t value,
		cceh_hash_t hash)
{
	struct cceh_extent_query *q = key_info;
	unsigned int i, si = cceh_slot_index(info, q->inode->i_ino + q->lcn);
	cceh_es_t *es;
	unsigned int forefront = q->lcn;
	unsigned int mask = cceh_extent_mask(q->lcn);
	unsigned int __mask = mask;

	while (1) {
		es = cceh_extent_insert(info, seg, q, VOID_PTR(value), hash,
				cceh_slot_index(info, q->inode->i_ino +
					forefront));
		if (es)
			return es;

		if (!__mask)
			break;
		__mask = (__mask << 1) & mask;

		forefront = cceh_extent_next_forefront(forefront, __mask);
	}

	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		es = cceh_extent_insert(info, seg, q, VOID_PTR(value), hash,
				lp_slot(info, si, i));
		if (es)
			return es;
	}
	es = ERR_PTR(-ENOSPC);

	return es;
}

static void spfs_cceh_data_persist(struct spfs_cceh_info *info, void *data)
{
	clwb_sfence(data, sizeof(cceh_es_t));
}

static void *spfs_cceh_data_get(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t key, cceh_hash_t hash)
{
	struct cceh_extent_query *q = key;
	cceh_es_t *es;
	unsigned int i, si;
	unsigned int forefront = q->lcn;
	unsigned int mask = cceh_extent_mask(q->lcn);
	unsigned int __mask = mask;

	while (1) {
		si = cceh_slot_index(info, q->inode->i_ino + forefront);

		i = 0;
		do {
			es = cceh_extent_match(info, seg, q, hash,
					lp_slot(info, si, i));
			if (es)
				return es;
		} while (++i < info->ppb * info->linear_probe_bkt_cnt);

		if (!__mask)
			break;
		__mask = (__mask << 1) & mask;

		forefront = cceh_extent_next_forefront(forefront, __mask);
	}

	return ERR_PTR(-ENOENT);
}

static void *spfs_cceh_data_delete(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t key, cceh_hash_t hash)
{
	u32 lock = hash;

	cceh_es_t *es = spfs_cceh_data_get(info, seg, key, hash);
	if (IS_ERR(es))
		return es;

	if (cmpxchg(&es->key, lock, SENTINEL) == lock) {
		es->key = INVALID;
		return es;
	} else
		BUG();

	return ERR_PTR(-ENOENT);
}

static void *cceh_extent_fast_delete(cceh_info_t *info, void *cached_slot)
{
	cceh_es_t *es = (cceh_es_t *) cached_slot;
	u32 lock = es->key;

	if (cmpxchg(&es->key, lock, SENTINEL) != lock)
		BUG(); /* inode is locked */

	es->key = INVALID;

	return es;
}

/* allow to change length only */
static void *cceh_extent_fast_update(struct spfs_cceh_info *info,
		cceh_query_t q, void *_es, cceh_value_t v)
{
	cceh_es_t *es = _es;
	cceh_eq_t *eq = q;

	switch (eq->pelcn) {
		case 0:
			es->extent.pcn = (u32) (uintptr_t) v;
			break;
		case 1:
			es->extent.len = (u32) (uintptr_t) v;
			break;
		case 2:
			es->prev_extent_lcn = (u32) (uintptr_t) v;
			break;
		default:
			BUG();
	}

	return es;
}

static void *cceh_extent_update(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_query_t q, cceh_value_t v,
		cceh_hash_t hash)
{
	cceh_es_t *es = spfs_cceh_data_get(info, seg, q, hash);

	return cceh_extent_fast_update(info, q, es, v);
}

void spfs_cceh_extent_init_segments(void)
{
	spfs_cceh_init_segments(&spfs_cceh_data_info,
			spfs_cceh_data_info.sbi->s_options.extent_hash_depth);
}

struct cceh_segment_operations spfs_cceh_data_sops = {
	.s_fast_delete	= cceh_extent_fast_delete,
	.s_delete	= spfs_cceh_data_delete,
	.s_get		= spfs_cceh_data_get,
	.s_insert	= spfs_cceh_data_insert,
	.s_insert4split	= spfs_cceh_data_insert4split,
	.s_persist	= spfs_cceh_data_persist,
	.s_fast_update	= cceh_extent_fast_update,
	.s_update	= cceh_extent_update,
};

struct cceh_operations spfs_cceh_data_ops = {
	.c_hash			= spfs_cceh_data_hash,
	.c_init_segments	= spfs_cceh_extent_init_segments,
};

struct spfs_cceh_info *spfs_cceh_data_init(struct spfs_sb_info *sbi)
{
	struct spfs_cceh_info *info = &spfs_cceh_data_info;

	sbi->s_data_info.hash = info;
	info->sbi = sbi;
	info->cceh = (struct cceh *) &sbi->s_psb->s_extent_hash;
	
	info->name = kstrdup("Data", GFP_KERNEL);
	info->magic = CCEH_DATA_MAGIC;

	info->ops = &spfs_cceh_data_ops;
	info->sops = &spfs_cceh_data_sops;

	/* XXX: smaller is better? */
	info->bps = BPS;
	info->mask = info->bps - 1;
	info->ppb = BLK_SIZE / sizeof(cceh_es_t);
	info->pps = info->bps * info->ppb;
	info->linear_probe_bkt_cnt = info->cceh->linear_probe_bkts;

	return info;
}

int spfs_seq_extent_cceh_show(struct seq_file *seq, void *offset)
{
	struct spfs_cceh_info *info = &spfs_cceh_data_info;

	write_seqlock(&info->dir_info.seqlock);
	seq_printf(seq, "Extent CCEH\n"
			"              depth: %u\n"
			"  linear probe bkts: %d/%ld\n\n",
			info->cceh->depth,
			info->cceh->linear_probe_bkts, BPS);

	cceh_dir_print(info, seq);
	write_sequnlock(&info->dir_info.seqlock);

	return 0;
}
