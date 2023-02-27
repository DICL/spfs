#include "spfs.h"
#include "namei.h"

struct spfs_cceh_info spfs_cceh_namei_info;


/* use dentry.d_name.name.hash as segment and bucket indexing */
static cceh_hash_t spfs_cceh_namei_hash(cceh_key_t key)
{
	return ((struct cceh_namei_kdata *) key)->name.hash;
}

static void *cceh_namei_fast_delete(cceh_info_t *info, void *cached_slot)
{
	cceh_slot_t *slot = (cceh_slot_t *) cached_slot;
	cceh_hash_t lock = slot->k;

	if (cmpxchg(&slot->k, lock, SENTINEL) != lock)
		BUG();

	slot->k = INVALID;

	return slot;
}

static void *spfs_cceh_namei_seg_delete(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t key, cceh_hash_t hash)
{
	struct cceh_namei_kdata *kdat = (struct cceh_namei_kdata *) key;
	unsigned int i;
	unsigned int slot = cceh_pair(hash, info->mask, info->ppb);
	cceh_hash_t lock = kdat->name.hash;

	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		struct cceh_key_value *kv = cceh_seg_nth_item(seg,
				lp_slot(info, slot, i), sizeof(*kv));
		struct spfs_dir_entry *de;

		if (!cceh_valid_slot(seg, kv->k))
			continue;

		/* fast path */
		if (kdat->fast_del_hint) {
			if (kv->v == kdat->fast_del_hint)
				goto got;
			continue;
 		}

		/* slow path */
		if (kv->k != lock) // internal hash mismatch
			continue;

		de = blk_addr(info->sbi, kv->v);

		if (kdat->find_dir && !(de->de_flags & DE_DIR))
			continue;

		if (kdat->dir->i_ino != de->de_pino)
			continue;

		if (kdat->name.len != de->de_len)
			continue;

		if (strncmp(kdat->name.name, de->de_name, de->de_len))
			continue;
got:
		// TODO: continue???
		if (cmpxchg(&kv->k, lock, SENTINEL) != lock)
			continue;

		kv->k = INVALID;
		return kv;
	}

	return ERR_PTR(-ENOENT);
}

static void spfs_cceh_namei_seg_insert4split(struct spfs_cceh_info *info,
		struct cceh_seg *splitting, struct cceh_seg *new_seg)
{
	unsigned int i;
	struct cceh_key_value *kv;

	for (i = 0; i < info->pps; i++) {
		kv = cceh_seg_nth_item(splitting, i,
				sizeof(struct cceh_key_value));

		if (kv->k == (u64) INVALID)
			continue;

		/* copy slots masked by new pattern */
		if (cceh_seg_hash_mask(kv->k, splitting->local_depth + 1))
			spfs_cceh_insert4split(info, splitting, new_seg,
					cceh_pair(kv->k, info->mask, info->ppb),
					kv);
	}
}

static void *spfs_cceh_namei_seg_insert(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t key, cceh_value_t value,
		cceh_hash_t hash)
{
	unsigned int i;
	unsigned int si = cceh_pair(hash, info->mask, info->ppb);

	/* TODO: how to take care of duplication? */
	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		cceh_slot_t *slot = cceh_cast_slot(seg, lp_slot(info, si, i),
				cceh_slot_t);
		u64 k = slot->k; // W(k) slot->k
		/*
		 * No need of READ_ONCE for ordering because of
		 * Principle 4:
		 * Reads may be reordered with older writes to different
		 * locations but *not with older writes to the same location*.
		 * (NO W->R!)
		 */
		if (cceh_valid_slot(seg, k)) // R(k)
			continue;

		if (cceh_stale_slot(seg, k)) {
			if (cmpxchg(&slot->k, k, (u64) SENTINEL) == k)
				goto set;
			continue;
		}

		/*
		 * cmpxchg implies total ordering, there is no race for same
		 * slot location.
		 */
		if (cmpxchg(&slot->k, INVALID, SENTINEL) == INVALID) {
set:
			slot->v = value;
			/*
			 * No need of sfence after writing value according
			 * to the following rules and cachline aligned slots.
			 *
			 * Principle 2
			 * Writes are not reordered with other writes. (W->W)
			 *
			 * Principle 6
			 * In a multiprocessor system, writes to the same
			 * location(cacheline) have a total order. (implied by
			 * cache coherence)
			 */
			slot->k = hash;

			return slot;
		}
	}

	return ERR_PTR(-ENOSPC);
}

static void spfs_cceh_namei_seg_persist(struct spfs_cceh_info *info, void *data)
{
	/* Make chagnes visible to other processors by flushing store buffer */
	clwb_sfence(data, sizeof(cceh_slot_t));
}

static void *spfs_cceh_namei_seg_get(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t key, cceh_hash_t hash)
{
	struct cceh_namei_kdata *kdat = key;
	unsigned int i;
	unsigned int slot = cceh_pair(hash, info->mask, info->ppb);

	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		struct cceh_key_value *kv = cceh_seg_nth_item(seg,
				lp_slot(info, slot, i), sizeof(*kv));
		struct spfs_dir_entry *de;

		if ((cceh_hash_t) kv->k != kdat->name.hash)
			continue;

		/* data comparison */
		de = blk_addr(SB_INFO(kdat->dir->i_sb), kv->v);

		if (de->de_flags & DE_DIR && !kdat->find_dir)
			continue;

		if (de->de_pino != kdat->dir->i_ino)
			continue;

		if (de->de_len != kdat->name.len)
			continue;

		/* TODO: long name */
		if (strncmp(de->de_name, kdat->name.name, kdat->name.len))
			continue;

		kdat->private = kv;
		return de;
	}

	return ERR_PTR(-ENOENT);
}


struct cceh_segment_operations spfs_cceh_namei_sops = {
	.s_fast_delete	= cceh_namei_fast_delete,
	.s_delete	= spfs_cceh_namei_seg_delete,
	.s_get		= spfs_cceh_namei_seg_get,
	.s_insert	= spfs_cceh_namei_seg_insert,
	.s_insert4split	= spfs_cceh_namei_seg_insert4split,
	.s_persist	= spfs_cceh_namei_seg_persist,
};

struct cceh_operations spfs_cceh_namei_ops = {
	.c_hash = spfs_cceh_namei_hash,
};

struct spfs_cceh_info *
spfs_cceh_init_namei_hash(struct spfs_sb_info *sbi)
{
	struct spfs_cceh_info *info = &spfs_cceh_namei_info;

	NAMEI_HASH(sbi) = info;
	info->sbi = sbi;
	info->cceh = (struct cceh *) &sbi->s_psb->s_namei_hash;

	info->name = kstrdup("Namei", GFP_KERNEL);
	info->magic = CCEH_NAME_MAGIC;

	info->ops = &spfs_cceh_namei_ops;
	info->sops = &spfs_cceh_namei_sops;

	info->bps = BPS;
	info->mask = info->bps - 1;
	info->ppb = BLK_SIZE / sizeof(struct cceh_key_value);
	info->pps = info->bps * info->ppb;
	info->linear_probe_bkt_cnt = info->cceh->linear_probe_bkts;


	return info;
}
