#include "spfs.h"
#include "calloc.h"

struct spfs_cceh_info spfs_cceh_cluster_info;

static void __spfs_cceh_cluster_seg_insert4split(struct spfs_cceh_info *info,
		struct cceh_seg *splitting, struct cceh_seg *new_seg,
		unsigned int pi, unsigned int pcn, unsigned short bitmap)
{
	unsigned int i;
	struct spfs_cluster_usage *c;

	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		c = (struct spfs_cluster_usage *)
			&new_seg->p[lp_slot(info, pi, i)];

		/* empty slot */
		if (c->pcn == INVALID) {
			c->pcn = pcn;
			c->bitmap = bitmap;
			segment_mov_count(splitting, new_seg);
			break;
		}
	}
}

static void spfs_cceh_cluster_seg_insert4split(struct spfs_cceh_info *info,
		struct cceh_seg *splitting, struct cceh_seg *new_seg)
{
	unsigned int i;
	cceh_hash_t hash;
	struct spfs_cluster_usage *c;

	for (i = 0; i < info->pps; i++) {
		c = (struct spfs_cluster_usage *) &splitting->p[i];
		hash = info->ops->c_hash(VOID_PTR(c->pcn));

		/* copy slots masked by new pattern */
		if (cceh_seg_hash_mask(hash, splitting->local_depth + 1))
			__spfs_cceh_cluster_seg_insert4split(info, splitting,
					new_seg,
					cceh_pair(hash, info->mask, info->ppb),
					c->pcn, c->bitmap);
	}
}

static void *spfs_cceh_cluster_seg_delete(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t deleting_key, cceh_hash_t hash)
{
	unsigned int i;
	unsigned int slot = cceh_pair(hash, info->mask, info->ppb);
	unsigned int lock = (unsigned int) (uintptr_t) deleting_key;

	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		struct spfs_cluster_usage *u = (struct spfs_cluster_usage *)
			&(seg->p[lp_slot(info, slot, i)]);

		if (cmpxchg(&u->pcn, lock, SENTINEL) != lock)
			continue;

		u->pcn = INVALID;
		return u;
	}

	return ERR_PTR(-ENOENT);
}

static void *spfs_cceh_cluster_seg_insert(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t key, cceh_value_t value,
		cceh_hash_t hash)
{
	unsigned int i;
	unsigned int slot = cceh_pair(hash, info->mask, info->ppb);

	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		struct spfs_cluster_usage *u = (struct spfs_cluster_usage *)
			&(seg->p[lp_slot(info, slot, i)]);
		unsigned int k = u->pcn;

		if (k < SENTINEL && cceh_seg_pattern(cceh_hash_32(VOID_PTR(k)),
					seg->local_depth) != seg->pattern) {
			if (cmpxchg(&u->pcn, k, SENTINEL) == k)
				goto set;
			continue;
		}

		if (cmpxchg(&u->pcn, INVALID, SENTINEL) == INVALID) {
set:
			u->bitmap = (unsigned short) value;
			u->pcn = (unsigned int) (uintptr_t) key;

			return u;
		}
	}

	return ERR_PTR(-ENOSPC);
}

static void spfs_cceh_cluster_seg_persist(struct spfs_cceh_info *info,
		void *data)
{
	clwb_sfence(data, sizeof(struct spfs_cluster_usage));
}


static void *spfs_cceh_cluster_seg_get(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_key_t key, cceh_hash_t hash)
{
	unsigned int i;
	unsigned int slot = cceh_pair(hash, info->mask, info->ppb);

	for (i = 0; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		struct spfs_cluster_usage *u = (struct spfs_cluster_usage *)
			&(seg->p[lp_slot(info, slot, i)]);

		if (u->pcn != (unsigned int) (uintptr_t) key)
			continue;

		return u;
	}

	return ERR_PTR(-ENOENT);
}

void spfs_cceh_cluster_s_init(struct spfs_cceh_info *info,
		struct cceh_seg *seg, unsigned int local_depth,
		unsigned int pattern)
{
	int i;

	for (i = 0; i < CPS; i++) {
		struct spfs_cluster_usage *u = (struct spfs_cluster_usage *)
			((char *) seg + i * CLUSTER_SIZE);

		memset(u, 0xff, CLUSTER_SIZE);
		u->pad = i;
	}

	seg->refcount = 0;
	seg->pad = 0;
	seg->local_depth = local_depth;
	seg->pattern = pattern;
	seg->magic = info->magic;

	clwb_sfence(seg, SEGMENT_SIZE);
}

// TODO: DRAM level validation
bool spfs_cceh_cluster_s_revalidate(struct spfs_cceh_info *info,
		cceh_query_t query)
{
	struct spfs_cluster_usage *u;
	struct cceh_seg *seg;

	u = (struct spfs_cluster_usage *) ((u64) query & CLUSTER_MASK);
	seg = (struct cceh_seg *) ((char *) u - u->pad * CLUSTER_SIZE);

	if (seg->magic != CCEH_CLUS_MAGIC) {
		cceh_debug_level(info, 3, "(%s) missing magic %llx",
				__func__, seg->magic);
		return false;
	}

	return true;
}

struct cceh_segment_operations spfs_cceh_cluster_sops = {
	.s_delete	= spfs_cceh_cluster_seg_delete,
	.s_get		= spfs_cceh_cluster_seg_get,
	.s_init		= spfs_cceh_cluster_s_init,
	.s_insert	= spfs_cceh_cluster_seg_insert,
	.s_insert4split	= spfs_cceh_cluster_seg_insert4split,
	.s_persist	= spfs_cceh_cluster_seg_persist,
	.s_revalidate	= spfs_cceh_cluster_s_revalidate,
};

struct cceh_operations spfs_cceh_cluster_ops = {
	.c_hash		= cceh_hash_32,
};

struct spfs_cceh_info
*spfs_cceh_init_cluster_hash(struct spfs_sb_info *sbi)
{
	struct spfs_cceh_info *info = &spfs_cceh_cluster_info;

	FREE_INFO(sbi)->hash = info;
	info->sbi = sbi;
	info->cceh = (struct cceh *) sbi->s_psb->s_cluster_hash;

	info->name = kstrdup("Cluster", GFP_KERNEL);
	info->magic = CCEH_CLUS_MAGIC;

	info->ops = &spfs_cceh_cluster_ops;
	info->sops = &spfs_cceh_cluster_sops;

	info->bps = BPS;
	info->mask = info->bps - 1;
	info->ppb = BLK_SIZE / sizeof(struct spfs_cluster_usage);
	info->pps = info->bps * info->ppb;
	info->linear_probe_bkt_cnt = info->cceh->linear_probe_bkts;


	return info;
}
