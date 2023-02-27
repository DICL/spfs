#ifndef __CCEH_EXTENT_H__
#define __CCEH_EXTENT_H__

#include "spfs.h"
#include "extent.h"
#include "stats.h"


typedef struct cceh_extent_query {
	struct inode	*inode;
	spfs_cluster_t	lcn;
	unsigned int	len;
	u32		max_extent_len;
	spfs_cluster_t	pelcn;
} cceh_eq_t;

static inline unsigned int cceh_extent_next_forefront(unsigned int forefront,
		unsigned int mask)
{
	return forefront & mask;
}

#define cceh_extent_mask(lcn)		((1 << fls(lcn)) - 1)

#define __EXTENT_QUERY_INITIALIZER(_inode, _lcn, _len, _pelcn)	\
{								\
	.inode	= _inode,					\
	.lcn	= _lcn,						\
	.len	= _len,						\
	.pelcn	= _pelcn,					\
	.max_extent_len	=					\
	S_OPTION(SB_INFO((_inode)->i_sb))->max_extent_len	\
}

#define DECLARE_EXTENT_QUERY(name, inode, lcn, len, pelcn)	\
	struct cceh_extent_query name =				\
	__EXTENT_QUERY_INITIALIZER(inode, lcn, len, pelcn)

static inline struct spfs_extent *spfs_search_extent(struct inode *inode,
		spfs_cluster_t lcn)
{
	cceh_es_t *es;
	DECLARE_EXTENT_QUERY(q, inode, lcn, 0, 0);

	es = spfs_cceh_get(SB_INFO(inode->i_sb)->s_data_info.hash, &q);
	if (!es)
		return NULL;

	CHECK_DATA_CORRUPTION(inode->i_ino != es->inode_no, "lcn %u es(0x%px)",
			lcn, es);

	return &es->extent;
}

static inline cceh_es_t *spfs_insert_extent(struct inode *inode,
		struct spfs_map_request *map, spfs_cluster_t pelcn)
{
	DECLARE_EXTENT_QUERY(q, inode, map->lcn, MAP_REQ_LEN(map), pelcn);
	stats_inc_extent_count();
	return spfs_cceh_insert(SB_INFO(inode->i_sb)->s_data_info.hash, &q,
			(uintptr_t) map);
}

static inline int spfs_delete_extent(struct inode *inode,
		struct spfs_extent_info *ei)
{
	DECLARE_EXTENT_QUERY(q, inode, ei->lcn, 0, 0);
	stats_dec_extent_count();
	return __spfs_cceh_delete(SB_INFO(inode->i_sb)->s_data_info.hash, &q,
			ei->es);
}

/* TODO: unified update helper */
static inline cceh_es_t *spfs_update_extent_pcn(struct inode *inode,
		spfs_ext_info_t *ei)
{
	DECLARE_EXTENT_QUERY(q, inode, ei->lcn, 0, 0);
	return spfs_cceh_update(SB_INFO(inode->i_sb)->s_data_info.hash, &q,
			ei->es, ei->pcn);
}

static inline cceh_es_t *__spfs_update_extent_len(struct inode *inode,
		struct spfs_extent_info *ei, unsigned int len)
{
	DECLARE_EXTENT_QUERY(q, inode, ei->lcn, 0, 1);
	return spfs_cceh_update(SB_INFO(inode->i_sb)->s_data_info.hash, &q,
			ei->es, len);
}

static inline cceh_es_t *spfs_update_extent_len(struct inode *inode,
		spfs_ext_info_t *ei)
{
	return __spfs_update_extent_len(inode, ei, ei->len);
}

static inline cceh_es_t *spfs_update_extent_list(struct inode *inode,
		spfs_ext_info_t *ei)
{
	DECLARE_EXTENT_QUERY(q, inode, ei->lcn, 0, 2);
	return spfs_cceh_update(SB_INFO(inode->i_sb)->s_data_info.hash, &q,
			ei->es, ei->prev_extent_lcn);
}

static inline cceh_es_t *cceh_extent_match(struct spfs_cceh_info *info,
		struct cceh_seg *seg, struct cceh_extent_query *q,
		cceh_hash_t hash, unsigned int si)
{
	cceh_es_t *es = cceh_cast_slot(seg, si, cceh_es_t);

	if (es->key != hash)
		return NULL;

	if (es->inode_no != q->inode->i_ino)
		return NULL;

	if (!spfs_extent_hold_lcn(&es->extent, q->lcn))
		return NULL;

	return es;
}

static inline cceh_es_t *cceh_extent_insert(struct spfs_cceh_info *info,
		struct cceh_seg *seg, struct cceh_extent_query *q,
		struct spfs_map_request *map, cceh_hash_t hash, unsigned int si)
{
	cceh_es_t *es;
	unsigned int key;

	es = cceh_cast_slot(seg, si, cceh_es_t);
	key = es->key;

	if (cceh_valid_slot(seg, key))
		return NULL;

	if (cceh_stale_slot(seg, key)) {
		if (cmpxchg(&es->key, key, SENTINEL) == key)
			goto set;
		return NULL;
	}

	if (cmpxchg(&es->key, INVALID, SENTINEL) == INVALID) {
set:
		es->inode_no = q->inode->i_ino;
		es->prev_extent_lcn = q->pelcn;
		es->extent.lcn = map->lcn;
		es->extent.pcn = map->pcn;
		es->extent.len = map->len;

		es->key = hash;

		return es;
	}

	return NULL;
}

static inline void __spfs_cceh_extent_insert4split(struct spfs_cceh_info *info,
		struct cceh_seg *new_seg, cceh_es_t *old)
{
	unsigned long inode_no = old->inode_no;
	unsigned int lcn = old->extent.lcn;
	unsigned int i, si = cceh_slot_index(info, inode_no + lcn);
	unsigned int forefront = lcn;
	unsigned int mask = cceh_extent_mask(lcn);
	unsigned int __mask = mask;
	cceh_es_t *es;

	while (1) {
		es = cceh_cast_slot(new_seg, cceh_slot_index(info, inode_no +
					forefront), cceh_es_t);
		if (es->key == INVALID) {
			*es = *old;
			return;
		}

		if (!__mask)
			break;
		__mask = (__mask << 1) & mask;

		forefront = cceh_extent_next_forefront(forefront, __mask);
	}

	for (i = 1; i < info->ppb * info->linear_probe_bkt_cnt; i++) {
		es = cceh_cast_slot(new_seg, lp_slot(info, si, i),
				cceh_es_t);
		if (es->key == INVALID) {
			*es = *old;
			return;
		}
	}

	pr_err("%s: 0x%px", __func__, new_seg);
	BUG();
}

#endif
