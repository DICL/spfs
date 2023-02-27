#ifndef __EXTENT_H__
#define __EXTENT_H__

#include "spfs.h"
#include "journal.h"
#include "inode.h"
#include "calloc.h"


//#define EXTENT_DEBUG
#ifdef EXTENT_DEBUG
#define spfs_ext_debug(fmt, ...)	\
	pr_err("%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define spfs_ext_debug(fmt, ...)	do {} while (0)
#endif

//#define EXT_TRUNC_DEBUG
#ifdef EXT_TRUNC_DEBUG
#define ext_trunc_msg(fmt, ...)		\
	pr_err("%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define ext_trunc_msg(fmt, ...)		do {} while (0)
#endif

struct spfs_extent {
	__le32	lcn, pcn;
	__le32	len; // TODO: can be short
} __attribute((__packed__));

struct spfs_map_request {
	spfs_cluster_t		lcn;
	spfs_cluster_t		pcn;
	unsigned int		len;
	unsigned int		pa_len;

	struct spfs_extent_info	*ei;
	unsigned int		flags;

	void			*jdata; // XXX:
};

#define DECLARE_MAP_REQUEST(name, _lcn, _len)		\
	struct spfs_map_request name = {		\
		.lcn	= (_lcn),			\
		.pcn	= 0,				\
		.len	= (_len),			\
		.pa_len	= 0,				\
		.ei	= NULL,				\
		.flags	= 0,				\
		.jdata	= NULL,				\
	}


#define MAP_REQ_LEN(m)		((m)->len) /* original requested length */
#define MAP_LEN(m)		((m)->len + (m)->pa_len)
#define LEN_TO_OFF(s, l)	((s) + (l) - 1)

#define range_hold_lcn(s, l, p)		\
	((s) <= (p) && (p) <= LEN_TO_OFF((s), (l)))
#define spfs_extent_hold_lcn(e, pos)   \
	range_hold_lcn((e)->lcn, (e)->len, (pos))
#define spfs_extent_hold_lcn_pa(e, pos)		\
	range_hold_lcn((e)->lcn, (e)->pa_len, (pos))

/* 32B */
struct cceh_extent_slot {
	__le32			key;			/* 00 */
	__le32			prev_extent_lcn;
	__le64			inode_no;
	struct spfs_extent	extent;			/* 10 */
	__le32			pad;
} __attribute((__packed__));

typedef struct cceh_extent_slot cceh_es_t;


#define I_EOF(inode)		(I_RAW(inode)->i_eof)

typedef struct spfs_extent_info {
	struct rb_node		rb_node;

	cceh_es_t		*es; // on PM

	spfs_cluster_t		prev_extent_lcn;
	spfs_cluster_t		lcn;
	spfs_cluster_t		pcn;
	unsigned int		len;

	struct list_head	pa_list;
	unsigned int		pa_len;

	void			*data;
} spfs_ext_info_t;

#define EXT_END(x, type)	LEN_TO_OFF((x)->type, (x)->len)

#define EI_TOTAL_LEN(ei)	((ei)->len + (ei)->pa_len)
#define EI_PA_END(ei, type)	LEN_TO_OFF((ei)->type, EI_TOTAL_LEN(ei))

#define map_lcn_end(m)		LEN_TO_OFF((m)->lcn, (m)->len)
#define map_pcn_end(m)		LEN_TO_OFF((m)->pcn, (m)->len)

extern int __spfs_extent_log_undo(struct inode *, struct spfs_map_request *);
extern spfs_ext_info_t *spfs_search_extent_info(struct inode *,
		spfs_cluster_t);
extern struct spfs_extent_info *spfs_insert_extent_info(struct inode *,
		struct spfs_extent_info *, bool);
extern int spfs_extent_map_clusters(struct inode *, struct spfs_map_request *,
		unsigned int);
extern int spfs_extent_truncate(struct inode *, spfs_cluster_t, spfs_cluster_t);
extern void spfs_truncate_extent_info(struct inode *, spfs_cluster_t);


static inline struct rb_root *inode_rb_root(struct inode *inode)
{
	return &I_INFO(inode)->i_extent_tree;
}

static inline
struct spfs_extent_info *__spfs_search_extent_info(struct inode *inode,
		spfs_cluster_t lcn, bool find_next)
{
	struct rb_node *node = inode_rb_root(inode)->rb_node;
	struct spfs_extent_info *ex = NULL;

	while (node) {
		ex = rb_entry(node, struct spfs_extent_info, rb_node);

		if (lcn < ex->lcn)
			node = node->rb_left;
		else if (lcn > EI_PA_END(ex, lcn))
			node = node->rb_right;
		else
			return ex;
	}

	if (!find_next)
		return NULL;

	if (ex && lcn < ex->lcn)
		return ex;

	if (ex && lcn > EI_PA_END(ex, lcn)) {
		node = rb_next(&ex->rb_node);
		return node ? rb_entry(node, struct spfs_extent_info, rb_node) :
			NULL;
	}

	return NULL;
}

static inline unsigned int spfs_extent_adjust_map_len(struct inode *inode,
		struct spfs_map_request *map, struct spfs_extent_info *rei)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);

	if (map_lcn_end(map) >= rei->lcn)
		map->len = rei->lcn - map->lcn;
	else if (S_OPTION(sbi)->pa_cluster_cnt) /* Can fill hole as prealloc */
		map->flags |= SPFS_MAP_GET_PREALLOC;

	return map->len;
}

static inline unsigned int
spfs_adjust_map_by_extent_info(struct spfs_map_request *map)
{
	unsigned int len = EI_TOTAL_LEN(map->ei);
	spfs_cluster_t pa_start = EI_PA_END(map->ei, lcn) - map->ei->pa_len + 1;

	/*
	 * read or overwrite...
	 * split the mapping at the boundary of preallocation
	 */
	if (map->lcn < pa_start)
		len = map->ei->len;
	else
		map->flags |= SPFS_MAP_USE_PREALLOC;

	map->len = MIN(map->len, len - (map->lcn - map->ei->lcn));
	map->pcn = map->ei->pcn + (map->lcn - map->ei->lcn);

	return map->len;
}

static inline void *ijnl_t1(struct inode *inode, u8 type, spfs_cluster_t data)
{
	struct op_type1 op = { data };
	return ijournal_log(inode, type, op);
}

static inline unsigned int __spfs_free_extent(struct inode *inode,
		struct spfs_extent_info *ei, spfs_cluster_t pos)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	unsigned int new_len;
	unsigned int free_len;

	BUG_ON(pos > EI_PA_END(ei, lcn));

	if (pos > EXT_END(ei, lcn)) {
		ei->pa_len -= (EI_PA_END(ei, lcn) - pos + 1);
		ext_trunc_msg("just cut prealloc. of %lu.. s=%u lcn=%u len=%u "
				"palen=%u", inode->i_ino, pos, ei->lcn, ei->len,
				ei->pa_len);
		return 0;
	}

	new_len = pos - ei->lcn;
	free_len = ei->len - new_len;

	if (ei->pcn) {
		spfs_free_clusters_durable(sbi, ei->pcn + new_len, free_len);
		spfs_free_clusters_volatile(sbi, ei->pcn + new_len,
				free_len + ei->pa_len, true);
		ei->pa_len = 0;
	}

	return free_len;
}

#define spfs_free_extent(inode, ei)	__spfs_free_extent(inode, ei, ei->lcn)

static inline bool spfs_is_append(struct inode *inode, spfs_cluster_t pos)
{
	spfs_ext_info_t *eof_ei;
	spfs_cluster_t eofc = I_EOF(inode);

	if (eofc == -1)
		return true;

	if (pos <= eofc)
		return false;

	eof_ei = spfs_search_extent_info(inode, eofc);
	BUG_ON(!eof_ei);

	if (EI_PA_END(eof_ei, lcn) < pos)
		return true;

	return false;
}

/*
 *    /\      /\     H: 3, cover 8 entries
 *   /  \    /  \
 *  /\  /\  /\  /\   H: 2, cover 4 entries
 * /\/\/\/\/\/\/\/\  H: 1, cover 2 entries
 * 0123456789abcdef  H: 0, leaf
 *    +               : 3 odd
 *   ++               : 2 can cover depth 1
 *  +                 : odd
 * ++++               : 0 can cover clusters of powers of 2 max.
 *     ++++           : 4 can cover depth 2(4-7) max.
 */
static inline unsigned int __spfs_carve_extent_len(spfs_cluster_t lcn,
		unsigned int len)
{
	/* Worst in terms of fragmentation */
	if (len == 1 || lcn % 2)
		return 1;

	if (!lcn)
		return __rounddown_pow_of_two(len);

	return 1 << (fls(MIN(len, 1 << (ffs(lcn) - 1))) - 1);
}

static inline void spfs_carve_extent_len(struct spfs_sb_info *sbi,
		struct spfs_map_request *map, struct spfs_extent_info *rei)
{
	u32 len = map->len;

	if (map->flags & SPFS_MAP_GET_PREALLOC) {
		len = MAX(S_OPTION(sbi)->pa_cluster_cnt, map->len);

		if (rei && LEN_TO_OFF(map->lcn, len) >= rei->lcn)
			len = rei->lcn - map->lcn;
	}

	len = __spfs_carve_extent_len(map->lcn, len);

	/* impossible to preallocation */
	if (len <= map->len)
		map->len = len;
	else
		/* preallocate as many as clusters possible from the lcn */
		map->pa_len = len - map->len;
}

static inline void *ijnl_write(struct inode *inode, u8 type, spfs_cluster_t lcn,
		spfs_cluster_t pcn, unsigned int len)
{
	struct op_type2 op = {lcn, ((u64) pcn) << 32 | len};
	return ijournal_log(inode, type, op);
}

static inline void *ijnl_undo(struct inode *inode, u8 type, spfs_cluster_t lcn,
		spfs_cluster_t pcn, unsigned int len, unsigned int pa_len)
{
	struct op_type2 op = {
		((u64) lcn) << 32 | pa_len ,
		((u64) pcn) << 32 | len
	};
	return ijournal_log(inode, type, op);
}

static inline int spfs_undo_utilization(struct spfs_map_request *map)
{
	return div_u64((u64) map->len * 100, (u64) map->ei->len);
}

static inline
int spfs_extent_log_undo(struct inode *inode, struct spfs_map_request *map)
{
	if (S_OPTION(SB_INFO(inode->i_sb))->consistency_mode != CONS_MODE_DATA)
		return 0;

	return __spfs_extent_log_undo(inode, map);
}

static inline int spfs_extent_commit_undo(struct inode *inode, u64 *jslot)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	spfs_cluster_t pcn = (*(jslot + 1) >> 32) & 0xffffffff;
	unsigned int len = *(jslot + 1) & 0xffffffff;
	unsigned int pa_len = *jslot & 0xFFFFFFFF;

	spfs_ext_debug("freeing %u-%u of jslot 0x%px", pcn, len, jslot);

//	spfs_free_clusters_durable(sbi, pcn, len);
	spfs_free_clusters_volatile(sbi, pcn, len, true);

	if (pa_len)
		spfs_free_clusters_volatile(sbi, pcn + len, pa_len, true);

	return 0;
}

static inline void spfs_zeroize_extent_partial(struct spfs_sb_info *sbi,
		loff_t pos, loff_t length, spfs_cluster_t pcn, unsigned int len)
{
	int soff = pos % CLUSTER_SIZE;
	int eoff = (pos + length) % CLUSTER_SIZE;

	if (soff) {
		memset(clu_addr(sbi, pcn), 0, soff);
		_clwb(clu_addr(sbi, pcn), soff);
	}

	if (ALIGN(length, CLUSTER_SIZE) == C2BYTES(len) && eoff) {
		char *paddr = (char *) clu_addr(sbi, LEN_TO_OFF(pcn, len)) +
			eoff;

		memset(paddr, 0, CLUSTER_SIZE - eoff);
		_clwb(paddr, CLUSTER_SIZE - eoff);
	}
}

#endif
