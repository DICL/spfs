#ifndef __CCEH_H__
#define __CCEH_H__

#include <linux/hash.h>
#include <linux/mm.h>

#include "spfs.h"


#define CCEH_CLUS_MAGIC		0x73756c6348454343
#define CCEH_NAME_MAGIC		0x656d616e48454343
#define CCEH_DATA_MAGIC		0x6174616448454343

#define SENTINEL	(-2)
#define INVALID		(-1)


typedef void*			cceh_key_t;
typedef unsigned int		cceh_hash_t;
typedef unsigned long long	cceh_value_t;
typedef cceh_hash_t		cceh_segment_t;
typedef void *			cceh_query_t;

static inline void *cceh_seg_nth_item(void *seg, unsigned int n,
		size_t item_size)
{
	return (char *) seg + item_size * n;
}

#define cceh_cast_slot(seg, si, type)				\
	((type *) ((char *) (seg) + sizeof(type) * (si)))

void __cceh_msg(struct spfs_cceh_info *info, const char *level, const char *fmt,
		...);

#if defined(CONFIG_SPFS_DEBUG) && defined(CCEH_DEBUG)
#define cceh_debug(info, fmt, ...)	\
	__cceh_msg(info, KERN_DEBUG, fmt, ##__VA_ARGS__)
#define cceh_debug_level(info, level, fmt, ...)	do {		\
	if (level <= CONFIG_SPFS_DEBUG_LEVEL) {			\
		if (info)					\
			cceh_debug(info, fmt, ##__VA_ARGS__);	\
		else						\
			pr_err(fmt, ##__VA_ARGS__);		\
	}							\
} while (0)
#else
#define cceh_debug(info, fmt, ...)		do {} while (0)
#define cceh_debug_level(info, level, fmt, ...)	do {} while (0)
#endif

//#define CCEH_DEBUG
#ifdef CCEH_DEBUG
#define cceh_debug_split(info, fmt, ...)	\
	cceh_err(info, fmt, ##__VA_ARGS__)
#define CCEH_BUG_ON				BUG_ON
#else
#define cceh_debug_split(info, fmt, ...)	do {} while (0)
#define CCEH_BUG_ON(condition)			do {} while (0)
#endif

/*
 * Logical right shift (64 - global depth) times for getting segment index.
 * MSB bits whose width is depth becomes a segment index.
 * If hash is 101..000(2) and depth is 1, we get MSB 1 as s segment index.
 * depth 1 _1_01..000
 * depth 2 _10_1..000
 * depth 3 _101_..000
 */
static inline cceh_segment_t cceh_seg(struct spfs_cceh_info *info,
		cceh_hash_t hash, unsigned int depth)
{
	cceh_segment_t seg = 0;

	if (!depth)
		return 0;

	seg = hash >> (BITS_PER_BYTE * sizeof(hash) - depth);
	cceh_debug_level(info, 2, "%llu %u %llu", (u64) hash, depth, (u64) seg);
	BUG_ON(seg > (1ULL << depth));

	return seg;
}

static inline cceh_hash_t
cceh_seg_hash_mask(cceh_hash_t hash, unsigned int depth)
{
	if (!depth)
		return 0;
	return hash & (1ULL << (BITS_PER_BYTE * sizeof(hash) - depth));
}

static inline unsigned int cceh_pair(cceh_hash_t hash, unsigned int mask,
		unsigned int ppx /* # of pairs in xpline */)
{
	return (hash % mask) * ppx;
}

static inline cceh_segment_t cceh_seg_pattern(cceh_hash_t hash,
		unsigned int local_depth)
{
	return cceh_seg(NULL, hash, local_depth);
//	return hash >> (BITS_PER_BYTE * sizeof(hash) - local_depth);
}

struct cceh_key_value {
	__le64	k;
	__le64	v;	/* can be value or pointer */
} __attribute((__packed__));

typedef struct cceh_key_value cceh_slot_t;

#define CPS		(2048)
#define SEGMENT_SIZE	(CPS * CLUSTER_SIZE) // 4MB
#define BPS		(CPS * BPC - 1) // buckets per segment

/* 4096B */
struct cceh_seg {
	/* slots in buckets */
	__le64	p[(SEGMENT_SIZE - 6 * sizeof(__le32)) / sizeof(__le64)];
	__le32	refcount;
	__le32	pad;
	__le32	pattern;
	__le32	local_depth;
	__le64 	magic;			/* SEG_MAGIC */
} __attribute((__packed__));

#define segment_refcount(s)	((atomic_t *) &(s)->refcount)
#define sput(s)			atomic_dec(segment_refcount(s))

#define cceh_stale_slot(seg, k)						\
	(k != INVALID && k != SENTINEL &&				\
	 cceh_seg_pattern(k, seg->local_depth) != seg->pattern)

#define cceh_valid_slot(seg, k)						\
	(k != INVALID && k != SENTINEL &&				\
	 cceh_seg_pattern(k, seg->local_depth) == seg->pattern)

struct cceh_dir {
	__le32	s[0];	/* cluster indexes for segments */
} __attribute((__packed__));

struct cceh {
	__le32	depth;
	__le32	dir_c_idx;
	__le32	linear_probe_bkts;
} __attribute((__packed__));

struct cceh_seg_info {
	struct cceh_seg *seg;
	seqlock_t	seqlock;
};

struct cceh_dir_info {
	struct cceh_dir	*dir;			/* CCEH dir. on PM */
	seqlock_t	seqlock;
};

struct spfs_cceh_info;
typedef struct spfs_cceh_info cceh_info_t;

extern struct spfs_cceh_info spfs_cceh_cluster_info;


// revalidate
struct cceh_segment_operations {
	void *(*s_fast_delete)(cceh_info_t *, void *);
	void *(*s_delete)(struct spfs_cceh_info *, struct cceh_seg *,
			cceh_key_t, cceh_hash_t);
	void *(*s_get)(struct spfs_cceh_info *, struct cceh_seg *, cceh_key_t,
			cceh_hash_t);
	void (*s_init)(struct spfs_cceh_info *, struct cceh_seg *,
			unsigned int, unsigned int);
	void *(*s_insert)(struct spfs_cceh_info *, struct cceh_seg *,
			cceh_key_t, cceh_value_t, cceh_hash_t);
	void (*s_insert4split)(struct spfs_cceh_info *, struct cceh_seg *,
			struct cceh_seg *);
	void (*s_persist)(struct spfs_cceh_info *, void *);
	bool (*s_revalidate)(struct spfs_cceh_info *, cceh_query_t);
	void *(*s_fast_update)(struct spfs_cceh_info *, cceh_query_t, void *,
			cceh_value_t);
	void *(*s_update)(struct spfs_cceh_info *, struct cceh_seg *,
			cceh_query_t, cceh_value_t, cceh_hash_t);
};

struct cceh_operations {
	cceh_hash_t (*c_hash)(cceh_key_t);
	void (*c_init_segments)(void);
};

struct spfs_cceh_info {
	struct list_head		list;

	struct spfs_sb_info		*sbi;

	const char			*name;
	unsigned long long		magic;
	
	struct cceh			*cceh;
	struct cceh_dir_info		dir_info;

	/* private info. */
	struct cceh_operations 		*ops;
	struct cceh_segment_operations	*sops;
	unsigned int			bps;	/* buckets per segment */
	unsigned int			mask;	/* mask for bucket indexing */
	unsigned int			ppb;	/* pairs per bucket */
	unsigned int			pps;	/* pairs per segment */
#define DEF_LINEAR_PROBE_BKT_CNT	(2)
	unsigned int			linear_probe_bkt_cnt;

	bool				fast_path;
};

#define cceh_msg(info, level, fmt, ...) \
	__cceh_msg(info, level, fmt, ##__VA_ARGS__)

#define cceh_err(info, fmt, ...)	\
	__cceh_msg(info, KERN_ERR, "%s: "fmt, __func__, ##__VA_ARGS__)

#define cceh_seq_err(info, seq, fmt, ...)	do {	\
	if (seq)					\
		seq_printf(seq, fmt"\n", __VA_ARGS__);	\
	else						\
		cceh_err(info, fmt, __VA_ARGS__);	\
} while (0)

static inline cceh_segment_t __cceh_dir_capa(unsigned int depth)
{
	return 1UL << depth;
}

#define cceh_dir_capa(info)	__cceh_dir_capa((info)->cceh->depth)

#define DIR_CLUSTER_COUNT(depth)	\
	(BYTES2C(ALIGN(__cceh_dir_capa(depth) * sizeof(__le32), CLUSTER_SIZE)))

static inline unsigned int
cceh_seg_depth_gap(struct cceh *cceh, struct cceh_seg *seg)
{
	return cceh->depth - seg->local_depth;
}

static inline unsigned int
cceh_seg_chunk_size(unsigned int g_depth, unsigned int l_depth)
{
	return 1 << (g_depth - l_depth);
}

static inline cceh_segment_t
cceh_seg_chunk_rep(cceh_segment_t seg_index, unsigned int chunk_size)
{
	return seg_index - (seg_index % chunk_size);
}

static inline cceh_hash_t cceh_hash_32(cceh_key_t k)
{
	unsigned int v = (unsigned int) (uintptr_t) k;
	return hash_32(v, sizeof(v) * 8);
}

static inline bool cceh_need_format(struct spfs_cceh_info *info)
{
	return info->cceh->depth == (unsigned int) -1;
}

static inline unsigned int cceh_slot_index(struct spfs_cceh_info *info,
		cceh_hash_t hash)
{
	return (hash % info->mask) * info->ppb;
}

/*
 * make barrier against insertion and deletion on this segment.
 * other segments are free to do something if they got segment already.
 */
static inline bool cceh_suspend(struct spfs_cceh_info *info,
		struct cceh_seg *seg)
{
	atomic_t *refcount = segment_refcount(seg);
	int old = atomic_read(refcount);

	do {
		if (old < 0)
			return false;
	} while (!atomic_try_cmpxchg(refcount, &old, -1));

	/* we need to wait in-flight OPs */
	while (old > 0 && atomic_read(refcount) != -(old + 1)) {
		cceh_debug_level(info, 4, "(%s): old=%d now=%d want=%d",
				__func__, old, atomic_read(refcount),
				-(old + 1));
	}

	cceh_debug(info, "(%s): suspended", __func__);

	return true;
}

static inline bool cceh_suspended(struct spfs_cceh_info *info,
		struct cceh_seg *seg, cceh_hash_t hash)
{
	/* XXX: is -1 OK? */
	if (!atomic_inc_unless_negative(segment_refcount(seg))) {
		cceh_debug(info, "(%s) someone is splitting segment or "
				"doubling dir.", __func__);
		return true;
	}

	if (seg->pattern != cceh_seg_pattern(hash, seg->local_depth)) {
		cceh_debug(info, "(%s) pattern updating is not yet", __func__);
		cceh_debug_level(info, 1, "(%s) %pK %x vs. %x, d=%x h=%x",
				__func__, seg, seg->pattern,
				cceh_seg_pattern(hash, seg->local_depth),
				seg->local_depth, hash);
		sput(seg);
		return true;
	}

	return false;
}

extern void *spfs_cceh_update(struct spfs_cceh_info *, cceh_query_t, void *,
		cceh_value_t);
extern struct spfs_cceh_info *spfs_cceh_data_init(struct spfs_sb_info *);
extern struct spfs_cceh_info *spfs_cceh_init_cluster_hash(struct spfs_sb_info *);
extern struct spfs_cceh_info *spfs_cceh_init_namei_hash(struct spfs_sb_info *);
extern void spfs_cceh_init_segments(struct spfs_cceh_info *, unsigned int);
extern void spfs_cceh_insert4split(struct spfs_cceh_info *, struct cceh_seg *,
		struct cceh_seg *, unsigned int, struct cceh_key_value *);
extern int spfs_seq_extent_cceh_show(struct seq_file *, void *);

static inline struct cceh_seg *spfs_cceh_get_seg(struct spfs_cceh_info *info,
		cceh_hash_t hash)
{
	cceh_segment_t si;
	spfs_cluster_t sc;
	struct cceh_dir *dir;
	struct cceh_seg *seg;
	unsigned long seq;

	do {
		/* segment operations are blocked when updating directory */
		seq = read_seqbegin(&info->dir_info.seqlock);

		dir = info->dir_info.dir;

		si = cceh_seg(info, hash, info->cceh->depth);
		sc = dir->s[si];
		seg = (struct cceh_seg *) clu_addr(info->sbi, sc);

		//cceh_debug_split(info, "(%s) si=%u clu=%lu seg=%pK 0x%x",
		//		__func__, si, sc, seg, hash);
		SPFS_BUG_ON_MSG(!seg || seg->magic != info->magic,
			"%s: segment(0x%llx) magic mismatch(0x%llx)", __func__,
			(u64) seg, seg->magic);
		BUG_ON(sc != dir->s[si] || sc != clu_idx(info->sbi, seg));
	} while (read_seqretry(&info->dir_info.seqlock, seq));

	return seg;
}


#ifdef CONFIG_SPFS_STATS
#define segment_count(s)	((atomic_t *) &(s)->pad)
#define segment_inc_count(s)	atomic_inc(segment_count(s))
#define segment_dec_count(s)	atomic_dec(segment_count(s))
#define segment_mov_count(o, n)	do {	\
	segment_inc_count(n);		\
	segment_dec_count(o);		\
} while (0)
#define segment_count_read(s)	atomic_read(segment_count(s))
#else
#define segment_inc_count(s)		do {} while (0)
#define segment_dec_count(s)		do {} while (0)
#define segment_mov_count(o, s)		do {} while (0)
#define segment_count_read(s)		0
#endif

static inline char *dec2bin(int n, int len, char *b)
{
	int c;
	for (c = len - 1, b[len] = '\0'; c >= 0; c--)
		b[len - 1 - c] = '0' + ((n >> c) & 1);
	return b;
}

static inline void cceh_dir_print(struct spfs_cceh_info *info,
		struct seq_file *seq)
{
	struct cceh_dir *dir = info->dir_info.dir;
	spfs_cluster_t prev = dir->s[0];
	unsigned long i = 1;
	struct cceh_seg *seg = clu_addr(info->sbi, dir->s[0]);
	char bin[33];

	memset(bin, 0, 33);

	//flush_cache_all();

	cceh_seq_err(info, seq, "%s", info->name);
	cceh_seq_err(info, seq, "[%10d] %8u.. %5d/%5d (%2d, %-32s)",
			0, prev, segment_count_read(seg), info->pps,
			seg->local_depth,
			dec2bin(seg->pattern, seg->local_depth, bin));

	for (i = 1; i < cceh_dir_capa(info); i++) {
		if (prev != dir->s[i]) {
			seg = (struct cceh_seg *) clu_addr(info->sbi,
					dir->s[i]);

			cceh_seq_err(info, seq, "[%10lu] %8u.. %5d/%5d (%2d, %-32s)",
					i, dir->s[i],
					segment_count_read(seg),
					info->pps,
					seg->local_depth,
					dec2bin(seg->pattern,
						seg->local_depth, bin));
		}
		prev = dir->s[i];
	}
	cceh_seq_err(info, seq, "done.. cap=%d", cceh_dir_capa(info));
}

#define lp_slot(info, slot, probe)	((slot + probe) % info->pps)

static inline cceh_slot_t *cceh_insert4split_slot(struct cceh_seg *splitting,
		struct cceh_seg *new_seg, unsigned int si, cceh_slot_t *old)
{
	cceh_slot_t *slot = cceh_seg_nth_item(new_seg, si, sizeof(*slot));

	if (slot->k == (u64) INVALID) {
		slot->k = old->k;
		slot->v = old->v;
		segment_mov_count(splitting, new_seg);

		return slot;
	}
	return NULL;
}

static inline int cceh_segment_hold_slot(struct cceh_seg *segment,
		void *slot)
{
	return ((char *) segment <= (char *) slot &&
			(char *) slot < (char *) &segment->refcount);
}

/* cceh.c */
extern int __spfs_cceh_delete(struct spfs_cceh_info *, cceh_key_t, void *);
#define spfs_cceh_delete(info, q)	__spfs_cceh_delete(info, q, NULL)
extern void *spfs_cceh_insert(struct spfs_cceh_info *, cceh_key_t,
		cceh_value_t);
extern void *spfs_cceh_get(struct spfs_cceh_info *, cceh_key_t);
extern int spfs_cceh_init(struct spfs_sb_info *);
extern int spfs_cceh_exit(struct spfs_sb_info *);
extern bool spfs_cceh_revalidate(struct spfs_cceh_info *, cceh_query_t);

#endif
