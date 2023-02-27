#ifndef __JOURNAL_H__
#define __JOURNAL_H__

#include <linux/bitfield.h>

#include "spfs.h"

enum {
	CR_DIR_HINS,
	CR_REG_HINS,
	CHG_INODE_CNT,
	/*
	 * op_type2
	 * UL_x_HDEL(1B), de blk(5B)
	 * hash(4B)
	 */
	UL_DIR_HDEL,
	UL_REG_HDEL,
	/* write */
	WR_NEW,		/* H(1B), pad(3B), LEN(4B), LCN(4B), PCN(4B) */
	WR_UNDO,
	WR_SPLIT,
	WR_REPLACE,
	WR_PREALLOC,
	WR_INC_CLU,
	/* rename */
	RENAME_MODIFIED_BLK,
	RENAME_UNDO_BLK,
	/* TODO: truncate */
	TR_EXTENT,
	TR_DEC_CLU,
	RENAME_DIR_HINS,
	RENAME_REG_HINS,
	RENAME_DIR_HDEL,
	RENAME_REG_HDEL,
	RENAME_REPLACE,
};

#define OP_DATA	GENMASK(55,  0)
#define OP_TYPE	GENMASK(63, 56)

struct op_type1 {
	u64	e;
};

struct op_type2 {
	u64	h;
	u64	d;
};

struct op_type4 {
	u64	h;
	u64	d[3];
};

static inline void op_seth_type(u64 *first, u8 type)
{
	*first |= FIELD_PREP(OP_TYPE, type);
}

static inline u8 op_geth_type(u64 *first)
{
	return FIELD_GET(OP_TYPE, *first);
}

static inline u64 op_geth_data(u64 *first)
{
	return FIELD_GET(OP_DATA, *first);
}

static inline void op_seth(u64 *header, u8 type, u64 data)
{
	BUG_ON(data & 0xff00000000000000);
	*header = (FIELD_PREP(OP_TYPE, type) | FIELD_PREP(OP_DATA, data));
}

static inline void journal_log(void *journal, u8 type, void *data, size_t size)
{
	BUG_ON(size != 8 && size != 16);
	op_seth_type(data, type);
	/*
	 * Although the log entries are temporal, we must persisting new
	 * entry before committing log tail. Also, other CPUs only care about
	 * log tail. Just avoid cache snoop protocol for entreis.
	 */
	memcpy_flushcache(journal, data, size);
	SPFS_SFENCE();
}

static inline void journal_update_tail(u32 *tail, u32 v)
{
	/* log tail is in first cacheline of inode... So, it's temporal */
	*tail = v;
	clwb_sfence(tail, sizeof(u32));
}

#endif
