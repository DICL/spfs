#include "spfs.h"
#include "calloc.h"
#include "extent.h"
#include "cceh_extent.h"
#include "stats.h"
#include "profiler.h"


static struct kmem_cache *spfs_extent_info_cachep;


static spfs_ext_info_t *spfs_alloc_extent_info(struct inode *inode,
		struct spfs_extent *ext, struct spfs_map_request *map)
{
	struct spfs_extent_info *ei;

	ei = kmem_cache_alloc(spfs_extent_info_cachep, GFP_ATOMIC); 
	if (!ei)
		return NULL;

	// TODO: revalidation
	ei->es = container_of(ext, cceh_es_t, extent);

	ei->prev_extent_lcn = ei->es->prev_extent_lcn;
	ei->lcn = ext->lcn;
	ei->pcn = ext->pcn;
	ei->len = ext->len;

	BUG_ON(!ei->len);

	INIT_LIST_HEAD(&ei->pa_list);
	if (map)
		ei->pa_len = MAP_LEN(map) - MAP_REQ_LEN(map);
	else
		ei->pa_len = 0;

	spfs_ext_debug("\tinode=%lu lcn=%u len=%u pa_len=%u eof=%u",
			inode->i_ino, ei->lcn, ei->len, ei->pa_len,
			I_EOF(inode));

	return ei;
}

void spfs_free_extent_info(struct inode *inode,
		struct spfs_extent_info *ei)
{
	spfs_ext_debug("inode=%lu lcn=%u 0x%px", inode->i_ino, ei->lcn, ei);
	kmem_cache_free(spfs_extent_info_cachep, ei);
}

struct spfs_extent_info *spfs_insert_extent_info(struct inode *inode,
		struct spfs_extent_info *ei, bool get_old)
{
	struct rb_node **p = &inode_rb_root(inode)->rb_node;
	struct rb_node *parent = NULL;
	struct spfs_extent_info *tmp;

	while (*p) {
		parent = *p;
		tmp = rb_entry(*p, struct spfs_extent_info, rb_node);

		if (ei->lcn < tmp->lcn)
			p = &(*p)->rb_left;
		else if (ei->lcn > EI_PA_END(tmp, lcn))
			p = &(*p)->rb_right;
		else {
			if (get_old) {
				spfs_free_extent_info(inode, ei);
				return tmp;
			}
			BUG();
		}
	}

	rb_link_node(&ei->rb_node, parent, p);
	rb_insert_color(&ei->rb_node, inode_rb_root(inode));

	return ei;
}

spfs_ext_info_t *spfs_search_extent_info(struct inode *inode,
		spfs_cluster_t lcn)
{
	struct spfs_extent_info *ei;
	struct spfs_extent *ext;

	read_lock(&I_INFO(inode)->i_extent_lock);
	ei = __spfs_search_extent_info(inode, lcn, false);
	read_unlock(&I_INFO(inode)->i_extent_lock);
	if (ei)
		return ei;

	ext = spfs_search_extent(inode, lcn);
	if (!ext)
		return NULL;

	ei = spfs_alloc_extent_info(inode, ext, NULL);
	write_lock(&I_INFO(inode)->i_extent_lock);
	ei = spfs_insert_extent_info(inode, ei, true);
	write_unlock(&I_INFO(inode)->i_extent_lock);

	return ei;
}

static
struct spfs_extent_info *spfs_search_extent_right_quad(struct inode *inode,
		spfs_cluster_t lcn)
{
	spfs_cluster_t plus = 1;
	struct spfs_extent_info *ei;

	do {
		ei = spfs_search_extent_info(inode, lcn + plus);
		if (ei)
			break;
	} while (lcn + (plus <<= 1) <= I_EOF(inode));

	return ei;
}

static struct spfs_extent_info *spfs_search_extent_right(struct inode *inode,
		spfs_cluster_t lcn)
{
	struct spfs_extent_info *ei;

	if (I_EOF(inode) == -1)
		return NULL;

	ei = spfs_search_extent_right_quad(inode, lcn);
	if (!ei) {
		/* get last extent holding EOF */
		ei = spfs_search_extent_info(inode, I_EOF(inode));
		BUG_ON(!ei);
	}

	while (ei->es->prev_extent_lcn != 0xDEADC0DE &&
			ei->es->prev_extent_lcn > lcn)
		ei = spfs_search_extent_info(inode, ei->es->prev_extent_lcn);

	return ei;
}

static int spfs_use_preallocation(struct spfs_sb_info *sbi,
		struct inode *inode, struct spfs_map_request *map)
{
	spfs_cluster_t pa_lcn = EXT_END(map->ei, lcn) + 1;
	spfs_cluster_t pa_pcn = EXT_END(map->ei, pcn) + 1;
	spfs_cluster_t pa_map_end = LEN_TO_OFF(map->lcn, map->len);
	unsigned int len = pa_map_end - pa_lcn + 1;

	stats_inc_prealloc_usage();

	ijnl_write(inode, WR_PREALLOC, pa_lcn, pa_pcn, len);
	spfs_alloc_clusters_durable(sbi, pa_pcn, len);

	map->ei->len += len;
	BUG_ON(map->ei->pa_len < len);
	map->ei->pa_len -= len;

	if (map->lcn != pa_lcn)
		memset_l(clu_addr(sbi, pa_pcn), 0, (map->lcn - pa_lcn + 1) *
				CLUSTER_SIZE / 8);

	spfs_update_extent_len(inode, map->ei);

	if (EXT_END(map->ei, lcn) > I_EOF(inode)) {
		I_EOF(inode) = EXT_END(map->ei, lcn);
		clwb_sfence(&I_EOF(inode), sizeof(u32));
	}

	/* we allocate hole in the middle of allocations by force */
	ijnl_t1(inode, WR_INC_CLU, len);
	spfs_inode_inc_clusters(inode, len);

	map->flags |= SPFS_MAP_NEW;

	return map->len;
}

static unsigned int spfs_map_migrated_extent(struct inode *inode,
		struct spfs_map_request *map, int *errp)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	ssize_t nread;
	ssize_t done = 0;
	loff_t pos = C2BYTES(map->ei->lcn);
	unsigned int len = map->ei->len;
	unsigned int n_alloc;

	map->ei->pcn = spfs_alloc_clusters_volatile(sbi, &len, true, true,
			errp);
	if (*errp) {
		spfs_debug_err(inode->i_sb, "failed to get %u clusters",
				map->ei->len);
		return *errp;
	}
	BUG_ON(len != map->ei->len); // TODO

	//pr_err("%s: inode=%lu lcn=%u len=%u pcn=%u", __func__,
	//		inode->i_ino, map->ei->lcn, map->ei->len, map->ei->pcn);
	/* TODO: size comparison */

	do {
		char *buf = (char *) clu_addr(sbi, map->ei->pcn) + done;

		nread = spfs_migr_fill_extent(inode, buf, C2BYTES(len) - done,
				&pos);
		if (nread < 0) {
			*errp = nread;
			goto out;
		}
	} while (C2BYTES(len) != (done += nread));

	ijnl_write(inode, WR_NEW, map->ei->lcn, map->ei->pcn, map->ei->len);
	spfs_alloc_clusters_durable(sbi, map->ei->pcn, map->ei->len);

	spfs_update_extent_pcn(inode, map->ei);

	n_alloc = spfs_adjust_map_by_extent_info(map);

	ijnl_t1(inode, WR_INC_CLU, map->ei->len);
	spfs_inode_inc_clusters(inode, map->ei->len);
	
	return n_alloc;

out:
	spfs_free_clusters_volatile(sbi, map->ei->pcn, len, true);
	map->ei->pcn = 0;
	return *errp;
}

int spfs_extent_map_clusters(struct inode *inode, struct spfs_map_request *map,
		unsigned int flags)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	int err = 0;
	unsigned int n_alloc = 0;
	struct spfs_extent *ext;
	struct spfs_extent_info *right_ei = NULL;
	cceh_es_t *es;
	int create = flags & GET_CLUSTERS_CREATE;
	int eof = flags & GET_CLUSTERS_EOF;
	spfs_cluster_t pelcn;


	map->len = MIN(map->len, S_OPTION(sbi)->max_extent_len);

	if (create && eof)
		goto carve;

	map->ei = spfs_search_extent_info(inode, map->lcn);

	/*
	 * Both reading and writing to hole need to find the right extent and
	 * adjust the request size.
	 */
	if (map->ei == NULL)
		goto adjust_right;

	/* got migrated extents */
	if (map->ei->pcn == 0) {
		if (create)
			n_alloc = spfs_map_migrated_extent(inode, map, &err);
		else
			map->flags |= SPFS_MAP_READ_LOWER;
		goto out;
	}

	/* got normal extents */
	n_alloc = spfs_adjust_map_by_extent_info(map);

	if ((map->flags & SPFS_MAP_USE_PREALLOC)) {
		if (create)
			n_alloc = spfs_use_preallocation(sbi, inode, map);
		else
			map->flags |= SPFS_MAP_HOLE;
		goto out;
	}

	if (create) /* overwriting */
		spfs_extent_log_undo(inode, map);

	/* read from existing extent */
	goto out;

adjust_right:
	right_ei = spfs_search_extent_right(inode, map->lcn);
	if (right_ei) {
		/* check possible overlap */
		if (right_ei->lcn < map->lcn) {
			struct spfs_extent_info *einfo =
				spfs_search_extent_info(inode, right_ei->lcn);

			spfs_err(inode->i_sb, "%s: %u %u %u %u %u %u %u %u",
					__func__,
					einfo->lcn, einfo->len, einfo->pa_len,
					map->lcn, map->len,
					right_ei->lcn, right_ei->len,
					right_ei->pa_len);
			BUG();
		}

		spfs_extent_adjust_map_len(inode, map, right_ei);
	}

	if (!create) {
		map->flags |= SPFS_MAP_HOLE;
		goto out;
	}

carve:
	spfs_carve_extent_len(sbi, map, right_ei);

	n_alloc = MAP_LEN(map);
	map->pcn = spfs_alloc_clusters_volatile(sbi, &n_alloc, false, false,
			&err);
	if (err) {
		spfs_err(inode->i_sb, "%s: failed to allocate %lu blocks",
				__func__, MAP_LEN(map));
		goto out;
	}

	/* TODO: carve again!! */
	if (n_alloc != MAP_LEN(map)) {
		spfs_debug(sbi->s_sb, "%s: %u %u %u %u", __func__, map->lcn, 
				map->len, map->pa_len, n_alloc);

		if (n_alloc <= map->len)
			map->len = n_alloc;
		else
			spfs_free_clusters_volatile(sbi, EXT_END(map, pcn),
					n_alloc - map->len, true);
		map->pa_len = 0;
	}

	/*
	 * It does not pointed by map->jdata because it's not an undo extent.
	 * Log legnth except preallocated clusters.
	 */
	ijnl_write(inode, WR_NEW, map->lcn, map->pcn, MAP_REQ_LEN(map));
	spfs_alloc_clusters_durable(sbi, map->pcn, MAP_REQ_LEN(map));

	if (right_ei)
		pelcn = right_ei->es->prev_extent_lcn;
	else if (I_EOF(inode) == -1)
		pelcn = 0xDEADC0DE;
	else
		pelcn = spfs_search_extent_info(inode, I_EOF(inode))->lcn;

	es = spfs_insert_extent(inode, map, pelcn);
	BUG_ON(!es || IS_ERR(es) || es->inode_no != inode->i_ino);
	ext = &es->extent;

	if (right_ei) { // insert between extents
		right_ei->prev_extent_lcn = map->lcn;
		spfs_update_extent_list(inode, right_ei);
	} else {
		I_EOF(inode) = LEN_TO_OFF(map->lcn, MAP_REQ_LEN(map));
		clwb_sfence(&I_EOF(inode), sizeof(u32));
	}

	ijnl_t1(inode, WR_INC_CLU, MAP_REQ_LEN(map));
	spfs_inode_inc_clusters(inode, MAP_REQ_LEN(map));

	map->ei = spfs_alloc_extent_info(inode, ext, map);
	spfs_insert_extent_info(inode, map->ei, false);

	map->flags |= SPFS_MAP_NEW;
out:
	BUG_ON(map->len == 0);
	return err ?: n_alloc;
}

/*
 * -------xxxxxxxxxx
 *        ^start   ^end
 * end is always file's end
 */
int spfs_extent_truncate(struct inode *inode, spfs_cluster_t start,
		spfs_cluster_t end)
{
	struct spfs_extent_info *ei = NULL;
	spfs_cluster_t pelcn = I_EOF(inode);
	spfs_cluster_t nfree = 0;

	set_bit(INODE_TRUNCATING, (unsigned long *) &I_RAW(inode)->i_flags);
	_clwb(&I_RAW(inode)->i_flags, sizeof(I_RAW(inode)->i_flags));

	while (1) {
		if (unlikely(!ei))
			ei = spfs_search_extent_info(inode, pelcn);
		CHECK_DATA_CORRUPTION(!ei, "inode=%lu pelcn=%u", inode->i_ino, pelcn);

		pelcn = ei->prev_extent_lcn; // next extent start

		ext_trunc_msg("inode=%lu s=%u lcn=%u len=%u palen=%u pelcn=%u",
				inode->i_ino, start, ei->lcn, ei->len,
				ei->pa_len, pelcn);

		if (likely(ei->lcn >= start)) {
			nfree += spfs_free_extent(inode, ei);
			BUG_ON(spfs_delete_extent(inode, ei));
		} else if (spfs_extent_hold_lcn_pa(ei, start)) {
			unsigned int nr;

			nr = __spfs_free_extent(inode, ei, start);
			if (!nr)
				break;

			nfree += nr;
			__spfs_update_extent_len(inode, ei, ei->len - nr);

			I_EOF(inode) = LEN_TO_OFF(ei->lcn, ei->len - nr);
			spfs_persist(&I_EOF(inode), sizeof(I_EOF(inode)));

			goto out;
		} else
			break;

		if (pelcn == 0xDEADC0DE) {
			I_EOF(inode) = -1;
			spfs_persist(&I_EOF(inode), sizeof(I_EOF(inode)));

			goto out;
		}

		ei = spfs_search_extent_info(inode, pelcn);

		I_EOF(inode) = LEN_TO_OFF(pelcn, ei->len);
		spfs_persist(&I_EOF(inode), sizeof(I_EOF(inode)));
	}
out:
	ext_trunc_msg("inode=%lu pelcn=%u eof=%u", inode->i_ino, pelcn,
			I_EOF(inode));

	if (CLU_OFF(inode->i_size)) {
		struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);

		ei = spfs_search_extent_info(inode, BYTES2C(inode->i_size));
		if (ei && spfs_extent_hold_lcn(ei, BYTES2C(inode->i_size))) {
			char *paddr;
			unsigned long size;

			paddr = (char *) clu_addr(sbi, ei->pcn) +
				inode->i_size - C2BYTES(ei->lcn);
			size = C2BYTES(ei->lcn + ei->len) - inode->i_size;

			memset(paddr, 0, size);
			_clwb(paddr, size);
		}
	}

	/*
	 * Since i_eof, i_blocks and i_flags are all in the same cache line,
	 * reordering is not allowed.
	 */
	spfs_inode_dec_clusters(inode, nfree);
	__clear_bit(INODE_TRUNCATING, (unsigned long *) &I_RAW(inode)->i_flags);
	clwb_sfence(I_RAW(inode), 64);

	return 0;
}

void spfs_truncate_extent_info(struct inode *inode, spfs_cluster_t lcn)
{
	struct spfs_extent_info *ei;
	struct rb_node *node;

	ei = __spfs_search_extent_info(inode, lcn, true);
	if (!ei)
		return;

	/* Got extent starting or containing lbn */
	while (1) {
		node = rb_next(&ei->rb_node); /* next */

		/* discard preallocation */
		if (ei->pa_len) {
			BUG_ON(inode->i_nlink == 0);
			spfs_free_clusters_volatile(SB_INFO(inode->i_sb),
					EXT_END(ei, pcn) + 1, ei->pa_len, true);
			ei->pa_len = 0;
		}

		if (lcn <= ei->lcn) {
			rb_erase(&ei->rb_node, inode_rb_root(inode));
			spfs_free_extent_info(inode, ei);
		} else /* truncating extent containing lbn */
			ei->len = lcn - ei->lcn;

		if (!node)
			break;

		ei = rb_entry(node, struct spfs_extent_info, rb_node);
	}
}

int spfs_alloc_inode_blocks(struct inode *inode, spfs_cluster_t lcn,
		unsigned int len, loff_t new_size, int flags)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	DECLARE_MAP_REQUEST(map, lcn, len);
	int ret = 0;
	loff_t epos;

	BUG_ON(map.len == 0);

	ext_trunc_msg("inode %lu %llu -> %llu", inode->i_ino,
			inode->i_size, new_size);


	while (ret >= 0 && len) {
		if (!(flags & GET_CLUSTERS_EOF) &&
				spfs_is_append(inode, map.lcn))
			flags |= GET_CLUSTERS_EOF;

		ret = spfs_extent_map_clusters(inode, &map, flags);
		if (ret <= 0) {
			spfs_debug_err(inode->i_sb, "inode %lu lcn %u len "
					"%u: %d", inode->i_ino, lcn, len, ret);
			break;
		}

		map.lcn += ret;
		map.len = len = len - ret;
		map.pa_len = 0;
		map.ei = NULL;
		map.jdata = NULL;

		if (!(map.flags & SPFS_MAP_NEW))
			goto commit;

		map.flags = 0;

		memset_l(clu_addr(sbi, map.pcn), 0, C2BYTES(ret) >> 3);
		clwb_sfence(clu_addr(sbi, map.pcn), C2BYTES(ret));

		epos = C2BYTES(map.lcn);
		inode->i_ctime = current_time(inode);
		if (new_size) {
			if (epos > new_size)
				epos = new_size;
			if (spfs_update_inode_size(inode, epos))
				inode->i_mtime = inode->i_ctime;
		}
commit:
		ijournal_commit(inode);
	}

	/* TODO: handle ENOSPC */
	return ret > 0 ? 0 : ret;
}

extern long __copy_user_nocache(void *dst, const void __user *src,
				unsigned size, int zerorest);
extern int split_extent(struct inode *inode, struct spfs_map_request *map);

int __spfs_extent_log_undo(struct inode *inode, struct spfs_map_request *map)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);
	struct spfs_extent_info *ei = map->ei;
	spfs_cluster_t pcn;
	int threshold = S_OPTION(sbi)->undo_opt_util;
	bool replace = threshold && spfs_undo_utilization(map) >= threshold;
	unsigned int len = replace ? EI_TOTAL_LEN(ei) : map->len;
	unsigned int result_len = len;
	int err;
	bool split = false;

	if (!replace && map->len >= 64) { /* 256KB */
		map->len = __spfs_carve_extent_len(map->lcn, map->len);
		split = true;
	}

	pcn = spfs_alloc_clusters_volatile(sbi, &result_len, false, true, &err);
	if (err) {
		spfs_err(inode->i_sb, "%s: ENOSPC while undoing.. just write "
				"inode=%lu", __func__, inode->i_ino);
		return err;
	}

	spfs_ext_debug("inode=%lu lcn=%u len=%u pa_len=%u replace=%d",
			inode->i_ino, ei->lcn, ei->len, ei->pa_len,
			replace);

	if (split) {
		struct op_type2 op = {
			((u64) pcn) << 32 | map->len,
			(u64) (uintptr_t) ei
		};

		ei->data = (void *) (uintptr_t) map->lcn;
		map->pcn = pcn;
		split_extent(inode, map);
		map->jdata = ijournal_log(inode, WR_SPLIT, op);
		spfs_alloc_clusters_durable(sbi, pcn, map->len);

		stats_log_cow();
		return 0;
	}

	/*
	 * If we failed to get as many as clusters we want, we give up
	 * replacement and shrink the IO size.
	 */
	if (len != result_len) {
		replace = false;
		map->len = MIN(result_len, map->len);
	}

	/* just make an undo copy */
	if (!replace) {
		__copy_user_nocache(clu_addr(sbi, pcn), clu_addr(sbi, map->pcn),
				C2BYTES(map->len), 0);
		/*
		 * ensure that stores for original blocks are issued before
		 * the log. This is not for cache coherency.
		 */
		SPFS_SFENCE();

		map->jdata = ijnl_undo(inode, WR_UNDO, map->lcn, pcn,
				map->len, 0);
	//	spfs_alloc_clusters_durable(sbi, pcn, map->len);

		stats_log_undo();
		return 0;
	}


	stats_log_replace();
	/*
	 * REPLACEMENT
	 * Log original extent and make pbn as real extent.
	 * Copy the area not written by this write.
	 */
	if (map->lcn != ei->lcn) {
		memcpy(clu_addr(sbi, pcn), clu_addr(sbi, ei->pcn),
				C2BYTES(map->lcn - ei->lcn));
		clwb_sfence(clu_addr(sbi, pcn), C2BYTES(map->lcn - ei->lcn));
	}
	if (map_lcn_end(map) != EXT_END(ei, lcn)) {
		memcpy(clu_addr(sbi, pcn + (map_lcn_end(map) - ei->lcn) + 1),
				clu_addr(sbi, map_pcn_end(map) + 1),
				C2BYTES(EXT_END(ei, lcn) - map_lcn_end(map)));
		clwb_sfence(clu_addr(sbi, pcn + (map_lcn_end(map) - ei->lcn) + 1),
				C2BYTES(EXT_END(ei, lcn) - map_lcn_end(map)));
	}


	/* log to journal entry first */
	map->jdata = ijnl_undo(inode, WR_REPLACE, ei->lcn, ei->pcn, ei->len,
			ei->pa_len);

	ei->pcn = pcn;
	spfs_update_extent_pcn(inode, ei);

	/* commit the clusters except prealloc. */
	spfs_commit_block_allocation(sbi, pcn, ei->len);

	return 0;
}

int __init spfs_init_extent(void)
{
	spfs_extent_info_cachep = kmem_cache_create("spfs_extent_info",
			sizeof(struct spfs_extent_info), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);
	if (!spfs_extent_info_cachep)
		return -ENOMEM;

	return 0;
}

void spfs_exit_extent(void)
{
	kmem_cache_destroy(spfs_extent_info_cachep);
}

/* len must be splited by extent hashing first */
int split_extent(struct inode *inode, struct spfs_map_request *map)
{
	unsigned int remain;
	unsigned int remain_total = map->ei->len;
	unsigned int len;
	struct spfs_map_request m;
	cceh_es_t *es, *prev = NULL;
	struct spfs_extent_info *rei;
	spfs_cluster_t lcn = map->ei->lcn;
	spfs_cluster_t split_lcn = map->lcn;
	unsigned int split_len = map->len;

	if (lcn == split_lcn)
		goto second;

	remain = split_lcn - lcn + 1;
	do {
		len = __spfs_carve_extent_len(lcn, remain);

		m.lcn = lcn;
		m.len = len;
		m.pcn = map->ei->pcn + lcn - map->ei->lcn;
		es = spfs_insert_extent(inode, &m, prev ?
				prev->extent.lcn :
				map->ei->prev_extent_lcn);
		prev = es;
		lcn += len;
		remain -= len;
		remain_total -= len;
	} while (remain);
second:
	remain = split_len;
	do {
		len = __spfs_carve_extent_len(lcn, remain);

		m.lcn = lcn;
		m.len = len;
		if (lcn == split_lcn)
			m.pcn = map->pcn;
		else
			m.pcn = map->ei->pcn + lcn - map->ei->lcn;
		es = spfs_insert_extent(inode, &m, prev ?
				prev->extent.lcn :
				map->ei->prev_extent_lcn);
		prev = es;
		lcn += len;
		remain -= len;
		remain_total -= len;
	} while (remain);

	if (!remain_total)
		goto out;

	remain = remain_total;
	do {
		len = __spfs_carve_extent_len(lcn, remain);

		m.lcn = lcn;
		m.len = len;
		m.pcn = map->ei->pcn + lcn - map->ei->lcn;
		es = spfs_insert_extent(inode, &m, prev ?
				prev->extent.lcn :
				map->ei->prev_extent_lcn);
		prev = es;

		lcn += len;
		remain -= len;
		remain_total -= len;
	} while (remain);
out:
	rei = spfs_search_extent_right(inode, map->ei->lcn);
	if (rei) {
		rei->es->prev_extent_lcn = prev->extent.lcn;
		rei->prev_extent_lcn = prev->extent.lcn;
	}

	return 0;
}
