#include <linux/mm.h>
#include <linux/xattr.h>
#include <linux/quotaops.h>

#include "inode.h"
#include "extent.h"
#include "namei.h"
#include "profiler.h"
#include "stats.h"
#include "cceh_extent.h"


extern loff_t __dir_i_size_read(struct dentry *);

/* TODO: dquot */
void spfs_inode_inc_clusters(struct inode *inode, spfs_cluster_t count)
{
	spfs_inode_persist_blocks(inode, count, true);
	__inode_add_bytes(inode, count << CLUSTER_SHIFT);
}

void spfs_inode_dec_clusters(struct inode *inode, spfs_cluster_t count)
{
	spfs_inode_persist_blocks(inode, count, false);
	__inode_sub_bytes(inode, count << CLUSTER_SHIFT);
}

int spfs_truncate(struct inode *inode, bool by_demotion)
{
	spfs_cluster_t last_cluster;

	if (!(inode->i_state & (I_NEW|I_FREEING)))
		BUG_ON(!inode_is_locked(inode));

	/* allow only regular and dir. files */
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)))
		return 0;

	last_cluster = (by_demotion ? 0 : inode->i_size + CLUSTER_SIZE - 1) 
		>> CLUSTER_SHIFT;

	return spfs_extent_truncate(inode, last_cluster, (spfs_cluster_t) -1);
}

int spfs_update_inode_size(struct inode *inode, loff_t newsize)
{
	struct spfs_inode *raw_inode = I_INFO(inode)->raw_inode;

	if (newsize <= inode->i_size)
		return 0;

	raw_inode->i_size = newsize;
	spfs_persist(&raw_inode->i_size, sizeof(raw_inode->i_size));

	i_size_write(inode, newsize);

	return 1;
}

int spfs_inode_test(struct inode *inode, void *data)
{
	/* bypass inode with same hash */
	if (I_INFO(inode)->lower_inode)
		return 0;

	return inode->i_ino == (unsigned long) data;
}

struct inode *spfs_iget(struct super_block *sb,
		spfs_block_t ibno, unsigned int flags)
{
	struct inode *inode;
	struct spfs_inode *raw_inode;
	struct spfs_inode_info *inode_info;

	raw_inode = blk_addr(SB_INFO(sb), ibno);

	inode = iget5_locked(sb, ibno, spfs_inode_test, NULL, (void *) ibno);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	/* found in inode cache */
	if (!(inode->i_state & I_NEW))
		return inode;

	inode_info = I_INFO(inode);
	inode_info->raw_inode = raw_inode;
	inode_info->i_flags = le32_to_cpu(raw_inode->i_flags);

	inode->i_mode = le16_to_cpu(raw_inode->i_mode);

	i_uid_write(inode, (uid_t) le32_to_cpu(raw_inode->i_uid));
	i_gid_write(inode, (uid_t) le32_to_cpu(raw_inode->i_uid));

	inode->i_size = le64_to_cpu(raw_inode->i_size);
	inode->i_blocks = le32_to_cpu(raw_inode->i_blocks) <<
		(CLUSTER_SHIFT - 9);

	atomic64_set(&inode->i_version, le32_to_cpu(raw_inode->i_version));

	inode->i_ino = ibno;
	set_nlink(inode, le16_to_cpu(raw_inode->i_links_count));

	BUG_ON(!S_ISREG(inode->i_mode));

	inode->i_op = &spfs_main_iops;
	inode->i_fop = &spfs_main_fops;
	inode->i_mapping->a_ops = &spfs_aops;

	unlock_new_inode(inode);

	return inode;
}

static int spfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct spfs_inode *raw_inode = I_INFO(inode)->raw_inode;
	int error;
	const unsigned int ia_valid = attr->ia_valid;

	if (spfs_should_bypass(inode))
		return spfs_setattr_bp(dentry, attr);

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((ia_valid & ATTR_UID && !uid_eq(attr->ia_uid, inode->i_uid)) ||
			(ia_valid & ATTR_GID &&
			 !gid_eq(attr->ia_gid, inode->i_gid))) {
		u64 uid_gid;

		if (attr->ia_valid & ATTR_UID)
			inode->i_uid = attr->ia_uid;
		if (attr->ia_valid & ATTR_GID)
			inode->i_gid = attr->ia_gid;

		uid_gid = __kgid_val(inode->i_gid);
		uid_gid <<= 32;
		uid_gid |= __kuid_val(inode->i_uid);

		*((u64 *) &raw_inode->i_uid) = uid_gid;
		spfs_persist(raw_inode, 8);
	}

	/* TODO: consistency */
	if (attr->ia_valid & ATTR_SIZE) {
		if (attr->ia_size > spfs_max_inode_size(inode))
			return -EFBIG;

		if (!S_ISREG(inode->i_mode))
			return -EINVAL;

		if (IS_I_VERSION(inode) && attr->ia_size != inode->i_size)
			inode_inc_iversion(inode);

		/* TODO: persisting time and handling partial */
		if (inode_get_bytes(inode) && attr->ia_size < inode->i_size) {
			ext_trunc_msg("inode %lu %llu -> %llu", inode->i_ino,
					inode->i_size, attr->ia_size);

			inode->i_mtime = current_time(inode);
			inode->i_ctime = inode->i_mtime;

			i_size_write(inode, attr->ia_size);

			spfs_truncate(inode, false);
			spfs_truncate_extent_info(inode, BYTES2C(inode->i_size +
						CLUSTER_SIZE - 1));
		} else if (attr->ia_size > inode->i_size) {
			inode->i_mtime = current_time(inode);
			inode->i_ctime = inode->i_mtime;

			error = spfs_alloc_inode_blocks(inode,
					BYTES2C(inode->i_size + CLUSTER_SIZE -
						1), attr->ia_size - inode->i_size,
					attr->ia_size, GET_CLUSTERS_CREATE);
			if (error)
				return error;
		}

	}

	setattr_copy(inode, attr); /* need dirty concept? */

	if (ia_valid & ATTR_MODE) {
		raw_inode->i_mode = cpu_to_le16(inode->i_mode);
		spfs_persist(&raw_inode->i_mode, 2);
	}

	return 0;
}

int spfs_update_time(struct inode *inode, struct timespec64 *now, int flags)
{
	if (spfs_should_bypass(inode))
		return generic_update_time(inode, now, flags);

	/* TODO */
	return 0;
}

static int spfs_permission(struct inode *inode, int mask)
{
	if (spfs_should_bypass(inode))
		return spfs_permission_bp(inode, mask);
	return generic_permission(inode, mask);
}

int spfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
		unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);

	if (spfs_should_bypass(inode))
		return spfs_getattr_bp(path, stat, request_mask, flags);

	generic_fillattr(inode, stat);
	return 0;
}

ssize_t spfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	if (spfs_should_bypass(d_inode(dentry)))
		return spfs_listxattr_bp(dentry, list, size);
	return -EOPNOTSUPP; /* TODO */
}

const struct inode_operations spfs_main_iops = {
	.permission	= spfs_permission,
	.setattr	= spfs_setattr,
	.getattr	= spfs_getattr,
	.listxattr	= spfs_listxattr,
	.update_time	= spfs_update_time,
};

const struct xattr_handler *spfs_xattr_handlers[] = {
	/* TODO: now bypass all extended attribute operations */
	&spfs_xattr_bp_handler,
	NULL
};

static void spfs_set_iomap(struct inode *inode, struct iomap *iomap,
		struct spfs_map_request *map)
{
	iomap->flags = 0;
	/* need below two lines? */
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->dax_dev = SB_INFO(inode->i_sb)->s_dax_device;
	iomap->offset = C2BYTES(map->lcn); /* used at fs/iomap/apply.c:62 */
	iomap->length = C2BYTES(map->len);

	/* TODO: transparent map status handling */
	if (map->flags & SPFS_MAP_HOLE) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
	} else { // TODO: unwritten
		iomap->type = IOMAP_MAPPED;
		iomap->addr = C2BYTES(map->pcn);
		iomap->flags = IOMAP_F_MERGED;
	}

	iomap->private = map->jdata;
}

static int spfs_iomap_begin(struct inode *inode, loff_t pos,
		loff_t length, unsigned flags, struct iomap *iomap)
{
	DECLARE_MAP_REQUEST(map, BYTES2C(pos),
			BYTES2C(pos + length - 1) - map.lcn + 1);
	unsigned int map_flags = 0;
	int ret;
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);

	SPFS_BUG_ON(!map.len);

	if (flags & IOMAP_WRITE) {
		map_flags |= GET_CLUSTERS_CREATE;
		spfs_set_inode_recovery(inode);
	}

	if (spfs_is_append(inode, map.lcn)) {
		if (!(map_flags & GET_CLUSTERS_CREATE)) {
			map.flags |= SPFS_MAP_HOLE;
			goto map_done;
		}
		map_flags |= GET_CLUSTERS_EOF;
		if (S_OPTION(sbi)->pa_cluster_cnt)
			map.flags |= SPFS_MAP_GET_PREALLOC;
	}


	ret = spfs_extent_map_clusters(inode, &map, map_flags);
	if (ret < 0) {
		spfs_err(inode->i_sb, "%s(%d): map failed.. %d 0x%llx",
				__func__, __LINE__, ret, (u64) &map);
		return ret;
	}

	if (map.flags & SPFS_MAP_NEW)
		spfs_zeroize_extent_partial(SB_INFO(inode->i_sb), pos, length,
				map.pcn, map.len);

	/* magic error number for lower read */
	if (map.flags & SPFS_MAP_READ_LOWER)
		return -ENODATA;
map_done:
	spfs_set_iomap(inode, iomap, &map);

	return 0;
}
extern void spfs_free_extent_info(struct inode *inode,
		struct spfs_extent_info *ei);
static int spfs_iomap_end(struct inode *inode, loff_t offset, loff_t length,
		ssize_t written, unsigned flags, struct iomap *iomap)
{
	struct spfs_sb_info *sbi = SB_INFO(inode->i_sb);

	if (!(flags & IOMAP_WRITE))
		return 0;

	// TODO
	if (iomap->private) {
		if (op_geth_type(iomap->private) == WR_SPLIT) {
			spfs_ext_info_t *ei = (spfs_ext_info_t *)
				*((u64 *) iomap->private + 1);
			spfs_cluster_t lcn = (spfs_cluster_t) (uintptr_t)
				ei->data;
			unsigned int len = (*(u64 *) iomap->private) &
				0xffffffff;

			spfs_free_clusters_durable(sbi, ei->pcn +
					lcn - ei->lcn, len);
			spfs_free_clusters_volatile(sbi, ei->pcn + lcn -
					ei->lcn, len, true);
			spfs_delete_extent(inode, ei);
			//pr_err("%pK %pK", ei, iomap->private);
			rb_erase(&ei->rb_node, inode_rb_root(inode));
			spfs_free_extent_info(inode, ei);
		} else
			spfs_extent_commit_undo(inode, iomap->private);
	}
	ijournal_commit(inode);

	return 0;
}

const struct iomap_ops spfs_iomap_ops = {
	.iomap_begin	= spfs_iomap_begin,
	.iomap_end	= spfs_iomap_end,
};

const struct address_space_operations spfs_aops = {
	.direct_IO	= noop_direct_IO,
	.set_page_dirty	= noop_set_page_dirty,
	.invalidatepage	= noop_invalidatepage,
};
