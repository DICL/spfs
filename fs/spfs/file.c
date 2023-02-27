#include "spfs.h"
#include "stats.h"
#include "inode.h"
#include "file.h"
#include "cceh_extent.h"

#include <linux/uio.h>


extern ssize_t spfs_iomap_rw(struct kiocb *, struct iov_iter *,
		const struct iomap_ops *);
extern const struct iomap_ops spfs_iomap_ops;

static long spfs_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	struct inode *inode = file_inode(file);
	int ret = 0;

	if (spfs_should_bypass(inode)) {
		struct file *lower_file = spfs_file_to_lower(file);

		ret = vfs_ioctl(lower_file, cmd, arg);
		if (!ret)
			fsstack_copy_attr_all(inode, file_inode(lower_file));
		return ret;
	}

	/* TODO: no CMD right now */
	return ret;
}

#ifdef CONFIG_COMPAT
static long spfs_compat_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	struct inode *inode = file_inode(file);
	int ret = 0;

	if (spfs_should_bypass(inode)) {
		struct file *lower_file = spfs_file_to_lower(file);

		if (lower_file->f_op->compat_ioctl) {
			ret = lower_file->f_op->compat_ioctl(lower_file, cmd,
					arg);
			if (!ret)
				fsstack_copy_attr_all(inode,
						file_inode(lower_file));
		}
		return ret;
	}

	/* TODO */
	return ret;
}
#endif


/* TODO: profiler */
static ssize_t spfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (spfs_should_bypass(inode))
		return spfs_read_iter_bp(iocb, to);

	if (!iov_iter_count(to))
		return 0;

	inode_lock_shared(inode);
	ret = spfs_iomap_rw(iocb, to, &spfs_iomap_ops);
	inode_unlock_shared(inode);

	stats_prof_inc_read_on_boosted(inode, ret);

	/* fallback to lower due to migrated inode */
	if (ret == -ENODATA) {
		ret = spfs_read_iter_bp(iocb, to);
		stats_prof_inc_read_fallback_on_boosted(inode, ret);
	}

	file_accessed(iocb->ki_filp);

	return ret;
}

static ssize_t spfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret;
	size_t count;
	loff_t offset;
	struct inode *inode = file_inode(iocb->ki_filp);

	if (spfs_should_bypass(inode))
		return spfs_write_iter_bp(iocb, from);

	inode_lock(inode);

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	ret = file_remove_privs(iocb->ki_filp);
	if (ret)
		goto out;

	spfs_add_tiering_rw_file(inode, iocb->ki_filp);

	offset = iocb->ki_pos;
	count = iov_iter_count(from);

	/* Should we handle new append write... refer to ext4 */
	ret = spfs_iomap_rw(iocb, from, &spfs_iomap_ops);
	if (ret > 0)
		spfs_update_inode_size(inode, offset + ret);

	spfs_del_tiering_rw_file(inode);
out:
	inode_unlock(inode);
	/* need? */
	if (ret > 0) {
		ret = generic_write_sync(iocb, ret);
		stats_prof_inc_write_on_boosted(inode, ret);
	}

	return ret;
}

int spfs_open(struct inode *inode, struct file *file)
{
	if (IS_TIERED_INODE(inode) || spfs_should_bypass(inode))
		return spfs_open_bp(inode, file);

	return generic_file_open(inode, file);
}

static int spfs_release(struct inode *inode, struct file *file)
{
	if (IS_TIERED_INODE(inode) || spfs_should_bypass(inode))
		return spfs_release_bp(inode, file);

	return 0;
}

/* need unwritten? */
long spfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	loff_t new_size = 0;
	unsigned int max_blocks;
	int flags = GET_CLUSTERS_CREATE;
	int ret;

	if (spfs_should_bypass(inode)) {
		ret = vfs_fallocate(spfs_file_to_lower(file), mode, offset,
				len);
		if (!ret)
			fsstack_copy_inode_size(inode,
					spfs_inode_to_lower(inode));
		return ret;
	}

	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	if (mode & FALLOC_FL_KEEP_SIZE)
		flags |= GET_CLUSTERS_KEEP_SIZE;

	max_blocks = CLU_ALIGN(len + offset) - BYTES2C(offset);

	inode_lock(inode);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
			(offset + len > i_size_read(inode))) {
		new_size = offset + len;
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out;
	}

	spfs_add_tiering_rw_file(inode, file);

	ret = spfs_alloc_inode_blocks(file_inode(file),
			offset >> inode->i_blkbits, max_blocks, new_size,
			flags);

	spfs_del_tiering_rw_file(file_inode(file));
out:
	inode_unlock(inode);

	return ret;
}

static int spfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	if (spfs_should_bypass(file_inode(file)))
		return spfs_mmap_bp(file, vma);
	/* TODO */
	return -ENODEV;
}

static int spfs_flush(struct file *file, fl_owner_t id)
{
	if (spfs_should_bypass(file_inode(file))) {
		struct file *lower_file = spfs_file_to_lower(file);

		if (lower_file->f_op->flush)
			return lower_file->f_op->flush(lower_file, id);
	}

	return 0;

}

static int spfs_fsync(struct file *file, loff_t start, loff_t end,
		int datasync)
{
	if (spfs_should_bypass(file_inode(file)))
		return spfs_fsync_bp(file, start, end, datasync);
	stats_prof_inc_fsync_on_boosted(file_inode(file));
	return 0;
}

static int spfs_fasync(int fd, struct file *file, int flag)
{
	if (spfs_should_bypass(file_inode(file))) {
		struct file *lower_file = spfs_file_to_lower(file);
		
		if (lower_file->f_op->fasync)
			return lower_file->f_op->fasync(fd, lower_file, flag);
	}

	return 0;
}

int spfs_fadvise(struct file *file, loff_t offset, loff_t len, int advice)
{
	if (spfs_should_bypass(file_inode(file)))
		return vfs_fadvise(spfs_file_to_lower(file), offset, len,
				advice);
	return 0;
}

/*
 * flush: flip_close
 * release: ___fput
 */
const struct file_operations spfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= spfs_file_read_iter,
	.write_iter	= spfs_file_write_iter,
	/* TODO: comapt ioctl */
	.unlocked_ioctl	= spfs_unlocked_ioctl,
	.mmap		= spfs_mmap,
	.open		= spfs_open,
	.release	= spfs_release,
	.flush		= spfs_flush,
	.fsync		= spfs_fsync,
	.fasync		= spfs_fasync,
	.fallocate	= spfs_fallocate,
	.fadvise	= spfs_fadvise,
};

