#include <linux/genhd.h>
#include <linux/uio.h>
#include <linux/sched/signal.h>
#include "../internal.h"

#include "spfs.h"
#include "stats.h"
#include "dax.h"

static loff_t spfs_iomap_actor(struct inode *inode, loff_t pos,
		loff_t length, void *data, struct iomap *iomap)
{
	struct iov_iter *iter = data;
	loff_t end = pos + length, done = 0;
	ssize_t ret = 0;
	size_t xfer;
	struct dax_device *dax_device = SB_INFO(inode->i_sb)->s_dax_device;
	//int id;

	if (iov_iter_rw(iter) == READ) {
		end = min(end, i_size_read(inode));
		if (pos >= end)
			return 0;

		if (iomap->type == IOMAP_HOLE || iomap->type == IOMAP_UNWRITTEN)
			return iov_iter_zero(min(length, end - pos), iter);
	}

	BUG_ON(iomap->type != IOMAP_MAPPED);

	//id = dax_read_lock();
	while (pos < end) {
		unsigned offset = CLU_OFF(pos);
		size_t map_len = iomap->length;
		void *kaddr = BASE(SB_INFO(inode->i_sb)) + iomap->addr;

		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		kaddr += offset;
		map_len -= offset;
		if (map_len > end - pos)
			map_len = end - pos;

		/* dax_device is used only for checking aliveness */
		if (iov_iter_rw(iter) == WRITE) {
			xfer = dax_copy_from_iter(dax_device, 0, kaddr, map_len,
					iter);
		} else {
#if 1
			const char *from = kaddr;

			/* relaxed version that same as NOVA COW mode */
			iterate_and_advance(iter, map_len,
					__copy_to_user(v.iov_base,
						(from += v.iov_len) - v.iov_len,
						v.iov_len));
			xfer = map_len;
#else
			xfer = dax_copy_to_iter(dax_device, 0, kaddr, map_len,
					iter);
#endif
		}

		pos += xfer;
		length -= xfer;
		done += xfer;

		if (xfer == 0)
			ret = -EFAULT;
		if (xfer < map_len)
			break;
	}
	//dax_read_unlock(id);

	return done ?: ret;
}

ssize_t spfs_iomap_rw(struct kiocb *iocb, struct iov_iter *iter,
		const struct iomap_ops *ops)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	loff_t pos = iocb->ki_pos, ret = 0, done = 0;
	unsigned flags = 0;

	if (iov_iter_rw(iter) == WRITE) {
		lockdep_assert_held_exclusive(&inode->i_rwsem);
		flags |= IOMAP_WRITE;
	} else {
		lockdep_assert_held(&inode->i_rwsem);
	}

	while (iov_iter_count(iter)) {
		ret = iomap_apply(inode, pos, iov_iter_count(iter), flags, ops,
				iter, spfs_iomap_actor);
		if (ret <= 0)
			break;
		pos += ret;
		done += ret;
	}

	iocb->ki_pos += done;
	return done ? done : ret;
}

/* READ */
size_t spfs_dax_copy_to_addr(struct spfs_sb_info *sbi,
		void *dst, void *src, size_t cnt)
{
	return memcpy_mcsafe(dst, src, cnt);
}

/* WRITE */
size_t spfs_dax_copy_from_addr(struct spfs_sb_info *sbi,
		void *dst, void *src, size_t cnt, bool sfence)
{
	memcpy_flushcache(dst, src, cnt);
	if (sfence)
		asm volatile ("sfence\n"::);

	return cnt; // TODO: naive return
}

void *spfs_map_dax_device(struct spfs_sb_info *sbi, long nr_pages)
{
	void *kaddr;

	sbi->s_map_len = dax_direct_access(sbi->s_dax_device, 0, nr_pages,
			&kaddr, NULL);
	if (sbi->s_map_len < 0)
		return ERR_PTR(sbi->s_map_len);

	spfs_msg(sbi->s_sb, KERN_INFO, "dax mapping done: %pK, %zd",
			kaddr, sbi->s_map_len);

	return kaddr;
}

struct dax_device *spfs_get_dax_device(struct super_block *sb)
{
	struct dax_device *dax_device;
	char *disk_name = sb->s_bdev->bd_disk->disk_name;
	int ret;

	spfs_msg(sb, KERN_INFO, "opening dax device %s", disk_name);

	ret = bdev_dax_supported(sb->s_bdev, PAGE_SIZE);
	if (!ret) {
		spfs_msg(sb, KERN_ERR, "%s does not support DAX",
				disk_name);
		return ERR_PTR(-EINVAL);
	}

	dax_device = dax_get_by_host(sb->s_bdev->bd_disk->disk_name);
	if (!dax_device) {
		spfs_msg(sb, KERN_ERR, "can not get dax device %s",
				disk_name);
		return ERR_PTR(-EINVAL);
	}

	return dax_device;
}
