#include "spfs.h"
#include "stats.h"
#include "inode.h"
#include "file.h"
#include "cceh_extent.h"

#include <linux/uio.h>
#include <linux/mount.h>


extern ssize_t spfs_iomap_rw(struct kiocb *, struct iov_iter *,
		const struct iomap_ops *);
extern const struct iomap_ops spfs_iomap_ops;
extern int migrate_file_to_lower(struct inode *inode, struct dentry *dentry);

static long spfs_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	struct inode *inode = file_inode(file);
	int ret = 0;
	struct spfs_migr_info *migr_info;

	if (spfs_should_bypass(inode)) {
		struct file *lower_file = spfs_file_to_lower(file);
		struct dentry *dentry;
		
		/* Force Bp file to Tiered file */
		switch (cmd) {
			case SPFS_IOC_SET_UP_MIGR:
				set_inode_flag(inode, INODE_NEED_TIERING);
				stats_prof_inc_boosted();
				dentry = file_dentry(file);
				//pr_info("ioctl: prepare up migr file=%s", 
				//		dentry->d_name.name);
				spfs_prepare_upward_migration(dentry);
				return ret;
		}

		ret = vfs_ioctl(lower_file, cmd, arg);
		if (!ret)
			fsstack_copy_attr_all(inode, file_inode(lower_file));
		return ret;
	}

	/* Force Tiered file to BP file */
	switch (cmd) {
		case SPFS_IOC_SET_DOWN_MIGR:
			//pr_info("ioctl: start down migr file=%s", 
			//		file->f_path.dentry->d_name.name);
	
			migr_info = I_INFO(inode)->migr_info; 
			
			inode_lock_shared(inode);
			list_del(&migr_info->migr_list);
			
			ret = migrate_file_to_lower(inode, file_dentry(file));
			if (ret != -EAGAIN) {
				dput(migr_info->dentry);
				kfree(migr_info);
			}
			break;
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

void spfs_handle_accum_sf_rd(struct work_struct *work)
{
	struct spfs_work_data *data = (struct spfs_work_data *)work;
	struct inode *inode = data->inode;
	struct dentry *dentry = data->dentry;
	unsigned int old;

	spin_lock(&dentry->d_lock);
	if (d_unlinked(dentry)) {
		spin_unlock(&dentry->d_lock);
		goto out;
	}
	spin_unlock(&dentry->d_lock);
	
	if (!inode_trylock(inode))
		goto out;
	
	if (__spfs_revalidate_tiered(inode))
		goto out2;

	atomic_set(&I_INFO(inode)->sf_rd_cnt, 0);
	old = I_RAW(inode)->i_sync_factor;
	spfs_inode_fast_update_sync_factor(inode, 0);
	
	spfs_calibrate_migr_list(inode, old);
out2:	
	inode_unlock(inode);
out:
	dput(dentry);
	kfree(data);
	atomic_set(&I_INFO(inode)->wq_doing, 0);
}

/* TODO: profiler */
static ssize_t spfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct spfs_mount_options *opts = S_OPTION(SB_INFO(inode->i_sb));
	ssize_t ret;

	if (spfs_should_bypass(inode)) {
bypass:
		return spfs_read_iter_bp(iocb, to);
	}

	if (!iov_iter_count(to))
		return 0;

	inode_lock_shared(inode);
	if (spfs_revalidate_tiered(inode, true)) {
		inode_unlock_shared(inode);
		goto bypass;
	}

	ret = spfs_iomap_rw(iocb, to, &spfs_iomap_ops);
	inode_unlock_shared(inode);

	if (!IS_OP_MODE_TIERING(SB_INFO(inode->i_sb)) || !opts->demotion)
		goto out;

	/* handle accum sf_rd_cnt by workqueue, XXX: ad-hoc thld */
	if (atomic_inc_return(&I_INFO(inode)->sf_rd_cnt) >= 
			SB_INFO(inode->i_sb)->sf_rd_thld && 
			!atomic_cmpxchg(&I_INFO(inode)->wq_doing, 0, 1)) {
		struct spfs_work_data *data; 

		data = kmalloc(sizeof(struct spfs_work_data), GFP_KERNEL);
		data->inode = inode;
		data->dentry = dget(file_dentry(iocb->ki_filp));
		
		INIT_WORK(&data->work, spfs_handle_accum_sf_rd);
		schedule_work(&data->work);	
	}
out:
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
	struct spfs_mount_options *opts = S_OPTION(SB_INFO(inode->i_sb));

	if (spfs_should_bypass(inode)) {
bypass:
		return spfs_write_iter_bp(iocb, from);
	}

	inode_lock(inode);
	if (spfs_revalidate_tiered(inode, false)) {
		inode_unlock(inode);
		goto bypass;
	}

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

	if (IS_OP_MODE_TIERING(SB_INFO(inode->i_sb)) && opts->demotion && 
			ret > 0) {
		unsigned int old;
		
		spfs_prof_update_bytes_written(inode, ret);
		spfs_profile_fsync2(iocb->ki_filp);

		old = I_RAW(inode)->i_sync_factor;
		spfs_inode_update_sync_factor(inode, 
				ret < opts->migr_written_bytes_btw_fsync ? 
				opts->migr_written_bytes_btw_fsync - ret : 0); 

		spfs_calibrate_migr_list(inode, old);
	}

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

extern struct kmem_cache *spfs_file_info_cachep;
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
bypass:
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
	if (spfs_revalidate_tiered(inode, false)) {
		inode_unlock(inode);
		goto bypass;
	}

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
	struct inode *inode = file_inode(file);

	if (spfs_should_bypass(inode)) {
		struct file *lower_file = spfs_file_to_lower(file);

		if (lower_file->f_op->flush)
			return lower_file->f_op->flush(lower_file, id);
	}

	return 0;
}

static int spfs_fsync(struct file *file, loff_t start, loff_t end,
		int datasync)
{
	struct inode *inode = file_inode(file);
	unsigned int old;
	int ret;

	if (spfs_should_bypass(inode)) {
bypass:
		return spfs_fsync_bp(file, start, end, datasync);
	}
	
	if (!IS_OP_MODE_TIERING(SB_INFO(inode->i_sb)) || 
			!S_OPTION(SB_INFO(inode->i_sb))->demotion)
		return 0;

	inode_lock(inode);
	if (__spfs_revalidate_tiered(inode)) {
		inode_unlock(inode);
		goto bypass;
	}

	/* 
	 * long interval, large write btw fsync 
	 * -> this file is not suitable for PM 
	 */
	ret = spfs_profile_fsync2(file);
	
	old = I_RAW(inode)->i_sync_factor;
	spfs_inode_update_sync_factor(inode, ret ? SF_SCALE : 0);

	spfs_calibrate_migr_list(inode, old);

	inode_unlock(inode);

	stats_prof_inc_fsync_on_boosted(inode);

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

