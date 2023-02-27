#include "spfs.h"
#include "profiler.h"
#include "inode.h"


struct kmem_cache *spfs_file_info_cachep;

ssize_t spfs_read_iter_bp(struct kiocb *iocb, struct iov_iter *i)
{
	struct file *file = iocb->ki_filp;
	struct file *lower_file = spfs_file_to_lower(file);
	ssize_t ret;

	get_file(lower_file);
	iocb->ki_filp = lower_file;

	ret = call_read_iter(lower_file, iocb, i);

	iocb->ki_filp = file;
	fput(lower_file);

	if (ret >= 0 || ret == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
				file_inode(lower_file));

	return ret;
}

ssize_t spfs_write_iter_bp(struct kiocb *iocb, struct iov_iter *i)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct file *lower_file = spfs_file_to_lower(file);
	ssize_t ret;
	int ret2;

	get_file(lower_file);
	iocb->ki_filp = lower_file;

	ret = call_write_iter(lower_file, iocb, i);
	if (ret <= 0 || !file_inode(lower_file)->i_op->fiemap)
		goto prof_done;

	spfs_prof_update_bytes_written(inode, ret);

	if (iocb->ki_flags & IOCB_DSYNC) {
#if defined(CONFIG_SPFS_1SEC_PROFILER) || defined(CONFIG_SPFS_BW_PROFILER)
		if (spfs_profile_write_size(file)) {
#else
		/*
		 * fsync was already done in lower, we just apply fsync
		 * profiling.
		 */
		if (spfs_profile_fsync(file, false)) {
#endif
			ret2 = spfs_prepare_upward_migration(
					file_dentry(file));
			if (ret2)
				spfs_debug_err(inode->i_sb, "failed to prepare"
						" migration: %d", ret2);
		}
	}
prof_done:
	iocb->ki_filp = file;
	fput(lower_file);

	if (ret >= 0 || ret == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
				file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
				file_inode(lower_file));
	}

	return ret;
}

int spfs_open_bp(struct inode *inode, struct file *file)
{
	struct spfs_file_info *info;
	struct file *lower_file;
	struct inode *lower_inode = spfs_inode_to_lower(inode);
	int ret = 0;

	info = kmem_cache_zalloc(spfs_file_info_cachep, GFP_KERNEL);
	if (!info)
		return -ENOMEM;

#if 0
	if (IS_TIERED_INODE(inode))
		spfs_prof_debug("opening tiered file %s(%lu-%lu)",
				file_dentry(file)->d_name.name, inode->i_ino,
				lower_inode->i_ino);
#endif

	spfs_set_file_private(file, info);

	lower_file = dentry_open(spfs_dentry_to_lower_path(file->f_path.dentry),
			file->f_flags, current_cred());
	if (IS_ERR(lower_file)) {
		ret = PTR_ERR(lower_file);
		lower_file = spfs_file_to_lower(file);
		if (lower_file) {
			spfs_set_file_lower(file, NULL);
			fput(lower_file);
		}
		kmem_cache_free(spfs_file_info_cachep, info);
		goto out;
	}

	spfs_set_file_lower(file, lower_file);
	fsstack_copy_attr_all(inode, lower_inode);
out:
	return ret;
}

int spfs_release_bp(struct inode *inode, struct file *file)
{
	struct file *lower_file = spfs_file_to_lower(file);

	if (lower_file) {
		spfs_set_file_lower(file, NULL);
		fput(lower_file);
	}
	kmem_cache_free(spfs_file_info_cachep, F_INFO(file));

	return 0;
}

int spfs_fsync_bp(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_inode;
	int ret;

	ret = vfs_fsync_range(spfs_file_to_lower(file), start, end, datasync);
	if (ret)
		return ret;

	if (!spfs_inode_to_lower(inode)->i_op->fiemap)
		return 0;

	if (spfs_profile_fsync(file, true)) {
		ret = spfs_prepare_upward_migration(file_dentry(file));
		if (ret)
			spfs_debug_err(inode->i_sb,
					"failed to prepare migration: %d", ret);
	}

	return 0;
}

int spfs_mmap_bp(struct file *file, struct vm_area_struct *vma)
{
	struct file *lower_file = spfs_file_to_lower(file);
	struct address_space *mapping = lower_file->f_mapping;
	const struct vm_operations_struct *saved_vm_ops = NULL;
	int err = 0;

	if (!lower_file->f_op->mmap)
		return -ENODEV;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;

	/* from generic_file_readonly_mmap */
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE) &&
			!mapping->a_ops->writepage)
		return -EINVAL;


	if (!F_INFO(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err)
			return err;

		saved_vm_ops = vma->vm_ops;
	}

	file_accessed(file);
	vma->vm_ops = &spfs_vm_ops_bp;

	file->f_mapping->a_ops = &spfs_aops_bp;
	if (!F_INFO(file)->lower_vm_ops)
		F_INFO(file)->lower_vm_ops = saved_vm_ops;
	vma->vm_private_data = file;
	get_file(lower_file);
	vma->vm_file = lower_file;

	return err;
}

int spfs_init_file_cache(void)
{
	spfs_file_info_cachep = kmem_cache_create("spfs_file_cache",
			sizeof(struct spfs_inode_info), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);
	if (!spfs_file_info_cachep) {
		pr_err("spfs: failed to create file cache\n");
		return -ENOMEM;
	}

	return 0;
}

void spfs_destroy_file_cache(void)
{
	kmem_cache_destroy(spfs_file_info_cachep);
}
