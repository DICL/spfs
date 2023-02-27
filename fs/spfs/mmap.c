#include "spfs.h"


static vm_fault_t spfs_fault(struct vm_fault *vmf)
{
	return F_INFO(vmf->vma->vm_private_data)->lower_vm_ops->fault(vmf);
}

static void spfs_vm_open(struct vm_area_struct *vma)
{
	get_file(vma->vm_private_data);
}

static void spfs_vm_close(struct vm_area_struct *vma)
{
	fput(vma->vm_private_data);
}

static vm_fault_t spfs_page_mkwrite(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_private_data;
	const struct vm_operations_struct *lower_vm_ops;

	lower_vm_ops = F_INFO(file)->lower_vm_ops;
	if (!lower_vm_ops->page_mkwrite)
		return 0;

	return lower_vm_ops->page_mkwrite(vmf);
}

const struct address_space_operations spfs_aops_bp = {
	.direct_IO	= noop_direct_IO,
};

const struct vm_operations_struct spfs_vm_ops_bp = {
	.fault		= spfs_fault,
	.page_mkwrite	= spfs_page_mkwrite,
	.open		= spfs_vm_open,
	.close		= spfs_vm_close,
};
