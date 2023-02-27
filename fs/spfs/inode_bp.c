#include <linux/mm.h>
#include <linux/xattr.h>

#include "spfs.h"
#include "profiler.h"
#include "namei.h"
#include "dir.h"


static int spfs_inode_test_bp(struct inode *inode, void *lower_inode)
{
	return I_INFO(inode)->lower_inode == lower_inode;
}

static int spfs_inode_set_bp(struct inode *inode, void *data)
{
	struct inode *lower_inode = data;

	spfs_set_inode_lower(inode, lower_inode);
	
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);

	inode->i_ino = lower_inode->i_ino;
	/* XXX: currently, bypass page cache and support direct IO */
	inode->i_mapping->a_ops = &spfs_aops_bp;

	if (S_ISLNK(inode->i_mode))
		inode->i_op = &spfs_symlink_bp_iops;
	else if (S_ISDIR(inode->i_mode))
		inode->i_op = &spfs_dir_iops;
	else
		inode->i_op = &spfs_main_iops;

	if (S_ISDIR(inode->i_mode))
		inode->i_fop = &spfs_dir_bp_fops;
	else if (special_file(inode->i_mode))
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	else
		inode->i_fop = &spfs_main_fops;

	return 0;
}

struct inode *__spfs_iget_bp(struct inode *lower_inode,
		struct super_block *sb)
{
	struct inode *inode;

	if (lower_inode->i_sb != SB_INFO(sb)->s_lower_sb)
		return ERR_PTR(-EXDEV);

	if (!igrab(lower_inode))
		return ERR_PTR(-ESTALE);

	inode = iget5_locked(sb, (unsigned long) lower_inode,
			spfs_inode_test_bp, spfs_inode_set_bp, lower_inode);
	if (!inode) {
		iput(lower_inode);
		/* XXX: need to check error code */
		return ERR_PTR(-ENOMEM);
	}

	if (!(inode->i_state & I_NEW))
		iput(lower_inode);

	return inode;
}

struct inode *spfs_iget_bp(struct inode *lower_inode,
		struct super_block *sb)
{
	struct inode *inode = __spfs_iget_bp(lower_inode, sb);

	if (!IS_ERR(inode) && (inode->i_state & I_NEW))
		unlock_new_inode(inode);

	return inode;
}

int spfs_create_bp(struct inode *dir, struct dentry *dentry,
		umode_t mode, bool excl)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct inode *inode;
	int rc;

	lower_dentry = spfs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	rc = vfs_create(d_inode(lower_dir_dentry), lower_dentry, mode, true);
	if (rc)
		goto out;

	inode = __spfs_iget_bp(d_inode(lower_dentry), dir->i_sb);
	if (IS_ERR(inode)) {
		rc = PTR_ERR(inode);
		vfs_unlink(d_inode(lower_dir_dentry), lower_dentry, NULL);
		goto out;
	}
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
out:
	unlock_dir(lower_dir_dentry);
	if (!rc)
		d_instantiate_new(dentry, inode);
	return rc;
}

int spfs_unlink_bp(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry = spfs_dentry_to_lower(dentry);
	struct dentry *lower_dir_dentry;
	struct inode *lower_dir_inode;
	int rc;

	lower_dir_dentry = lock_parent(lower_dentry);
	lower_dir_inode = d_inode(lower_dir_dentry);
	dget(lower_dentry);

	rc = vfs_unlink(d_inode(lower_dir_dentry), lower_dentry, NULL);
	if (rc)
		goto out;

	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);

	set_nlink(d_inode(dentry), d_inode(lower_dentry)->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;

	d_drop(dentry);
out:
	dput(lower_dentry);
	unlock_dir(lower_dir_dentry);
	return rc;
}

int spfs_mkdir_bp(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	//pr_err("%s: %s/%s/%s", __func__,
	//		dentry->d_parent->d_parent->d_name.name,
	//		dentry->d_parent->d_name.name,
	//		dentry->d_name.name);

	lower_dentry = spfs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	rc = vfs_mkdir(d_inode(lower_dir_dentry), lower_dentry, mode);
	if (rc)
		goto out;

	rc = spfs_interpose_bp(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out;
	/* XXX: what case? */
	BUG_ON(d_really_is_negative(lower_dentry));

	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

	if (is_inode_flag_set(dir, INODE_DIR_USE_PM))
		set_inode_flag(d_inode(dentry), INODE_DIR_USE_PM);
out:
	unlock_dir(lower_dir_dentry);
	return rc;
}

int spfs_rmdir_bp(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry = spfs_dentry_to_lower(dentry);
	struct dentry *lower_dir_dentry = lock_parent(lower_dentry);
	struct inode *lower_dir_inode = d_inode(lower_dir_dentry);
	int rc = -ENOTEMPTY;

	if (is_inode_flag_set(d_inode(dentry), INODE_HAS_PM_CHILDREN)) {
		BUG_ON(blist_empty(SB_INFO(dentry->d_sb), SPFS_DE_LIST(dentry)));
		goto out;
	}

	rename_msg_tree(dentry);

	BUG_ON(!S_ISDIR(d_inode(dentry)->i_mode));

	rc = vfs_rmdir(lower_dir_inode, lower_dentry);
	if (rc)
		goto out;

	d_drop(dentry);
	clear_nlink(d_inode(dentry));

	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);
out:
	unlock_dir(lower_dir_dentry);
	return rc;
}

static const char *
spfs_get_link_bp(struct dentry *dentry, struct inode *inode,
		struct delayed_call *done)
{
	if (!dentry)
		return ERR_PTR(-ECHILD);

	return vfs_get_link(spfs_dentry_to_lower(dentry), done);
}

int spfs_setattr_bp(struct dentry *dentry, struct iattr *ia)
{
	struct inode *inode = d_inode(dentry);
	struct inode *lower_inode = spfs_inode_to_lower(inode);
	struct dentry *lower_dentry = spfs_dentry_to_lower(dentry);
	struct iattr lower_ia;
	int rc;

	rc = setattr_prepare(dentry, ia);
	if (rc)
		goto out;

	memcpy(&lower_ia, ia, sizeof(lower_ia));

	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = spfs_file_to_lower(ia->ia_file);

	if (ia->ia_valid & ATTR_SIZE)
		truncate_setsize(inode, ia->ia_size);

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	inode_lock(d_inode(lower_dentry));
	rc = notify_change(lower_dentry, &lower_ia, NULL);
	inode_unlock(d_inode(lower_dentry));
out:
	fsstack_copy_attr_all(inode, lower_inode);
	return rc;
}

int spfs_getattr_bp(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int flags)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = d_inode(dentry);
	struct kstat lower_stat;
	int rc;

	rc = vfs_getattr(&D_INFO(dentry)->lower_path, &lower_stat,
			request_mask, flags);
	if (!rc) {
		fsstack_copy_attr_all(inode, spfs_inode_to_lower(inode));
		generic_fillattr(inode, stat);
		stat->blocks = lower_stat.blocks;
	}

	return rc;
}

ssize_t spfs_listxattr_bp(struct dentry *dentry, char *list, size_t size)
{
	int rc = 0;
	struct dentry *lower_dentry = spfs_dentry_to_lower(dentry);

	if (!d_inode(lower_dentry)->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	inode_lock(d_inode(lower_dentry));
	rc = d_inode(lower_dentry)->i_op->listxattr(lower_dentry, list, size);
	inode_unlock(d_inode(lower_dentry));
out:
	return rc;
}

int spfs_permission_bp(struct inode *inode, int mask)
{
	return inode_permission(spfs_inode_to_lower(inode), mask);
}

const struct inode_operations spfs_symlink_bp_iops = {
	.get_link	= spfs_get_link_bp,
	.permission	= spfs_permission_bp,
	.setattr	= spfs_setattr_bp,
	.getattr	= spfs_getattr_bp,
	.listxattr	= spfs_listxattr_bp,
};

static int spfs_xattr_get_bp(const struct xattr_handler *handler,
		struct dentry *dentry, struct inode *inode,
		const char *name, void *value, size_t size)
{
	/* currently, no consideration for partial inode */
	if (!spfs_should_bypass(inode))
		return -EOPNOTSUPP;

	return __vfs_getxattr(spfs_dentry_to_lower(dentry),
			spfs_inode_to_lower(inode), name, value, size);
}

static int spfs_xattr_set_bp(const struct xattr_handler *handler,
		struct dentry *dentry, struct inode *inode,
		const char *name, const void *value, size_t size,
		int flags)
{
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	int ret;

	if (!spfs_should_bypass(inode))
		return -EOPNOTSUPP;

	lower_dentry = spfs_dentry_to_lower(dentry);
	lower_inode = d_inode(lower_dentry);

	if (value)
		ret = vfs_setxattr(lower_dentry, name, value, size, flags);
	else {
		BUG_ON(flags != XATTR_REPLACE);

		inode_lock(lower_inode);
		ret = __vfs_removexattr(lower_dentry, name);
		inode_unlock(lower_inode);
	}

	if (!ret && inode)
		fsstack_copy_attr_all(inode, lower_inode);

	return ret;
}

const struct xattr_handler spfs_xattr_bp_handler = {
	.prefix	= "",
	.get	= spfs_xattr_get_bp,
	.set	= spfs_xattr_set_bp,
};
