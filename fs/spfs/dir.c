#include <linux/xattr.h>
#include <linux/random.h>

#include "spfs.h"
#include "namei.h"
#include "profiler.h"
#include "inode.h"
#include "stats.h"
#include "dir.h"

#include <trace/events/spfs.h>


static loff_t spfs_dir_llseek_bp(struct file *file, loff_t offset, int whence)
{
	struct file *lower_file = spfs_file_to_lower(file);
	loff_t ret;

	ret = generic_file_llseek(file, offset, whence);
	if (ret < 0)
		goto out;

	ret = generic_file_llseek(lower_file, offset, whence);
out:
	return ret;
}

static loff_t __dir_i_size_read(struct dentry *dentry)
{
	spfs_debug_level(dentry->d_sb, 1, "%s: dir. %s has %u children",
			__func__, dentry->d_name.name,
			SPFS_DE_CHILDREN(dentry));

	return i_size_read(d_inode(dentry)) +
		SPFS_DE_CHILDREN(dentry) * BLK_SIZE;
}

#define dir_i_size_read(file)	__dir_i_size_read((file)->f_path.dentry)

/*
 * spfs_dir_llseek calculates inode size by adding 256B per dir. entries
 */
static loff_t spfs_dir_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host; /* why not use f_inode? */
	loff_t ret;

	/* bypass fallback */
	if (!is_inode_flag_set(file->f_inode, INODE_HAS_PM_CHILDREN))
		return spfs_dir_llseek_bp(file, offset, whence);

	ret = generic_file_llseek_size(file, offset, whence, ULLONG_MAX,
			dir_i_size_read(file));
	/* XXX: should understand the meaning */
	file->f_version = inode_peek_iversion(inode) - 1;

	return ret;
}

static int spfs_dir_open(struct inode *inode, struct file *file)
{
	int rc;
	/*
	 * TODO??: should check this file has PM inode
	 * and set a flag indicating bypass or merged dir operations.
	 */

	rc = spfs_open_bp(inode, file);
	if(!rc)
		clr_dir_eof(file); /* init. readdir info */

	return rc;
}

/* copied from ecryptfs */
struct spfs_getdents_callback {
	struct dir_context	ctx;
	struct dir_context	*caller;
	int			filldir_called;
	int			entries_written;
	struct super_block	*sb;
	struct dentry		*base;
};

static int spfs_filldir(struct dir_context *ctx, const char *lower_name,
		 int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct spfs_getdents_callback *buf =
		container_of(ctx, struct spfs_getdents_callback, ctx);
	int rc = 0;
	struct dentry *res = NULL;

	buf->filldir_called++;
	buf->caller->pos = buf->ctx.pos;

	readdir_msg("%llu for %.*s", buf->ctx.pos, lower_namelen,
			lower_name);

	/*
	 * Check whether the lower_name is a tiered inode and we emit the
	 * lower_name only once in upper if it is.
	 */
	if (buf->base)
		res = lookup_one_len(lower_name, buf->base, lower_namelen);

	/* XXX: can be negative? */
	if (IS_ERR_OR_NULL(res) || d_is_negative(res) ||
			!S_ISREG(d_inode(res)->i_mode) ||
			!IS_TIERED_INODE(d_inode(res))) {
		rc = !dir_emit(buf->caller, lower_name, lower_namelen, ino,
				d_type);
		if (!rc) {
			readdir_msg("emit %llu for %.*s", buf->ctx.pos,
					lower_namelen, lower_name);
			buf->entries_written++;
		}
	}

	if (!IS_ERR_OR_NULL(res))
		dput(res);

	return rc;
}

/* TODO: handle version mismatch */
static int spfs_iterate_dir(struct file *file, struct dir_context *ctx)
{
	struct spfs_sb_info *sbi = SB_INFO(file->f_inode->i_sb);
	struct file *lower_file = spfs_file_to_lower(file);
	struct inode *inode = file->f_inode;
	struct spfs_dentry_info *dinfo = D_INFO(file->f_path.dentry);
	int forward, i;
	int rc = 0;
	bool has_pm_children = is_inode_flag_set(inode, INODE_HAS_PM_CHILDREN);
#ifdef CONFIG_SPFS_READDIR_RADIX_TREE
	struct list_head *pos;
#else
	struct blist_head *pos;
	struct spfs_dir_entry *pde;
#endif

	struct spfs_getdents_callback buf = {
		.ctx.actor		= spfs_filldir,
		.caller			= ctx,
		.filldir_called		= 0,
		.entries_written	= 0,
		.sb			= inode->i_sb,
		.base			= has_pm_children &&
			IS_OP_MODE_TIERING(sbi) ? file_dentry(file) : NULL,
	};

	/*
	 * We do not trust dir_context.pos because some fs use it privately
	 * with own policy, for exmple dir. hash of EXT4.
	 * So, we keep EOF information for directory in private data of file.
	 */
	if (test_dir_eof(file)) {
		readdir_msg("EOF.. skip lower %llu", ctx->pos);
		goto lower_eof;
	}

	rc = iterate_dir(lower_file, &buf.ctx);
	if (rc < 0)
		return rc;

	/* error on emit due to ENOSPC and so on... */
	if (buf.filldir_called && !buf.entries_written)
		return rc;
	else if (buf.filldir_called) { /* there may be unwritten entries */
		readdir_msg("got %d entries from lower", buf.entries_written);
		goto out;
	}

	if (!test_dir_eof(file)) {
		readdir_msg("let's do readdir on PM");
		/* iterated all lower entries */
		set_dir_eof(file, ctx->pos);
		ctx->pos = i_size_read(inode);
	}

lower_eof:
	if (!has_pm_children)
		goto out;

	/* TODO: cache last entry */
	forward = BYTES2B(ctx->pos - i_size_read(inode));
	i = 0;

#ifdef CONFIG_SPFS_READDIR_RADIX_TREE
	list_for_each(pos, dinfo->children) {
		struct spfs_dir_entry *de;
		struct spfs_readdir_node *node;

		if (i < forward) {
			i++;
			continue;
		}

		if (fatal_signal_pending(current))
			return -ERESTARTSYS;

		node = list_entry(pos, struct spfs_readdir_node, list);
		de = blk_addr(sbi, node->dirent_blk);
		if (!dir_emit(ctx, de->de_name, de->de_len, de->de_inode_bno,
					DT_REG))
			break;

		ctx->pos += BLK_SIZE;
	}
#else
	readdir_msg("readdir further %s %d", file->f_path.dentry->d_name.name, rc);

	pde = dinfo->de;

	blist_for_each(sbi, pos, &pde->de_sib) {
		struct spfs_dir_entry *de;

		if (i < forward) {
			readdir_msg("skip %d", i);
			i++;
			continue;
		}

		if (fatal_signal_pending(current))
			return -ERESTARTSYS;

		de = blist_entry(pos, struct spfs_dir_entry, de_sib);
		if (!dir_emit(ctx, de->de_name, de->de_len, de->de_inode_bno,
					DT_REG))
			break;
		readdir_msg("emit %.*s", de->de_len, de->de_name);
		ctx->pos += BLK_SIZE;
	}
#endif
out:
	fsstack_copy_attr_atime(file_inode(file), file_inode(lower_file));
	readdir_msg("end of readdir %d", rc);

	return rc;
}

static long spfs_dir_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	struct file *lower_file = spfs_file_to_lower(file);
	long ret;

	switch (cmd) {
		case SPFS_IOC_SET_USE_PM:
			ret = vfs_setxattr(lower_file->f_path.dentry,
					SPFS_XATTR_SET_USE_PM, NULL, 0,
					XATTR_CREATE);
			if (!ret) {
				set_inode_flag(file->f_inode, INODE_DIR_USE_PM);
				/* TODO: revalidation */
				d_invalidate(file->f_path.dentry);
				d_invalidate(lower_file->f_path.dentry);
			}
			return ret;
		case SPFS_IOC_SET_USE_DISK:
			ret = vfs_removexattr(lower_file->f_path.dentry,
					SPFS_XATTR_SET_USE_PM);
			if (!ret) {
				clear_inode_flag(file->f_inode,
						INODE_DIR_USE_PM);
				d_invalidate(file->f_path.dentry);
				d_invalidate(lower_file->f_path.dentry);
			}
			return ret;
	}

	ret = vfs_ioctl(lower_file, cmd, arg);
	if (!ret)
		fsstack_copy_attr_all(file_inode(file), file_inode(lower_file));

	return ret;
}

extern int spfs_fsync_bp(struct file *, loff_t, loff_t, int); 
extern int spfs_release_bp(struct inode *, struct file *);
 
const struct file_operations spfs_dir_bp_fops = {
	.llseek		= spfs_dir_llseek,
	.iterate_shared	= spfs_iterate_dir,
	.unlocked_ioctl	= spfs_dir_unlocked_ioctl,
//#ifdef CONFIG_COMPAT
//	.compat_ioctl	= spfs_compat_ioctl_bp,
//#endif
	.open		= spfs_dir_open,
	.release	= spfs_release_bp,
	.fsync		= spfs_fsync_bp,
};

static int spfs_dir_getattr(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int flags)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = d_inode(dentry);
	int rc;

	rc = spfs_getattr_bp(path, stat, request_mask, flags);
	if (rc)
		return rc;

	if (!is_inode_flag_set(inode, INODE_HAS_PM_CHILDREN))
		goto out;

	stat->size = __dir_i_size_read(dentry);
	/* XXX: right? */
	stat->blocks = DIV_ROUND_UP(stat->size, 512);
out:
	return 0;
}

static int __spfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	struct spfs_sb_info *sbi = SB_INFO(dir->i_sb);
	struct inode *inode;
	struct spfs_inode *raw_inode;
	struct spfs_inode_info *info;
	int ret;
	struct spfs_dir_entry *de, *dir_de = NULL;
	void *retp;

	spfs_block_t prefetch[3] = {0, };
	unsigned long prefetch_len[3] = {0, };
	int i = 0;
	int prefetch_cnt = 2;
	int remain;

	if (unlikely(!is_inode_flag_set(dir, INODE_HAS_PM_CHILDREN)))
		prefetch_cnt++;

	remain = prefetch_cnt;
	do {
		spfs_block_t pbn;
		unsigned long len = remain;
		int k;

		pbn = spfs_alloc_blocks(sbi, &len, true, false, &ret);
		if (ret) {
			spfs_debug_err(dir->i_sb, "can't get %lu blocks",
					prefetch_cnt);
			goto out1;
		}

		for (k = 0; k < len; k++)
			prefetch[i + k] = pbn + k;

		prefetch_len[i] = len;
		i += len;
		remain -= len;
	} while (unlikely(remain));

	inode = new_inode(dir->i_sb);
	if (unlikely(!inode)) {
		ret = -ENOMEM;
		goto out1;
	}

	info = I_INFO(inode);

	inode_init_owner(inode, dir, mode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_flags = dir->i_flags; // TODO:
	set_inode_flag(inode, INODE_PM);
	inode->i_generation = prandom_u32();
	inode->i_ino = prefetch[0];
	
	ret = insert_inode_locked4(inode, inode->i_ino, spfs_inode_test,
			(void *) (uintptr_t) inode->i_ino);
	if (unlikely(ret)) {
		spfs_debug_err(dir->i_sb, "someone created same inode");
		goto out2; // XXX:
	}

	inode->i_op = &spfs_main_iops;
	inode->i_fop = &spfs_main_fops;
	inode->i_mapping->a_ops = &spfs_aops;

	raw_inode = spfs_init_new_inode(inode);
	I_INFO(inode)->raw_inode = raw_inode;

	if (unlikely(!is_inode_flag_set(dir, INODE_HAS_PM_CHILDREN))) {
		struct dentry *parent = dentry->d_parent;

		dir_de = init_dir_entry(D_INFO(parent), prefetch[2],
				d_inode(parent->d_parent), parent,
				(spfs_block_t) -1, DE_DIR);
		set_inode_flag(dir, INODE_HAS_PM_CHILDREN);
	}

	de = init_dir_entry(D_INFO(dentry), prefetch[1], dir, dentry,
			prefetch[0], 0);

	spfs_persist(raw_inode, BLK_SIZE);
	spfs_persist(de, BLK_SIZE);
	if (unlikely(dir_de))
		spfs_persist(dir_de, BLK_SIZE);
	/*
	 * ensuare that all stores for inode and directory entreis issued
	 * before the log.
	 */
	SPFS_SFENCE();

	/*
	 * Preparation of inode, dir_de and de done.
	 * Let's make a redo log before hash insertion. Note that we have
	 * allocated blocks only in DRAM and all redo information except dentry
	 * hash is in directory entry blocks indicated by log.
	 */
	if (unlikely(dir_de))
		ijournal_log_dir_entry(inode, CR_DIR_HINS, blk_idx(sbi, dir_de),
				dentry->d_parent->d_name.hash);
	ijournal_log_dir_entry(inode, CR_REG_HINS, blk_idx(sbi, de),
			dentry->d_name.hash);

	spfs_set_inode_recovery(inode);
	spfs_add_inode_list(inode);

	for (i = 0; i < prefetch_cnt; i++) {
		if (prefetch_len[i])
			spfs_commit_block_allocation(sbi, prefetch[i],
					prefetch_len[i]);
	}

	if (unlikely(dir_de)) {
		retp = spfs_namei_cceh_insert(sbi, dentry->d_parent,
				blk_idx(sbi, dir_de), DE_DIR);
		if (IS_ERR(retp)) {
			spfs_debug_err(dir->i_sb,
					"can't insert parent dir. entry of %s",
					dentry->d_name.name);
			ret = PTR_ERR(retp);
			goto out3;
		}
	}

	retp = spfs_namei_cceh_insert(sbi, dentry, blk_idx(sbi, de), 0);
	if (unlikely(IS_ERR(retp))) {
		spfs_debug_err(dir->i_sb,
				"can't insert dir. entry of %s",
				dentry->d_name.name);
		ret = PTR_ERR(retp);
		goto out4;
	}

	//spfs_inode_update_time(dir, S_MTIME | S_CTIME);
	dir->i_mtime = dir->i_ctime = current_time(dir);

	spfs_add_dirent_list(sbi, dentry);

	spfs_inc_inodes_count(inode->i_sb);

	ijournal_log_inode_count(inode);
	ijournal_commit(inode);

	spfs_clear_inode_recovery(inode);

	d_instantiate_new(dentry, inode);

	return 0;
out4:
	if (dir_de) {
		ret = spfs_namei_cceh_delete(sbi, d_inode(dentry->d_parent),
				dentry->d_parent, true);
		if (ret)
			spfs_err(dir->i_sb, "%s: can't delete hash for dir.",
					__func__);
	}
out3:
	spfs_del_inode_list(inode);
	ijournal_init(inode);

	for (i = 0; i < prefetch_cnt; i++) {
		if (prefetch_len[i])
			spfs_free_blocks(sbi, prefetch[i], prefetch_len[i]);
	}

	unlock_new_inode(inode);
	clear_nlink(inode);
out2:
	make_bad_inode(inode);
	iput(inode);	// XXX: will free inode block
out1:
	for (i = 0; i < prefetch_cnt; i++) {
		if (prefetch_len[i])
			spfs_commit_block_deallocation(sbi, prefetch[i],
					prefetch_len[i]);
	}
	return ret;
}


static int spfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	if (!spfs_create_interest(dentry, 0))
		return spfs_create_bp(dir, dentry, mode, excl);

	return __spfs_create(dir, dentry, mode, excl);
}


static int spfs_atomic_open(struct inode *dir, struct dentry *dentry,
		struct file *file, unsigned open_flags, umode_t create_mode)
{
	struct dentry *res = NULL;
	bool excl = open_flags & O_EXCL;
	int ret;
	int (*create)(struct inode *, struct dentry *, umode_t, bool);
	int (*open)(struct inode *, struct file *);
	unsigned int lookup_flags = 0;

	rename_msg_tree(dentry);

	if (open_flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (open_flags & O_CREAT)
		lookup_flags |= LOOKUP_CREATE;

	create = spfs_create_bp;
	open = spfs_open_bp;

	if (d_in_lookup(dentry)) {
		res = spfs_lookup(dir, dentry, lookup_flags);
		if (IS_ERR(res)) {
			ret = PTR_ERR(res);
			goto out;
		}

		BUG_ON(res); /* we don't allow hard links */
	}

	if (!(open_flags & O_CREAT) || d_really_is_positive(dentry)) {
		ret = finish_no_open(file, res);
		goto out;
	}

	file->f_mode |= FMODE_CREATED;

	if (spfs_create_interest(dentry, open_flags)) {
		create = __spfs_create;
		open = spfs_open;
	}

	ret = create(dir, dentry, create_mode, excl);
	if (ret)
		goto out_dput;

	ret = finish_open(file, dentry, open);
out_dput:
	dput(res);
out:
	return ret;
}

static int spfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct spfs_sb_info *sbi = SB_INFO(dir->i_sb);
	struct inode *inode = d_inode(dentry);
	int ret = 0;
	int n_children;

	rename_msg_tree(dentry);

	BUG_ON(S_ISDIR(d_inode(dentry)->i_mode));

	if (spfs_should_bypass(d_inode(dentry)))
		return spfs_unlink_bp(dir, dentry);

	if (IS_TIERED_INODE(d_inode(dentry))) {
		ret = spfs_unlink_bp(dir, dentry);
		if (ret)
			goto out;
	}

	if (unlikely(SPFS_DE_CHILDREN(dentry->d_parent) == 1))
		ijournal_log_dir_entry(inode, UL_DIR_HDEL,
				blk_idx(sbi, D_INFO(dentry->d_parent)->de),
				dentry->d_parent->d_name.hash);
	ijournal_log_dir_entry(inode, UL_REG_HDEL,
			blk_idx(sbi, D_INFO(dentry)->de), dentry->d_name.hash);

	spfs_set_inode_recovery(inode);

	n_children = spfs_del_nondir(dentry);
	if (unlikely(n_children == 0))
		spfs_del_dir(dentry->d_parent);

	/* XXX: should update dir. bypass inode? */
	clear_nlink(inode);
	// TODO: pm nlink persisting
	inode->i_ctime = current_time(inode);
	// TODO: timestamps on PM
	//spfs_inode_update_time(dir, S_MTIME | S_CTIME);
	dir->i_mtime = dir->i_ctime = current_time(inode);

	spfs_dec_inodes_count(inode->i_sb);
	ijournal_log_inode_count(inode);

	d_drop(dentry);

	/* XXX: no demotion opt, migr_info must be NULL */
	if (is_inode_flag_set(inode, INODE_TIERED) && 
			I_INFO(inode)->migr_info) {
		BUG_ON(!S_OPTION(sbi)->demotion);
		spfs_remove_migr_list(inode);
	}
out:
	return ret;
}

/* copied from ecryptfs */
static int spfs_rename2_bp(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry,
		unsigned int flags)
{
	int rc;
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;
	struct dentry *trap;
	struct inode *target_inode;

	lower_old_dir_dentry = spfs_dentry_to_lower(old_dentry->d_parent);
	lower_new_dir_dentry = spfs_dentry_to_lower(new_dentry->d_parent);

	lower_old_dentry = spfs_dentry_to_lower(old_dentry);
	lower_new_dentry = spfs_dentry_to_lower(new_dentry);

	target_inode = d_inode(new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dget(lower_new_dentry);
	rc = -EINVAL;
	if (lower_old_dentry->d_parent != lower_old_dir_dentry)
		goto out_lock;
	if (lower_new_dentry->d_parent != lower_new_dir_dentry)
		goto out_lock;
	if (d_unhashed(lower_old_dentry) || d_unhashed(lower_new_dentry))
		goto out_lock;
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry)
		goto out_lock;
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		rc = -ENOTEMPTY;
		goto out_lock;
	}
	rc = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			d_inode(lower_new_dir_dentry), lower_new_dentry,
			NULL, 0);
	if (rc)
		goto out_lock;
	if (target_inode)
		fsstack_copy_attr_all(target_inode,
				spfs_inode_to_lower(target_inode));
	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir)
		fsstack_copy_attr_all(old_dir, d_inode(lower_old_dir_dentry));
out_lock:
	dput(lower_new_dentry);
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	return rc;
}

/* renaming positive source to negative target */
static int spfs_rename_new(struct inode *old_dir,
		struct dentry *old_dentry, struct inode *new_dir,
		struct dentry *new_dentry, unsigned int flags)
{
	struct spfs_sb_info *sbi = SB_INFO(old_dir->i_sb);
	struct inode *source = d_inode(old_dentry);
	struct spfs_dir_entry *dirent = D_INFO(old_dentry)->de;
	struct spfs_dir_entry *np_dirent = NULL;
	struct spfs_dir_entry *dirent_undo = NULL;
	int ret;
	bool make_parent_dirent = S_ISREG(source->i_mode) &&
		!is_inode_flag_set(new_dir, INODE_HAS_PM_CHILDREN);

	DECLARE_PREFETCH(pf, 2, make_parent_dirent ? 2 : 1);
	PREFETCH_ALLOC_BLOCKS(sbi, pf, return ret);

	rename_msg("%s/%s/%s(%lu) -> %s/%s/%s",
			old_dentry->d_parent->d_parent->d_name.name,
			old_dentry->d_parent->d_name.name,
			old_dentry->d_name.name,
			old_dentry->d_inode->i_ino,
			new_dentry->d_parent->d_parent->d_name.name,
			new_dentry->d_parent->d_name.name,
			new_dentry->d_name.name);

	BUG_ON(!S_ISDIR(source->i_mode) &&
			dirent->de_inode_bno != source->i_ino);
	BUG_ON(S_ISDIR(source->i_mode) && !is_inode_flag_set(source,
				INODE_HAS_PM_CHILDREN));
	WARN_ON(!make_parent_dirent && SPFS_DE(new_dentry->d_parent) &&
			!SPFS_DE_CHILDREN(new_dentry->d_parent));

	/* init the dirent for new parent */
	if (make_parent_dirent) {
		struct dentry *parent = new_dentry->d_parent;
		struct dentry *pparent = dget_parent(parent);

		np_dirent = init_dir_entry(D_INFO(parent), pf[1],
				d_inode(pparent), parent, (spfs_block_t) -1,
				DE_DIR);
		dput(pparent);
		_clwb(np_dirent, BLK_SIZE);
	}

	/* make undo of old dirent */
	dirent_undo = blk_addr(sbi, pf[0]);
	memcpy_flushcache(dirent_undo, dirent, BLK_SIZE);
	SPFS_SFENCE();

	jnl_rename_undo(source, pf[0]);

	/* modify the original(old) dirent with new name and parent */
	init_dir_entry_name(dirent, new_dentry);
	if (old_dir != new_dir)
		dirent->de_pino = new_dir->i_ino;
	clwb_sfence(dirent, BLK_SIZE);

	/* log hasn insertion and commit blocks */
	if (np_dirent) {
		jnl_rename_hash_insert(source, pf[1],
				new_dentry->d_parent->d_name.hash);
		set_inode_flag(new_dir, INODE_HAS_PM_CHILDREN);
	}
	jnl_rename_hash_insert(source, SPFS_DE_BLK(sbi, old_dentry),
			new_dentry->d_name.hash);

	PREFETCH_COMMIT_ALLOC_BLOCKS(sbi, pf);

	/* insert new hash entries */
	ret = __spfs_insert_dir_entries(new_dentry,
			SPFS_DE_BLK(sbi, old_dentry),
			np_dirent ? new_dentry->d_parent : NULL, pf[1]);
	if (ret) {
		spfs_debug_err(sbi->s_sb, "can't insert new dirents for %s",
				new_dentry->d_name.name);
		goto out1;
	}

	/* TODO: logging */
	source->i_ctime = current_time(source);
//	SPFS_INODE_SET_TIME(i_ctime, source, I_RAW(source));
//	clwb_sfence(&I_RAW(source)->i_ctime, sizeof(source->i_ctime));

	/*
	 * We can delete stale hash slot with fast_del_hint even though name
	 * of dir. entry has been modified.
	 */
	jnl_rename_hash_delete(source, old_dentry, old_dir != new_dir);
	ret = spfs_namei_cceh_delete(sbi, old_dir, old_dentry,
			S_ISDIR(source->i_mode));
	if (ret) {
		spfs_debug_err(sbi->s_sb, "failed to delete old %s",
				old_dentry->d_name.name);
		goto out2;
	}

	/* free undo block */
	spfs_free_blocks(sbi, pf[0], 1);

	if (!S_ISREG(source->i_mode))
		goto commit;

	if (old_dir == new_dir)
		goto commit;

	if (!spfs_del_dirent_list(sbi, old_dentry))
		spfs_del_dir(old_dentry->d_parent);

	__spfs_add_dirent_list(sbi, old_dentry, new_dentry->d_parent);
commit:
	jnl_rename_commit(source);
	spfs_commit_block_deallocation(sbi, pf[0], 1);

	return 0;
out2:
	BUG();
	/* We can't use fast del. hint here */
	if (spfs_namei_cceh_delete(sbi, new_dir, new_dentry, 0))
		spfs_err(sbi->s_sb, "out2-1 failed");

	if (np_dirent) {
		if (spfs_namei_cceh_delete(sbi,
					d_inode(new_dentry->d_parent->d_parent),
					new_dentry->d_parent, DE_DIR))
			spfs_err(sbi->s_sb, "out2-2 failed");
	}
out1:
	PREFETCH_FREE_BLOCKS(sbi, pf);
	PREFETCH_COMMIT_FREE_BLOCKS(sbi, pf);
	jnl_rename_commit(source);
	return ret;
}

/*
 * Renaming to positive dentry.
 * We dont' care renaming dir. to regular file case because it was done
 * at may_delete().
 * 1. update inode number in dir. entry
 * 2. delete old entry
 * 3. unlink target inode
 */
static int spfs_rename_replace(struct inode *old_dir,
		struct dentry *old_dentry, struct inode *new_dir,
		struct dentry *new_dentry, unsigned int flags)
{
	struct spfs_sb_info *sbi = SB_INFO(old_dir->i_sb);
	struct inode *source = d_inode(old_dentry);
	struct inode *target = d_inode(new_dentry);
	struct spfs_dir_entry *dirent = SPFS_DE(old_dentry);
	int ret = 0;
	int nr_children;

	rename_msg("%s/%s/%s(%lu) -> %s/%s/%s(%lu)",
			old_dentry->d_parent->d_parent->d_name.name,
			old_dentry->d_parent->d_name.name,
			old_dentry->d_name.name,
			old_dentry->d_inode->i_ino,
			new_dentry->d_parent->d_parent->d_name.name,
			new_dentry->d_parent->d_name.name,
			new_dentry->d_name.name,
			new_dentry->d_inode->i_ino);

	/*
	 * The replace renaming can be done between empty dirs. and
	 * non-empty dir. to empty dir.. The former must be done in bypass mode
	 * and the latter is same as renaming new from the view of dir. entry.
	 * For example, new dentry's dir. entry must be created.
	 */
	BUG_ON(S_ISDIR(source->i_mode));

	/*
	 * Replace the inode number of new_dentry to old_dentry's one because
	 * old_dentry will be modified to new_dentry's contents in d_move().
	 */
	jnl_rename_replace(source, blk_idx(sbi, dirent));
	SPFS_DE(new_dentry)->de_inode_bno = source->i_ino;
	clwb_sfence(&SPFS_DE(new_dentry)->de_inode_bno,
			sizeof(SPFS_DE(new_dentry)->de_inode_bno));

	// TODO: persisting
	source->i_ctime = current_time(source);
	SPFS_INODE_SET_TIME(i_ctime, source, I_RAW(source));
	clwb_sfence(&I_RAW(source)->i_ctime, sizeof(source->i_ctime));

	/* delete the old name in hash */
	jnl_rename_hash_delete(source, old_dentry, old_dir != new_dir);
	ret = spfs_namei_cceh_delete(sbi, old_dir, old_dentry,
			S_ISDIR(source->i_mode));
	if (ret) {
		spfs_debug_err(sbi->s_sb, "failed to delete old %s",
				old_dentry->d_name.name);
		goto out;
	}

	/* free dirent of old name */
	spfs_free_blocks(sbi, SPFS_DE_BLK(sbi, old_dentry), 1);

	nr_children = spfs_del_dirent_list(sbi, old_dentry);
	if (nr_children == 0)
		spfs_del_dir(old_dentry->d_parent);

	/* unlink the inode of new_dentry */
	clear_nlink(target);
	target->i_ctime = current_time(target);
	SPFS_INODE_SET_TIME(i_ctime, target, I_RAW(target));
	clwb_sfence(&I_RAW(target)->i_ctime, sizeof(target->i_ctime));

	spfs_inode_update_time(old_dir, S_MTIME | S_CTIME);

	spfs_commit_block_deallocation(sbi, SPFS_DE_BLK(sbi, old_dentry), 1);

	/* Old dentry's dirent block will be commited in d_iput() of
	 * new(victim) dentry.
	 */
	spfs_swap_dirent(old_dentry, new_dentry);
	jnl_rename_commit(source);

	return 0;
out:
	BUG();
	SPFS_DE(new_dentry)->de_inode_bno = target->i_ino;
	clwb_sfence(&SPFS_DE(new_dentry)->de_inode_bno,
			sizeof(SPFS_DE(new_dentry)->de_inode_bno));
	jnl_rename_commit(source);
	return ret;
}

/* allow renaming in same tier */
static int spfs_rename2(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry,
		unsigned int flags)
{
	struct spfs_sb_info *sbi = SB_INFO(old_dir->i_sb);
	struct inode *source = d_inode(old_dentry);
	struct inode *target = d_inode(new_dentry);
	int ret = 0;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	if (!target)
		goto rule_done;
	/*
	 * Because we don't support RENAME_EXCHANGE, renaming dir. to regular
	 * file is blocked by vfs as ENOTDIR on namei.c:4415, and the reverse
	 * also blocked as EISDIR.
	 * Here we only block the case where target is not empty dir..
	 */
	if (S_ISDIR(target->i_mode) &&
			spfs_dirent_children_count(new_dentry)) {
		return -ENOTEMPTY;
	}

	if (IS_OP_MODE_TIERING(sbi) && !spfs_may_rename(source, target))
		return -EINVAL;
rule_done:
	/*
	 * for bypassing files and directories without PM children, delegate
	 * renaming to the lower filesystem.
	 */
	if (spfs_should_bypass(source)) {
		ret = spfs_rename2_bp(old_dir, old_dentry, new_dir, new_dentry,
				flags);
		if (ret || !spfs_should_rename_both(source))
			return ret;
	}
	/* TODO: dir. has PM children.... there is no raw inode in dir...... */

	/* RENAMING in PM */
	if (target && S_ISREG(source->i_mode))
		ret = spfs_rename_replace(old_dir, old_dentry, new_dir,
				new_dentry, flags);
	else {
		ret = spfs_rename_new(old_dir, old_dentry, new_dir,
				new_dentry, flags);
		if (target && S_ISDIR(source->i_mode)) {
			clear_nlink(target);
			BUG_ON(SPFS_DE(new_dentry));
		}
	}

	/* TODO: handle rename */
	//if (IS_TIERED_INODE(source))
	//	spfs_remove_migr_list(source);

	//if (target && IS_TIERED_INODE(target) && 
	//		spfs_inode_is_full_extents_mapped(target))
	//	spfs_add_migr_list(target, new_dentry, true);

	return ret;
}

const struct inode_operations spfs_dir_iops = {
	.create		= spfs_create,
	.lookup		= spfs_lookup,
	.unlink		= spfs_unlink,
	.mkdir		= spfs_mkdir_bp,
	.rmdir		= spfs_rmdir_bp,
	.rename		= spfs_rename2,
	.permission	= spfs_permission_bp,
	.setattr	= spfs_setattr_bp,
	.getattr	= spfs_dir_getattr,
	.listxattr	= spfs_listxattr_bp,
	.atomic_open	= spfs_atomic_open,
};
