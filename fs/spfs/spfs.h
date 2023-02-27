#ifndef _SPFS_H_
#define _SPFS_H_

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/fs_stack.h>
#include <linux/namei.h>
#include <linux/dax.h>
#include <linux/magic.h>
#include <linux/iversion.h>
#include <linux/iomap.h>
#include <linux/seq_file.h>
#include <linux/percpu_counter.h>
#include <linux/file.h>
#include <linux/kthread.h>

#include "persist.h"

#define spfs_msg(sb, level, fmt, ...)	\
	__spfs_msg(sb, level, fmt, ##__VA_ARGS__)

#define spfs_err(sb, fmt, ...)		\
	spfs_msg(sb, KERN_ERR, fmt, ##__VA_ARGS__)

#define SPFS_DEBUG_ERROR
#ifdef SPFS_DEBUG_ERROR
#define spfs_debug_err(sb, fmt, ...)			\
	spfs_err(sb, "%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define spfs_debug_err(sb, fmt, ...)			do {} while (0)
#endif

#ifdef CONFIG_SPFS_DEBUG
#define SPFS_BUG_ON				BUG_ON
#define SPFS_BUG_ON_MSG(exp, fmt, ...)				\
do {								\
	if (exp) {						\
		pr_err("%s: "fmt, __func__, ##__VA_ARGS__);	\
		BUG();						\
	}							\
} while (0)
#define spfs_debug(sb, fmt, ...)			\
	__spfs_msg(sb, KERN_INFO, fmt, ##__VA_ARGS__)
#define spfs_debug_level(sb, level, fmt, ...)	do {	\
	if (level <= CONFIG_SPFS_DEBUG_LEVEL)		\
		spfs_debug(sb, fmt, ##__VA_ARGS__);	\
} while (0)
#else
#define SPFS_BUG_ON(exp)			do {} while (0)
#define SPFS_BUG_ON_MSG(exp, fmt, ...)		do {} while (0)
#define spfs_debug(sb, fmt, ...)		do {} while (0)
#define spfs_debug_level(sb, level, fmt, ...)	do {} while (0)
#endif

#if CONFIG_SPFS_BLOCK_BITS < 12
#define SPFS_SMALL_BLOCK
#endif

#define BLK_SHIFT	(CONFIG_SPFS_BLOCK_BITS)
#define BLK_SIZE	(1UL << BLK_SHIFT)
#define BLK_MASK	(~(BLK_SIZE-1))

#define CLUSTER_SHIFT	PAGE_SHIFT
#define CLUSTER_SIZE	PAGE_SIZE
#define CLUSTER_MASK	PAGE_MASK

#define BC_SHIFT	(CLUSTER_SHIFT - BLK_SHIFT)
#define BPC		(1UL << BC_SHIFT) // blocks per cluster

#define B2C(b)		((b) >> BC_SHIFT)
#define C2B(c)		((c) << BC_SHIFT)

#define B2BYTES(b)	((b) << BLK_SHIFT)
#define C2BYTES(c)	(((u64) (c)) << CLUSTER_SHIFT)
#define BYTES2B(b)	((b) >> BLK_SHIFT)
#define BYTES2C(b)	((b) >> CLUSTER_SHIFT)

#define BLK_OFF(p)	((p) & (BLK_SIZE - 1))
#define CLU_OFF(p)	((p) & (CLUSTER_SIZE - 1))

#define BIIC(b)		((b) % BPC) // block index in cluster
#define BLK_ALIGN(pos)	(BYTES2B(ALIGN((pos), BLK_SIZE)))
#define CLU_ALIGN(pos)	(BYTES2C(ALIGN((pos), CLUSTER_SIZE)))

/* Because 5bytes can cover 255TB, 3B can be used privately.. */
typedef unsigned long long	spfs_block_t;
typedef unsigned int		spfs_cluster_t;
#define VOID_PTR(v)		((void *) (uintptr_t) (v))

/* Flags used by mapping */
#define GET_CLUSTERS_CREATE		0x0001
#define GET_CLUSTERS_KEEP_SIZE		0x0002
#define GET_CLUSTERS_EOF		0x0004

#define SPFS_MAP_HOLE			0x0001
#define SPFS_MAP_READ_LOWER		0x0002
#define SPFS_MAP_USE_PREALLOC		0x0004
#define SPFS_MAP_GET_PREALLOC		0x0008
#define SPFS_MAP_NEW			0x0010


/* for cluster bitmap not usage */
static inline void spfs_persist_bitmap_range(unsigned long *bitmap,
		unsigned long start, unsigned long len,
		void (*func)(unsigned long *, unsigned int, unsigned int))
{
	func(bitmap, start, len);
	_clwb(bitmap + BIT_WORD(start), ALIGN(len, BITS_PER_LONG) >> 3);
}

/* Byte offset list */
struct blist_head {
	__le64	next, prev;
};

struct spfs_rename_jnl {
	__le32			jnl_tail;
	__le32			pad;
	__le64			jnl_inode;
	__le64			jnl[(BLK_SIZE - 16) >> 3];
};

struct spfs_super_block {
	struct spfs_rename_jnl	s_rename_jnl;
	__le32			s_magic;			/* 100 */
	__le32			s_block_size;
	__le32			s_cluster_size;
	__le32			s_inode_size;
	__le64			s_clusters_count;		/* 110 */
	__le32			s_first_main_clu;
	__le32			s_flags;
	__le32			s_bitmap_cluster_count;		/* 120 */
	__le32			s_cluster_hash[3];
	__le32			s_namei_hash[3];		/* 130 */
	__le32			s_extent_hash[3];
	__le32			s_inodes_count;
	__le32			s_pad;
	char			s_last_mounted[16];		/* 150 */
	struct blist_head	s_migration_list;		/* 160 */
	struct blist_head	s_inode_list[0];		/* 170 */
} __attribute((__packed__));

#define SUPER_BLOCK_CLUSTERS	(10)
#define INODE_LIST_SIZE		(CLUSTER_SIZE * SUPER_BLOCK_CLUSTERS -	\
			offsetof(struct spfs_super_block, s_inode_list))
#define INODE_LIST_COUNT	(INODE_LIST_SIZE / sizeof(struct blist_head))

struct spfs_inode {
	struct blist_head	i_list;				/* 00 */
	__le32			i_uid;				/* 10 */
	__le32			i_gid;
	__le16			i_mode;
	__le16			i_links_count;
	__le32			i_flags;
	__le64			i_size;				/* 20 */
	__le32			i_blocks;
	__le32			i_journal_tail;
	__le64			i_version;			/* 30 */
	__le32			i_eof;
	__le32			i_atime;
	__le32			i_mtime;			/* 40 */
	__le32			i_ctime;
	__le32          	i_sync_factor;
	__le32          	padding;
	/* 22 entries for 8B */
	__le64			i_journal[0];
} __attribute((__packed__));


enum {
	CONS_MODE_META,
	CONS_MODE_DATA,
};

enum { OP_MODE_TIERING, OP_MODE_PM, OP_MODE_DISK };

struct spfs_mount_options {
	const char	*bdev_path;
	bool		format;

	int		extent_hash_lp; // constant number or percentage
	int		extent_hash_depth;

	int		consistency_mode;
	int		operation_mode;

	/* profiler */
#define PROF_EXT_CNT	(16)
#define PROF_EXT_LEN	(8)
	char		prof_extensions[PROF_EXT_CNT][PROF_EXT_LEN];
	int		prof_ext_cnt;

	unsigned int	migr_fsync_interval;
	unsigned int	migr_written_bytes_btw_fsync;
	unsigned int	migr_continual_cnt;
	bool		migr_dir_boost;
#ifdef CONFIG_SPFS_1SEC_PROFILER
	unsigned int	prof_written_bytes_1sec;
#elif defined(CONFIG_SPFS_BW_PROFILER)
	unsigned int	prof_write_bandwidth;
	unsigned int	prof_fsync_bandwidth;
#endif
	bool		stats_exclude_init;

#define DEF_MAX_EXTENT_LEN	(65536)
#define DEF_PA_CLUSTER_CNT	(4)	/* 16KB */
#define DEF_UNDO_OPT_UTIL	(70)
	u32		max_extent_len;
	u32		pa_cluster_cnt;
	int		undo_opt_util;

	bool		cceh_fast_path;

	bool		no_gfi;
	
	int		demotion;
	int		demotion_hard_limit;
	int		demotion_sync_write;
	int		sf_alp_perc;
	int		migr_test_num_trigger;
};

struct spfs_data_info {
	struct spfs_cceh_info	*hash;
};

// Background migration thread
struct spfs_kthread {
	struct task_struct *spfs_task;
	int index;
	wait_queue_head_t wait_queue_head;
};

struct spfs_sb_info {
	struct super_block		*s_sb;
	struct super_block		*s_lower_sb;
	struct spfs_super_block		*s_psb;
	struct spfs_mount_options	s_options;
	struct dax_device		*s_dax_device;
	ssize_t				s_map_len;

	void				*s_free_info;
	void				*s_namei_info;
	struct spfs_data_info		s_data_info;
#ifdef CONFIG_SPFS_STATS
	void				*s_stats_info;
#endif
	struct proc_dir_entry		*s_proc;
	spinlock_t			s_inode_list_lock[INODE_LIST_COUNT];
#ifdef CONFIG_SPFS_READDIR_RADIX_TREE
	spinlock_t			s_readdir_index_lock;
	struct radix_tree_root		s_readdir_index;
#endif
	struct list_head *migr_lists;
	struct mutex *ml_locks; /* using mutex due to bg migration */
	struct spfs_kthread *bm_thread;
	struct spfs_kthread *usage_thread;
	int sf_rd_thld; 
};

#define S_OPTION(sbi)		(&(sbi)->s_options)

#define IS_OP_MODE_TIERING(sbi)	\
	(S_OPTION(sbi)->operation_mode == OP_MODE_TIERING)
#define IS_OP_MODE_PM(sbi)	(S_OPTION(sbi)->operation_mode == OP_MODE_PM)
#define IS_OP_MODE_DISK(sbi)	(S_OPTION(sbi)->operation_mode == OP_MODE_DISK)

#define BASE(sbi)		((char *) sbi->s_psb)
#define A2O(sbi, addr)		((u64) ((char *) (addr) - BASE(sbi)))
#define O2A(sbi, offset)	((void *) (BASE(sbi) + (offset)))

#define FIRST_BITMAP_CLU	(SUPER_BLOCK_CLUSTERS)

static inline void *clu_addr(struct spfs_sb_info *sbi, spfs_cluster_t clu_nr)
{
	return BASE(sbi) + C2BYTES(clu_nr);
}

static inline spfs_cluster_t clu_idx(struct spfs_sb_info *sbi, void *addr)
{
	return BYTES2C((char *) addr - BASE(sbi));
}

static inline void *blk_addr(struct spfs_sb_info *sbi, spfs_block_t blk_nr)
{
	return BASE(sbi) + B2BYTES(blk_nr);
}

static inline spfs_block_t blk_idx(struct spfs_sb_info *sbi, void *addr)
{
	return BYTES2B((char *) addr - BASE(sbi));
}

#define CLUSTER_BITMAP(sbi)	(clu_addr(sbi, FIRST_BITMAP_CLU))


struct spfs_file_info {
	struct file				*lower_file;
	const struct vm_operations_struct	*lower_vm_ops;
	void					*f_private;
};

static inline struct spfs_file_info *F_INFO(struct file *file)
{
	return (struct spfs_file_info *) file->private_data;
}

static inline void spfs_set_file_private(struct file *file,
		struct spfs_file_info *info)
{
	file->private_data = info;
}

static inline struct file *spfs_file_to_lower(struct file *file)
{
	return F_INFO(file)->lower_file;
}

static inline void spfs_set_file_lower(struct file *file,
		struct file *lower_file)
{
	F_INFO(file)->lower_file = lower_file;
}

static inline void clr_dir_eof(struct file *f)
{
	F_INFO(f)->f_private = 0;
}

static inline void set_dir_eof(struct file *file, loff_t pos)
{
	F_INFO(file)->f_private = (void *) pos;
}

/* We know the actual or virtual EOF of lower dir. file */
static inline loff_t get_dir_eof(struct file *file)
{
	return (loff_t) F_INFO(file)->f_private;
}

/* EOF can't be zero because of . and .. */
static inline bool test_dir_eof(struct file *file)
{
	/* never been EOF */
	if (!get_dir_eof(file))
		return false;
	/* readdir for lower file was ended at EOF and ready to start at PM */
	if (file->f_pos == (loff_t) F_INFO(file)->f_private)
		return true;
	/* doing readdir at PM */
	if (file->f_pos > i_size_read(file->f_inode))
		return true;
	return false;
}

struct spfs_migr_info {
	struct list_head migr_list;
	struct inode *inode;
	struct dentry *dentry;
};

/*
 * If it's on PM, inode.i_ino means block number where it's located.
 */
struct spfs_inode_info {
	struct inode		vfs_inode;
	struct inode		*lower_inode;

	unsigned long		i_flags;

	struct spfs_inode	*raw_inode;	/* cached on-PM inode */
	spinlock_t		i_raw_lock;
	struct rb_root		i_extent_tree;
	rwlock_t		i_extent_lock;

	void			*i_profiler;	/* for DISK mode inode */

	struct file		*i_file_doing_rw;

	struct spfs_migr_info 	*migr_info; /* for fg. sync factor detection */
	spinlock_t		migr_lock;
	atomic_t		sf_rd_cnt; /* for delayed sync factor calc. */
	atomic_t		wq_doing;
};

#ifdef CONFIG_SPFS_READDIR_RADIX_TREE
struct spfs_readdir_node {
	struct list_head	list;
	spfs_block_t		dirent_blk;
};
#endif

/* XXX: should set different info according to type? */
struct spfs_dentry_info {
	/* for bypass */
	struct path lower_path;

	/* for PM */
	struct spfs_dir_entry *de;
	void *dirent_slot;
#ifdef CONFIG_SPFS_READDIR_RADIX_TREE
	struct list_head		*children;	/* dir */
	struct spfs_readdir_node	*node;		/* reg */
#endif
};

struct spfs_work_data {
	struct work_struct work;
	struct inode *inode;
	struct dentry *dentry;
};

static inline struct spfs_sb_info *SB_INFO(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct spfs_inode_info *I_INFO(struct inode *inode)
{
	return (struct spfs_inode_info *) inode;
}

#define I_RAW(inode)	(I_INFO((inode))->raw_inode)

static inline struct spfs_migr_info *I_MIGR(struct inode *inode)
{
	return I_INFO(inode)->migr_info;
}

static inline struct inode *spfs_inode_to_lower(struct inode *inode)
{
	return I_INFO(inode)->lower_inode;
}

static inline void
spfs_set_inode_lower(struct inode *inode, struct inode *lower_inode)
{
	I_INFO(inode)->lower_inode = lower_inode;
}

static inline struct spfs_dentry_info *D_INFO(struct dentry *dentry)
{
	return (struct spfs_dentry_info *) dentry->d_fsdata;
}

static inline struct dentry *spfs_dentry_to_lower(struct dentry *dentry)
{
	return D_INFO(dentry)->lower_path.dentry;
}

static inline struct path *spfs_dentry_to_lower_path(struct dentry *dentry)
{
	return &D_INFO(dentry)->lower_path;
}

static inline void spfs_set_dentry_lower_path(struct dentry *dentry,
		struct path *path)
{
	D_INFO(dentry)->lower_path = *path;
}

extern const struct super_operations spfs_sops;

extern const struct address_space_operations spfs_aops;
extern const struct address_space_operations spfs_aops_bp;

extern const struct vm_operations_struct spfs_vm_ops_bp;

extern const struct inode_operations spfs_dir_iops;
extern const struct inode_operations spfs_main_iops;

extern const struct file_operations spfs_dir_bp_fops;
extern const struct file_operations spfs_main_fops;

extern const struct inode_operations spfs_symlink_bp_iops;

/* calloc.c */
extern int spfs_init_cluster_cache(void);
extern void spfs_destroy_cluster_cache(void);
extern int spfs_init_allocator(struct spfs_sb_info *);
extern void spfs_exit_allocator(struct spfs_sb_info *);

/* dax.c */
extern size_t spfs_dax_copy_to_addr(struct spfs_sb_info *,
		void *, void *, size_t);
extern size_t spfs_dax_copy_from_addr(struct spfs_sb_info *,
		void *, void *, size_t, bool);
extern void *spfs_map_dax_device(struct spfs_sb_info *, long);
extern struct dax_device *spfs_get_dax_device(struct super_block *);

/* dentry.c */
extern int __spfs_d_init(struct dentry *);
extern int spfs_init_dentry_cache(void);
extern void spfs_destory_dentry_cache(void);

/* extent.c */
extern int spfs_alloc_inode_blocks(struct inode *, spfs_cluster_t,
		unsigned int, loff_t, int);
extern int __init spfs_init_extent(void);
extern void spfs_exit_extent(void);

/* file.c */
extern int spfs_open(struct inode *, struct file *);
extern int spfs_init_file_cache(void);
extern void spfs_destroy_file_cache(void);

/* file_bp.c */
extern ssize_t spfs_read_iter_bp(struct kiocb *, struct iov_iter *);
extern ssize_t spfs_write_iter_bp(struct kiocb *, struct iov_iter *);
extern int spfs_open_bp(struct inode *, struct file *);
extern int spfs_release_bp(struct inode *, struct file *);
extern int spfs_fsync_bp(struct file *, loff_t, loff_t, int);
extern int spfs_mmap_bp(struct file *, struct vm_area_struct *);

/* format.c */
extern int spfs_format(struct spfs_sb_info *sbi);

/* inode.c */
extern int spfs_update_inode_size(struct inode *, loff_t);
extern void spfs_inode_inc_clusters(struct inode *, spfs_cluster_t);
extern void spfs_inode_dec_clusters(struct inode *, spfs_cluster_t);
extern int spfs_inode_test(struct inode *, void *);
extern struct inode *spfs_iget(struct super_block *, spfs_block_t,
		unsigned int);

/* inode_bp.c */
extern int spfs_unlink_bp(struct inode *, struct dentry *);
extern int spfs_getattr_bp(const struct path *, struct kstat *, u32,
		unsigned int);
extern int spfs_setattr_bp(struct dentry *, struct iattr *);
extern int spfs_permission_bp(struct inode *, int);
extern int spfs_rmdir_bp(struct inode *, struct dentry *);
extern int spfs_mkdir_bp(struct inode *, struct dentry *, umode_t);
extern int spfs_create_bp(struct inode *, struct dentry *, umode_t, bool);
extern struct inode *__spfs_iget_bp(struct inode *, struct super_block *);
extern struct inode *spfs_iget_bp(struct inode *, struct super_block *);
ssize_t spfs_listxattr_bp(struct dentry *, char *, size_t);
extern const struct xattr_handler spfs_xattr_bp_handler;

/* migration.c */
extern ssize_t spfs_migr_fill_extent(struct inode *, void *, size_t, loff_t *);
extern int spfs_prepare_upward_migration(struct dentry *);
extern int spfs_migrate_extent_map(struct inode *inode);
extern void spfs_add_migr_list(struct inode *, struct dentry *);
extern void spfs_calibrate_migr_list(struct inode *, unsigned int);
extern void spfs_remove_migr_list(struct inode *);
extern int spfs_alloc_migr_lists(struct spfs_sb_info *);
extern int spfs_destroy_migr_lists(struct spfs_sb_info *); 
extern int spfs_start_usage_thread(struct spfs_sb_info *);
extern void spfs_stop_usage_thread(struct spfs_sb_info *);
extern int spfs_start_bm_thread(struct spfs_sb_info *);
extern void spfs_stop_bm_thread(struct spfs_sb_info *);
extern int spfs_seq_migr_lists_show(struct seq_file *, void *);

/* namei.c */
extern int spfs_del_dir(struct dentry *);
extern int spfs_del_nondir(struct dentry *);
extern int __spfs_insert_dir_entries(struct dentry *, spfs_block_t,
		struct dentry *, spfs_block_t);
extern int spfs_insert_dir_entries(struct dentry *, struct dentry *);
extern int spfs_interpose_bp(struct dentry *, struct dentry *,
		struct super_block *);
extern struct dentry *spfs_lookup(struct inode *, struct dentry *,
		unsigned int);
extern int spfs_namei_init(struct spfs_sb_info *);
extern int spfs_namei_exit(struct spfs_sb_info *);

/* super.c */
extern int spfs_fill_super(struct super_block *, const char *, void *, int);
extern int spfs_init_inode_cache(void);
extern void spfs_destory_inode_cache(void);
extern void __spfs_msg(struct super_block *, const char *, const char *,
		...);

/* stats.c */
extern int spfs_seq_stats_show(struct seq_file *, void *);
extern int spfs_stats_init(struct spfs_sb_info *);
extern void spfs_stats_exit(struct spfs_sb_info *);

/* sysfs.c */
extern int spfs_register_sysfs(struct super_block *);
extern void spfs_unregister_sysfs(struct super_block *);
extern int __init spfs_init_sysfs(void);
extern void spfs_exit_sysfs(void);

#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) < (b) ? (b) : (a))

/* copied from fs/ecryptfs/inode.c */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir;

	dir = dget_parent(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

/* copied from fs/ecryptfs/inode.c */
static inline void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}

static inline spfs_block_t spfs_inode_block(struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);

	/* only allowed for PM inode */
	BUG_ON(I_INFO(inode)->raw_inode == NULL);

	return inode->i_ino;
}

static inline void spfs_inc_inodes_count(struct super_block *sb)
{
	le32_add_cpu(&SB_INFO(sb)->s_psb->s_inodes_count, 1);
}

static inline void spfs_dec_inodes_count(struct super_block *sb)
{
	le32_add_cpu(&SB_INFO(sb)->s_psb->s_inodes_count, -1);
}

/* inode flags */
enum {
	/* DRAM */
	INODE_HAS_PM_CHILDREN,
	INODE_DIR_USE_PM,
	INODE_NEED_TIERING,
	INODE_PM,
	/* both */
	INODE_TIERED,
	/* PM */
	INODE_NEED_RECOVERY,
	INODE_TRUNCATING,

	INODE_SUSPENDED,
};

static inline void set_inode_flag(struct inode *inode, int flag)
{
	test_and_set_bit(flag, &I_INFO(inode)->i_flags);
}

static inline bool is_inode_flag_set(struct inode *inode, int flag)
{
	return test_bit(flag, &I_INFO(inode)->i_flags);
}

static inline void clear_inode_flag(struct inode *inode, int flag)
{
	test_and_clear_bit(flag, &I_INFO(inode)->i_flags);
}

static inline bool spfs_should_bypass(struct inode *inode)
{
	return !(is_inode_flag_set(inode, INODE_PM) ||
			is_inode_flag_set(inode, INODE_TIERED));
}

/* inode state change: tiered => bypass by demotion */
static inline bool __spfs_revalidate_tiered(struct inode *inode)
{
	return !is_inode_flag_set(inode, INODE_TIERED);
}

static inline bool spfs_revalidate_tiered(struct inode *inode, bool is_read)
{
	if (is_inode_flag_set(inode, INODE_PM))
		return false;
	/* Inevitably, we have no choice but to wait for PM data to be freed */
	if (is_read)
		while (spin_is_locked(&I_INFO(inode)->migr_lock)) { }

	return __spfs_revalidate_tiered(inode);
}

static inline void init_blist_head_nt(struct spfs_sb_info *sbi,
		struct blist_head *list)
{
	movntq(&list->next, A2O(sbi, list));
	movntq(&list->prev, A2O(sbi, list));
}

/* Expected to be persisted by a caller */
static inline void init_blist_head(struct spfs_sb_info *sbi,
		struct blist_head *list)
{
	WRITE_ONCE(list->next, A2O(sbi, list));
	list->prev = A2O(sbi, list);
}

static inline int blist_empty(struct spfs_sb_info *sbi, struct blist_head *head)
{
	return READ_ONCE(head->next) == A2O(sbi, head);
}

static inline bool __blist_add_valid(struct spfs_sb_info *sbi,
		struct blist_head *new, struct blist_head *prev,
		struct blist_head *next)
{
	if (CHECK_DATA_CORRUPTION(O2A(sbi, next->prev) != prev,
			"list_add corruption. next->prev should be prev (%px), "
			"but was %px. (next=%px).\n",
			prev, O2A(sbi, next->prev), next) ||
	    CHECK_DATA_CORRUPTION(O2A(sbi, prev->next) != next,
			"list_add corruption. prev->next should be next (%px), "
			"but was %px. (prev=%px).\n",
			next, O2A(sbi, prev->next), prev) ||
	    CHECK_DATA_CORRUPTION(new == prev || new == next,
			"list_add double add: new=%px, prev=%px, next=%px.\n",
			new, prev, next))
		return false;

	return true;
}

static inline void __blist_add_nt(struct spfs_sb_info *sbi,
		struct blist_head *new, struct blist_head *prev,
		struct blist_head *next)
{
	u64 new_offset = A2O(sbi, new);

	if (!__blist_add_valid(sbi, new, prev, next))
		return;

	movntq(&new->next, A2O(sbi, next));
	movntq(&new->prev, A2O(sbi, prev));

	movntq(&next->prev, new_offset);
	movntq(&prev->next, new_offset);
}

/* must be used inside of lock.. XXX: is the persisting sequence OK? */
static inline void __blist_add(struct spfs_sb_info *sbi,
		struct blist_head *new, struct blist_head *prev,
		struct blist_head *next)
{
	u64 new_offset = A2O(sbi, new);

	if (!__blist_add_valid(sbi, new, prev, next))
		return;

	new->next = A2O(sbi, next);
	new->prev = A2O(sbi, prev);
	next->prev = new_offset;
	WRITE_ONCE(prev->next, new_offset);

	spfs_persist(&next->prev, sizeof(next->prev));
	spfs_persist(&prev->next, sizeof(prev->next));
}

static inline void __blist_add_nt_sfence(struct spfs_sb_info *sbi,
		struct blist_head *new, struct blist_head *prev,
		struct blist_head *next)
{
	__blist_add_nt(sbi, new, prev, next);
	SPFS_SFENCE();
}

#define blist_add_tail_nt(sbi, new, head)	\
	__blist_add_nt(sbi, new, O2A(sbi, (head)->prev), head)

#define blist_add_tail(sbi, new, head)		\
	__blist_add(sbi, new, O2A(sbi, (head)->prev), head)

static inline void __blist_del_nt(struct spfs_sb_info *sbi,
		struct blist_head *prev, struct blist_head *next)
{
	movntq(&next->prev, A2O(sbi, prev));
	movntq(&prev->next, A2O(sbi, next));
}

static inline void __blist_del_nt_sfence(struct spfs_sb_info *sbi,
		struct blist_head *prev, struct blist_head *next)
{
	__blist_del_nt(sbi, prev, next);
	SPFS_SFENCE();
}

/* must be called inside of lock */
static inline void __blist_del(struct spfs_sb_info *sbi,
		struct blist_head *prev, struct blist_head *next)
{
	next->prev = A2O(sbi, prev);
	WRITE_ONCE(prev->next, A2O(sbi, next));

	spfs_persist(&next->prev, sizeof(next->prev));
	spfs_persist(&prev->next, sizeof(prev->next));
}

static inline void blist_del_nt(struct spfs_sb_info *sbi,
		struct blist_head *entry)
{
	__blist_del_nt(sbi, O2A(sbi, entry->prev), O2A(sbi, entry->next));
}

static inline void blist_del(struct spfs_sb_info *sbi,
		struct blist_head *entry)
{
	__blist_del(sbi, O2A(sbi, entry->prev), O2A(sbi, entry->next));
}

static inline void blist_del_init(struct spfs_sb_info *sbi,
		struct blist_head *entry)
{
	blist_del(sbi, entry);
	init_blist_head(sbi, entry);
}

#define blist_entry			list_entry
#define blist_next_entry(sbi, pos, member)			\
	blist_entry(O2A(sbi, (pos)->member.next), typeof(*(pos)), member)
#define blist_last_entry(sbi, ptr, type, member)		\
	blist_entry(O2A(sbi, (ptr)->prev), type, member)

#define blist_for_each(sbi, pos, head)				\
	for (pos = O2A(sbi, (head)->next); pos != (head);	\
			pos = O2A(sbi, pos->next))

#define blist_for_each_from(sbi, pos, head)			\
	for (; pos != head; pos = O2A(sbi, (pos)->next))

#define blist_for_each_safe_from(sbi, pos, n, head)		\
	for (n = O2A(sbi, (pos)->next); pos != head;		\
			pos = n, n = O2A(sbi, n->next))

/* ioctl */
#define SPFS_IOC_SET_USE_PM	_IO('=', 0)
#define SPFS_IOC_SET_USE_DISK	_IO('=', 1)
#define SPFS_IOC_SET_UP_MIGR	_IO('=', 2)
#define SPFS_IOC_SET_DOWN_MIGR	_IO('=', 3)

#define SPFS_XATTR_SET_USE_PM	(XATTR_USER_PREFIX "SPFS.boost")


#define CREATE_TRACE_POINTS

#endif // _SPFS_H_

#include "cceh.h"
