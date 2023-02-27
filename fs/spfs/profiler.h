#ifndef __PROFILER_H__
#define __PROFILER_H__

#include <linux/xattr.h>

#include "spfs.h"
#include "stats.h"

//#define PROF_DEBUG
#ifdef PROF_DEBUG
#define spfs_prof_debug(fmt, ...)	\
	pr_err("%s: "fmt, __func__, ##__VA_ARGS__)
#else
#define spfs_prof_debug(fmt, ...)	do {} while (0)
#endif

enum {
#ifdef CONFIG_SPFS_1SEC_PROFILER
	WB_1SEC,	/* written bytes from 1sec ago */
#else
	WB_WRITE,
	WB_FSYNC,	/* written bytes between consecutive fsync() calls */
	WB_AVERAGE,	/* average by # of fsync() calls */
#endif
	WB_TYPE_END
};

struct spfs_profiler {
#ifdef CONFIG_SPFS_1SEC_PROFILER
	unsigned long	written_when;
#else
	unsigned long	created_when;
	unsigned long	fsynced_when;
#endif
	unsigned long	first_fsync_jiffies;

	size_t		wrtb[WB_TYPE_END];	/* written bytes */
	u64		cumulative_cnt;

	unsigned int	continual_cnt;

	spinlock_t	lock;
	atomic64_t	dir_fsync_cnt;			/* only for dir */
};

#define I_PROFILER(inode)		\
	((struct spfs_profiler *) (I_INFO(inode)->i_profiler))

#define jiffies_to_secs(j)		(jiffies_to_msecs(j) / MSEC_PER_SEC)

static inline void spfs_prof_update_bytes_written(struct inode *inode,
		size_t written)
{
	struct spfs_profiler *prof = I_PROFILER(inode);
//	struct spfs_mount_options *opts = S_OPTION(SB_INFO(inode->i_sb));

	spin_lock(&prof->lock);

#ifdef CONFIG_SPFS_1SEC_PROFILER
	if (likely(prof->written_when && jiffies_to_secs(jiffies) ==
				jiffies_to_secs(prof->written_when)))
		prof->wrtb[WB_1SEC] += written;
	else {
		prof->wrtb[WB_1SEC] = written;
		prof->written_when = jiffies;
	}
#else
	prof->wrtb[WB_WRITE] += written;
	prof->wrtb[WB_FSYNC] += written;
#endif
	spin_unlock(&prof->lock);
}

#if !defined(CONFIG_SPFS_1SEC_PROFILER) && !defined(CONFIG_SPFS_BW_PROFILER)
static inline bool spfs_prof_fsync_interval(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct spfs_profiler *prof = I_PROFILER(inode);
	struct spfs_mount_options *opts = S_OPTION(SB_INFO(inode->i_sb));
	unsigned long old = prof->fsynced_when;

	prof->fsynced_when = jiffies;
	/* first time of fsync... let's give a change */
	if (!old)
		return true;

	if (time_after(msecs_to_jiffies(opts->migr_fsync_interval) + old, jiffies))
		return true;

	spfs_prof_debug("[RESET] %s(%lu) %lu sec. elapsed",
			file_dentry(file)->d_name.name, inode->i_ino,
			(jiffies - old) / HZ);

	return false;
}

static inline size_t spfs_prof_avg_filter(size_t avg, size_t new, u64 cnt)
{
	return (avg * (cnt - 1) / cnt) + (new / cnt);
}

static inline void spfs_prof_update_avg_bytes_written(struct inode *inode)
{
	struct spfs_profiler *prof = I_PROFILER(inode);

	/* TODO: just keep counter as max? */
	if (prof->cumulative_cnt != ULLONG_MAX)
		prof->cumulative_cnt++;

	prof->wrtb[WB_AVERAGE] = spfs_prof_avg_filter(prof->wrtb[WB_AVERAGE],
			prof->wrtb[WB_FSYNC], prof->cumulative_cnt);

	prof->wrtb[WB_FSYNC] = 0;
}

static inline bool spfs_prof_written_fsync_bytes(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct spfs_profiler *prof = I_PROFILER(inode);
	struct spfs_mount_options *opts = S_OPTION(SB_INFO(inode->i_sb));

	/* Only data writes are accounted not to mess up the average */
	if (prof->wrtb[WB_FSYNC])
		spfs_prof_update_avg_bytes_written(inode);

	if (prof->wrtb[WB_AVERAGE] < opts->migr_written_bytes_btw_fsync)
		return true;

	spfs_prof_debug("[RESET] %s(%lu) %lu bytes written",
			file_dentry(file)->d_name.name, inode->i_ino,
			prof->wrtb[WB_AVERAGE]);

	return false;
}
#endif

static inline void spfs_boost_locked(struct inode *inode)
{
	set_inode_flag(inode, INODE_NEED_TIERING);
	stats_prof_inc_boosted();
}

#define BOOST_LOG(file, inode, fmt, ...) do {				\
	spfs_prof_debug("[BOOST] %s(%lu) "#fmt,				\
			file_dentry(file)->d_name.name, inode->i_ino,	\
			__VA_ARGS__);					\
} while (0)

#ifdef CONFIG_SPFS_1SEC_PROFILER
static inline bool proportional_1s_write(struct spfs_profiler *prof,
		struct spfs_mount_options *opts)
{
	unsigned long j = jiffies;
	unsigned int us = jiffies_to_usecs(j);
	unsigned int p = MIN((us % USEC_PER_SEC) * 100 / USEC_PER_SEC,
			(us - jiffies_to_usecs(prof->written_when)) * 100 /
			USEC_PER_SEC);

	spfs_prof_debug("%lu %lu %u%% %lu vs. %u", jiffies_to_secs(j),
			jiffies_to_secs(prof->written_when),
			p, prof->wrtb[WB_1SEC],
			opts->prof_written_bytes_1sec * p / 100);

	if (prof->wrtb[WB_1SEC] > opts->prof_written_bytes_1sec * p / 100)
		return false;

	return true;
}

static inline bool __spfs_profile_fsync(struct file *file, struct inode *inode,
		struct spfs_profiler *prof, struct spfs_mount_options *opts)
{
	if (!proportional_1s_write(prof, opts))
		return false;

	BOOST_LOG(file, inode, "1s=%lu(%u)", prof->wrtb[WB_1SEC],
			opts->prof_written_bytes_1sec);

	spfs_boost_locked(inode);
	return true;
}
#elif defined(CONFIG_SPFS_BW_PROFILER)
static inline unsigned int BW(unsigned long count, unsigned long when)
{
	unsigned int ms = jiffies_delta_to_msecs(jiffies - when);

	if (ms < MSEC_PER_SEC)
		return UINT_MAX;

	return count / (ms / MSEC_PER_SEC);
}

static inline bool __spfs_profile_fsync(struct file *file, struct inode *inode,
		struct spfs_profiler *prof, struct spfs_mount_options *opts)
{
	unsigned int bw;
	unsigned long old = prof->fsynced_when;

	prof->fsynced_when = jiffies;
	if (!old)
		return false;

	if (!opts->prof_fsync_bandwidth)
		return false;

	if ((bw = BW(prof->wrtb[WB_FSYNC], old)) != UINT_MAX &&
			bw > opts->prof_fsync_bandwidth)
		return false;

	BOOST_LOG(file, inode, "bandwidth=%u(%u) %lu %lu", bw,
			opts->prof_fsync_bandwidth, prof->wrtb[WB_FSYNC], old);

	spfs_boost_locked(inode);
	return true;
}
#else
static inline bool __spfs_profile_fsync(struct file *file, struct inode *inode,
		struct spfs_profiler *prof, struct spfs_mount_options *opts)
{
	if (!spfs_prof_fsync_interval(file) ||
			!spfs_prof_written_fsync_bytes(file)) {
		prof->continual_cnt = 0;
		return false;
	}

	if (++prof->continual_cnt >= opts->migr_continual_cnt) {
		BOOST_LOG(file, inode, "cont=%u wrtb=%lu", prof->continual_cnt,
				prof->wrtb[WB_AVERAGE]);
		spfs_boost_locked(inode);
	} else
		return false;
	return true;
}
#endif

static inline bool __spfs_profile_fsync2(struct file *file, struct inode *inode,
		struct spfs_profiler *prof)
{
	if (!spfs_prof_fsync_interval(file) ||
			!spfs_prof_written_fsync_bytes(file)) {
		return false;
	}

	return true;
}

static inline int spfs_profile_fsync(struct file *file, bool from_fsync)
{
	struct inode *inode = file_inode(file);
	struct inode *dir;
	struct spfs_profiler *prof = I_PROFILER(inode);
	struct spfs_profiler *dir_prof;
	struct spfs_mount_options *opts = S_OPTION(SB_INFO(inode->i_sb));
	int ret = 0;
	unsigned int ms;
	s64 cnt;

	/* Let's do burst dir. profile only in the fsync path */
	if (!from_fsync || !opts->migr_dir_boost)
		goto lock;

	dir = d_inode(file->f_path.dentry->d_parent);
	dir_prof = I_PROFILER(dir);

	if (is_inode_flag_set(dir, INODE_DIR_USE_PM))
		goto lock;

	if (!dir_prof->first_fsync_jiffies) {
		cmpxchg(&dir_prof->first_fsync_jiffies, 0, jiffies);
		goto lock;
	}

	ms = jiffies_delta_to_msecs(jiffies - dir_prof->first_fsync_jiffies);
	cnt = atomic64_inc_return(&dir_prof->dir_fsync_cnt);
	if (ms && (cnt / ms) >= 1) { /* 1000 fsync calls() per second */
		BOOST_LOG(file, inode, "boost burst dir %lld/%ums", cnt, ms);
		set_inode_flag(dir, INODE_DIR_USE_PM);
		return 1;
	}
lock:
	spin_lock(&prof->lock);

	if (is_inode_flag_set(inode, INODE_NEED_TIERING) ||
			is_inode_flag_set(inode, INODE_TIERED))
		goto out;

	if (__spfs_profile_fsync(file, inode, prof, opts))
		ret++;
out:
	spin_unlock(&prof->lock);
	return ret;
}

static inline int spfs_profile_fsync2(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct spfs_profiler *prof = I_PROFILER(inode);
	int ret = 0;

	spin_lock(&prof->lock);

	if (is_inode_flag_set(inode, INODE_NEED_TIERING))
		goto out;

	if (__spfs_profile_fsync2(file, inode, prof))
		ret++;
out:
	spin_unlock(&prof->lock);
	return ret;
}

static inline int spfs_interest_dir(struct dentry *dentry, struct inode *inode)
{
	struct spfs_sb_info *sbi = SB_INFO(dentry->d_sb);
	struct path *lower_path = spfs_dentry_to_lower_path(dentry);
	struct inode *dir = d_inode(dentry->d_parent);
	int ret;

	if (IS_OP_MODE_DISK(sbi))
		return 0;

	if (is_inode_flag_set(dir, INODE_DIR_USE_PM)) {
		set_inode_flag(inode, INODE_DIR_USE_PM);
		return 0;
	}

	if (IS_OP_MODE_PM(sbi))
		goto set;

	ret = __vfs_getxattr(lower_path->dentry, d_inode(lower_path->dentry),
			SPFS_XATTR_SET_USE_PM, NULL, 0);
	if (ret < 0)
		return ret;
set:
	set_inode_flag(inode, INODE_DIR_USE_PM);
	return 0;
}

static inline int interest_extension(const char *s, const char *ext)
{
	size_t slen = strlen(s);
	size_t extlen = strlen(ext);
	int i;

	if (slen < extlen + 2)
		return 0;

	for (i = 1; i < slen - extlen; i++) {
		if (s[i] != '.')
			continue;
		if (!strncasecmp(s + i + 1, ext, extlen))
			return 1;
	}

	return 0;
}

static inline bool spfs_create_interest(struct dentry *dentry,
		unsigned int open_flags)
{
	struct spfs_sb_info *sbi = SB_INFO(dentry->d_sb);
	int i;

	if (IS_OP_MODE_PM(sbi))
		return true;
	else if (IS_OP_MODE_DISK(sbi))
		return false;

	/* OP_MODE_TIERING from now on */
	if (open_flags & (O_DIRECT | O_SYNC))
		return true;

	if (is_inode_flag_set(d_inode(dentry->d_parent), INODE_DIR_USE_PM))
		return true; /* dir. based */

	/* TODO: select extensions */
	for (i = 0; i < S_OPTION(sbi)->prof_ext_cnt; i++) {
		if (interest_extension(dentry->d_name.name,
					S_OPTION(sbi)->prof_extensions[i]))
			return true;
	}

	return false;
}

#ifdef CONFIG_SPFS_1SEC_PROFILER
static inline bool __spfs_profile_write_size(struct file *file,
		struct inode *inode, struct spfs_profiler *prof,
		struct spfs_mount_options *opts)
{
	if (!proportional_1s_write(prof, opts))
		return false;
	BOOST_LOG(file, inode, "1s=%lu(%u)", prof->wrtb[WB_1SEC],
			opts->prof_written_bytes_1sec);
	spfs_boost_locked(inode);
	return true;
}
#elif defined(CONFIG_SPFS_BW_PROFILER)
static inline bool __spfs_profile_write_size(struct file *file,
		struct inode *inode, struct spfs_profiler *prof,
		struct spfs_mount_options *opts)
{
	unsigned int bw;

	if (!opts->prof_write_bandwidth)
		return false;

	if ((bw = BW(prof->wrtb[WB_WRITE], prof->created_when)) >
			opts->prof_write_bandwidth)
		return false;

	BOOST_LOG(file, inode, "bandwidth=%u(%u) written=%lu",
			bw, opts->prof_write_bandwidth, prof->wrtb[WB_WRITE]);

	spfs_boost_locked(inode);
	return true;
}
#endif

#if defined(CONFIG_SPFS_1SEC_PROFILER) || defined(CONFIG_SPFS_BW_PROFILER)
static inline bool spfs_profile_write_size(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct spfs_profiler *prof = I_PROFILER(inode);
	struct spfs_mount_options *opts = S_OPTION(SB_INFO(inode->i_sb));
	bool boost = false;

	spin_lock(&prof->lock);

	if (is_inode_flag_set(inode, INODE_NEED_TIERING) ||
			is_inode_flag_set(inode, INODE_TIERED))
		goto out;

	boost = __spfs_profile_write_size(file, inode, prof, opts);
out:
	spin_unlock(&prof->lock);
	return boost;
}
#endif

/* XXX: hard coded sync factor value... */	
enum sync_factor_config {
	SF_SCALE 	= 4 * (1 << 20), // XXX: same as small write
	//SF_SMOOTH_PERC	= 5, // XXX: option
	/* 
	 * let bins: [0] [1] ... [9] [10] 
	 * ex: bin [1] covers 100 <= x < 200
	 * each bin covers range(i-1) <= x < range(i)
	 * SF_MAX(SF_SCALE) goes to the last bin, so we +1 for total bins 
	 */
	SF_BIN_RANGE 	= 4 * (1 << 10),
	SF_NUM_BINS 	= SF_SCALE / SF_BIN_RANGE + 1,
	
	SF_HARD_LIMIT  	= SF_SCALE / (SF_NUM_BINS - 1), /* smallest bin */
};

#define SF_ALP(perc) (SF_SCALE * perc / 100)

static inline unsigned int spfs_calc_sync_factor(struct spfs_sb_info * sbi, 
		unsigned int old, unsigned int value)
{
	int alp_perc = S_OPTION(sbi)->sf_alp_perc;
	return (SF_ALP(alp_perc) * value + 
			(1UL * SF_SCALE - SF_ALP(alp_perc)) * old) / SF_SCALE;
}

static inline unsigned int spfs_calc_sf_rd_thld(struct spfs_sb_info *sbi)
{
	unsigned int value = SF_SCALE;
	unsigned int cnt = 0;
	
	while (1) {
		cnt++;
		value = spfs_calc_sync_factor(sbi, value, 0);
		if (value <= 0)
			break;
	}

	return cnt;
}

#endif /* __PROFILER_H__ */
