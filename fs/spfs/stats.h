#ifndef __STATS_H__
#define __STATS_H__

#include "spfs.h"
#include <linux/percpu_counter.h>

#ifdef CONFIG_SPFS_STATS

extern struct percpu_counter stats_extent_counter;
extern atomic64_t stats_extent_counter_accumulated;
extern atomic64_t stats_extent_prealloc_usage_counter;

extern struct percpu_counter stats_undo_counter;
extern struct percpu_counter stats_replace_counter;
extern struct percpu_counter stats_cow_counter;

extern int spfs_seq_extent_count_show(struct seq_file *, void *);

#define stats_inc_prealloc_usage()				\
	atomic64_inc(&stats_extent_prealloc_usage_counter)

#define stats_inc_extent_count() do {				\
	percpu_counter_add(&stats_extent_counter, 1);		\
	atomic64_inc(&stats_extent_counter_accumulated);	\
} while (0)

#define stats_dec_extent_count()			\
	percpu_counter_sub(&stats_extent_counter, 1)


extern int spfs_seq_profiler_show(struct seq_file *, void *);
extern struct percpu_counter stats_prof_boosted;
extern struct percpu_counter stats_prof_fsync_on_boosted;
extern struct percpu_counter stats_prof_write_on_boosted;
extern struct percpu_counter stats_prof_read_on_boosted;
extern struct percpu_counter stats_prof_read_fallback_on_boosted;
extern struct percpu_counter stats_prof_migration_read_on_boosted;

#define stats_prof_inc(inode, name) do {				\
	if (is_inode_flag_set(inode, INODE_TIERED))			\
		percpu_counter_add(&stats_prof_##name, 1);		\
} while (0)

#define stats_prof_inc_boosted()					\
	percpu_counter_add(&stats_prof_boosted, 1)

#define stats_prof_inc_fsync_on_boosted(inode)				\
	stats_prof_inc(inode, fsync_on_boosted)

#define stats_prof_inc_migration_read_on_boosted(inode)			\
	stats_prof_inc(inode, migration_read_on_boosted)

#define stats_prof_inc_rw(inode, nr, name) do {				\
	if (nr > 0)							\
		stats_prof_inc(inode, name);				\
} while (0)

#define stats_prof_inc_write_on_boosted(inode, nr)			\
	stats_prof_inc_rw(inode, nr, write_on_boosted)

#define stats_prof_inc_read_on_boosted(inode, nr)			\
	stats_prof_inc_rw(inode, nr, read_on_boosted)

#define stats_prof_inc_read_fallback_on_boosted(inode, nr)		\
	stats_prof_inc_rw(inode, nr, read_fallback_on_boosted)

extern int spfs_seq_logging_count_show(struct seq_file *seq, void *v);
#define stats_log_undo()	percpu_counter_add(&stats_undo_counter, 1)
#define stats_log_replace()	percpu_counter_add(&stats_replace_counter, 1)
#define stats_log_cow()		percpu_counter_add(&stats_cow_counter, 1)

extern int spfs_seq_demotion_show(struct seq_file *seq, void *v);
extern struct percpu_counter stats_succ_on_demoted;
extern struct percpu_counter stats_succ_amounts_on_demoted;
extern struct percpu_counter stats_susp_on_demoted;
extern struct percpu_counter stats_susp_amounts_on_demoted;
extern struct percpu_counter stats_full_mapped_on_demoted;
extern struct percpu_counter stats_partial_mapped_on_demoted;
extern struct percpu_counter stats_nothing_mapped_on_demoted;

#define stats_inc_succ_on_demoted()					\
	percpu_counter_add(&stats_succ_on_demoted, 1)
#define stats_inc_succ_amounts_on_demoted(nr)				\
	percpu_counter_add(&stats_succ_amounts_on_demoted, nr)
#define stats_inc_susp_on_demoted()					\
	percpu_counter_add(&stats_susp_on_demoted, 1)
#define stats_inc_susp_amounts_on_demoted(nr)				\
	percpu_counter_add(&stats_susp_amounts_on_demoted, nr)
#define stats_inc_full_mapped_on_demoted()				\
	percpu_counter_add(&stats_full_mapped_on_demoted, 1)
#define stats_inc_partial_mapped_on_demoted()				\
	percpu_counter_add(&stats_partial_mapped_on_demoted, 1)
#define stats_inc_nothing_mapped_on_demoted()				\
	percpu_counter_add(&stats_nothing_mapped_on_demoted, 1)

#else
#define stats_inc_prealloc_usage()			do {} while (0)
#define stats_inc_extent_count()			do {} while (0)
#define stats_dec_extent_count()			do {} while (0)

#define stats_prof_inc_boosted()			do {} while (0)
#define stats_prof_inc_fsync_on_boosted(i)		do {} while (0)
#define stats_prof_inc_write_on_boosted(i, n)		do {} while (0)
#define stats_prof_inc_read_on_boosted(i, n)		do {} while (0)
#define stats_prof_inc_read_fallback_on_boosted(i, n)	do {} while (0)
#define stats_prof_inc_migration_read_on_boosted(i)	do {} while (0)

#define stats_log_undo()				do {} while (0)
#define stats_log_replace()				do {} while (0)
#define stats_log_cow()					do {} while (0)

#define stats_inc_succ_on_demoted()			do {} while (0)
#define stats_inc_succ_amounts_on_demoted(nr)		do {} while (0)
#define stats_inc_susp_on_demoted()			do {} while (0)
#define stats_inc_susp_amounts_on_demoted(nr)		do {} while (0)
#define stats_inc_full_mapped_on_demoted()		do {} while (0)
#define stats_inc_partial_mapped_on_demoted()		do {} while (0)
#define stats_inc_nothing_mapped_on_demoted()		do {} while (0)

#endif

#endif
