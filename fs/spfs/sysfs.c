#include <linux/proc_fs.h>
#include "spfs.h"
#include "stats.h"
#include "profiler.h"

static const char proc_dirname[] = "fs/spfs";
static struct proc_dir_entry *spfs_proc_root;

struct percpu_counter memory_barrier_counter;

int spfs_seq_memory_barrier_show(struct seq_file *seq, void *offset)
{
	seq_printf(seq, "sfence: %lld\n",
			percpu_counter_sum(&memory_barrier_counter));

	percpu_counter_set(&memory_barrier_counter, 0);

	return 0;
}

int spfs_register_sysfs(struct super_block *sb)
{
	struct spfs_sb_info *sbi = SB_INFO(sb);

	if (spfs_proc_root)
		sbi->s_proc = proc_mkdir(sb->s_id, spfs_proc_root);

	if (sbi->s_proc) {
#ifdef CONFIG_SPFS_STATS
		int err = 0;
#define COUNTER_INIT(c) do {				\
	err = percpu_counter_init(c, 0, GFP_KERNEL);	\
	if (err)					\
		return err;				\
} while (0)
		COUNTER_INIT(&stats_extent_counter);
		COUNTER_INIT(&stats_prof_boosted);
		COUNTER_INIT(&stats_prof_fsync_on_boosted);
		COUNTER_INIT(&stats_prof_write_on_boosted);
		COUNTER_INIT(&stats_prof_read_on_boosted);
		COUNTER_INIT(&stats_prof_read_fallback_on_boosted);
		COUNTER_INIT(&stats_prof_migration_read_on_boosted);
		COUNTER_INIT(&stats_undo_counter);
		COUNTER_INIT(&stats_replace_counter);
		COUNTER_INIT(&stats_cow_counter);

		COUNTER_INIT(&stats_succ_on_demoted);
		COUNTER_INIT(&stats_succ_amounts_on_demoted);
		COUNTER_INIT(&stats_susp_on_demoted);
		COUNTER_INIT(&stats_susp_amounts_on_demoted);
		COUNTER_INIT(&stats_full_mapped_on_demoted);
		COUNTER_INIT(&stats_partial_mapped_on_demoted);
		COUNTER_INIT(&stats_nothing_mapped_on_demoted);
		
		proc_create_single_data("extent_count", S_IRUGO, sbi->s_proc,
				spfs_seq_extent_count_show, sb);
		proc_create_single_data("profiler", S_IRUGO, sbi->s_proc,
				spfs_seq_profiler_show, sb);
		proc_create_single_data("logging", S_IRUGO, sbi->s_proc,
				spfs_seq_logging_count_show, sb);
		proc_create_single_data("demotion", S_IRUGO, sbi->s_proc,
				spfs_seq_demotion_show, sb);
#endif
		proc_create_single_data("extent_CCEH", S_IRUGO, sbi->s_proc,
				spfs_seq_extent_cceh_show, sb);
		proc_create_single_data("memory_barrier", S_IRUGO, sbi->s_proc,
				spfs_seq_memory_barrier_show, sb);
		proc_create_single_data("migr_lists", S_IRUGO, sbi->s_proc,
				spfs_seq_migr_lists_show, sb);
	}

	return 0;
}

void spfs_unregister_sysfs(struct super_block *sb)
{
	struct spfs_sb_info *sbi = SB_INFO(sb);

	if (sbi->s_proc) {
#ifdef CONFIG_SPFS_STATS
		percpu_counter_destroy(&stats_extent_counter);
		percpu_counter_destroy(&stats_prof_boosted);
		percpu_counter_destroy(&stats_prof_fsync_on_boosted);
		percpu_counter_destroy(&stats_prof_write_on_boosted);
		percpu_counter_destroy(&stats_prof_read_on_boosted);
		percpu_counter_destroy(&stats_prof_read_fallback_on_boosted);
		percpu_counter_destroy(&stats_prof_migration_read_on_boosted);
		percpu_counter_destroy(&stats_undo_counter);
		percpu_counter_destroy(&stats_replace_counter);
		percpu_counter_destroy(&stats_cow_counter);

		percpu_counter_destroy(&stats_succ_on_demoted);
		percpu_counter_destroy(&stats_succ_amounts_on_demoted);
		percpu_counter_destroy(&stats_susp_on_demoted);
		percpu_counter_destroy(&stats_susp_amounts_on_demoted);
		percpu_counter_destroy(&stats_full_mapped_on_demoted);
		percpu_counter_destroy(&stats_partial_mapped_on_demoted);
		percpu_counter_destroy(&stats_nothing_mapped_on_demoted);
#endif
		remove_proc_subtree(sb->s_id, spfs_proc_root);
	}
}

int __init spfs_init_sysfs(void)
{
	int err;

	spfs_proc_root = proc_mkdir(proc_dirname, NULL);

	err = percpu_counter_init(&memory_barrier_counter, 0, GFP_KERNEL);
	if (err)
		return err;

	return 0;
}

void spfs_exit_sysfs(void)
{
	percpu_counter_destroy(&memory_barrier_counter);
	remove_proc_entry(proc_dirname, NULL);
	spfs_proc_root = NULL;
}
