#include "stats.h"

struct percpu_counter stats_extent_counter;
atomic64_t stats_extent_counter_accumulated;
atomic64_t stats_extent_prealloc_usage_counter;

int spfs_seq_extent_count_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "    Max. Extent Count: %llu\n",
			atomic64_read(&stats_extent_counter_accumulated));
	seq_printf(seq, "   Final Extent Count: %lld\n",
			percpu_counter_sum(&stats_extent_counter));
	seq_printf(seq, "Prealloc Extent Usage: %llu\n",
			atomic64_read(&stats_extent_prealloc_usage_counter));
	atomic64_set(&stats_extent_counter_accumulated, 0);
	atomic64_set(&stats_extent_prealloc_usage_counter, 0);
	percpu_counter_set(&stats_extent_counter, 0);
	return 0;
}

struct percpu_counter stats_undo_counter;
struct percpu_counter stats_replace_counter;
struct percpu_counter stats_cow_counter;

int spfs_seq_logging_count_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "   Undo: %lld\n",
			percpu_counter_sum(&stats_undo_counter));
	seq_printf(seq, "Replace: %lld\n",
			percpu_counter_sum(&stats_replace_counter));
	seq_printf(seq, "    CoW: %lld\n",
			percpu_counter_sum(&stats_cow_counter));
	percpu_counter_set(&stats_undo_counter, 0);
	percpu_counter_set(&stats_replace_counter, 0);
	percpu_counter_set(&stats_cow_counter, 0);
	return 0;
}

struct percpu_counter stats_prof_boosted;
struct percpu_counter stats_prof_fsync_on_boosted;
struct percpu_counter stats_prof_write_on_boosted;
struct percpu_counter stats_prof_read_on_boosted;
struct percpu_counter stats_prof_read_fallback_on_boosted;
struct percpu_counter stats_prof_migration_read_on_boosted;

int spfs_seq_profiler_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "                  Boosted: %llu\n",
			percpu_counter_sum(&stats_prof_boosted));
	seq_printf(seq, "         Fsync on Boosted: %llu\n",
			percpu_counter_sum(&stats_prof_fsync_on_boosted));
	seq_printf(seq, "         Write on Boosted: %llu\n",
			percpu_counter_sum(&stats_prof_write_on_boosted));
	seq_printf(seq, "          Read on Boosted: %llu\n",
			percpu_counter_sum(&stats_prof_read_on_boosted));
	seq_printf(seq, " Read fallback on Boosted: %llu\n",
		percpu_counter_sum(&stats_prof_read_fallback_on_boosted));
	seq_printf(seq, "Migration read on Boosted: %llu\n",
		percpu_counter_sum(&stats_prof_migration_read_on_boosted));
#if 0
	percpu_counter_set(&stats_prof_boosted, 0);
	percpu_counter_set(&stats_prof_fsync_on_boosted, 0);
	percpu_counter_set(&stats_prof_write_on_boosted, 0);
	percpu_counter_set(&stats_prof_read_on_boosted, 0);
	percpu_counter_set(&stats_prof_read_fallback_on_boosted, 0);
	percpu_counter_set(&stats_prof_migration_read_on_boosted, 0);
#endif
	return 0;
}

struct percpu_counter stats_succ_on_demoted;
struct percpu_counter stats_succ_amounts_on_demoted;
struct percpu_counter stats_susp_on_demoted;
struct percpu_counter stats_susp_amounts_on_demoted;
struct percpu_counter stats_full_mapped_on_demoted;
struct percpu_counter stats_partial_mapped_on_demoted;
struct percpu_counter stats_nothing_mapped_on_demoted;

int spfs_seq_demotion_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "        Num Files Succ on Demoted: %llu\n",
			percpu_counter_sum(&stats_succ_on_demoted));
	seq_printf(seq, "Write Amounts Succ on Demoted(KB): %llu\n",
			percpu_counter_sum(&stats_succ_amounts_on_demoted) 
			>> 10);
	seq_printf(seq, "        Num Files Susp on Demoted: %llu\n",
			percpu_counter_sum(&stats_susp_on_demoted));
	seq_printf(seq, "Write Amounts Susp on Demoted(KB): %llu\n",
			percpu_counter_sum(&stats_susp_amounts_on_demoted) 
			>> 10);
	seq_printf(seq, "           Full Mapped on Demoted: %llu\n",
			percpu_counter_sum(&stats_full_mapped_on_demoted));
	seq_printf(seq, "        Partial Mapped on Demoted: %llu\n",
			percpu_counter_sum(&stats_partial_mapped_on_demoted));
	seq_printf(seq, "        Nothing Mapped on Demoted: %llu\n",
			percpu_counter_sum(&stats_nothing_mapped_on_demoted));
#if 0
	percpu_counter_set(&stats_succ_on_demoted, 0);
	percpu_counter_set(&stats_succ_amounts_on_demoted, 0);
	percpu_counter_set(&stats_susp_on_demoted, 0);
	percpu_counter_set(&stats_susp_amounts_on_demoted, 0);
	percpu_counter_set(&stats_full_mapped_on_demoted, 0);
	percpu_counter_set(&stats_partial_mapped_on_demoted, 0);
	percpu_counter_set(&stats_nothing_mapped_on_demoted, 0);
#endif
	return 0;
}
