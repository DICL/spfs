#ifndef __PERSIST_H__
#define __PERSIST_H__

#include <asm-generic/cacheflush.h>


extern struct percpu_counter memory_barrier_counter;

#ifdef CONFIG_SPFS_STATS
#define stats_inc_sfence_counter()				\
	percpu_counter_add(&memory_barrier_counter, 1)
#else
#define stats_inc_sfence_counter()	do {} while (0)
#endif

#define SPFS_SFENCE() do {					\
	wmb();							\
	stats_inc_sfence_counter();				\
} while (0)

static inline void movntl(void *dst, u32 src)
{
	asm volatile ("movntil %1, %0" : "=m"(*(u32 *) dst) : "r"(src));
}

static inline void movntl_sfence(void *dst, u32 src)
{
	movntl(dst, src);
	SPFS_SFENCE();
}

static inline void movntq(void *dst, u64 src)
{
	asm volatile ("movntiq %1, %0" : "=m"(*(u64 *) dst) : "r"(src));
}

static inline void movntq_sfence(void *dst, u32 src)
{
	movntq(dst, src);
	SPFS_SFENCE();
}

/* TODO: what should we use? */
#define spfs_clwb(addr)
extern void arch_wb_cache_pmem(void *, size_t);
static inline void spfs_persist(void *addr, size_t size)
{
#ifdef CONFIG_ARCH_HAS_PMEM_API
	arch_wb_cache_pmem(addr, size);
#endif
}

#define _clwb		spfs_persist

static inline void clwb_sfence(void *addr, size_t size)
{
	spfs_persist(addr, size);
	SPFS_SFENCE();
}

#endif
