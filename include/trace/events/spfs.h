/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM spfs

#if !defined(_TRACE_KEYFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KEYFS_H

#include <linux/tracepoint.h>


TRACE_EVENT(spfs_create_enter,

		TP_PROTO(struct inode *dir, struct dentry *dentry),

		TP_ARGS(dir, dentry),

		TP_STRUCT__entry(
			__field(	ino_t,	dir			)
			__array(	char,	name,	MAX_NAME_LEN	)
		),

		TP_fast_assign(
			__entry->dir	= dir->i_ino;
			sprintf(__entry->name, "%s", dentry->d_name.name);
		),

		TP_printk("dir %lu name %s", (unsigned long) __entry->dir,
			__entry->name)
);

TRACE_EVENT(spfs_create_exit,

		TP_PROTO(struct inode *dir, struct dentry *dentry, int ret),

		TP_ARGS(dir, dentry, ret),

		TP_STRUCT__entry(
			__field(	ino_t,	dir			)
			__field(	int,	ret			)
			__array(	char,	name,	MAX_NAME_LEN	)
		),

		TP_fast_assign(
			__entry->dir	= dir->i_ino;
			__entry->ret		= ret;
			sprintf(__entry->name, "%s", dentry->d_name.name);
		),

		TP_printk("dir %lu name %s ret %d",
			(unsigned long) __entry->dir, __entry->name,
			__entry->ret)
);


#endif

#include <trace/define_trace.h>
