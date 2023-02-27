#ifndef __FILE_H__
#define __FILE_H__

#include <linux/bitfield.h>
#include <linux/falloc.h>
#include "spfs.h"
#include "inode.h"

/* TODO: */
#define SPFS_FALLOC_FL_SUPPORTED	(FALLOC_FL_KEEP_SIZE)

static inline void spfs_add_tiering_rw_file(struct inode *inode,
		struct file *file)
{
	if (IS_TIERED_INODE(inode))
		I_INFO(inode)->i_file_doing_rw =
			get_file(spfs_file_to_lower(file));
}

static inline void spfs_del_tiering_rw_file(struct inode *inode)
{
	if (I_INFO(inode)->i_file_doing_rw) {
		fput(I_INFO(inode)->i_file_doing_rw);
		I_INFO(inode)->i_file_doing_rw = NULL;
	}
}

#endif
