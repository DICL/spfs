# SPFS (Stackable Persistent Memory File System)

## Introduction

SPFS is a stackable file system for Persistent Memory which can be stacked on any block device-optimized file system. By layering a NVMM-optimized stackable file system on a disk-optimized file system, SPFS avoids reinventing a file system for disks while providing a combined view of two file systems and leveraging the strengths of both layers. SPFS improves I/O performance as it absorbs frequent synchronous small writes on PM while also exploiting the VFS cache of the underlying disk-optimized file system for non-synchronous writes. As a stackable file system, SPFS is lightweight in that it manages only NVMM and does not manage disks nor the VFS cache. SPFS manages all file system metadata in simple but highly efficient dynamic hash tables. Our extensive performance study shows that SPFS effectively improves I/O performance of the lower file system by up to 7.1×.

Further details on the design and implementation of SPFS can be found in the following [paper]([https://www.usenix.org/conference/fast23/presentation/woo](https://www.usenix.org/conference/fast23/presentation/woo)).
We encourage you to cite our paper at FAST 2023 as follows:

```
@inproceedings{woo2023stacking,
  title={On stacking a persistent memory file system on legacy file systems},
  author={Woo, Hobin and Han, Daegyu and Ha, Seungjoon and Noh, Sam H and Nam, Beomseok},
  booktitle={21st USENIX Conference on File and Storage Technologies (FAST 23)}, 
  pages={281--296},
  year={2023}
}
```

## Compiling and Installing SPFS

Please download the latest version of `spfs` from Github:

```bash
$ git clone https://github.com/DICL/spfs.git
```

Ensure prerequisites and compile SPFS
```bash
$ sudo apt-get install -y git build-essential kernel-package fakeroot libncurses5-dev libssl-dev ccache bison flex
```

```bash
$ cd spfs
$ make menuconfig
$ make -j 8 && sudo make -j 8 modules_install install
```

`CONFIG_FS_DAX` is required to build SPFS. The recommended configurations are as follows.

```
CONFIG_SPFS=m
CONFIG_SPFS_BLOCK_BITS=8
# CONFIG_SPFS_UNIFIED_PCL is not set
# CONFIG_SPFS_DEBUG is not set
CONFIG_SPFS_READDIR_RADIX_TREE=y
# CONFIG_SPFS_STATS is not set
# CONFIG_SPFS_1SEC_PROFILER is not set
# CONFIG_SPFS_BW_PROFILER is not set
```

(Optional) Reduce the size of kernel module files and remove unnecessary information to reduce memory usage.

```bash
$ cd /lib/modules/5.1.0+
$ sudo find . -name "*".ko -exec strip --strip-unneeded {} +
$ sudo update-initramfs -c -k 5.1.0+
```

After rebooting, you will be able to find SPFS
```bash
$ modinfo spfs
filename:       /lib/modules/5.1.0+/kernel/fs/spfs/spfs.ko
license:        GPL
...
```

## Using SPFS

**Stacked Mode**
Mounting disk file system 
```bash
$ sudo mount -t ext4 /dev/sdb /mnt/spfs
```
Mounting SPFS on the top of the block device file system
```bash
$ sudo mount -t spfs -o pmem=/dev/pmem0,format,consistency=meta /mnt/spfs /mnt/spfs
```

**Standalone Mode**
```bash
$ sudo mount -t spfs -o pmem=/dev/pmem0,format,consistency=meta,mode=pm /mnt/spfs /mnt/spfs
```

### You can now start using SPFS
```bash
$ mount | grep "/mnt/spfs"
/dev/sdb on /mnt/spfs type ext4 (rw,relatime)
/mnt/spfs on /mnt/spfs type spfs (rw,relatime,pmem=/dev/pmem0,mode=tiering, ... ,consistency=meta)

$ dmesg -w
spfs: module init
spfs (pmem0): draft
spfs (pmem0): opening dax device pmem0
spfs (pmem0): dax mapping done: ffff99a7bc200000, 65027584
spfs (pmem0): CCEH format.. dir=1995 seg=1996 depth=4294967295 lp=2
spfs (pmem0): CCEH format.. dir=4044 seg=4045 depth=4294967295 lp=2
spfs (pmem0): CCEH format.. dir=6093 seg=6094 depth=4294967295 lp=8
spfs (pmem0): format done
spfs (pmem0): init. CCEH
spfs (pmem0): spfs_show_groups: Total=65025589 CPUs=40 Groups=41 CPC=1572864 BCPG

spfs (pmem0): spfs_show_groups: Group    0 start=0 nr=1572864 free=1042482
spfs (pmem0): spfs_show_groups: Group    1 start=1572864 nr=1572864 free=1572864
...
spfs (pmem0): spfs_show_groups: Group   39 start=61341696 nr=1572864 free=1572864
spfs (pmem0): spfs_show_groups: Group   40 start=62914560 nr=2111029 free=2111029
```

### Umounting SPFS
```bash
$ sudo umount /mnt/spfs
```

### Enabling Demotion
Move to the "demotion" branch:
```bash
$ git checkout demotion
```
Follow the steps mentioned earlier for building the SPFS.

## Limitations
- SPFS is under development, and only some functions have been implemented and tested. Please use it at your own risk.
- Currently, mount-time format option(`format` mount option) is required for every mount attempt because `CONFIG_SPFS_READDIR_RADIX_TREE` is under development.
- More mount options can be found in `fs/spfs/main.c`
