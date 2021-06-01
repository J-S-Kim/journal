#
# Makefile for the linux ext4mj-filesystem routines.
#

obj-$(CONFIG_EXT4MJ_FS) := ext4mj.o

unexport CONFIG_EXT4MJ_FS_SEC

ext4mj-y	:= balloc.o bitmap.o block_validity.o dir.o ext4mj_zj.o extents.o \
		extents_status.o file.o fsmap.o fsync.o hash.o ialloc.o \
		indirect.o inline.o inode.o ioctl.o mballoc.o migrate.o \
		mmp.o move_extent.o namei.o page-io.o readpage.o resize.o \
		super.o symlink.o sysfs.o xattr.o xattr_trusted.o xattr_user.o
