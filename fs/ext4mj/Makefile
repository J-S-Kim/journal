#
# Makefile for the linux ext4mj-filesystem routines.
#

all: kernel_modules

obj-m := ext4mj.o

CFLAGS_ext4mj.o := -g -DDEBUG
CFLAGS_super.o := -I$(src)

MY_CFLAGS += -g -DDEBUG
CC += ${MY_CFLAGS}

unexport CONFIG_EXT4MJ_FS_SEC

KDIR := /home/jongseok/linux-4.14.78/
ZDIR := /home/jongseok/linux-4.14.78/fs/zj/

ext4mj-y	:= balloc.o bitmap.o block_validity.o dir.o ext4mj_zj.o extents.o \
		extents_status.o file.o fsmap.o fsync.o hash.o ialloc.o \
		indirect.o inline.o inode.o ioctl.o mballoc.o migrate.o \
		mmp.o move_extent.o namei.o page-io.o readpage.o resize.o \
		super.o symlink.o sysfs.o xattr.o xattr_trusted.o xattr_user.o

ccflags-y += -I$(JDIR)
ccflags-y += -I$(KDIR)

KBUILD_EXTRA_SYMBOLS += $(ZDIR)/Module.symvers


$.ko: %.o
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) $@

kernel_modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

#ext4mj-$(CONFIG_EXT4MJ_FS_POSIX_ACL)	+= acl.o
#ext4mj-$(CONFIG_EXT4MJ_FS_SECURITY)		+= xattr_security.o

