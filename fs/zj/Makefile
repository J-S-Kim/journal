#
## Makefile for the linux journaling routines.
#
all: kernel_modules

obj-m := zj.o

CFLAGS_journal.o := -DDEBUG -g -I$(src)

MY_CFLAGS += -g -DDEBUG
CC += ${MY_CFLAGS}

KDIR := /home/jongseok/linux-4.14.78/

zj-objs := transaction.o commit.o recovery.o checkpoint.o revoke.o journal.o

$.ko: %.o
		$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) $@

kernel_modules:
		$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
		$(MAKE) -C $(KDIR) M=$(PWD) clean
