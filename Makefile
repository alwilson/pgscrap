obj-m := pgscrap.o
KDIR := /lib/modules/$(shell uname -r)/build

CFLAGS_pgscrap.o := -DDEBUG

all:
	make -C $(KDIR) M=`pwd` modules

clean:
	make -C $(KDIR) M=`pwd` clean
