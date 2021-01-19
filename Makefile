obj-m := tcpsecrets.o

KVER  ?= $(shell uname -r)
KDIR  ?= /lib/modules/${KVER}/build
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

test: kallsyms_test
	./$<

kallsyms_test: kallsyms_test.c kallsyms.h
	$(CC) $< -o $@

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean: 
	@rm -f *.o .*.cmd .*.*.cmd .*.flags *.mod.c *.order

distclean: clean 
	@rm -f *.ko *.mod *.symvers kallsyms_test
