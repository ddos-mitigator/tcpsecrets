obj-m := tcpsecrets.o

KVER  ?= $(shell uname -r)
KDIR  ?= /lib/modules/${KVER}/build
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean: 
	@rm -f *.o .*.cmd .*.*.cmd .*.flags *.mod.c *.order

disclean: clean 
	@rm *.ko *.mod *.symvers
