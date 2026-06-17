KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

obj-m := vma_cherrypick.o
vma_cherrypick-y := core.o syms_lookup.o
