KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

obj-m := criu_capbypass.o
criu_capbypass-y := core.o syms_lookup.o
