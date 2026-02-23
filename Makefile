obj-m := tch_driver.o
tch_driver-objs := tch_driver.o tch_buffer.o tch_kprobe.o tch_device.o tch_filter.o

KVERSION := $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
