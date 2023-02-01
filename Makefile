obj-m := func_client.o
KERNELBUILD := /lib/modules/$(shell uname -r)/build
CURRENT_PATH := $(shell pwd)
all:
	make -C $(KERNELBUILD) M=$(CURRENT_PATH) modules
clean:
	make -C $(KERNELBUILD) M=$(CURRENT_PATH) clean
