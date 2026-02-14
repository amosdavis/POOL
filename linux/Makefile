# Makefile for POOL Protocol kernel module + userspace tools
#
# Build kernel module:
#   make
#
# Build userspace tools:
#   make tools
#
# Install into a node image:
#   make install DESTDIR=/mnt/node1

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC ?= gcc

.PHONY: all clean install tools

all: tools
	$(MAKE) -C $(KDIR) M=$(PWD) modules

tools: poolctl pool_test poold

poolctl: poolctl.c pool.h
	$(CC) -Wall -O2 -o poolctl poolctl.c

pool_test: pool_test.c pool.h
	$(CC) -Wall -O2 -o pool_test pool_test.c

poold: poold.c pool.h
	$(CC) -Wall -O2 -o poold poold.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f poolctl pool_test poold

install:
ifdef DESTDIR
	install -D -m 644 pool.ko $(DESTDIR)/lib/modules/6.1.0-42-amd64/extra/pool.ko
	install -D -m 755 poolctl $(DESTDIR)/usr/sbin/poolctl
	install -D -m 755 pool_test $(DESTDIR)/usr/sbin/pool_test
	install -D -m 755 poold $(DESTDIR)/usr/sbin/poold
else
	$(error DESTDIR is not set. Usage: make install DESTDIR=/mnt/node1)
endif
