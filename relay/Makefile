# pool_relay - POOL relay daemon with operator incentives

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lm

all: pool_relay

pool_relay: pool_relay.c ../linux/pool.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: pool_relay
	install -m 755 pool_relay /usr/sbin/
	mkdir -p /var/lib/pool

clean:
	rm -f pool_relay

.PHONY: all install clean
