# pool_migrate - Gradual TCP→POOL migration tool

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lpthread

all: pool_bridge pool_migrate

pool_bridge: pool_bridge.c ../linux/pool.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

pool_migrate: pool_migrate.c ../linux/pool.h
	$(CC) $(CFLAGS) -o $@ $<

install: pool_bridge pool_migrate
	install -m 755 pool_bridge /usr/sbin/
	install -m 755 pool_migrate /usr/sbin/

clean:
	rm -f pool_bridge pool_migrate

.PHONY: all install clean
