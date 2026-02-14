# POOL Socket Shim — Transparent POSIX Compatibility Layer

CC = gcc
CFLAGS = -Wall -O2 -fPIC -shared
LDFLAGS = -ldl -lpthread

all: libpool_shim.so

libpool_shim.so: pool_shim.c ../linux/pool.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: libpool_shim.so
	install -m 755 libpool_shim.so /usr/lib/
	@echo "Installed. Usage: LD_PRELOAD=/usr/lib/libpool_shim.so <command>"

clean:
	rm -f libpool_shim.so

.PHONY: all install clean
