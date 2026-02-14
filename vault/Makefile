# pool_vault - Encrypted distributed file vault

CC = gcc
CFLAGS = -Wall -O2
LDFLAGS =

all: pool_vault

pool_vault: pool_vault.c ../linux/pool.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: pool_vault
	install -m 755 pool_vault /usr/sbin/

clean:
	rm -f pool_vault

.PHONY: all install clean
