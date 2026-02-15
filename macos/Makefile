# POOL macOS/BSD Build
#
# Build poold_darwin daemon + userspace tools for macOS.
# Requires OpenSSL (Homebrew: brew install openssl@3).
#
# Usage:
#   make OPENSSL_PREFIX=$(brew --prefix openssl@3)
#   make install DESTDIR=/usr/local
#   make clean

CC ?= clang
CFLAGS = -Wall -O2
OPENSSL_PREFIX ?= /opt/homebrew/opt/openssl@3
CFLAGS += -I$(OPENSSL_PREFIX)/include -I../common
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lpthread
PREFIX ?= /usr/local

.PHONY: all clean install tools

all: poold_darwin tools

poold_darwin: pool_darwin_platform.c pool_darwin_daemon.c ../common/pool_proto.h ../common/pool_platform.h
	$(CC) $(CFLAGS) -o $@ pool_darwin_platform.c pool_darwin_daemon.c $(LDFLAGS)

tools:
	$(MAKE) -C ../bridge CC=$(CC)
	$(MAKE) -C ../vault CC=$(CC)
	$(MAKE) -C ../relay CC=$(CC)

clean:
	rm -f poold_darwin
	$(MAKE) -C ../bridge clean
	$(MAKE) -C ../vault clean
	$(MAKE) -C ../relay clean

install: poold_darwin tools
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 poold_darwin $(DESTDIR)$(PREFIX)/sbin/poold_darwin
	install -m 755 ../bridge/pool_bridge $(DESTDIR)$(PREFIX)/sbin/pool_bridge
	install -m 755 ../bridge/pool_migrate $(DESTDIR)$(PREFIX)/sbin/pool_migrate
	install -m 755 ../vault/pool_vault $(DESTDIR)$(PREFIX)/sbin/pool_vault
	install -m 755 ../relay/pool_relay $(DESTDIR)$(PREFIX)/sbin/pool_relay
	install -d $(DESTDIR)/Library/LaunchDaemons
	install -m 644 com.pool.protocol.plist $(DESTDIR)/Library/LaunchDaemons/com.pool.protocol.plist
