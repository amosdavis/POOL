# POOL Windows Build (MinGW cross-compilation)
#
# Cross-compile from Linux/macOS:
#   make CC=x86_64-w64-mingw32-gcc
#
# Native build with MSVC:
#   cl /O2 /W4 pool_win_platform.c pool_win_service.c /Fe:pool_service.exe
#      /link bcrypt.lib ws2_32.lib advapi32.lib

CC ?= x86_64-w64-mingw32-gcc
CFLAGS = -Wall -O2 -I../common
LDFLAGS = -lbcrypt -lws2_32 -ladvapi32

.PHONY: all clean

all: pool_service.exe

pool_service.exe: pool_win_platform.c pool_win_service.c ../common/pool_proto.h ../common/pool_platform.h
	$(CC) $(CFLAGS) -o $@ pool_win_platform.c pool_win_service.c $(LDFLAGS)

clean:
	rm -f pool_service.exe
