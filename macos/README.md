# POOL for macOS and BSD

Cross-platform userspace implementation of the POOL protocol for macOS,
FreeBSD, OpenBSD, NetBSD, and DragonFly BSD.

## Architecture

Like the Windows version, the macOS/BSD implementation runs as a userspace
daemon communicating via a Unix domain socket at `/var/run/pool.sock`.

| Component | File | Purpose |
|-----------|------|---------|
| Platform layer | `pool_darwin_platform.c` | CommonCrypto/OpenSSL, BSD sockets, pthreads |
| Daemon | `pool_darwin_daemon.c` | Daemon with Unix socket control interface |
| launchd plist | `com.pool.protocol.plist` | macOS service definition |

## Building

### macOS

```sh
clang -O2 -Wall -Wextra \
    pool_darwin_daemon.c pool_darwin_platform.c \
    -I../common \
    -framework Security -framework CoreFoundation \
    -o poold
```

**Note:** For production use on macOS, link against libsodium for proper
ChaCha20-Poly1305 support:

```sh
brew install libsodium
clang -O2 pool_darwin_daemon.c pool_darwin_platform.c \
    -I../common -I/opt/homebrew/include \
    -L/opt/homebrew/lib -lsodium \
    -framework Security -o poold
```

### FreeBSD

```sh
cc -O2 -Wall pool_darwin_daemon.c pool_darwin_platform.c \
    -I../common -lssl -lcrypto -lpthread -o poold
```

### OpenBSD

```sh
cc -O2 pool_darwin_daemon.c pool_darwin_platform.c \
    -I../common -lssl -lcrypto -lpthread -o poold
```

## Usage

### macOS (launchd)

```sh
sudo cp poold /usr/local/bin/
sudo cp com.pool.protocol.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.pool.protocol.plist
```

### FreeBSD (rc.d)

```sh
sudo cp poold /usr/local/sbin/
sudo sysrc poold_enable=YES
sudo service poold start
```

### Manual

```sh
# Foreground
sudo ./poold --foreground

# Daemon
sudo ./poold --daemon
```

## Control Interface

The daemon listens on `/var/run/pool.sock` (Unix domain socket) and accepts
the same command protocol as the Linux and Windows versions:

| Command | Code | Description |
|---------|------|-------------|
| CONNECT | 2 | Connect to a POOL peer |
| SESSIONS | 5 | List active sessions |
| CLOSE | 6 | Close a session |
| STOP | 7 | Stop the daemon |

## Crypto Backend

### macOS
- **X25519**: CommonCrypto (with SHA-256 fallback)
- **ChaCha20-Poly1305**: Requires libsodium (CommonCrypto placeholder included)
- **HMAC-SHA256**: `CCHmac` with `kCCHmacAlgSHA256`
- **HKDF**: Software implementation using HMAC-SHA256
- **RNG**: `CCRandomGenerateBytes`

### FreeBSD/OpenBSD
- **X25519**: OpenSSL `EVP_PKEY_X25519`
- **ChaCha20-Poly1305**: OpenSSL `EVP_chacha20_poly1305`
- **HMAC-SHA256**: OpenSSL `HMAC`
- **HKDF**: Software implementation using HMAC-SHA256
- **RNG**: OpenSSL `RAND_bytes`

## Minimum Requirements

- macOS 10.15 Catalina or later
- FreeBSD 12.0 or later
- OpenBSD 6.6 or later (with LibreSSL)
- Compiler: Clang 11+ or GCC 9+
