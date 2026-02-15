# POOL for Windows

Windows userspace implementation of the POOL protocol using the cross-platform
abstraction layer (`common/pool_platform.h`).

## Architecture

Unlike the Linux version (which is a kernel module), the Windows implementation
runs as a userspace Windows service communicating via named pipes.

| Component | File | Purpose |
|-----------|------|---------|
| Platform layer | `pool_win_platform.c` | BCrypt crypto, Winsock2 networking, Windows threads |
| Service | `pool_win_service.c` | Windows service with named pipe control interface |

## Building

Requires Visual Studio 2019+ or Windows SDK with CL compiler:

```cmd
cl /O2 /W4 pool_win_service.c pool_win_platform.c ^
   /I..\common ^
   /link bcrypt.lib ws2_32.lib advapi32.lib
```

## Usage

### Install as a Windows service
```cmd
pool_service.exe --install
net start POOLProtocol
```

### Run in console mode (for testing)
```cmd
pool_service.exe --console
```

### Uninstall
```cmd
net stop POOLProtocol
pool_service.exe --uninstall
```

## Control Interface

The service exposes a named pipe at `\\.\pipe\pool_control` that accepts
commands mirroring the Linux ioctl interface:

| Command | Code | Description |
|---------|------|-------------|
| CONNECT | 2 | Connect to a POOL peer |
| SESSIONS | 5 | List active sessions |
| CLOSE | 6 | Close a session |
| STOP | 7 | Stop the service |

## Crypto Backend

Uses Windows CNG (Cryptography Next Generation) via BCrypt:

- **X25519**: `BCryptGenerateKeyPair` with `BCRYPT_ECC_CURVE_25519`
- **ChaCha20-Poly1305**: `BCRYPT_CHACHA20_POLY1305_ALGORITHM` (Windows 10 1903+)
- **HMAC-SHA256**: `BCRYPT_SHA256_ALGORITHM` with `BCRYPT_ALG_HANDLE_HMAC_FLAG`
- **HKDF**: Software implementation using HMAC-SHA256
- **RNG**: `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`

## Minimum Requirements

- Windows 10 version 1903 (for ChaCha20-Poly1305 support)
- Visual Studio 2019+ for building
- Administrator privileges for service installation
