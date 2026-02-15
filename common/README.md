# POOL Common — Cross-Platform Protocol Core

This directory contains platform-independent POOL protocol definitions and logic, designed to be shared across all implementations (Linux kernel, Windows, macOS, userspace).

## Files

| File | Purpose |
|------|---------|
| `pool_proto.h` | Protocol constants, packet formats, wire structures |
| `pool_platform.h` | Platform abstraction layer (crypto, networking, memory, threading) |
| `pool_state.h` | Session state machine (transitions, packet validation) |

## Design Principles

1. **No platform headers** — Only `<stdint.h>` and `<stddef.h>` are required
2. **No dynamic allocation in headers** — Memory allocation goes through `pool_platform.h`
3. **All crypto is abstracted** — Each platform provides its own crypto backend
4. **Packed structs for wire format** — `#pragma pack` ensures consistent layout

## Porting to a New Platform

To port POOL to a new platform:

1. Include `pool_proto.h` for all protocol definitions
2. Implement all functions declared in `pool_platform.h`
3. Use `pool_state.h` for session state machine logic
4. The protocol logic (handshake, data transfer, fragmentation, MTU discovery) can then be built on top of these abstractions

## Platform Implementations

| Platform | Location | Status |
|----------|----------|--------|
| Linux kernel | `linux/` | ✅ Complete |
| Windows | `windows/` | ❌ Not started |
| macOS/BSD | — | ❌ Not started |
| Userspace (portable) | — | ❌ Not started |
