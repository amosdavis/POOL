# POOL Completion Plan — What's Needed Before Ubiquitous Deployment

## Problem Statement

POOL (Protected Orchestrated Overlay Link) is a secure transport protocol implemented as a Linux kernel module. The core protocol is **working** — 500 MB encrypted transfers have been tested between two QEMU VMs. However, for POOL to be deployed "everywhere" (across organizations, operating systems, and use cases), several gaps must be addressed across the kernel module, adoption tools, cross-platform support, testing, and operational readiness.

## Current State Summary

| Component | Status | Completeness |
|-----------|--------|-------------|
| Kernel module (pool.ko) | ✅ Working | ~90% — core crypto, handshake, data transfer all functional |
| Userspace tools (poolctl, poold, pool_test) | ✅ Working | 100% |
| Shim (libpool_shim.so) | ✅ Implemented | 100% code, ~15% test coverage |
| Bridge (pool_bridge, pool_migrate) | ✅ Implemented | 100% code, ~60% test coverage |
| Vault (pool_vault) | ✅ Implemented | 100% code, 0% test coverage |
| Relay (pool_relay) | ✅ Implemented | 100% code, 0% test coverage |
| Windows driver | ❌ Empty directory | 0% |
| Common (cross-platform) | ❌ Empty directory | 0% |
| Tools (additional) | ❌ Empty directory | 0% |
| BDD tests | ⚠️ Partial | ~50% step defs implemented, many stubs |
| Specs/docs | ✅ Complete | 5 spec documents, comprehensive README |

## Completion Plan

### Area 1: Kernel Module Gaps

These are features the spec promises but the code doesn't implement yet.

#### 1.1 Fragment Reassembly (receive side) — ✅ DONE
- Implemented `pool_data_handle_fragment()` in `pool_data.c`
- RX thread dispatches fragments through reassembly
- Fixed bug: fragment cleanup only freed 4/16 slots

#### 1.2 MTU Discovery — ✅ DONE
- Implemented `pool_mtu.c` with DISCOVER packet (type 0xA)
- Binary search between POOL_MIN_MTU and POOL_DEFAULT_MTU
- Auto re-probe every 60 seconds
- Data send now uses dynamic MTU from `pool_mtu_effective()`

#### 1.3 Atomic Configuration & Rollback — ✅ DONE
- Implemented `pool_config.c` with CONFIG (0x8) and ROLLBACK (0x9) handlers
- Versioned config with automatic rollback on deadline expiry
- CONFIG/ROLLBACK dispatch added to RX thread
- Config deadline checking in maintenance loop

#### 1.4 Loss Rate Telemetry — ✅ DONE
- Added sequence gap detection in `pool_net.c` receive path
- `pool_telemetry_record_recv()` now computes loss_rate_ppm
- Added `expected_remote_seq` and `packets_lost` to session struct

#### 1.5 IP Protocol 253 Support — PENDING (P3)
- TCP overlay works for now

### Area 2: Test Infrastructure Completion

#### 2.1 Kernel Module Test Steps — ✅ DONE
- Implemented all remaining stubs (fragment timeout, dead peer, loss telemetry)
- Added fragment reassembly scenario and loss rate telemetry scenario

#### 2.2 Bridge Test Steps — ✅ DONE
- Implemented `exactlyBridgeThreadsAreCreated()` (reads /proc/pid/task)
- Implemented `noDuplicateBridgesExist()` (process health check)
- Implemented `noFileDescriptorsAreLeaked()` (reads /proc/pid/fd)

#### 2.3 Shim Test Steps — ✅ DONE
- Complete rewrite: all 25+ stubs replaced with real implementations

#### 2.4 Missing Test Suites — ✅ DONE
- Created `vault.feature` (6 scenarios) + `vault_steps.go`
- Created `relay.feature` (7 scenarios) + `relay_steps.go`
- Registered InitializeVaultScenario and InitializeRelayScenario
- Added test-vault and test-relay Makefile targets

### Area 3: Cross-Platform Support

#### 3.1 Windows Driver — PENDING (P3)
#### 3.2 macOS/BSD Support — PENDING (P3)

#### 3.3 Common Cross-Platform Code — ✅ DONE
- Created `pool_proto.h`: All protocol constants, packet formats, wire structures
- Created `pool_platform.h`: Platform abstraction layer (crypto, networking, memory, threading)
- Created `pool_state.h`: Session state machine (transitions, packet validation)

### Area 4: Operational Readiness

#### 4.1 Packaging & Distribution — ✅ DONE
- Created systemd units: pool-module.service, poold.service, pool-relay.service, pool-bridge.service, pool-exporter.service
- Created DKMS configuration (dkms.conf)
- Created install.sh script with --dkms, --systemd, --all options

#### 4.2 Configuration Management — ✅ DONE (via config-rollback)

#### 4.3 Monitoring & Alerting Integration — ✅ DONE
- Created `pool_exporter.py`: Prometheus exporter reading /proc/pool/sessions and /proc/pool/telemetry
- Exposes per-session and aggregate metrics on :9254/metrics
- Health check endpoint on /health

#### 4.4 Security Hardening (Crypto Self-Tests) — ✅ DONE
- Added HMAC-SHA256 known-answer test (RFC 4231 Test Case 2)
- Added ChaCha20-Poly1305 AEAD round-trip self-test
- Module refuses to load if any self-test fails

#### 4.5 Documentation Gaps — ✅ DONE
- Created man pages: poolctl(8), poold(8), pool_bridge(8), pool_vault(8), pool_relay(8), pool_test(8)

### Area 5: Protocol Maturity

#### 5.1 Cipher Negotiation / Post-quantum — PENDING (P3)
#### 5.2 Multi-Channel Multiplexing API — ✅ DONE
- Added POOL_IOC_CHANNEL ioctl (command 8)
- Subscribe/Unsubscribe/List operations
- Per-session channel subscription bitmap (256 bits)

#### 5.3 Peer Discovery — PENDING (P3)

## Priority Order (for "use everywhere")

| # | Priority | Item | Status |
|---|----------|------|--------|
| 1 | **P0** | Fragment reassembly (1.1) | ✅ Done |
| 2 | **P0** | Complete shim tests (2.3) | ✅ Done |
| 3 | **P0** | Vault & relay BDD tests (2.4) | ✅ Done |
| 4 | **P1** | Complete kernel module tests (2.1) | ✅ Done |
| 5 | **P1** | Complete bridge tests (2.2) | ✅ Done |
| 6 | **P1** | Loss rate telemetry (1.4) | ✅ Done |
| 7 | **P1** | MTU discovery (1.2) | ✅ Done |
| 8 | **P1** | Systemd units & DKMS (4.1) | ✅ Done |
| 9 | **P1** | Cross-platform core library (3.3) | ✅ Done |
| 10 | **P2** | Config & rollback (1.3) | ✅ Done |
| 11 | **P2** | Monitoring integration (4.3) | ✅ Done |
| 12 | **P2** | Man pages & ops docs (4.5) | ✅ Done |
| 13 | **P2** | Crypto self-tests on load (4.4) | ✅ Done |
| 14 | **P2** | Multi-channel multiplexing API (5.2) | ✅ Done |
| 15 | **P3** | Windows driver/support (3.1) | ❌ Pending |
| 16 | **P3** | macOS/BSD support (3.2) | ❌ Pending |
| 17 | **P3** | IP proto 253 native (1.5) | ❌ Pending |
| 18 | **P3** | Peer discovery (5.3) | ❌ Pending |
| 19 | **P3** | Post-quantum crypto (5.1) | ❌ Pending |
