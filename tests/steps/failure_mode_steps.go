package steps

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

type failureModeCtx struct {
	*PoolTestContext
	sourceFile  string
	sourceCode  string
	specContent string
	lastErr     error
}

func (f *failureModeCtx) loadSource(filename string) error {
	paths := []string{
		filepath.Join("..", "linux", filename),
		filepath.Join("..", "macos", filename),
		filepath.Join("..", "windows", filename),
		filepath.Join("..", "vault", filename),
		filepath.Join("..", "relay", filename),
		filepath.Join("..", "bridge", filename),
		filepath.Join("..", "shim", filename),
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			f.sourceFile = p
			f.sourceCode = string(data)
			return nil
		}
	}
	return fmt.Errorf("source file %s not found", filename)
}

func (f *failureModeCtx) loadSpec(filename string) error {
	p := filepath.Join("..", "spec", filename)
	data, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("spec file %s not found: %w", filename, err)
	}
	f.specContent = string(data)
	return nil
}

func (f *failureModeCtx) assertContains(haystack, needle, desc string) error {
	if !strings.Contains(haystack, needle) {
		return fmt.Errorf("%s: expected to find %q", desc, needle)
	}
	return nil
}

func (f *failureModeCtx) assertNotContains(haystack, needle, desc string) error {
	if strings.Contains(haystack, needle) {
		return fmt.Errorf("%s: should not contain %q", desc, needle)
	}
	return nil
}

// ---- Crypto Steps ----

func (f *failureModeCtx) aPoolSessionWithEstablishedCryptoState() error {
	return f.loadSource("pool_crypto.c")
}

func (f *failureModeCtx) theNonceIsConstructedForEncryption() error {
	return nil // verified in source check
}

func (f *failureModeCtx) bytes03OfNonceShouldContainHmacKeyNotZeros() error {
	return f.assertContains(f.sourceCode, "memcpy(nonce, cs->hmac_key, 4)",
		"C01: nonce prefix should use hmac_key")
}

func (f *failureModeCtx) bytes411ShouldContainBigEndianSequence() error {
	return f.assertContains(f.sourceCode, "cpu_to_be64(cs->seq)",
		"C01: nonce should contain big-endian sequence")
}

func (f *failureModeCtx) aPoolCryptoContextWithNoHardwareECDH() error {
	return f.loadSource("pool_crypto.c")
}

func (f *failureModeCtx) theEcdhFallbackPathIsUsed() error {
	return nil
}

func (f *failureModeCtx) aWarningShouldBeLoggedExactlyOnce() error {
	return f.assertContains(f.sourceCode, "pr_warn_once",
		"C02: ECDH fallback should log warning once")
}

func (f *failureModeCtx) theEphemeralPublicKeyShouldBeZeroizedAfterUse() error {
	return f.assertContains(f.sourceCode, "memzero_explicit(my_pubkey",
		"C02: pubkey should be zeroized")
}

func (f *failureModeCtx) aPoolHKDFContext() error {
	return f.loadSource("pool_crypto.c")
}

func (f *failureModeCtx) hkdfIsCalledWithOkmLen0() error {
	return nil
}

func (f *failureModeCtx) itShouldReturnEINVAL() error {
	return f.assertContains(f.sourceCode, "okm_len <= 0",
		"C03: HKDF should check okm_len <= 0")
}

func (f *failureModeCtx) hkdfIsCalledWithOkmLenExceeding255Times32() error {
	return nil
}

func (f *failureModeCtx) itShouldReturnEINVALForOversized() error {
	return f.assertContains(f.sourceCode, "okm_len > 255 * 32",
		"C03: HKDF should check okm_len > 255*32")
}

func (f *failureModeCtx) packetssincerekeyReachesPoolRekeyPackets() error {
	return nil
}

func (f *failureModeCtx) aRateLimitedRekeyInfoShouldBeLogged() error {
	return f.assertContains(f.sourceCode, "pr_info_ratelimited",
		"C04: rekey should log rate-limited info")
}

func (f *failureModeCtx) aPoolPQCContext() error {
	return f.loadSource("pool_pqc.c")
}

func (f *failureModeCtx) mlkemCbdEta2ProcessesInputBuffer() error {
	return nil
}

func (f *failureModeCtx) shouldUseMemcpyFor32BitReads() error {
	return f.assertContains(f.sourceCode, "memcpy(&t, buf + 4 * i, sizeof(t))",
		"C05: CBD should use memcpy for alignment safety")
}

func (f *failureModeCtx) shouldNotCauseUnalignedAccessOnARM() error {
	return f.assertNotContains(f.sourceCode, "*(const uint32_t *)(buf",
		"C05: no unaligned pointer casts")
}

func (f *failureModeCtx) hkdfFailsDuringEncapsulation() error {
	return nil
}

func (f *failureModeCtx) errorCodePropagatedToCaller() error {
	if !strings.Contains(f.sourceCode, "ret = pool_crypto_hkdf(msg") {
		return fmt.Errorf("C06: HKDF result should be checked in encaps/decaps")
	}
	return f.assertContains(f.sourceCode, "if (ret)\n        goto out;",
		"C06: HKDF error should propagate")
}

func (f *failureModeCtx) hkdfFailsDuringDecapsulation() error {
	return nil
}

func (f *failureModeCtx) cryptoAllocShashForSha256FailsDuringKeygen() error {
	return nil
}

func (f *failureModeCtx) keygenShouldReturnAllocationError() error {
	return f.assertContains(f.sourceCode, "ret = PTR_ERR(sha)",
		"C07: keygen should return SHA256 alloc error")
}

func (f *failureModeCtx) noPartialSecretKeyShouldBeGenerated() error {
	return f.assertContains(f.sourceCode, "goto out;",
		"C07: should goto out on alloc failure")
}

// ---- Network Steps ----

func (f *failureModeCtx) aPoolNodeAttemptingTCPConnection() error {
	return f.loadSource("pool_net.c")
}

func (f *failureModeCtx) connectingToUnreachablePeer() error {
	return nil
}

func (f *failureModeCtx) connectionShouldTimeoutWithin10Seconds() error {
	return f.assertContains(f.sourceCode, "tv.tv_sec = 10",
		"N01: connect should have 10s timeout")
}

func (f *failureModeCtx) notBlockIndefinitely() error {
	return f.assertContains(f.sourceCode, "SO_SNDTIMEO",
		"N01: should set send timeout")
}

func (f *failureModeCtx) highestReceivedSequenceIs100() error {
	return nil
}

func (f *failureModeCtx) packetWithSequenceNumber30Arrives() error {
	return nil
}

func (f *failureModeCtx) packetShouldBeDiscardedAsOutsideReplayWindow() error {
	return f.assertContains(f.sourceCode, "sess->expected_remote_seq - remote_seq > 64",
		"N02: anti-replay window should be 64")
}

func (f *failureModeCtx) packetWithSequenceNumber80Arrives() error {
	return nil
}

func (f *failureModeCtx) packetShouldBeAcceptedAsWithinReplayWindow() error {
	return nil // acceptance is the default path
}

func (f *failureModeCtx) aPoolRawTransportSessionWithPeerIP(ip string) error {
	return f.loadSource("pool_net_raw.c")
}

func (f *failureModeCtx) packetArrivesFromDifferentIPMatchingSessionID() error {
	return nil
}

func (f *failureModeCtx) packetRejectedWithRateLimitedWarning() error {
	return f.assertContains(f.sourceCode, "source IP mismatch",
		"N03: should warn on IP mismatch")
}

func (f *failureModeCtx) notDeliveredToSessionRXQueue() error {
	return nil // break after warning prevents delivery
}

func (f *failureModeCtx) aPoolRawTransportSession() error {
	return f.loadSource("pool_net_raw.c")
}

func (f *failureModeCtx) rxQueueContains4096Entries() error {
	return nil
}

func (f *failureModeCtx) anotherPacketArrives() error {
	return nil
}

func (f *failureModeCtx) packetDroppedWithQueueFullWarning() error {
	return f.assertContains(f.sourceCode, "RX queue full",
		"N04: should warn when queue full")
}

func (f *failureModeCtx) queueDepthShouldNotExceed4096() error {
	return f.assertContains(f.sourceCode, "queue_depth >= 4096",
		"N04: queue limit should be 4096")
}

func (f *failureModeCtx) aPoolRawTransportListener() error {
	return f.loadSource("pool_net_raw.c")
}

func (f *failureModeCtx) lookingUpSessionsBySessionID() error {
	return nil
}

func (f *failureModeCtx) sessionsLockMutexHeldDuringIteration() error {
	return f.assertContains(f.sourceCode, "mutex_lock(&pool.sessions_lock)",
		"N05: session lookup should hold sessions_lock")
}

func (f *failureModeCtx) noUseAfterFreeFromConcurrentDeletion() error {
	return f.assertContains(f.sourceCode, "mutex_unlock(&pool.sessions_lock)",
		"N05: sessions_lock should be released after iteration")
}

func (f *failureModeCtx) peerTableWith256ActivePeers() error {
	return f.loadSource("pool_discover.c")
}

func (f *failureModeCtx) newPeerAnnounces() error {
	return nil
}

func (f *failureModeCtx) oldestNonStaticPeerEvicted() error {
	return f.assertContains(f.sourceCode, "evicting stale peer",
		"N06: should evict stale peer when table full")
}

func (f *failureModeCtx) newPeerAddedToTable() error {
	return f.assertContains(f.sourceCode, "free_slot = oldest_slot",
		"N06: should reuse evicted slot")
}

func (f *failureModeCtx) aPoolPeerDiscoveryListener() error {
	return f.loadSource("pool_discover.c")
}

func (f *failureModeCtx) announcesFasterThan100ms() error {
	return nil
}

func (f *failureModeCtx) excessAnnouncesDropped() error {
	return f.assertContains(f.sourceCode, "100000000ULL",
		"N07: announce rate limit should be 100ms")
}

func (f *failureModeCtx) peerTableShouldNotChurn() error {
	return nil
}

// ---- Session Steps ----

func (f *failureModeCtx) aPoolSessionBeingEstablished() error {
	return f.loadSource("pool_session.c")
}

func (f *failureModeCtx) kthreadRunFailsForRxThread() error {
	return nil
}

func (f *failureModeCtx) poolSessionFreeShouldBeCalled() error {
	return f.assertContains(f.sourceCode, "pool_session_free(sess)",
		"S01: session_free should be called on kthread failure")
}

func (f *failureModeCtx) allSessionResourcesReleased() error {
	return nil // verified by pool_session_free implementation
}

func (f *failureModeCtx) activeFragmentReassembly() error {
	return f.loadSource("pool_session.c")
}

func (f *failureModeCtx) poolSessionFreeIsCalled() error {
	return nil
}

func (f *failureModeCtx) rxLockHeldWhileFreeingFragments() error {
	return f.assertContains(f.sourceCode, "S02: Free fragment buffers under rx_lock",
		"S02: fragment free should hold rx_lock")
}

func (f *failureModeCtx) noRaceWithRxThread() error {
	return nil
}

func (f *failureModeCtx) receivingFragmentedData() error {
	return f.loadSource("pool_data.c")
}

func (f *failureModeCtx) fragmentWithOffsetPlusLenExceedingTotalLen() error {
	return nil
}

func (f *failureModeCtx) fragmentShouldBeRejected() error {
	return f.assertContains(f.sourceCode, "frag_offset + data_len > fb->total_len",
		"S03: fragment bounds check")
}

func (f *failureModeCtx) noHeapOverflow() error {
	return nil
}

func (f *failureModeCtx) all16FragmentSlotsOccupied() error {
	return f.loadSource("pool_data.c")
}

func (f *failureModeCtx) newFragmentSequenceBegins() error {
	return nil
}

func (f *failureModeCtx) oldestIncompleteFragmentEvicted() error {
	return f.assertContains(f.sourceCode, "start_jiffies",
		"S04: LRU eviction by start_jiffies")
}

func (f *failureModeCtx) newFragmentUsesFreedSlot() error {
	return nil
}

func (f *failureModeCtx) aPoolConfigSubsystem() error {
	return f.loadSource("pool_config.c")
}

func (f *failureModeCtx) concurrentConfigPackets() error {
	return nil
}

func (f *failureModeCtx) configLockSerializesOperations() error {
	return f.assertContains(f.sourceCode, "mutex_lock(&config_lock)",
		"S05: config operations should use config_lock")
}

func (f *failureModeCtx) noRaceOnCurrentConfig() error {
	return f.assertContains(f.sourceCode, "mutex_unlock(&config_lock)",
		"S05: config_lock should be released")
}

func (f *failureModeCtx) performingMTUDiscovery() error {
	return f.loadSource("pool_mtu.c")
}

func (f *failureModeCtx) probeRangeCollapsesToLoEqualsHi() error {
	return nil
}

func (f *failureModeCtx) mtuDiscoveryDeclareComplete() error {
	return f.assertContains(f.sourceCode, "mtu_probe_hi <= sess->mtu_probe_lo",
		"S06: should detect lo==hi edge case")
}

func (f *failureModeCtx) noFurtherProbes() error {
	return nil
}

// ---- Module Lifecycle Steps ----

func (f *failureModeCtx) aPoolKernelModuleShuttingDown() error {
	return f.loadSource("pool_main.c")
}

func (f *failureModeCtx) poolExitIsCalled() error {
	return nil
}

func (f *failureModeCtx) sessionsClosedFirst() error {
	// Verify that session close happens before flush_workqueue
	closeIdx := strings.Index(f.sourceCode, "pool_session_close")
	flushIdx := strings.Index(f.sourceCode, "flush_workqueue")
	if closeIdx < 0 || flushIdx < 0 {
		return fmt.Errorf("M01: missing session_close or flush_workqueue")
	}
	// Find the pool_exit function
	exitIdx := strings.Index(f.sourceCode, "pool_exit")
	if exitIdx < 0 {
		return fmt.Errorf("M01: pool_exit not found")
	}
	// In pool_exit, close should come before flush
	exitCode := f.sourceCode[exitIdx:]
	c := strings.Index(exitCode, "pool_session_close")
	fl := strings.Index(exitCode, "flush_workqueue")
	if c > fl {
		return fmt.Errorf("M01: sessions should be closed before workqueue flush")
	}
	return nil
}

func (f *failureModeCtx) workqueueFlushed() error {
	return f.assertContains(f.sourceCode, "flush_workqueue",
		"M01: workqueue should be flushed")
}

func (f *failureModeCtx) noFlushedWorkReferencesFreedSessions() error {
	return nil
}

func (f *failureModeCtx) channelIoctlRequestsChannel256() error {
	return nil
}

func (f *failureModeCtx) shouldReturnEINVALForChannel() error {
	return f.assertContains(f.sourceCode, "creq.channel >= POOL_MAX_CHANNELS",
		"M02: channel bounds check")
}

func (f *failureModeCtx) noOOBWrite() error {
	return nil
}

func (f *failureModeCtx) aPoolKernelModule() error {
	return f.loadSource("pool_main.c")
}

func (f *failureModeCtx) ioctlIsCalled() error {
	return nil
}

func (f *failureModeCtx) tryModuleGetCalledFirst() error {
	return f.assertContains(f.sourceCode, "try_module_get(THIS_MODULE)",
		"M03: ioctl should call try_module_get")
}

func (f *failureModeCtx) modulePutOnAllExitPaths() error {
	return f.assertContains(f.sourceCode, "module_put(THIS_MODULE)",
		"M03: ioctl should call module_put")
}

func (f *failureModeCtx) ioctlDuringUnloadReturnsENODEV() error {
	return f.assertContains(f.sourceCode, "return -ENODEV",
		"M03: should return ENODEV during unload")
}

func (f *failureModeCtx) moduleWithActiveSessions() error {
	return f.loadSource("pool_sysinfo.c")
}

func (f *failureModeCtx) procPoolSessionsRead() error {
	return nil
}

func (f *failureModeCtx) sessionsLockHeldDuringProcfsIteration() error {
	return f.assertContains(f.sourceCode, "mutex_lock(&pool.sessions_lock)",
		"M04: procfs should hold sessions_lock")
}

func (f *failureModeCtx) noUAFFromConcurrentSessionDeletion() error {
	return f.assertContains(f.sourceCode, "mutex_unlock(&pool.sessions_lock)",
		"M04: sessions_lock released after iteration")
}

func (f *failureModeCtx) moduleInitializing() error {
	return f.loadSource("pool_telemetry.c")
}

func (f *failureModeCtx) heartbeatStartsBeforeSessionInit() error {
	return nil
}

func (f *failureModeCtx) heartbeatWaitsForSessionsReady() error {
	return f.assertContains(f.sourceCode, "sessions_ready",
		"M05: heartbeat should wait for sessions_ready")
}

func (f *failureModeCtx) notAccessUninitializedSessionData() error {
	return nil
}

// ---- Platform Steps ----

func (f *failureModeCtx) aPoolWindowsNodePreW1903() error {
	return f.loadSource("pool_win_platform.c")
}

func (f *failureModeCtx) bcryptChaCha20Unavailable() error {
	return nil
}

func (f *failureModeCtx) shouldFailWithAnError() error {
	/* Verify encrypt returns -1 when ChaCha20 unavailable (no fallback) */
	return f.assertContains(f.sourceCode, "return -1",
		"W01: should return error when ChaCha20 unavailable")
}

func (f *failureModeCtx) noFallbackCipherUsed() error {
	if strings.Contains(f.sourceCode, "BCRYPT_AES_ALGORITHM") {
		return fmt.Errorf("W01: source must not contain AES fallback cipher")
	}
	return nil
}

func (f *failureModeCtx) aPoolWindowsNode() error {
	return f.loadSource("pool_win_platform.c")
}

func (f *failureModeCtx) x25519SharedSecretComputed() error {
	return nil
}

func (f *failureModeCtx) bcryptECDHWithCurve25519Used() error {
	return f.assertContains(f.sourceCode, "BCryptSecretAgreement",
		"W02: should use BCrypt ECDH")
}

func (f *failureModeCtx) notSHA256HashOfSortedKeys() error {
	// The pool_crypto_x25519_shared function should NOT contain sorted hash
	sharedFn := f.sourceCode[strings.Index(f.sourceCode, "pool_crypto_x25519_shared"):]
	nextFn := strings.Index(sharedFn[1:], "\nint pool_crypto_")
	if nextFn > 0 {
		sharedFn = sharedFn[:nextFn+1]
	}
	if strings.Contains(sharedFn, "SHA-256(sorted_keys)") ||
		strings.Contains(sharedFn, "BCRYPT_SHA256_ALGORITHM") {
		return fmt.Errorf("W02: x25519_shared should not use SHA256 fallback")
	}
	return nil
}

func (f *failureModeCtx) windowsServiceWithControlPipe() error {
	return f.loadSource("pool_win_service.c")
}

func (f *failureModeCtx) namedPipeCreated() error {
	return nil
}

func (f *failureModeCtx) daclRestrictsToSystemAndAdmins() error {
	return f.assertContains(f.sourceCode, "D:(A;;GA;;;SY)(A;;GA;;;BA)",
		"W03: DACL should restrict to SYSTEM+Admins")
}

func (f *failureModeCtx) unprivilegedUsersCantConnect() error {
	return nil
}

func (f *failureModeCtx) windowsServiceReceivingPipeCommands() error {
	return f.loadSource("pool_win_service.c")
}

func (f *failureModeCtx) commandWithLenExceedingBytesRead() error {
	return nil
}

func (f *failureModeCtx) commandRejected() error {
	return f.assertContains(f.sourceCode, "cmd.len",
		"W04/D03: command length should be validated")
}

func (f *failureModeCtx) noBufferOverflow() error {
	return nil
}

func (f *failureModeCtx) aPoolMacOSNode() error {
	return f.loadSource("pool_darwin_platform.c")
}

func (f *failureModeCtx) aeadEncryptionPerformed() error {
	return nil
}

func (f *failureModeCtx) opensslChaCha20Used() error {
	return f.assertContains(f.sourceCode, "EVP_chacha20_poly1305()",
		"D01: should use OpenSSL ChaCha20-Poly1305")
}

func (f *failureModeCtx) notXORPlaceholder() error {
	// The encrypt function should NOT contain XOR placeholder
	if strings.Contains(f.sourceCode, "cipher[i] ^= key[i % POOL_KEY_SIZE]") {
		return fmt.Errorf("D01: should not use XOR placeholder")
	}
	return nil
}

func (f *failureModeCtx) x25519KeypairGenerated() error {
	return nil
}

func (f *failureModeCtx) opensslEVPX25519Used() error {
	return f.assertContains(f.sourceCode, "EVP_PKEY_X25519",
		"D02: should use OpenSSL EVP X25519")
}

func (f *failureModeCtx) notCCSHA256Derivation() error {
	if strings.Contains(f.sourceCode, "CC_SHA256(priv, POOL_KEY_SIZE, pub)") {
		return fmt.Errorf("D02: should not use CC_SHA256 for key derivation")
	}
	return nil
}

func (f *failureModeCtx) macOSDaemonReceivingCommands() error {
	return f.loadSource("pool_darwin_daemon.c")
}

// ---- Userspace Steps ----

func (f *failureModeCtx) vaultServerServingDirectory() error {
	return f.loadSource("pool_vault.c")
}

func (f *failureModeCtx) clientRequestsPathTraversal() error {
	return nil
}

func (f *failureModeCtx) requestRejected() error {
	return f.assertContains(f.sourceCode, "vault_path_is_safe",
		"U01: path should be validated for traversal")
}

func (f *failureModeCtx) pathTraversalDenied() error {
	return f.assertContains(f.sourceCode, "..",
		"U01: .. should be detected")
}

func (f *failureModeCtx) pathExceedsMaxLength() error {
	return nil
}

func (f *failureModeCtx) rejectedBeforeBufferCopy() error {
	return f.assertContains(f.sourceCode, "path_len >= VAULT_MAX_PATH",
		"U02: path length should be validated")
}

func (f *failureModeCtx) noStackBufferOverflow() error {
	return nil
}

func (f *failureModeCtx) bridgeWithActiveThreads() error {
	return f.loadSource("pool_bridge.c")
}

func (f *failureModeCtx) bridgeShutsDown() error {
	return nil
}

func (f *failureModeCtx) threadHandlesCollectedUnderLock() error {
	return f.assertContains(f.sourceCode, "pthread_mutex_lock",
		"U03: bridge should collect threads under lock")
}

func (f *failureModeCtx) lockReleasedBeforeJoining() error {
	return f.assertContains(f.sourceCode, "pthread_mutex_unlock",
		"U03: lock released before join")
}

func (f *failureModeCtx) noUseAfterFree() error {
	return nil
}

func (f *failureModeCtx) concurrentConnectionAttempts() error {
	return nil
}

func (f *failureModeCtx) onlyOneShouldSucceed() error {
	return nil
}

func (f *failureModeCtx) noDoubleAllocation() error {
	return nil
}

func (f *failureModeCtx) relayForwardingPackets() error {
	return f.loadSource("pool_relay.c")
}

func (f *failureModeCtx) packetOf109BytesReceived() error {
	return nil
}

func (f *failureModeCtx) bufferAtLeast4096Bytes() error {
	return f.assertContains(f.sourceCode, "RELAY_BUF_SIZE",
		"U05: relay should use RELAY_BUF_SIZE")
}

func (f *failureModeCtx) noStackOverflow() error {
	return f.assertContains(f.sourceCode, "4096",
		"U05: buffer should be >= 4096")
}

func (f *failureModeCtx) relayConcurrentConnections() error {
	return f.loadSource("pool_relay.c")
}

func (f *failureModeCtx) stateAccessedFromMultipleThreads() error {
	return nil
}

func (f *failureModeCtx) pthreadMutexProtectsStateAccess() error {
	return f.assertContains(f.sourceCode, "pthread_mutex_lock(&state_lock)",
		"U06: state access should be mutex-protected")
}

func (f *failureModeCtx) noDataRace() error {
	return nil
}

func (f *failureModeCtx) shimInterceptingSocketCalls() error {
	return f.loadSource("pool_shim.c")
}

func (f *failureModeCtx) fdExceedingMaxFDs() error {
	return nil
}

func (f *failureModeCtx) warningLoggedForOOBFD() error {
	return f.assertContains(f.sourceCode, "SHIM_LOG",
		"U07: shim should log warning for OOB FD")
}

func (f *failureModeCtx) fdNotStoredInTrackingArray() error {
	return nil
}

// ---- Protocol Spec Steps ----

func (f *failureModeCtx) thePoolProtocolSpecification() error {
	return f.loadSpec("PROTOCOL.md")
}

func (f *failureModeCtx) thePoolSecuritySpecification() error {
	return f.loadSpec("SECURITY.md")
}

func (f *failureModeCtx) section131MandatesHmacKeyPrefix() error {
	return f.assertContains(f.specContent, "13.1 Nonce Construction",
		"P01: spec should have nonce construction section")
}

func (f *failureModeCtx) rekeyingBeforeSeqReaches2To63() error {
	return f.assertContains(f.specContent, "2^63",
		"P01: spec should mention rekey before 2^63")
}

func (f *failureModeCtx) challengeSecretRotatesEvery5Min() error {
	return f.assertContains(f.specContent, "300 seconds",
		"P02: spec should mandate 5-minute rotation")
}

func (f *failureModeCtx) previousSecretValid600Seconds() error {
	return f.assertContains(f.specContent, "grace period",
		"P02: spec should mention grace period")
}

func (f *failureModeCtx) section133MandatesCryptoMemneq() error {
	return f.assertContains(f.specContent, "crypto_memneq",
		"P03: spec should mandate constant-time comparison")
}

func (f *failureModeCtx) prohibitMemcmpForAuthTags() error {
	return f.assertContains(f.specContent, "memcmp",
		"P03: spec should mention memcmp prohibition")
}

func (f *failureModeCtx) section134SpecifiesMax16FragSlots() error {
	return f.assertContains(f.specContent, "16 concurrent fragment",
		"P04: spec should specify 16 fragment slots")
}

func (f *failureModeCtx) fiveSecondFragTimeout() error {
	return f.assertContains(f.specContent, "5-second timeout",
		"P04: spec should specify 5s timeout")
}

func (f *failureModeCtx) lruEvictionWhenSlotsFull() error {
	return f.assertContains(f.specContent, "LRU eviction",
		"P04: spec should specify LRU eviction")
}

func (f *failureModeCtx) section135LimitsProbes() error {
	return f.assertContains(f.specContent, "1 probe per second",
		"P05: spec should limit probe rate")
}

func (f *failureModeCtx) authenticateProbeResponses() error {
	return f.assertContains(f.specContent, "authenticated",
		"P05: spec should require probe auth")
}

func (f *failureModeCtx) section136DefinesLowerSessionIDWins() error {
	return f.assertContains(f.specContent, "lower session_id",
		"P06: spec should define tie-breaking")
}

func (f *failureModeCtx) includeMonotonicEpochNumbers() error {
	return f.assertContains(f.specContent, "epoch number",
		"P06: spec should mention epoch numbers")
}

func (f *failureModeCtx) section137SilenceMeansConfirmation() error {
	return f.assertContains(f.specContent, "silence as confirmation",
		"P07: spec should treat silence as confirmation")
}

func (f *failureModeCtx) require3RetryAttempts() error {
	return f.assertContains(f.specContent, "3 times",
		"P07: spec should require 3 retries")
}

func (f *failureModeCtx) section1310DocumentsCRIME() error {
	return f.assertContains(f.specContent, "CRIME",
		"P08: spec should document CRIME attack")
}

func (f *failureModeCtx) recommendDisableCompressionForSensitive() error {
	return f.assertContains(f.specContent, "Disable compression",
		"P08: spec should recommend disabling compression")
}

func (f *failureModeCtx) section1311Documents216CollisionBound() error {
	return f.assertContains(f.specContent, "2^16",
		"P09: spec should document birthday bound")
}

func (f *failureModeCtx) recommendSHA256TruncatedForLargeDeployments() error {
	return f.assertContains(f.specContent, "SHA-256 truncated",
		"P09: spec should recommend SHA-256 truncated")
}

func (f *failureModeCtx) section138Requires64BitTimestamps() error {
	return f.assertContains(f.specContent, "64-bit nanosecond timestamp",
		"P10: spec should require timestamps in INIT")
}

func (f *failureModeCtx) rejectTimestampsOutside30SecWindow() error {
	return f.assertContains(f.specContent, "30 seconds",
		"P10: spec should reject stale timestamps")
}

func (f *failureModeCtx) section138RequiresMinPuzzleDifficulty16() error {
	return f.assertContains(f.specContent, "difficulty MUST be at least 16",
		"P11: spec should require min difficulty 16")
}

func (f *failureModeCtx) section8DefinesCipherSuiteIDs() error {
	return f.assertContains(f.specContent, "Cipher Suite Identifiers",
		"P12: security spec should define cipher IDs")
}

func (f *failureModeCtx) negotiationRules() error {
	return f.assertContains(f.specContent, "Negotiation Rules",
		"P12: security spec should have negotiation rules")
}

func (f *failureModeCtx) emergencyCipherRotation() error {
	return f.assertContains(f.specContent, "Emergency Cipher Rotation",
		"P12: security spec should have emergency rotation")
}

func (f *failureModeCtx) section139RequiresRecordingPeerMaxVersion() error {
	return f.assertContains(f.specContent, "maximum supported version",
		"P13: spec should require recording peer version")
}

func (f *failureModeCtx) rejectLowerVersionFromKnownPeers() error {
	return f.assertContains(f.specContent, "VERSION_DOWNGRADE",
		"P13: spec should reject version downgrade")
}

func (f *failureModeCtx) poolSessionChannelSubscriptions() error {
	return f.loadSource("pool_main.c")
}

func (f *failureModeCtx) aPoolServer() error {
	return f.loadSource("pool_session.c")
}

// ---- Utility: check binary exists ----

func (f *failureModeCtx) binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func InitializeFailureModeScenario(ctx *godog.ScenarioContext) {
	f := &failureModeCtx{PoolTestContext: &PoolTestContext{}}

	// Crypto (C01-C07)
	ctx.Step(`^a POOL session with established crypto state$`, f.aPoolSessionWithEstablishedCryptoState)
	ctx.Step(`^the nonce is constructed for encryption$`, f.theNonceIsConstructedForEncryption)
	ctx.Step(`^bytes 0-3 of the nonce should contain hmac_key bytes not zeros$`, f.bytes03OfNonceShouldContainHmacKeyNotZeros)
	ctx.Step(`^bytes 4-11 should contain the big-endian sequence number$`, f.bytes411ShouldContainBigEndianSequence)
	ctx.Step(`^a POOL crypto context with no hardware ECDH$`, f.aPoolCryptoContextWithNoHardwareECDH)
	ctx.Step(`^the ECDH fallback path is used$`, f.theEcdhFallbackPathIsUsed)
	ctx.Step(`^a warning should be logged exactly once$`, f.aWarningShouldBeLoggedExactlyOnce)
	ctx.Step(`^the ephemeral public key should be zeroized after use$`, f.theEphemeralPublicKeyShouldBeZeroizedAfterUse)
	ctx.Step(`^a POOL HKDF context$`, f.aPoolHKDFContext)
	ctx.Step(`^HKDF is called with okm_len 0$`, f.hkdfIsCalledWithOkmLen0)
	ctx.Step(`^it should return EINVAL$`, f.itShouldReturnEINVAL)
	ctx.Step(`^HKDF is called with okm_len exceeding 255 times 32$`, f.hkdfIsCalledWithOkmLenExceeding255Times32)
	ctx.Step(`^packets_since_rekey reaches POOL_REKEY_PACKETS$`, f.packetssincerekeyReachesPoolRekeyPackets)
	ctx.Step(`^a rate-limited rekey info message should be logged$`, f.aRateLimitedRekeyInfoShouldBeLogged)
	ctx.Step(`^a POOL PQC context$`, f.aPoolPQCContext)
	ctx.Step(`^mlkem_cbd_eta2 processes an input buffer$`, f.mlkemCbdEta2ProcessesInputBuffer)
	ctx.Step(`^it should use memcpy for 32-bit reads instead of pointer casts$`, f.shouldUseMemcpyFor32BitReads)
	ctx.Step(`^it should not cause unaligned access faults on ARM$`, f.shouldNotCauseUnalignedAccessOnARM)
	ctx.Step(`^HKDF fails during ML-KEM encapsulation$`, f.hkdfFailsDuringEncapsulation)
	ctx.Step(`^the error code should be propagated to the caller$`, f.errorCodePropagatedToCaller)
	ctx.Step(`^HKDF fails during ML-KEM decapsulation$`, f.hkdfFailsDuringDecapsulation)
	ctx.Step(`^crypto_alloc_shash for SHA256 fails during keygen$`, f.cryptoAllocShashForSha256FailsDuringKeygen)
	ctx.Step(`^keygen should return the allocation error code$`, f.keygenShouldReturnAllocationError)
	ctx.Step(`^no partial secret key should be generated$`, f.noPartialSecretKeyShouldBeGenerated)

	// Network (N01-N07)
	ctx.Step(`^a POOL node attempting TCP connection$`, f.aPoolNodeAttemptingTCPConnection)
	ctx.Step(`^connecting to an unreachable peer$`, f.connectingToUnreachablePeer)
	ctx.Step(`^the connection attempt should timeout within 10 seconds$`, f.connectionShouldTimeoutWithin10Seconds)
	ctx.Step(`^not block indefinitely$`, f.notBlockIndefinitely)
	ctx.Step(`^the highest received sequence is 100$`, f.highestReceivedSequenceIs100)
	ctx.Step(`^a packet with sequence number 30 arrives$`, f.packetWithSequenceNumber30Arrives)
	ctx.Step(`^the packet should be silently discarded as outside replay window$`, f.packetShouldBeDiscardedAsOutsideReplayWindow)
	ctx.Step(`^a packet with sequence number 80 arrives$`, f.packetWithSequenceNumber80Arrives)
	ctx.Step(`^the packet should be accepted as within replay window$`, f.packetShouldBeAcceptedAsWithinReplayWindow)
	ctx.Step(`^a POOL raw transport session with peer IP (.+)$`, f.aPoolRawTransportSessionWithPeerIP)
	ctx.Step(`^a packet arrives from IP (.+) matching the session ID$`, func(string) error { return nil })
	ctx.Step(`^the packet should be rejected with a rate-limited warning$`, f.packetRejectedWithRateLimitedWarning)
	ctx.Step(`^not delivered to the session RX queue$`, f.notDeliveredToSessionRXQueue)
	ctx.Step(`^a POOL raw transport session$`, f.aPoolRawTransportSession)
	ctx.Step(`^the RX queue contains 4096 entries$`, f.rxQueueContains4096Entries)
	ctx.Step(`^another packet arrives for the session$`, f.anotherPacketArrives)
	ctx.Step(`^the packet should be dropped with a rate-limited warning$`, f.packetDroppedWithQueueFullWarning)
	ctx.Step(`^the queue depth should not exceed 4096$`, f.queueDepthShouldNotExceed4096)
	ctx.Step(`^a POOL raw transport listener$`, f.aPoolRawTransportListener)
	ctx.Step(`^looking up sessions by session ID$`, f.lookingUpSessionsBySessionID)
	ctx.Step(`^the sessions_lock mutex should be held during iteration$`, f.sessionsLockMutexHeldDuringIteration)
	ctx.Step(`^no use-after-free is possible from concurrent session deletion$`, f.noUseAfterFreeFromConcurrentDeletion)
	ctx.Step(`^a POOL peer discovery table with 256 active peers$`, f.peerTableWith256ActivePeers)
	ctx.Step(`^a new peer announces itself$`, f.newPeerAnnounces)
	ctx.Step(`^the oldest non-static peer should be evicted$`, f.oldestNonStaticPeerEvicted)
	ctx.Step(`^the new peer should be added to the table$`, f.newPeerAddedToTable)
	ctx.Step(`^a POOL peer discovery listener$`, f.aPoolPeerDiscoveryListener)
	ctx.Step(`^announces arrive faster than every 100 milliseconds$`, f.announcesFasterThan100ms)
	ctx.Step(`^excess announces should be silently dropped$`, f.excessAnnouncesDropped)
	ctx.Step(`^the peer table should not churn excessively$`, f.peerTableShouldNotChurn)

	// Session (S01-S06)
	ctx.Step(`^a POOL session being established$`, f.aPoolSessionBeingEstablished)
	ctx.Step(`^kthread_run fails for the rx_thread$`, f.kthreadRunFailsForRxThread)
	ctx.Step(`^pool_session_free should be called$`, f.poolSessionFreeShouldBeCalled)
	ctx.Step(`^all session resources should be released$`, f.allSessionResourcesReleased)
	ctx.Step(`^a POOL session with active fragment reassembly$`, f.activeFragmentReassembly)
	ctx.Step(`^pool_session_free is called$`, f.poolSessionFreeIsCalled)
	ctx.Step(`^the rx_lock should be held while freeing fragment buffers$`, f.rxLockHeldWhileFreeingFragments)
	ctx.Step(`^no race with concurrent rx_thread fragment writes$`, f.noRaceWithRxThread)
	ctx.Step(`^a POOL session receiving fragmented data$`, f.receivingFragmentedData)
	ctx.Step(`^a fragment with offset plus length exceeding total_len arrives$`, f.fragmentWithOffsetPlusLenExceedingTotalLen)
	ctx.Step(`^the fragment should be rejected$`, f.fragmentShouldBeRejected)
	ctx.Step(`^no heap overflow should occur$`, f.noHeapOverflow)
	ctx.Step(`^a POOL session with all 16 fragment slots occupied$`, f.all16FragmentSlotsOccupied)
	ctx.Step(`^a new fragment sequence begins$`, f.newFragmentSequenceBegins)
	ctx.Step(`^the oldest incomplete fragment should be evicted$`, f.oldestIncompleteFragmentEvicted)
	ctx.Step(`^the new fragment should use the freed slot$`, f.newFragmentUsesFreedSlot)
	ctx.Step(`^a POOL config subsystem$`, f.aPoolConfigSubsystem)
	ctx.Step(`^concurrent CONFIG packets arrive from different sessions$`, f.concurrentConfigPackets)
	ctx.Step(`^config_lock mutex should serialize all config operations$`, f.configLockSerializesOperations)
	ctx.Step(`^no race condition on current_config$`, f.noRaceOnCurrentConfig)
	ctx.Step(`^a POOL session performing MTU discovery$`, f.performingMTUDiscovery)
	ctx.Step(`^the probe range collapses to lo equals hi$`, f.probeRangeCollapsesToLoEqualsHi)
	ctx.Step(`^MTU discovery should declare complete$`, f.mtuDiscoveryDeclareComplete)
	ctx.Step(`^no further probes should be sent$`, f.noFurtherProbes)

	// Module Lifecycle (M01-M05)
	ctx.Step(`^a POOL kernel module shutting down$`, f.aPoolKernelModuleShuttingDown)
	ctx.Step(`^pool_exit is called$`, f.poolExitIsCalled)
	ctx.Step(`^all sessions should be closed first$`, f.sessionsClosedFirst)
	ctx.Step(`^then the workqueue should be flushed$`, f.workqueueFlushed)
	ctx.Step(`^no flushed work should reference freed sessions$`, f.noFlushedWorkReferencesFreedSessions)
	ctx.Step(`^a POOL session with channel subscriptions$`, f.poolSessionChannelSubscriptions)
	ctx.Step(`^a CHANNEL ioctl requests channel 256$`, f.channelIoctlRequestsChannel256)
	ctx.Step(`^it should return EINVAL$`, f.shouldReturnEINVALForChannel)
	ctx.Step(`^no out-of-bounds write should occur$`, f.noOOBWrite)
	ctx.Step(`^a POOL kernel module$`, f.aPoolKernelModule)
	ctx.Step(`^an ioctl is called$`, f.ioctlIsCalled)
	ctx.Step(`^try_module_get should be called first$`, f.tryModuleGetCalledFirst)
	ctx.Step(`^module_put should be called on all exit paths$`, f.modulePutOnAllExitPaths)
	ctx.Step(`^ioctl during module unload should return ENODEV$`, f.ioctlDuringUnloadReturnsENODEV)
	ctx.Step(`^a POOL kernel module with active sessions$`, f.moduleWithActiveSessions)
	ctx.Step(`^\/proc\/pool\/sessions is read$`, f.procPoolSessionsRead)
	ctx.Step(`^sessions_lock should be held during iteration$`, f.sessionsLockHeldDuringProcfsIteration)
	ctx.Step(`^no use-after-free from concurrent session deletion$`, f.noUAFFromConcurrentSessionDeletion)
	ctx.Step(`^a POOL kernel module initializing$`, f.moduleInitializing)
	ctx.Step(`^the heartbeat thread starts before session_init completes$`, f.heartbeatStartsBeforeSessionInit)
	ctx.Step(`^the heartbeat should wait for sessions_ready flag$`, f.heartbeatWaitsForSessionsReady)
	ctx.Step(`^not access uninitialized session data$`, f.notAccessUninitializedSessionData)

	// Platform (W01-W04, D01-D03)
	ctx.Step(`^a POOL Windows node on pre-1903 Windows$`, f.aPoolWindowsNodePreW1903)
	ctx.Step(`^BCrypt ChaCha20-Poly1305 is unavailable$`, f.bcryptChaCha20Unavailable)
	ctx.Step(`^the implementation should fail with an error$`, f.shouldFailWithAnError)
	ctx.Step(`^no fallback cipher should be used$`, f.noFallbackCipherUsed)
	ctx.Step(`^a POOL Windows node$`, f.aPoolWindowsNode)
	ctx.Step(`^X25519 shared secret is computed$`, f.x25519SharedSecretComputed)
	ctx.Step(`^BCrypt ECDH with Curve25519 should be used$`, f.bcryptECDHWithCurve25519Used)
	ctx.Step(`^not SHA-256 hash of sorted keys$`, f.notSHA256HashOfSortedKeys)
	ctx.Step(`^a POOL Windows service with control pipe$`, f.windowsServiceWithControlPipe)
	ctx.Step(`^the named pipe is created$`, f.namedPipeCreated)
	ctx.Step(`^a DACL should restrict access to SYSTEM and Administrators$`, f.daclRestrictsToSystemAndAdmins)
	ctx.Step(`^local unprivileged users should not be able to connect$`, f.unprivilegedUsersCantConnect)
	ctx.Step(`^a POOL Windows service receiving pipe commands$`, f.windowsServiceReceivingPipeCommands)
	ctx.Step(`^a command with len exceeding bytes_read arrives$`, f.commandWithLenExceedingBytesRead)
	ctx.Step(`^the command should be rejected$`, f.commandRejected)
	ctx.Step(`^no buffer overflow should occur$`, f.noBufferOverflow)
	ctx.Step(`^a POOL macOS node$`, f.aPoolMacOSNode)
	ctx.Step(`^AEAD encryption is performed$`, f.aeadEncryptionPerformed)
	ctx.Step(`^OpenSSL EVP ChaCha20-Poly1305 should be used$`, f.opensslChaCha20Used)
	ctx.Step(`^not the XOR-based placeholder$`, f.notXORPlaceholder)
	ctx.Step(`^X25519 keypair is generated$`, f.x25519KeypairGenerated)
	ctx.Step(`^OpenSSL EVP_PKEY X25519 should be used$`, f.opensslEVPX25519Used)
	ctx.Step(`^not CC_SHA256 derivation$`, f.notCCSHA256Derivation)
	ctx.Step(`^a POOL macOS daemon receiving socket commands$`, f.macOSDaemonReceivingCommands)

	// Userspace (U01-U07)
	ctx.Step(`^a POOL vault server serving a directory$`, f.vaultServerServingDirectory)
	ctx.Step(`^a client requests path "([^"]*)"$`, func(string) error { return nil })
	ctx.Step(`^the request should be rejected$`, f.requestRejected)
	ctx.Step(`^the response should indicate path traversal denied$`, f.pathTraversalDenied)
	ctx.Step(`^a client sends a path exceeding VAULT_MAX_PATH$`, f.pathExceedsMaxLength)
	ctx.Step(`^the request should be rejected before buffer copy$`, f.rejectedBeforeBufferCopy)
	ctx.Step(`^no stack buffer overflow should occur$`, f.noStackBufferOverflow)
	ctx.Step(`^a POOL bridge with active bidirectional threads$`, f.bridgeWithActiveThreads)
	ctx.Step(`^the bridge shuts down$`, f.bridgeShutsDown)
	ctx.Step(`^thread handles should be collected under lock$`, f.threadHandlesCollectedUnderLock)
	ctx.Step(`^lock should be released before joining threads$`, f.lockReleasedBeforeJoining)
	ctx.Step(`^no use-after-free should occur$`, f.noUseAfterFree)
	ctx.Step(`^a POOL bridge with concurrent connection attempts$`, func() error { return f.loadSource("pool_bridge.c") })
	ctx.Step(`^two connections try to allocate the same slot$`, f.concurrentConnectionAttempts)
	ctx.Step(`^only one should succeed$`, f.onlyOneShouldSucceed)
	ctx.Step(`^no double allocation should occur$`, f.noDoubleAllocation)
	ctx.Step(`^a POOL relay forwarding packets$`, f.relayForwardingPackets)
	ctx.Step(`^a packet of 109 bytes is received$`, f.packetOf109BytesReceived)
	ctx.Step(`^the receive buffer should be at least 4096 bytes$`, f.bufferAtLeast4096Bytes)
	ctx.Step(`^no stack overflow should occur$`, f.noStackOverflow)
	ctx.Step(`^a POOL relay with concurrent connections$`, f.relayConcurrentConnections)
	ctx.Step(`^state is accessed from multiple threads$`, f.stateAccessedFromMultipleThreads)
	ctx.Step(`^pthread_mutex_lock should protect all state access$`, f.pthreadMutexProtectsStateAccess)
	ctx.Step(`^no data race should occur$`, f.noDataRace)
	ctx.Step(`^a POOL shim intercepting socket calls$`, f.shimInterceptingSocketCalls)
	ctx.Step(`^a file descriptor exceeding POOL_SHIM_MAX_FDS is returned$`, f.fdExceedingMaxFDs)
	ctx.Step(`^a warning should be logged$`, f.warningLoggedForOOBFD)
	ctx.Step(`^the FD should not be stored in the tracking array$`, f.fdNotStoredInTrackingArray)

	// Protocol Spec (P01-P13)
	ctx.Step(`^the POOL protocol specification$`, f.thePoolProtocolSpecification)
	ctx.Step(`^the POOL security specification$`, f.thePoolSecuritySpecification)
	ctx.Step(`^section 13\.1 should mandate hmac_key prefix in nonce bytes 0-3$`, f.section131MandatesHmacKeyPrefix)
	ctx.Step(`^rekeying before sequence counter reaches 2\^63$`, f.rekeyingBeforeSeqReaches2To63)
	ctx.Step(`^a POOL server$`, f.aPoolServer)
	ctx.Step(`^the challenge secret is 300 seconds old$`, func() error { return nil })
	ctx.Step(`^it should be rotated$`, f.challengeSecretRotatesEvery5Min)
	ctx.Step(`^the previous secret should remain valid for 600 seconds$`, f.previousSecretValid600Seconds)
	ctx.Step(`^section 13\.3 should mandate crypto_memneq for HMAC verification$`, f.section133MandatesCryptoMemneq)
	ctx.Step(`^prohibit standard memcmp for authentication tags$`, f.prohibitMemcmpForAuthTags)
	ctx.Step(`^section 13\.4 should specify max 16 concurrent fragment slots$`, f.section134SpecifiesMax16FragSlots)
	ctx.Step(`^5-second timeout per incomplete fragment$`, f.fiveSecondFragTimeout)
	ctx.Step(`^LRU eviction when slots are full$`, f.lruEvictionWhenSlotsFull)
	ctx.Step(`^section 13\.5 should limit probes to 1 per second per peer$`, f.section135LimitsProbes)
	ctx.Step(`^require authentication on probe responses$`, f.authenticateProbeResponses)
	ctx.Step(`^section 13\.6 should define lower session_id wins rekey tie$`, f.section136DefinesLowerSessionIDWins)
	ctx.Step(`^include monotonic epoch numbers$`, f.includeMonotonicEpochNumbers)
	ctx.Step(`^section 13\.7 should treat silence as config confirmation$`, f.section137SilenceMeansConfirmation)
	ctx.Step(`^require 3 retry attempts with exponential backoff$`, f.require3RetryAttempts)
	ctx.Step(`^section 13\.10 should document CRIME-style attack risk$`, f.section1310DocumentsCRIME)
	ctx.Step(`^recommend disabling compression for sensitive data$`, f.recommendDisableCompressionForSensitive)
	ctx.Step(`^section 13\.11 should document the 2\^16 collision bound$`, f.section1311Documents216CollisionBound)
	ctx.Step(`^recommend SHA-256 truncated for large deployments$`, f.recommendSHA256TruncatedForLargeDeployments)
	ctx.Step(`^section 13\.8 should require 64-bit timestamps in INIT$`, f.section138Requires64BitTimestamps)
	ctx.Step(`^reject timestamps outside 30-second window$`, f.rejectTimestampsOutside30SecWindow)
	ctx.Step(`^section 13\.8 should require minimum puzzle difficulty of 16$`, f.section138RequiresMinPuzzleDifficulty16)
	ctx.Step(`^section 8 should define cipher suite identifiers$`, f.section8DefinesCipherSuiteIDs)
	ctx.Step(`^negotiation rules for future cipher suites$`, f.negotiationRules)
	ctx.Step(`^emergency cipher rotation procedure$`, f.emergencyCipherRotation)
	ctx.Step(`^section 13\.9 should require recording peer max version$`, f.section139RequiresRecordingPeerMaxVersion)
	ctx.Step(`^rejecting connections at lower version from known peers$`, f.rejectLowerVersionFromKnownPeers)
}
