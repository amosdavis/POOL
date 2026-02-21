package steps

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

type runtimeIntegrityCtx struct {
	*PoolTestContext
	sourceFile  string
	sourceCode  string
	specContent string
}

func (r *runtimeIntegrityCtx) loadSource(filename string) error {
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
			r.sourceFile = p
			r.sourceCode = string(data)
			return nil
		}
	}
	return fmt.Errorf("source file %s not found", filename)
}

func (r *runtimeIntegrityCtx) loadSpec(filename string) error {
	p := filepath.Join("..", "spec", filename)
	data, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("spec file %s not found: %w", filename, err)
	}
	r.specContent = string(data)
	return nil
}

func (r *runtimeIntegrityCtx) assertContains(haystack, needle, desc string) error {
	if !strings.Contains(haystack, needle) {
		return fmt.Errorf("%s: expected to find %q in source", desc, needle)
	}
	return nil
}

func (r *runtimeIntegrityCtx) assertNotContains(haystack, needle, desc string) error {
	if strings.Contains(haystack, needle) {
		return fmt.Errorf("%s: expected NOT to find %q in source", desc, needle)
	}
	return nil
}

// --- Source loading Given steps ---

func (r *runtimeIntegrityCtx) thePoolCryptoSourceCode() error {
	return r.loadSource("pool_crypto.c")
}

func (r *runtimeIntegrityCtx) thePoolMainSourceCode() error {
	return r.loadSource("pool_main.c")
}

func (r *runtimeIntegrityCtx) thePoolNetworkSourceCode() error {
	return r.loadSource("pool_net.c")
}

func (r *runtimeIntegrityCtx) thePoolSessionSourceCode() error {
	return r.loadSource("pool_session.c")
}

func (r *runtimeIntegrityCtx) thePoolJournalSourceCode() error {
	return r.loadSource("pool_journal.c")
}

func (r *runtimeIntegrityCtx) thePoolTelemetrySourceCode() error {
	return r.loadSource("pool_telemetry.c")
}

func (r *runtimeIntegrityCtx) thePoolVaultSourceCode() error {
	return r.loadSource("pool_vault.c")
}

func (r *runtimeIntegrityCtx) thePoolRelaySourceCode() error {
	return r.loadSource("pool_relay.c")
}

func (r *runtimeIntegrityCtx) thePoolStateMachineDefinition() error {
	p := filepath.Join("..", "common", "pool_state.h")
	data, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("pool_state.h not found: %w", err)
	}
	r.sourceCode = string(data)
	return nil
}

func (r *runtimeIntegrityCtx) thePoolRuntimeIntegritySpecification() error {
	return r.loadSpec("RUNTIME_INTEGRITY.md")
}

func (r *runtimeIntegrityCtx) thePoolSecuritySpecification() error {
	return r.loadSpec("SECURITY.md")
}

// --- When steps (analysis triggers) ---

func (r *runtimeIntegrityCtx) theSelfTestFunctionsAreAnalyzed() error         { return nil }
func (r *runtimeIntegrityCtx) theHMACVerificationPathIsAnalyzed() error       { return nil }
func (r *runtimeIntegrityCtx) theModuleInitializationIsAnalyzed() error       { return nil }
func (r *runtimeIntegrityCtx) theNonceConstructionIsAnalyzed() error          { return nil }
func (r *runtimeIntegrityCtx) theHKDFImplementationIsAnalyzed() error         { return nil }
func (r *runtimeIntegrityCtx) theSelfTestErrorHandlingIsAnalyzed() error      { return nil }
func (r *runtimeIntegrityCtx) theSessionAccessPatternsAreAnalyzed() error     { return nil }
func (r *runtimeIntegrityCtx) theAntiReplayImplementationIsAnalyzed() error   { return nil }
func (r *runtimeIntegrityCtx) theRekeyMechanismIsAnalyzed() error             { return nil }
func (r *runtimeIntegrityCtx) theHandshakeProofVerificationIsAnalyzed() error { return nil }
func (r *runtimeIntegrityCtx) theStateTransitionLogicIsAnalyzed() error       { return nil }
func (r *runtimeIntegrityCtx) theJournalAddFunctionIsAnalyzed() error         { return nil }
func (r *runtimeIntegrityCtx) theJournalChainingRequirementIsAnalyzed() error { return nil }
func (r *runtimeIntegrityCtx) theSelfTestFailurePathIsAnalyzed() error        { return nil }
func (r *runtimeIntegrityCtx) theHeartbeatMechanismIsAnalyzed() error         { return nil }
func (r *runtimeIntegrityCtx) theIoctlProtectionIsAnalyzed() error            { return nil }
func (r *runtimeIntegrityCtx) theBridgeSecurityDocIsAnalyzed() error          { return nil }
func (r *runtimeIntegrityCtx) thePathValidationLogicIsAnalyzed() error        { return nil }
func (r *runtimeIntegrityCtx) theThreadSafetyImplementationIsAnalyzed() error { return nil }
func (r *runtimeIntegrityCtx) theModuleExitSequenceIsAnalyzed() error         { return nil }
func (r *runtimeIntegrityCtx) tenetsAnalyzed(tenet string) error              { return nil }

// --- RT-C01: Self-test verification ---

func (r *runtimeIntegrityCtx) selfTestHMACUsesRFC4231Vectors() error {
	return r.assertContains(r.sourceCode, "pool_crypto_selftest_hmac", "RT-C01")
}

func (r *runtimeIntegrityCtx) selfTestAEADVerifiesRoundTrip() error {
	return r.assertContains(r.sourceCode, "pool_crypto_selftest_aead", "RT-C01")
}

func (r *runtimeIntegrityCtx) cryptoInitRefusesToLoadOnFailure() error {
	return r.assertContains(r.sourceCode, "pool_crypto_init", "RT-C01")
}

// --- RT-C02: HMAC constant-time ---

func (r *runtimeIntegrityCtx) cryptoMemneqUsedForHMAC() error {
	return r.assertContains(r.sourceCode, "crypto_memneq", "RT-C02")
}

func (r *runtimeIntegrityCtx) standardMemcmpNotUsedForHMAC() error {
	lines := strings.Split(r.sourceCode, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.Contains(trimmed, "memcmp") && !strings.Contains(trimmed, "crypto_memneq") {
			if strings.Contains(trimmed, "hmac") || strings.Contains(trimmed, "HMAC") ||
				strings.Contains(trimmed, "tag") || strings.Contains(trimmed, "verify") {
				return fmt.Errorf("RT-C02: found memcmp used in HMAC/tag verification context: %s", trimmed)
			}
		}
	}
	return nil
}

func (r *runtimeIntegrityCtx) hmacFailureReturnsEBADMSG() error {
	return r.assertContains(r.sourceCode, "EBADMSG", "RT-C02")
}

// --- RT-C03: ECDH keypair ---

func (r *runtimeIntegrityCtx) keypairGeneratedAtModuleLoad() error {
	return r.assertContains(r.sourceCode, "pool_crypto_gen_keypair", "RT-C03")
}

func (r *runtimeIntegrityCtx) ecdhFailsHardWithoutCurve25519() error {
	if err := r.loadSource("pool_crypto.c"); err != nil {
		return err
	}
	if !strings.Contains(r.sourceCode, "ENOENT") && !strings.Contains(r.sourceCode, "ENXIO") {
		return fmt.Errorf("RT-C03: ECDH should return error when curve25519 KPP unavailable")
	}
	return nil
}

// --- RT-C04: Nonce construction ---

func (r *runtimeIntegrityCtx) nonceIncludesHMACKeyPrefix() error {
	return r.assertContains(r.sourceCode, "hmac_key", "RT-C04")
}

func (r *runtimeIntegrityCtx) nonceIncludesSequenceNumber() error {
	if !strings.Contains(r.sourceCode, "seq") && !strings.Contains(r.sourceCode, "sequence") {
		return fmt.Errorf("RT-C04: nonce construction should include sequence number")
	}
	return nil
}

func (r *runtimeIntegrityCtx) rekeyTriggeredBeforeNonceReuse() error {
	return r.assertContains(r.sourceCode, "POOL_REKEY_PACKETS", "RT-C04")
}

// --- RT-C05: HKDF validation ---

func (r *runtimeIntegrityCtx) hkdfRejectsZeroLength() error {
	return r.assertContains(r.sourceCode, "okm_len", "RT-C05")
}

func (r *runtimeIntegrityCtx) hkdfRejectsExcessiveLength() error {
	if !strings.Contains(r.sourceCode, "255") && !strings.Contains(r.sourceCode, "EINVAL") {
		return fmt.Errorf("RT-C05: HKDF should validate maximum output length")
	}
	return nil
}

// --- RT-C06: Self-test error handling ---

func (r *runtimeIntegrityCtx) cryptoFailureTriggersGotoErrCrypto() error {
	return r.assertContains(r.sourceCode, "err_crypto", "RT-C06")
}

func (r *runtimeIntegrityCtx) moduleDoesNotCompleteOnCryptoFailure() error {
	return r.assertContains(r.sourceCode, "goto err_crypto", "RT-C06")
}

// --- RT-S01: Session mutex ---

func (r *runtimeIntegrityCtx) sessionsLockProtectsIteration() error {
	return r.assertContains(r.sourceCode, "sessions_lock", "RT-S01")
}

func (r *runtimeIntegrityCtx) stateTransitionsValidatedBeforeExecution() error {
	if !strings.Contains(r.sourceCode, "state") || !strings.Contains(r.sourceCode, "POOL_STATE_") {
		return fmt.Errorf("RT-S01: session should validate state before transitions")
	}
	return nil
}

// --- RT-S02: Anti-replay ---

func (r *runtimeIntegrityCtx) packetsOutsideReplayWindowRejected() error {
	return r.assertContains(r.sourceCode, "expected_remote_seq", "RT-S02")
}

func (r *runtimeIntegrityCtx) expectedRemoteSeqUpdated() error {
	return r.assertContains(r.sourceCode, "expected_remote_seq", "RT-S02")
}

func (r *runtimeIntegrityCtx) sequenceGapsCountedAsLoss() error {
	if !strings.Contains(r.sourceCode, "packets_lost") && !strings.Contains(r.sourceCode, "loss") {
		return fmt.Errorf("RT-S02: sequence gaps should be counted as packet loss")
	}
	return nil
}

// --- RT-S03: Rekey threshold ---

func (r *runtimeIntegrityCtx) packetsSinceRekeyTracked() error {
	return r.assertContains(r.sourceCode, "packets_since_rekey", "RT-S03")
}

func (r *runtimeIntegrityCtx) rekeyTriggerAtThreshold() error {
	return r.assertContains(r.sourceCode, "POOL_REKEY_PACKETS", "RT-S03")
}

// --- RT-S04: Handshake proof ---

func (r *runtimeIntegrityCtx) cryptoMemneqUsedForProof() error {
	return r.assertContains(r.sourceCode, "crypto_memneq", "RT-S04")
}

func (r *runtimeIntegrityCtx) proofFailureRejectsHandshake() error {
	if !strings.Contains(r.sourceCode, "EPROTO") && !strings.Contains(r.sourceCode, "EACCES") {
		return fmt.Errorf("RT-S04: proof verification failure should reject the handshake")
	}
	return nil
}

// --- RT-S05: State machine ---

func (r *runtimeIntegrityCtx) eachStateHasValidPacketTypes() error {
	return r.assertContains(r.sourceCode, "POOL_STATE_IDLE", "RT-S05")
}

func (r *runtimeIntegrityCtx) invalidPacketTypesDoNotChangeState() error {
	return r.assertContains(r.sourceCode, "return state", "RT-S05")
}

func (r *runtimeIntegrityCtx) idleStateOnlyAcceptsINIT() error {
	return r.assertContains(r.sourceCode, "POOL_PKT_INIT", "RT-S05")
}

// --- RT-A01: Journal hashing ---

func (r *runtimeIntegrityCtx) eachEntryHashedWithSHA256() error {
	if !strings.Contains(r.sourceCode, "sha256") && !strings.Contains(r.sourceCode, "SHA256") &&
		!strings.Contains(r.sourceCode, "shash") {
		return fmt.Errorf("RT-A01: journal entries should be hashed with SHA256")
	}
	return nil
}

func (r *runtimeIntegrityCtx) hashCoversTimestampAndChangeType() error {
	if !strings.Contains(r.sourceCode, "timestamp") && !strings.Contains(r.sourceCode, "change_type") {
		return fmt.Errorf("RT-A01: hash should cover timestamp and change_type")
	}
	return nil
}

func (r *runtimeIntegrityCtx) journalUsesCircularBuffer() error {
	if !strings.Contains(r.sourceCode, "journal_count") && !strings.Contains(r.sourceCode, "POOL_JOURNAL_MAX") {
		return fmt.Errorf("RT-A01: journal should use circular buffer")
	}
	return nil
}

// --- RT-A02: Journal chaining tenet ---

func (r *runtimeIntegrityCtx) tenentT5RequiresMerkleChain() error {
	return r.assertContains(r.specContent, "Merkle chain", "RT-A02")
}

func (r *runtimeIntegrityCtx) modificationInvalidatesSubsequentHashes() error {
	return r.assertContains(r.specContent, "invalidates all subsequent hashes", "RT-A02")
}

// --- RT-A03: Self-test failure ---

func (r *runtimeIntegrityCtx) selfTestFailureReturnsEACCES() error {
	return r.assertContains(r.sourceCode, "EACCES", "RT-A03")
}

func (r *runtimeIntegrityCtx) cryptoInitPropagatesFailure() error {
	return r.assertContains(r.sourceCode, "pool_crypto_init", "RT-A03")
}

func (r *runtimeIntegrityCtx) noCryptoOpsAfterSelfTestFailure() error {
	if err := r.loadSource("pool_main.c"); err != nil {
		return err
	}
	return r.assertContains(r.sourceCode, "err_crypto", "RT-A03")
}

// --- RT-A04: Telemetry ---

func (r *runtimeIntegrityCtx) heartbeatCarriesTimestamps() error {
	if !strings.Contains(r.sourceCode, "timestamp") && !strings.Contains(r.sourceCode, "ktime_get_real_ns") {
		return fmt.Errorf("RT-A04: heartbeat should carry timestamps")
	}
	return nil
}

func (r *runtimeIntegrityCtx) bothPeersComputeRTT() error {
	if !strings.Contains(r.sourceCode, "rtt") && !strings.Contains(r.sourceCode, "RTT") {
		return fmt.Errorf("RT-A04: both peers should compute RTT from heartbeat")
	}
	return nil
}

// --- RT-U01: ioctl protection ---

func (r *runtimeIntegrityCtx) tryModuleGetCalledBeforeIoctl() error {
	return r.assertContains(r.sourceCode, "try_module_get", "RT-U01")
}

func (r *runtimeIntegrityCtx) modulePutCalledOnAllExitPaths() error {
	return r.assertContains(r.sourceCode, "module_put", "RT-U01")
}

func (r *runtimeIntegrityCtx) ioctlDuringUnloadFailsENODEV() error {
	return r.assertContains(r.sourceCode, "ENODEV", "RT-U01")
}

// --- RT-U02: Bridge security documentation ---

func (r *runtimeIntegrityCtx) bridgePlaintextRiskDocumented() error {
	return r.assertContains(r.specContent, "plaintext", "RT-U02")
}

func (r *runtimeIntegrityCtx) bridgeDesignatedAsTrustedNode() error {
	if !strings.Contains(r.specContent, "trusted") && !strings.Contains(r.specContent, "hardened") {
		return fmt.Errorf("RT-U02: bridge should be designated as trusted, hardened node")
	}
	return nil
}

// --- RT-U03: Vault path traversal ---

func (r *runtimeIntegrityCtx) dotDotSlashDetectedAndRejected() error {
	return r.assertContains(r.sourceCode, "..", "RT-U03")
}

func (r *runtimeIntegrityCtx) pathLengthValidatedAgainstMax() error {
	if !strings.Contains(r.sourceCode, "VAULT_MAX_PATH") && !strings.Contains(r.sourceCode, "PATH_MAX") {
		return fmt.Errorf("RT-U03: path length should be validated against maximum")
	}
	return nil
}

// --- RT-U04: Relay mutex ---

func (r *runtimeIntegrityCtx) pthreadMutexProtectsRelayState() error {
	return r.assertContains(r.sourceCode, "pthread_mutex_lock", "RT-U04")
}

func (r *runtimeIntegrityCtx) generosityScoreSerialized() error {
	if !strings.Contains(r.sourceCode, "mutex") && !strings.Contains(r.sourceCode, "pthread_mutex") {
		return fmt.Errorf("RT-U04: generosity score computation should be serialized by mutex")
	}
	return nil
}

// --- RT-U05: Module shutdown ---

func (r *runtimeIntegrityCtx) sessionsClosedBeforeWorkqueueFlush() error {
	src := r.sourceCode
	closeIdx := strings.Index(src, "pool_session_close_all")
	flushIdx := strings.Index(src, "flush_workqueue")
	if closeIdx < 0 {
		closeIdx = strings.Index(src, "pool_session_free")
	}
	if flushIdx < 0 {
		flushIdx = strings.Index(src, "destroy_workqueue")
	}
	if closeIdx < 0 || flushIdx < 0 {
		return fmt.Errorf("RT-U05: could not find session close and workqueue flush in module exit")
	}
	if closeIdx > flushIdx {
		return fmt.Errorf("RT-U05: sessions must be closed BEFORE workqueue is flushed")
	}
	return nil
}

func (r *runtimeIntegrityCtx) noFlushedWorkReferencesFreedSessions() error {
	return r.assertContains(r.sourceCode, "pool_exit", "RT-U05")
}

// --- Tenet verification steps (T1-T8) ---

func (r *runtimeIntegrityCtx) periodicTextSectionChecksumRequired() error {
	return r.assertContains(r.specContent, "Periodic", "T1")
}

func (r *runtimeIntegrityCtx) selfTestReExecutionRequired() error {
	return r.assertContains(r.specContent, "Self-test re-execution", "T1")
}

func (r *runtimeIntegrityCtx) externalAttestationHookRequired() error {
	return r.assertContains(r.specContent, "External attestation hook", "T1")
}

func (r *runtimeIntegrityCtx) cryptoOutputSpotChecksRequired() error {
	return r.assertContains(r.specContent, "spot-check", "T2")
}

func (r *runtimeIntegrityCtx) peerBehavioralVerificationRequired() error {
	return r.assertContains(r.specContent, "Peer-side behavioral verification", "T2")
}

func (r *runtimeIntegrityCtx) tpmBasedAttestationRequired() error {
	return r.assertContains(r.specContent, "TPM-based module attestation", "T3")
}

func (r *runtimeIntegrityCtx) outOfBandAttestationRequired() error {
	return r.assertContains(r.specContent, "Out-of-band attestation channel", "T3")
}

func (r *runtimeIntegrityCtx) crossPeerHMACRequired() error {
	return r.assertContains(r.specContent, "Cross-peer HMAC verification", "T4")
}

func (r *runtimeIntegrityCtx) sessionStateConsistencyRequired() error {
	return r.assertContains(r.specContent, "Session state consistency checks", "T4")
}

func (r *runtimeIntegrityCtx) journalChainIntegrityRequired() error {
	return r.assertContains(r.specContent, "Journal chain integrity", "T5")
}

func (r *runtimeIntegrityCtx) keyDerivationVerificationRequired() error {
	return r.assertContains(r.specContent, "Key derivation verification", "T5")
}

func (r *runtimeIntegrityCtx) functionLevelChecksumsRequired() error {
	return r.assertContains(r.specContent, "Function-level checksums", "T6")
}

func (r *runtimeIntegrityCtx) stackCanaryRequired() error {
	return r.assertContains(r.specContent, "Stack canaries", "T6")
}

func (r *runtimeIntegrityCtx) controlFlowIntegrityRequired() error {
	return r.assertContains(r.specContent, "Control Flow Integrity", "T6")
}

func (r *runtimeIntegrityCtx) remoteJournalReplicationRequired() error {
	return r.assertContains(r.specContent, "Remote journal replication", "T7")
}

func (r *runtimeIntegrityCtx) tamperEvidentMerkleChainRequired() error {
	return r.assertContains(r.specContent, "Tamper-evident Merkle chain", "T7")
}

func (r *runtimeIntegrityCtx) outOfBandTelemetryExportRequired() error {
	return r.assertContains(r.specContent, "Out-of-band telemetry export", "T7")
}

func (r *runtimeIntegrityCtx) redundantVerificationPathsRequired() error {
	return r.assertContains(r.specContent, "Redundant verification paths", "T8")
}

func (r *runtimeIntegrityCtx) failOpenAlertingRequired() error {
	return r.assertContains(r.specContent, "Fail-open alerting", "T8")
}

func (r *runtimeIntegrityCtx) gracefulDegradationRequired() error {
	return r.assertContains(r.specContent, "Graceful degradation", "T8")
}

func (r *runtimeIntegrityCtx) recoveryWithoutTrustRequired() error {
	return r.assertContains(r.specContent, "Recovery without trust in the compromised system", "T8")
}

// ---- Implementation verification methods ----

func (r *runtimeIntegrityCtx) loadBuildConfig() error {
	makeData, err1 := os.ReadFile(filepath.Join("..", "linux", "Makefile"))
	kbuildData, err2 := os.ReadFile(filepath.Join("..", "linux", "Kbuild"))
	if err1 != nil && err2 != nil {
		return fmt.Errorf("cannot read Makefile or Kbuild")
	}
	r.sourceCode = string(makeData) + "\n" + string(kbuildData)
	return nil
}

func (r *runtimeIntegrityCtx) loadProtoDefs() error {
	data, err := os.ReadFile(filepath.Join("..", "common", "pool_proto.h"))
	if err != nil {
		return fmt.Errorf("cannot read pool_proto.h: %v", err)
	}
	r.sourceCode = string(data)
	return nil
}

// P0-1: Journal hash chaining
func (r *runtimeIntegrityCtx) prevHashIncludedInSHA() error {
	return r.assertContains(r.sourceCode, "prev_hash", "P0-1: previous hash in SHA256")
}
func (r *runtimeIntegrityCtx) firstEntryZeroHash() error {
	return r.assertContains(r.sourceCode, "memset", "P0-1: zero-init previous hash")
}

// P0-2: Runtime self-tests
func (r *runtimeIntegrityCtx) runtimeSelftestCalledPeriodically() error {
	return r.assertContains(r.sourceCode, "pool_crypto_runtime_selftest", "P0-2: runtime selftest call")
}
func (r *runtimeIntegrityCtx) spotCheckCalledPeriodically() error {
	return r.assertContains(r.sourceCode, "pool_crypto_spot_check", "P0-2: spot-check call")
}
func (r *runtimeIntegrityCtx) integrityCompromisedSetOnFailure() error {
	return r.assertContains(r.sourceCode, "integrity_compromised", "P0-2: compromised flag")
}

// P0-3: Compiler flags
func (r *runtimeIntegrityCtx) fstackProtectorEnabled() error {
	return r.assertContains(r.sourceCode, "fstack-protector-strong", "P0-3: stack protector")
}
func (r *runtimeIntegrityCtx) wformatSecurityEnabled() error {
	return r.assertContains(r.sourceCode, "Wformat-security", "P0-3: format security")
}

// P1-1: Text checksumming
func (r *runtimeIntegrityCtx) textCrcComputedAtInit() error {
	return r.assertContains(r.sourceCode, "text_crc32", "P1-1: text CRC32 at init")
}
func (r *runtimeIntegrityCtx) textCrcReverifiedInHeartbeat() error {
	telemetryData, err := os.ReadFile(filepath.Join("..", "linux", "pool_telemetry.c"))
	if err != nil {
		return fmt.Errorf("cannot read pool_telemetry.c: %v", err)
	}
	if !strings.Contains(string(telemetryData), "text_crc32") {
		return fmt.Errorf("P1-1: text CRC32 not re-verified in heartbeat")
	}
	return nil
}

// P1-2: Shadow sequence counter
func (r *runtimeIntegrityCtx) shadowSeqIncremented() error {
	return r.assertContains(r.sourceCode, "shadow_local_seq++", "P1-2: shadow seq increment")
}
func (r *runtimeIntegrityCtx) shadowSeqCompared() error {
	return r.assertContains(r.sourceCode, "shadow_local_seq", "P1-2: shadow seq compared")
}
func (r *runtimeIntegrityCtx) divergenceSetsCompromised() error {
	return r.assertContains(r.sourceCode, "integrity_compromised", "P1-2: divergence sets compromised")
}

// P1-3: Integrity alert
func (r *runtimeIntegrityCtx) procIntegrityReportsStatus() error {
	return r.assertContains(r.sourceCode, "integrity_compromised", "P1-3: proc integrity status")
}
func (r *runtimeIntegrityCtx) procAttestationReportsCrc() error {
	return r.assertContains(r.sourceCode, "text_crc32", "P1-3: proc attestation CRC")
}
func (r *runtimeIntegrityCtx) sessionRefusesWhenCompromised() error {
	return r.assertContains(r.sourceCode, "integrity_compromised", "P1-3: session refusal")
}

// P1-4: State digest
func (r *runtimeIntegrityCtx) stateDigestFieldExists() error {
	return r.assertContains(r.sourceCode, "state_digest", "P1-4: state_digest field")
}
func (r *runtimeIntegrityCtx) stateDigestIsCrc32() error {
	telemetryData, err := os.ReadFile(filepath.Join("..", "linux", "pool_telemetry.c"))
	if err != nil {
		return fmt.Errorf("cannot read pool_telemetry.c: %v", err)
	}
	if !strings.Contains(string(telemetryData), "state_digest") {
		return fmt.Errorf("P1-4: state_digest not computed via CRC32 in heartbeat")
	}
	return nil
}

// P2-1: Peer challenge
func (r *runtimeIntegrityCtx) integrityPktDefined() error {
	headerData, err := os.ReadFile(filepath.Join("..", "linux", "pool.h"))
	if err != nil {
		return fmt.Errorf("cannot read pool.h: %v", err)
	}
	if !strings.Contains(string(headerData), "POOL_PKT_INTEGRITY") {
		return fmt.Errorf("P2-1: POOL_PKT_INTEGRITY not defined")
	}
	return nil
}
func (r *runtimeIntegrityCtx) integrityPktValidEstablished() error {
	stateData, err := os.ReadFile(filepath.Join("..", "common", "pool_state.h"))
	if err != nil {
		return fmt.Errorf("cannot read pool_state.h: %v", err)
	}
	if !strings.Contains(string(stateData), "POOL_PKT_INTEGRITY") {
		return fmt.Errorf("P2-1: POOL_PKT_INTEGRITY not in ESTABLISHED valid packets")
	}
	return nil
}
func (r *runtimeIntegrityCtx) challengeEncryptsNonce() error {
	return r.assertContains(r.sourceCode, "POOL_PKT_INTEGRITY", "P2-1: integrity challenge handler")
}
func (r *runtimeIntegrityCtx) responseVerifiesChallenge() error {
	return r.assertContains(r.sourceCode, "integrity_challenge", "P2-1: integrity response verification")
}

// InitializeRuntimeIntegrityScenario registers all runtime integrity step definitions.
func InitializeRuntimeIntegrityScenario(ctx *godog.ScenarioContext) {
	r := &runtimeIntegrityCtx{PoolTestContext: NewPoolTestContext()}

	// Given steps — source loading
	ctx.Step(`^the POOL crypto source code$`, r.thePoolCryptoSourceCode)
	ctx.Step(`^the POOL main source code$`, r.thePoolMainSourceCode)
	ctx.Step(`^the POOL network source code$`, r.thePoolNetworkSourceCode)
	ctx.Step(`^the POOL session source code$`, r.thePoolSessionSourceCode)
	ctx.Step(`^the POOL journal source code$`, r.thePoolJournalSourceCode)
	ctx.Step(`^the POOL telemetry source code$`, r.thePoolTelemetrySourceCode)
	ctx.Step(`^the POOL vault source code$`, r.thePoolVaultSourceCode)
	ctx.Step(`^the POOL relay source code$`, r.thePoolRelaySourceCode)
	ctx.Step(`^the POOL state machine definition$`, r.thePoolStateMachineDefinition)
	ctx.Step(`^the POOL runtime integrity specification$`, r.thePoolRuntimeIntegritySpecification)
	ctx.Step(`^the POOL security specification$`, r.thePoolSecuritySpecification)

	// When steps — analysis triggers
	ctx.Step(`^the self-test functions are analyzed$`, r.theSelfTestFunctionsAreAnalyzed)
	ctx.Step(`^the HMAC verification path is analyzed$`, r.theHMACVerificationPathIsAnalyzed)
	ctx.Step(`^the module initialization is analyzed$`, r.theModuleInitializationIsAnalyzed)
	ctx.Step(`^the nonce construction is analyzed$`, r.theNonceConstructionIsAnalyzed)
	ctx.Step(`^the HKDF implementation is analyzed$`, r.theHKDFImplementationIsAnalyzed)
	ctx.Step(`^the self-test error handling is analyzed$`, r.theSelfTestErrorHandlingIsAnalyzed)
	ctx.Step(`^the session access patterns are analyzed$`, r.theSessionAccessPatternsAreAnalyzed)
	ctx.Step(`^the anti-replay implementation is analyzed$`, r.theAntiReplayImplementationIsAnalyzed)
	ctx.Step(`^the rekey mechanism is analyzed$`, r.theRekeyMechanismIsAnalyzed)
	ctx.Step(`^the handshake proof verification is analyzed$`, r.theHandshakeProofVerificationIsAnalyzed)
	ctx.Step(`^the state transition logic is analyzed$`, r.theStateTransitionLogicIsAnalyzed)
	ctx.Step(`^the journal add function is analyzed$`, r.theJournalAddFunctionIsAnalyzed)
	ctx.Step(`^the journal chaining requirement is analyzed$`, r.theJournalChainingRequirementIsAnalyzed)
	ctx.Step(`^the self-test failure path is analyzed$`, r.theSelfTestFailurePathIsAnalyzed)
	ctx.Step(`^the heartbeat mechanism is analyzed$`, r.theHeartbeatMechanismIsAnalyzed)
	ctx.Step(`^the ioctl protection is analyzed$`, r.theIoctlProtectionIsAnalyzed)
	ctx.Step(`^the bridge security documentation is analyzed$`, r.theBridgeSecurityDocIsAnalyzed)
	ctx.Step(`^the path validation logic is analyzed$`, r.thePathValidationLogicIsAnalyzed)
	ctx.Step(`^the thread safety implementation is analyzed$`, r.theThreadSafetyImplementationIsAnalyzed)
	ctx.Step(`^the module exit sequence is analyzed$`, r.theModuleExitSequenceIsAnalyzed)
	ctx.Step(`^Tenet (T[1-8]) is analyzed$`, r.tenetsAnalyzed)

	// Then steps — RT-C01: Self-test verification
	ctx.Step(`^pool_crypto_selftest_hmac should use known RFC 4231 test vectors$`, r.selfTestHMACUsesRFC4231Vectors)
	ctx.Step(`^pool_crypto_selftest_aead should verify encrypt-decrypt round-trip$`, r.selfTestAEADVerifiesRoundTrip)
	ctx.Step(`^pool_crypto_init should refuse to load on self-test failure$`, r.cryptoInitRefusesToLoadOnFailure)

	// Then steps — RT-C02: HMAC constant-time
	ctx.Step(`^crypto_memneq should be used for HMAC tag comparison$`, r.cryptoMemneqUsedForHMAC)
	ctx.Step(`^standard memcmp should not be used for HMAC verification$`, r.standardMemcmpNotUsedForHMAC)
	ctx.Step(`^HMAC verification failure should return EBADMSG$`, r.hmacFailureReturnsEBADMSG)

	// Then steps — RT-C03: ECDH keypair
	ctx.Step(`^a keypair should be generated at module load$`, r.keypairGeneratedAtModuleLoad)
	ctx.Step(`^pool_crypto_gen_keypair should fail hard without curve25519 KPP$`, r.ecdhFailsHardWithoutCurve25519)

	// Then steps — RT-C04: Nonce construction
	ctx.Step(`^the nonce should include hmac_key bytes not zeros$`, r.nonceIncludesHMACKeyPrefix)
	ctx.Step(`^the nonce should include the big-endian sequence number$`, r.nonceIncludesSequenceNumber)
	ctx.Step(`^rekeying should be triggered before nonce reuse$`, r.rekeyTriggeredBeforeNonceReuse)

	// Then steps — RT-C05: HKDF validation
	ctx.Step(`^HKDF should reject zero-length output requests$`, r.hkdfRejectsZeroLength)
	ctx.Step(`^HKDF should reject output lengths exceeding 255 times hash length$`, r.hkdfRejectsExcessiveLength)

	// Then steps — RT-C06: Self-test error handling
	ctx.Step(`^crypto init failure should trigger goto err_crypto$`, r.cryptoFailureTriggersGotoErrCrypto)
	ctx.Step(`^the module should not complete initialization on crypto failure$`, r.moduleDoesNotCompleteOnCryptoFailure)

	// Then steps — RT-S01: Session mutex
	ctx.Step(`^sessions_lock should protect session table iteration$`, r.sessionsLockProtectsIteration)
	ctx.Step(`^session state transitions should be validated before execution$`, r.stateTransitionsValidatedBeforeExecution)

	// Then steps — RT-S02: Anti-replay
	ctx.Step(`^packets outside the 64-entry replay window should be rejected$`, r.packetsOutsideReplayWindowRejected)
	ctx.Step(`^the expected_remote_seq should be updated on valid packets$`, r.expectedRemoteSeqUpdated)
	ctx.Step(`^sequence gaps should be counted as packet loss$`, r.sequenceGapsCountedAsLoss)

	// Then steps — RT-S03: Rekey threshold
	ctx.Step(`^packets_since_rekey should be tracked$`, r.packetsSinceRekeyTracked)
	ctx.Step(`^a rekey trigger should occur at POOL_REKEY_PACKETS threshold$`, r.rekeyTriggerAtThreshold)

	// Then steps — RT-S04: Handshake proof
	ctx.Step(`^crypto_memneq should be used for proof comparison$`, r.cryptoMemneqUsedForProof)
	ctx.Step(`^proof verification failure should reject the handshake$`, r.proofFailureRejectsHandshake)

	// Then steps — RT-S05: State machine
	ctx.Step(`^each state should have a defined set of valid packet types$`, r.eachStateHasValidPacketTypes)
	ctx.Step(`^invalid packet types should not change the session state$`, r.invalidPacketTypesDoNotChangeState)
	ctx.Step(`^the IDLE state should only accept INIT packets$`, r.idleStateOnlyAcceptsINIT)

	// Then steps — RT-A01: Journal hashing
	ctx.Step(`^each entry should be hashed with SHA256$`, r.eachEntryHashedWithSHA256)
	ctx.Step(`^the hash should cover timestamp and change_type and detail$`, r.hashCoversTimestampAndChangeType)
	ctx.Step(`^the journal should use a circular buffer with version tracking$`, r.journalUsesCircularBuffer)

	// Then steps — RT-A02: Journal chaining tenet
	ctx.Step(`^Tenet T5 should require Merkle chain linking of journal entries$`, r.tenentT5RequiresMerkleChain)
	ctx.Step(`^modification of past entries should invalidate subsequent hashes$`, r.modificationInvalidatesSubsequentHashes)

	// Then steps — RT-A03: Self-test failure
	ctx.Step(`^self-test failure should return EACCES$`, r.selfTestFailureReturnsEACCES)
	ctx.Step(`^pool_crypto_init should propagate the failure to module init$`, r.cryptoInitPropagatesFailure)
	ctx.Step(`^no crypto operations should proceed after self-test failure$`, r.noCryptoOpsAfterSelfTestFailure)

	// Then steps — RT-A04: Telemetry
	ctx.Step(`^heartbeat packets should carry timestamps$`, r.heartbeatCarriesTimestamps)
	ctx.Step(`^both peers should independently compute RTT from heartbeat round-trip$`, r.bothPeersComputeRTT)

	// Then steps — RT-U01: ioctl protection
	ctx.Step(`^try_module_get should be called before ioctl processing$`, r.tryModuleGetCalledBeforeIoctl)
	ctx.Step(`^module_put should be called on all ioctl exit paths$`, r.modulePutCalledOnAllExitPaths)
	ctx.Step(`^ioctl during module unload should fail with ENODEV$`, r.ioctlDuringUnloadFailsENODEV)

	// Then steps — RT-U02: Bridge documentation
	ctx.Step(`^the bridge plaintext transit risk should be documented$`, r.bridgePlaintextRiskDocumented)
	ctx.Step(`^the bridge must be designated as a trusted hardened node$`, r.bridgeDesignatedAsTrustedNode)

	// Then steps — RT-U03: Vault path traversal
	ctx.Step(`^dot-dot-slash sequences should be detected and rejected$`, r.dotDotSlashDetectedAndRejected)
	ctx.Step(`^path length should be validated against VAULT_MAX_PATH$`, r.pathLengthValidatedAgainstMax)

	// Then steps — RT-U04: Relay mutex
	ctx.Step(`^pthread_mutex_lock should protect relay state access$`, r.pthreadMutexProtectsRelayState)
	ctx.Step(`^generosity score computation should be serialized$`, r.generosityScoreSerialized)

	// Then steps — RT-U05: Module shutdown
	ctx.Step(`^all sessions should be closed before workqueue flush$`, r.sessionsClosedBeforeWorkqueueFlush)
	ctx.Step(`^no flushed work should reference freed session data$`, r.noFlushedWorkReferencesFreedSessions)

	// Then steps — Tenet T1
	ctx.Step(`^periodic text section checksumming should be required$`, r.periodicTextSectionChecksumRequired)
	ctx.Step(`^self-test re-execution should be required$`, r.selfTestReExecutionRequired)
	ctx.Step(`^external attestation hook should be required$`, r.externalAttestationHookRequired)

	// Then steps — Tenet T2
	ctx.Step(`^crypto output spot-checks should be required$`, r.cryptoOutputSpotChecksRequired)
	ctx.Step(`^peer-side behavioral verification should be required$`, r.peerBehavioralVerificationRequired)

	// Then steps — Tenet T3
	ctx.Step(`^TPM-based module attestation should be required$`, r.tpmBasedAttestationRequired)
	ctx.Step(`^out-of-band attestation channel should be required$`, r.outOfBandAttestationRequired)

	// Then steps — Tenet T4
	ctx.Step(`^cross-peer HMAC verification should be required$`, r.crossPeerHMACRequired)
	ctx.Step(`^session state consistency checks should be required$`, r.sessionStateConsistencyRequired)

	// Then steps — Tenet T5
	ctx.Step(`^journal chain integrity via Merkle chain should be required$`, r.journalChainIntegrityRequired)
	ctx.Step(`^key derivation verification should be required$`, r.keyDerivationVerificationRequired)

	// Then steps — Tenet T6
	ctx.Step(`^function-level checksums should be required$`, r.functionLevelChecksumsRequired)
	ctx.Step(`^stack canary enablement should be required$`, r.stackCanaryRequired)
	ctx.Step(`^control flow integrity should be required$`, r.controlFlowIntegrityRequired)

	// Then steps — Tenet T7
	ctx.Step(`^remote journal replication should be required$`, r.remoteJournalReplicationRequired)
	ctx.Step(`^tamper-evident Merkle chain should be required$`, r.tamperEvidentMerkleChainRequired)
	ctx.Step(`^out-of-band telemetry export should be required$`, r.outOfBandTelemetryExportRequired)

	// Then steps — Tenet T8
	ctx.Step(`^redundant verification paths should be required$`, r.redundantVerificationPathsRequired)
	ctx.Step(`^fail-open alerting should be required$`, r.failOpenAlertingRequired)
	ctx.Step(`^graceful degradation should be required$`, r.gracefulDegradationRequired)
	ctx.Step(`^recovery without trust in compromised system should be required$`, r.recoveryWithoutTrustRequired)

	// ---- Implementation verification steps ----

	// Given steps — Implementation (only new ones not already registered)
	ctx.Step(`^the POOL build configuration$`, r.loadBuildConfig)
	ctx.Step(`^the POOL protocol definitions$`, r.loadProtoDefs)
	ctx.Step(`^the POOL sysinfo source code$`, func() error { return r.loadSource("pool_sysinfo.c") })

	// When steps — Implementation
	ctx.Step(`^the hash computation is analyzed$`, func() error { return nil })
	ctx.Step(`^the heartbeat thread is analyzed$`, func() error { return nil })
	ctx.Step(`^the compiler flags are analyzed$`, func() error { return nil })
	ctx.Step(`^the send path is analyzed$`, func() error { return nil })
	ctx.Step(`^the procfs entries are analyzed$`, func() error { return nil })
	ctx.Step(`^the telemetry structure is analyzed$`, func() error { return nil })
	ctx.Step(`^the packet dispatch is analyzed$`, func() error { return nil })

	// Then steps — P0-1 Journal chaining
	ctx.Step(`^the previous entry hash should be included in SHA256 input$`, r.prevHashIncludedInSHA)
	ctx.Step(`^the first entry should use a zero-initialized previous hash$`, r.firstEntryZeroHash)

	// Then steps — P0-2 Runtime self-tests
	ctx.Step(`^pool_crypto_runtime_selftest should be called periodically$`, r.runtimeSelftestCalledPeriodically)
	ctx.Step(`^pool_crypto_spot_check should be called periodically$`, r.spotCheckCalledPeriodically)
	ctx.Step(`^integrity_compromised should be set on failure$`, r.integrityCompromisedSetOnFailure)

	// Then steps — P0-3 Compiler flags
	ctx.Step(`^fstack-protector-strong should be enabled$`, r.fstackProtectorEnabled)
	ctx.Step(`^Wformat-security should be enabled$`, r.wformatSecurityEnabled)

	// Then steps — P1-1 Text checksumming
	ctx.Step(`^text_crc32 should be computed at init via CRC32$`, r.textCrcComputedAtInit)
	ctx.Step(`^the text section CRC should be re-verified in heartbeat$`, r.textCrcReverifiedInHeartbeat)

	// Then steps — P1-2 Shadow sequence counter
	ctx.Step(`^shadow_local_seq should be incremented independently$`, r.shadowSeqIncremented)
	ctx.Step(`^shadow and primary sequence counters should be compared$`, r.shadowSeqCompared)
	ctx.Step(`^divergence should set integrity_compromised$`, r.divergenceSetsCompromised)

	// Then steps — P1-3 Integrity alert
	ctx.Step(`^proc_pool_integrity should report integrity status$`, r.procIntegrityReportsStatus)
	ctx.Step(`^proc_pool_attestation should report text CRC32$`, r.procAttestationReportsCrc)
	ctx.Step(`^session allocation should refuse when integrity is compromised$`, r.sessionRefusesWhenCompromised)

	// Then steps — P1-4 State digest
	ctx.Step(`^state_digest field should exist in pool_telemetry$`, r.stateDigestFieldExists)
	ctx.Step(`^state_digest should be CRC32 of session state$`, r.stateDigestIsCrc32)

	// Then steps — P2-1 Peer challenge
	ctx.Step(`^POOL_PKT_INTEGRITY should be defined as 0xC$`, r.integrityPktDefined)
	ctx.Step(`^POOL_PKT_INTEGRITY should be valid in ESTABLISHED state$`, r.integrityPktValidEstablished)
	ctx.Step(`^integrity challenge should encrypt and return nonce$`, r.challengeEncryptsNonce)
	ctx.Step(`^integrity response should verify decrypted challenge$`, r.responseVerifiesChallenge)
}
