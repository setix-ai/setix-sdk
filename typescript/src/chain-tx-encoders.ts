/**
 * SDK chain-tx encoders — B.1.b M2 (ADR-2026-0224 D5+D6 + Founder Decision 2
 * 2026-05-18 "bridge-as-mailroom").
 *
 * 11 borsh encoders for native COSR chain inner transactions, byte-identical
 * to the bridge-side implementations in
 * `platform/src/platform/mcp-bridge/native-chain-tools.ts`. This file is the
 * SDK-side carve-out of Decision 2: the SDK must hold chain-tx encoders so
 * it can build + sign chain inners locally, then submit the resulting
 * `chain_inner_sig_hex` via the bridge-as-mailroom flow. Document signing
 * stays bridge-issued via `thread.build_doc` per ADR-0224 D6.
 *
 * Each function mirrors the borsh `ChainTx` enum discriminant + payload
 * layout pinned by the chain ABCI (`cosr-chain/src/tx.rs`):
 *
 *   1  CapitalExit:     agent(32) ‖ micro_cosr(u64 LE) ‖ nonce(u64 LE)       = 49 B
 *   3  UpdateManifest:  agent(32) ‖ vec4(manifest) ‖ nonce(u64 LE)           = variable
 *   5  PostOffer:       seller(32) ‖ offer(32) ‖ category(u32 LE) ‖ slots(u32 LE)
 *                          ‖ min_price(u64 LE) ‖ nonce(u64 LE)               = 89 B
 *   6  PostBid:         buyer(32) ‖ bid(32) ‖ offer(32) ‖ price(u64 LE) ‖ nonce = 113 B
 *   7  AcceptBid:       seller(32) ‖ bid(32) ‖ escrow(32) ‖ price(u64) ‖ nonce = 113 B
 *   8  SubmitDelivery:  seller(32) ‖ escrow(32) ‖ output_hash(32) ‖ nonce    = 105 B
 *   9  Settle:          caller(32) ‖ escrow(32) ‖ nonce(u64)                 = 73 B
 *  10  MarkDisputed:    escrow(32) ‖ dispute(32) ‖ filer(32) ‖ nonce         = 105 B
 *  11  PartialRelease:  caller(32) ‖ escrow(32) ‖ released_micro(u64)
 *                          ‖ refunded_micro(u64) ‖ nonce(u64)                = 89 B
 *  12  Refund:          filer(32) ‖ escrow(32) ‖ nonce(u64)                  = 73 B
 *  13  Expire:          caller(32) ‖ escrow(32) ‖ deadline_slot(u64) ‖ nonce = 81 B
 *
 * The encoders are pure functions; no I/O, no allocations beyond the
 * returned `Uint8Array`, no `process.env` dependencies. Encoder byte-output
 * MUST stay byte-equivalent to the bridge encoders — the test suite at
 * `tests/chain-tx-encoders.test.ts` asserts this invariant per encoder
 * with deterministic sample params.
 *
 * Signing helper: `signChainTxLocal(innerBytes, privateKey) → 64-byte sig`
 * Ed25519-signs the inner bytes via `@noble/curves/ed25519`. The bridge
 * forwards the signature verbatim to `submitChainTx` via the
 * `chain_inner_sig_hex` passthrough at every chain-tx endpoint that
 * accepted `secret_key_hex` pre-B.1.b.
 *
 * Cross-references:
 *   - ADR-2026-0224 D5+D6+D8+D14 — SDK thin-client carve-out for chain tx
 *   - ADR-2026-0228 Founder Decision 2 — bridge-as-mailroom pattern
 *   - platform/src/platform/mcp-bridge/native-chain-tools.ts — bridge twin
 *   - architecture/34b §11a — visa-class 8/8 items 3-5 (closes at B.1.b M5)
 */

// @ts-ignore — @noble/curves resolves at runtime from the monorepo's platform/node_modules
import { ed25519 } from '@noble/curves/ed25519';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function writeU32LE(view: DataView, offset: number, value: number): void {
    view.setUint32(offset, value, true);
}

function writeU64LE(view: DataView, offset: number, value: bigint): void {
    view.setBigUint64(offset, value, true);
}

function copyBytes(dst: Uint8Array, src: Uint8Array, dstOffset: number, len: number): void {
    dst.set(src.subarray(0, len), dstOffset);
}

// ---------------------------------------------------------------------------
// Encoders — byte-equivalent to native-chain-tools.ts
// ---------------------------------------------------------------------------

/** Variant 1 — CapitalExit: agent(32) ‖ micro_cosr(u64 LE) ‖ nonce(u64 LE). */
export function encodeCapitalExit(
    agent: Uint8Array,
    microCosr: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(49);
    const view = new DataView(buf.buffer);
    buf[0] = 1;
    copyBytes(buf, agent, 1, 32);
    writeU64LE(view, 33, microCosr);
    writeU64LE(view, 41, nonce);
    return buf;
}

/** Variant 3 — UpdateManifest: agent(32) ‖ vec4(manifest) ‖ nonce(u64 LE). */
export function encodeUpdateManifest(
    agentId: Uint8Array,
    manifestBytes: Uint8Array,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(1 + 32 + 4 + manifestBytes.length + 8);
    const view = new DataView(buf.buffer);
    buf[0] = 3;
    copyBytes(buf, agentId, 1, 32);
    writeU32LE(view, 33, manifestBytes.length);
    buf.set(manifestBytes, 37);
    writeU64LE(view, 37 + manifestBytes.length, nonce);
    return buf;
}

/** Variant 5 — PostOffer:
 *  seller(32) ‖ offer(32) ‖ category(u32 LE) ‖ slots(u32 LE)
 *  ‖ min_price(u64 LE) ‖ nonce(u64 LE) = 89 B. */
export function encodePostOffer(
    sellerId: Uint8Array,
    offerId: Uint8Array,
    categoryCode: number,
    slotsAvailable: number,
    minPriceMicro: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(89);
    const view = new DataView(buf.buffer);
    buf[0] = 5;
    copyBytes(buf, sellerId, 1, 32);
    copyBytes(buf, offerId, 33, 32);
    writeU32LE(view, 65, categoryCode);
    writeU32LE(view, 69, slotsAvailable);
    writeU64LE(view, 73, minPriceMicro);
    writeU64LE(view, 81, nonce);
    return buf;
}

/** Variant 6 — PostBid:
 *  buyer(32) ‖ bid(32) ‖ offer(32) ‖ price(u64 LE) ‖ nonce(u64 LE) = 113 B. */
export function encodePostBid(
    buyerId: Uint8Array,
    bidId: Uint8Array,
    offerId: Uint8Array,
    quotedPriceMicro: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(113);
    const view = new DataView(buf.buffer);
    buf[0] = 6;
    copyBytes(buf, buyerId, 1, 32);
    copyBytes(buf, bidId, 33, 32);
    copyBytes(buf, offerId, 65, 32);
    writeU64LE(view, 97, quotedPriceMicro);
    writeU64LE(view, 105, nonce);
    return buf;
}

/** Variant 7 — AcceptBid:
 *  seller(32) ‖ bid(32) ‖ escrow(32) ‖ price(u64 LE) ‖ nonce(u64 LE) = 113 B. */
export function encodeAcceptBid(
    sellerId: Uint8Array,
    bidId: Uint8Array,
    escrowId: Uint8Array,
    agreedPriceMicro: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(113);
    const view = new DataView(buf.buffer);
    buf[0] = 7;
    copyBytes(buf, sellerId, 1, 32);
    copyBytes(buf, bidId, 33, 32);
    copyBytes(buf, escrowId, 65, 32);
    writeU64LE(view, 97, agreedPriceMicro);
    writeU64LE(view, 105, nonce);
    return buf;
}

/** Variant 8 — SubmitDelivery:
 *  seller(32) ‖ escrow(32) ‖ output_hash(32) ‖ nonce(u64 LE) = 105 B. */
export function encodeSubmitDelivery(
    sellerId: Uint8Array,
    escrowId: Uint8Array,
    outputHash: Uint8Array,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(105);
    const view = new DataView(buf.buffer);
    buf[0] = 8;
    copyBytes(buf, sellerId, 1, 32);
    copyBytes(buf, escrowId, 33, 32);
    copyBytes(buf, outputHash, 65, 32);
    writeU64LE(view, 97, nonce);
    return buf;
}

/** Variant 9 — Settle: caller(32) ‖ escrow(32) ‖ nonce(u64 LE) = 73 B. */
export function encodeSettle(
    callerId: Uint8Array,
    escrowId: Uint8Array,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(73);
    const view = new DataView(buf.buffer);
    buf[0] = 9;
    copyBytes(buf, callerId, 1, 32);
    copyBytes(buf, escrowId, 33, 32);
    writeU64LE(view, 65, nonce);
    return buf;
}

/** Variant 10 — MarkDisputed:
 *  escrow(32) ‖ dispute(32) ‖ filer(32) ‖ nonce(u64 LE) = 105 B. */
export function encodeMarkDisputed(
    escrowId: Uint8Array,
    disputeId: Uint8Array,
    filerId: Uint8Array,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(105);
    const view = new DataView(buf.buffer);
    buf[0] = 10;
    copyBytes(buf, escrowId, 1, 32);
    copyBytes(buf, disputeId, 33, 32);
    copyBytes(buf, filerId, 65, 32);
    writeU64LE(view, 97, nonce);
    return buf;
}

/** Variant 11 — PartialRelease:
 *  caller(32) ‖ escrow(32) ‖ released_micro(u64 LE) ‖ refunded_micro(u64 LE)
 *  ‖ nonce(u64 LE) = 89 B. */
export function encodePartialRelease(
    callerId: Uint8Array,
    escrowId: Uint8Array,
    releasedMicro: bigint,
    refundedMicro: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(89);
    const view = new DataView(buf.buffer);
    buf[0] = 11;
    copyBytes(buf, callerId, 1, 32);
    copyBytes(buf, escrowId, 33, 32);
    writeU64LE(view, 65, releasedMicro);
    writeU64LE(view, 73, refundedMicro);
    writeU64LE(view, 81, nonce);
    return buf;
}

/** Variant 12 — Refund: filer(32) ‖ escrow(32) ‖ nonce(u64 LE) = 73 B. */
export function encodeRefund(
    filerId: Uint8Array,
    escrowId: Uint8Array,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(73);
    const view = new DataView(buf.buffer);
    buf[0] = 12;
    copyBytes(buf, filerId, 1, 32);
    copyBytes(buf, escrowId, 33, 32);
    writeU64LE(view, 65, nonce);
    return buf;
}

/** Variant 13 — Expire:
 *  caller(32) ‖ escrow(32) ‖ deadline_slot(u64 LE) ‖ nonce(u64 LE) = 81 B. */
export function encodeExpire(
    callerId: Uint8Array,
    escrowId: Uint8Array,
    deadlineSlot: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(81);
    const view = new DataView(buf.buffer);
    buf[0] = 13;
    copyBytes(buf, callerId, 1, 32);
    copyBytes(buf, escrowId, 33, 32);
    writeU64LE(view, 65, deadlineSlot);
    writeU64LE(view, 73, nonce);
    return buf;
}

// ---------------------------------------------------------------------------
// Signing helper
// ---------------------------------------------------------------------------

/**
 * Ed25519-sign the encoded chain inner bytes locally. Returns the 64-byte
 * signature that the SDK submits to the bridge via `chain_inner_sig_hex`.
 *
 * The bridge forwards the signature verbatim to `submitChainTx`; chain ABCI
 * is the authoritative verifier (the signed-tx wire format wraps the inner
 * bytes plus the 64-byte signature). Bridge-as-mailroom invariant intact —
 * the bridge never holds the agent's private key in passthrough mode.
 */
export function signChainTxLocal(
    innerBytes: Uint8Array,
    privateKeySeed: Uint8Array,
): Uint8Array {
    if (privateKeySeed.byteLength !== 32) {
        throw new Error('signChainTxLocal: privateKeySeed must be 32 bytes (Ed25519 seed)');
    }
    return ed25519.sign(innerBytes, privateKeySeed);
}

/** Hex-encode the signature for transmission as `chain_inner_sig_hex`. */
export function signChainTxLocalHex(
    innerBytes: Uint8Array,
    privateKeySeed: Uint8Array,
): string {
    return Buffer.from(signChainTxLocal(innerBytes, privateKeySeed)).toString('hex');
}
