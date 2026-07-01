/**
 * chain-tx encoders + signing for native COSR chain transactions.
 *
 * These build the exact inner-transaction bytes the chain expects, then sign
 * them locally with your Ed25519 key. The signature travels to the bridge as
 * `chain_inner_sig_hex`; the bridge relays it to the chain verbatim and never
 * holds your private key. Encoder byte-output must match the chain's
 * transaction layout exactly — a single-byte divergence makes the chain reject
 * the signature.
 *
 * Transaction layout (u8 discriminant, then fields; all integers little-endian):
 *
 *   1  CapitalExit:     agent(32) | micro_cosr(u64) | nonce(u64)            = 49 B
 *   3  UpdateManifest:  agent(32) | len(u32) | manifest | nonce(u64)        = variable
 *   5  PostOffer:       seller(32) | offer(32) | category(u32) | slots(u32)
 *                          | min_price(u64) | nonce(u64)                    = 89 B
 *   6  PostBid:         buyer(32) | bid(32) | offer(32) | price(u64) | nonce = 113 B
 *   7  AcceptBid:       seller(32) | bid(32) | escrow(32) | price(u64) | nonce = 113 B
 *   8  SubmitDelivery:  seller(32) | escrow(32) | output_hash(32) | nonce   = 105 B
 *   9  Settle:          caller(32) | escrow(32) | nonce(u64)                = 73 B
 *  10  MarkDisputed:    escrow(32) | dispute(32) | filer(32) | nonce        = 105 B
 *  11  PartialRelease:  caller(32) | escrow(32) | released_micro(u64)
 *                          | refunded_micro(u64) | nonce(u64)               = 89 B
 *  12  Refund:          filer(32) | escrow(32) | nonce(u64)                 = 73 B
 *  13  Expire:          caller(32) | escrow(32) | nonce(u64)                = 73 B
 *
 * The encoders are pure functions; no I/O, no allocations beyond the returned
 * `Uint8Array`, no `process.env` dependencies. The test suite at
 * `tests/chain-tx-encoders.test.ts` asserts the exact byte layout per encoder
 * with deterministic sample params.
 *
 * Signing: `signChainTxLocal(innerBytes, privateKeySeed, chainId) -> 64-byte
 * sig` Ed25519-signs the chain-id-domain-separated pre-image (see
 * `signingPayload`) via `@noble/curves/ed25519`, binding the signature to one
 * network. Read `chainId` once from `platform_health.native_chain_id`.
 */

// @ts-ignore — @noble/curves resolves at runtime from the monorepo's platform/node_modules
import { ed25519 } from '@noble/curves/ed25519';
import { createHash } from 'node:crypto';

function sha256(data: Uint8Array): Uint8Array {
    return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * The Ed25519 signing pre-image with chain-id domain separation:
 * `sha256("setix-tx-v2" || chain_id) || inner`. Binds a signature to one
 * network so a signature made for a test network can never be replayed on
 * another. Your identity stays portable across networks; only the
 * authorization is network-scoped. `chain_id` is the chain's genesis id —
 * read it once from `platform_health.native_chain_id`. Must match the chain's
 * signing pre-image byte-for-byte.
 */
const B6_DOMAIN = new TextEncoder().encode('setix-tx-v2');
export function signingPayload(chainId: string, inner: Uint8Array): Uint8Array {
    const cid = new TextEncoder().encode(chainId);
    const pre = new Uint8Array(B6_DOMAIN.length + cid.length);
    pre.set(B6_DOMAIN, 0);
    pre.set(cid, B6_DOMAIN.length);
    const prefix = sha256(pre); // 32 bytes
    const out = new Uint8Array(32 + inner.length);
    out.set(prefix, 0);
    out.set(inner, 32);
    return out;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function writeU32LE(view: DataView, offset: number, value: number): void {
    view.setUint32(offset, value, true);
}

function writeU64LE(view: DataView, offset: number, value: bigint): void {
    view.setBigUint64(offset, value, true);
}

/** 16-byte little-endian u128 — the µCOSR price/amount width on the chain
 *  (must match the chain's transaction encoder byte-for-byte). */
function writeU128LE(view: DataView, offset: number, value: bigint): void {
    const mask = (1n << 64n) - 1n;
    view.setBigUint64(offset, value & mask, true);
    view.setBigUint64(offset + 8, (value >> 64n) & mask, true);
}

function copyBytes(dst: Uint8Array, src: Uint8Array, dstOffset: number, len: number): void {
    dst.set(src.subarray(0, len), dstOffset);
}

// ---------------------------------------------------------------------------
// Encoders
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
 *  poster(32) ‖ offer(32) ‖ category(u32 LE) ‖ slots(u32 LE)
 *  ‖ max_price(u128 LE) ‖ nonce(u64 LE) = 97 B (u128 price ceiling). */
export function encodePostOffer(
    posterId: Uint8Array,
    offerId: Uint8Array,
    categoryCode: number,
    slotsAvailable: number,
    maxPriceMicro: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(97);
    const view = new DataView(buf.buffer);
    buf[0] = 5;
    copyBytes(buf, posterId, 1, 32);
    copyBytes(buf, offerId, 33, 32);
    writeU32LE(view, 65, categoryCode);
    writeU32LE(view, 69, slotsAvailable);
    writeU128LE(view, 73, maxPriceMicro);
    writeU64LE(view, 89, nonce);
    return buf;
}

/** Variant 6 — PostBid:
 *  seller(32) ‖ bid(32) ‖ offer(32) ‖ price(u128 LE)
 *  ‖ quoted_latency_ms(u64 LE) ‖ nonce(u64 LE) = 129 B (u128 price). */
export function encodePostBid(
    sellerId: Uint8Array,
    bidId: Uint8Array,
    offerId: Uint8Array,
    quotedPriceMicro: bigint,
    quotedLatencyMs: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(129);
    const view = new DataView(buf.buffer);
    buf[0] = 6;
    copyBytes(buf, sellerId, 1, 32);
    copyBytes(buf, bidId, 33, 32);
    copyBytes(buf, offerId, 65, 32);
    writeU128LE(view, 97, quotedPriceMicro);
    writeU64LE(view, 113, quotedLatencyMs);
    writeU64LE(view, 121, nonce);
    return buf;
}

/** Variant 7 — AcceptBid:
 *  buyer(32) ‖ bid(32) ‖ escrow(32) ‖ price(u128 LE) ‖ nonce(u64 LE) = 121 B. */
export function encodeAcceptBid(
    buyerId: Uint8Array,
    bidId: Uint8Array,
    escrowId: Uint8Array,
    agreedPriceMicro: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(121);
    const view = new DataView(buf.buffer);
    buf[0] = 7;
    copyBytes(buf, buyerId, 1, 32);
    copyBytes(buf, bidId, 33, 32);
    copyBytes(buf, escrowId, 65, 32);
    writeU128LE(view, 97, agreedPriceMicro);
    writeU64LE(view, 113, nonce);
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
 *  caller(32) ‖ escrow(32) ‖ released_micro(u128 LE) ‖ refunded_micro(u128 LE)
 *  ‖ nonce(u64 LE) = 105 B (u128 amounts). */
export function encodePartialRelease(
    callerId: Uint8Array,
    escrowId: Uint8Array,
    releasedMicro: bigint,
    refundedMicro: bigint,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(105);
    const view = new DataView(buf.buffer);
    buf[0] = 11;
    copyBytes(buf, callerId, 1, 32);
    copyBytes(buf, escrowId, 33, 32);
    writeU128LE(view, 65, releasedMicro);
    writeU128LE(view, 81, refundedMicro);
    writeU64LE(view, 97, nonce);
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

/** Variant 13 — Expire: caller(32) | escrow(32) | nonce(u64 LE) = 73 B.
 *  The delivery deadline lives on the chain (stamped when the bid is
 *  accepted); the transaction carries no caller-supplied deadline. */
export function encodeExpire(
    callerId: Uint8Array,
    escrowId: Uint8Array,
    nonce: bigint,
): Uint8Array {
    const buf = new Uint8Array(73);
    const view = new DataView(buf.buffer);
    buf[0] = 13;
    copyBytes(buf, callerId, 1, 32);
    copyBytes(buf, escrowId, 33, 32);
    writeU64LE(view, 65, nonce);
    return buf;
}

// ---------------------------------------------------------------------------
// Signing helper
// ---------------------------------------------------------------------------

/**
 * Ed25519-sign the encoded chain inner bytes locally. Returns the 64-byte
 * signature that the SDK submits to the bridge via `chain_inner_sig_hex`.
 *
 * The signature is over the chain-id-domain-separated pre-image (see
 * `signingPayload`), not the raw inner bytes — this binds it to one network.
 * The bridge relays the signature to the chain verbatim; the chain is the
 * authoritative verifier, and your private key never leaves this process.
 */
export function signChainTxLocal(
    innerBytes: Uint8Array,
    privateKeySeed: Uint8Array,
    chainId: string,
): Uint8Array {
    if (privateKeySeed.byteLength !== 32) {
        throw new Error('signChainTxLocal: privateKeySeed must be 32 bytes (Ed25519 seed)');
    }
    if (!chainId) {
        throw new Error('signChainTxLocal: chainId required (read it from platform_health.native_chain_id)');
    }
    // Sign the chain-id-domain-separated pre-image, not the raw inner.
    return ed25519.sign(signingPayload(chainId, innerBytes), privateKeySeed);
}

/** Hex-encode the signature for transmission as `chain_inner_sig_hex`. */
export function signChainTxLocalHex(
    innerBytes: Uint8Array,
    privateKeySeed: Uint8Array,
    chainId: string,
): string {
    return Buffer.from(signChainTxLocal(innerBytes, privateKeySeed, chainId)).toString('hex');
}
