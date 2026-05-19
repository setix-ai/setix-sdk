"""
SDK Python chain-tx encoders — B.1.b M4 (ADR-2026-0224 D5+D6 + Founder Decision
2 2026-05-18 "bridge-as-mailroom").

11 borsh encoders for native COSR chain inner transactions, byte-identical
to the bridge-side TypeScript implementations in
`platform/src/platform/mcp-bridge/native-chain-tools.ts` AND the SDK-side
TS encoders in `sdks/typescript/chain-tx-encoders.ts`. Cross-language
equivalence is asserted by the integration test pair
`sdks/typescript/tests/chain-tx-encoders.test.ts` +
`sdks/python/tests/test_chain_tx_encoders.py` — both encode the same
deterministic samples and compare bytes-hex.

Per ADR-2026-0228 Founder Decision 2 ("bridge-as-mailroom") and ADR-2026-0224
D5+D6: chain inner-tx bytes are NOT THREAD documents — they're native COSR
chain transactions. The SDK must hold these encoders client-side; the bridge
forwards `chain_inner_sig_hex` to chain ABCI without ever touching the
agent's private key.

ChainTx enum (borsh u8 discriminant, mirrors cosr-chain/src/tx.rs):
  1  CapitalExit:     agent(32) ‖ micro_cosr(u64 LE) ‖ nonce(u64 LE)            = 49 B
  3  UpdateManifest:  agent(32) ‖ vec4(manifest) ‖ nonce(u64 LE)                = variable
  5  PostOffer:       seller(32) ‖ offer(32) ‖ category(u32 LE) ‖ slots(u32 LE)
                         ‖ min_price(u64 LE) ‖ nonce(u64 LE)                    = 89 B
  6  PostBid:         buyer(32) ‖ bid(32) ‖ offer(32) ‖ price(u64) ‖ nonce      = 113 B
  7  AcceptBid:       seller(32) ‖ bid(32) ‖ escrow(32) ‖ price(u64) ‖ nonce    = 113 B
  8  SubmitDelivery:  seller(32) ‖ escrow(32) ‖ output_hash(32) ‖ nonce         = 105 B
  9  Settle:          caller(32) ‖ escrow(32) ‖ nonce(u64)                      = 73 B
 10  MarkDisputed:    escrow(32) ‖ dispute(32) ‖ filer(32) ‖ nonce              = 105 B
 11  PartialRelease:  caller(32) ‖ escrow(32) ‖ released_micro(u64)
                         ‖ refunded_micro(u64) ‖ nonce(u64)                     = 89 B
 12  Refund:          filer(32) ‖ escrow(32) ‖ nonce(u64)                       = 73 B
 13  Expire:          caller(32) ‖ escrow(32) ‖ deadline_slot(u64) ‖ nonce      = 81 B
"""

from __future__ import annotations

import struct

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "setix_thread.chain_tx_encoders requires cryptography: pip install cryptography"
    ) from e


def _require_32(name: str, b: bytes) -> bytes:
    if not isinstance(b, (bytes, bytearray)) or len(b) != 32:
        raise ValueError(f"{name} must be 32 bytes (got {len(b) if isinstance(b, (bytes, bytearray)) else type(b).__name__})")
    return bytes(b)


def encode_capital_exit(agent: bytes, micro_cosr: int, nonce: int) -> bytes:
    """Variant 1 — agent(32) ‖ micro_cosr(u64 LE) ‖ nonce(u64 LE)."""
    return b"\x01" + _require_32("agent", agent) + struct.pack("<QQ", micro_cosr, nonce)


def encode_update_manifest(agent_id: bytes, manifest_bytes: bytes, nonce: int) -> bytes:
    """Variant 3 — agent(32) ‖ vec4(manifest_bytes) ‖ nonce(u64 LE)."""
    agent_id = _require_32("agent_id", agent_id)
    return (
        b"\x03"
        + agent_id
        + struct.pack("<I", len(manifest_bytes))
        + bytes(manifest_bytes)
        + struct.pack("<Q", nonce)
    )


def encode_post_offer(
    seller_id: bytes,
    offer_id: bytes,
    category_code: int,
    slots_available: int,
    min_price_micro: int,
    nonce: int,
) -> bytes:
    """Variant 5 — seller(32) ‖ offer(32) ‖ category(u32 LE) ‖ slots(u32 LE)
    ‖ min_price(u64 LE) ‖ nonce(u64 LE) = 89 B."""
    return (
        b"\x05"
        + _require_32("seller_id", seller_id)
        + _require_32("offer_id", offer_id)
        + struct.pack("<IIQQ", category_code, slots_available, min_price_micro, nonce)
    )


def encode_post_bid(
    buyer_id: bytes,
    bid_id: bytes,
    offer_id: bytes,
    quoted_price_micro: int,
    nonce: int,
) -> bytes:
    """Variant 6 — buyer(32) ‖ bid(32) ‖ offer(32) ‖ price(u64) ‖ nonce(u64) = 113 B."""
    return (
        b"\x06"
        + _require_32("buyer_id", buyer_id)
        + _require_32("bid_id", bid_id)
        + _require_32("offer_id", offer_id)
        + struct.pack("<QQ", quoted_price_micro, nonce)
    )


def encode_accept_bid(
    seller_id: bytes,
    bid_id: bytes,
    escrow_id: bytes,
    agreed_price_micro: int,
    nonce: int,
) -> bytes:
    """Variant 7 — seller(32) ‖ bid(32) ‖ escrow(32) ‖ price(u64) ‖ nonce(u64) = 113 B."""
    return (
        b"\x07"
        + _require_32("seller_id", seller_id)
        + _require_32("bid_id", bid_id)
        + _require_32("escrow_id", escrow_id)
        + struct.pack("<QQ", agreed_price_micro, nonce)
    )


def encode_submit_delivery(
    seller_id: bytes,
    escrow_id: bytes,
    output_hash: bytes,
    nonce: int,
) -> bytes:
    """Variant 8 — seller(32) ‖ escrow(32) ‖ output_hash(32) ‖ nonce(u64) = 105 B."""
    return (
        b"\x08"
        + _require_32("seller_id", seller_id)
        + _require_32("escrow_id", escrow_id)
        + _require_32("output_hash", output_hash)
        + struct.pack("<Q", nonce)
    )


def encode_settle(caller_id: bytes, escrow_id: bytes, nonce: int) -> bytes:
    """Variant 9 — caller(32) ‖ escrow(32) ‖ nonce(u64) = 73 B."""
    return (
        b"\x09"
        + _require_32("caller_id", caller_id)
        + _require_32("escrow_id", escrow_id)
        + struct.pack("<Q", nonce)
    )


def encode_mark_disputed(
    escrow_id: bytes,
    dispute_id: bytes,
    filer_id: bytes,
    nonce: int,
) -> bytes:
    """Variant 10 — escrow(32) ‖ dispute(32) ‖ filer(32) ‖ nonce(u64) = 105 B."""
    return (
        b"\x0a"
        + _require_32("escrow_id", escrow_id)
        + _require_32("dispute_id", dispute_id)
        + _require_32("filer_id", filer_id)
        + struct.pack("<Q", nonce)
    )


def encode_partial_release(
    caller_id: bytes,
    escrow_id: bytes,
    released_micro: int,
    refunded_micro: int,
    nonce: int,
) -> bytes:
    """Variant 11 — caller(32) ‖ escrow(32) ‖ released_micro(u64)
    ‖ refunded_micro(u64) ‖ nonce(u64) = 89 B."""
    return (
        b"\x0b"
        + _require_32("caller_id", caller_id)
        + _require_32("escrow_id", escrow_id)
        + struct.pack("<QQQ", released_micro, refunded_micro, nonce)
    )


def encode_refund(filer_id: bytes, escrow_id: bytes, nonce: int) -> bytes:
    """Variant 12 — filer(32) ‖ escrow(32) ‖ nonce(u64) = 73 B."""
    return (
        b"\x0c"
        + _require_32("filer_id", filer_id)
        + _require_32("escrow_id", escrow_id)
        + struct.pack("<Q", nonce)
    )


def encode_expire(
    caller_id: bytes,
    escrow_id: bytes,
    deadline_slot: int,
    nonce: int,
) -> bytes:
    """Variant 13 — caller(32) ‖ escrow(32) ‖ deadline_slot(u64) ‖ nonce(u64) = 81 B."""
    return (
        b"\x0d"
        + _require_32("caller_id", caller_id)
        + _require_32("escrow_id", escrow_id)
        + struct.pack("<QQ", deadline_slot, nonce)
    )


def sign_chain_tx_local(inner_bytes: bytes, sk: Ed25519PrivateKey) -> bytes:
    """Ed25519-sign the encoded chain inner bytes locally. Returns a 64-byte
    signature. The bridge forwards verbatim to chain ABCI via
    `chain_inner_sig_hex` — bridge-as-mailroom invariant intact (the SDK's
    private key never crosses the process boundary)."""
    return sk.sign(inner_bytes)


def sign_chain_tx_local_hex(inner_bytes: bytes, sk: Ed25519PrivateKey) -> str:
    """Hex-encoded variant of sign_chain_tx_local for `chain_inner_sig_hex`
    transmission."""
    return sign_chain_tx_local(inner_bytes, sk).hex()
