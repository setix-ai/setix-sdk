"""
chain_tx_encoders — borsh encoders + signing for native COSR chain transactions.

These build the exact inner-transaction bytes the chain expects, then sign them
locally with your Ed25519 key. The signature travels to the bridge as
``chain_inner_sig_hex``; the bridge relays it to the chain verbatim and never
holds your private key. Encoder byte-output must match the chain's transaction
layout exactly — a single-byte divergence makes the chain reject the signature.

Transaction layout (u8 discriminant, then fields; all integers little-endian).
µCOSR PRICE/amount fields are u128 (16 B), not u64 — the chain's transaction
encoder is the source of truth; these MUST match byte-for-byte or the chain
rejects the signature.
  1  CapitalExit:     agent(32) | micro_cosr(u128) | nonce(u64)                 = 57 B
  3  UpdateManifest:  agent(32) | len(u32) | manifest | nonce(u64)             = variable
  5  PostOffer:       poster(32) | offer(32) | category(u32) | slots(u32)
                         | max_price(u128) | nonce(u64)                         = 97 B
  6  PostBid:         seller(32) | bid(32) | offer(32) | price(u128)
                         | quoted_latency_ms(u64) | nonce(u64)                   = 129 B
  7  AcceptBid:       buyer(32) | bid(32) | escrow(32) | price(u128) | nonce    = 121 B
  8  SubmitDelivery:  seller(32) | escrow(32) | output_hash(32) | nonce(u64)    = 105 B
  9  Settle:          caller(32) | escrow(32) | nonce(u64)                      = 73 B
 10  FileDispute:     escrow(32) | dispute(32) | filer(32) | reason(u8)
                         | evidence_hash(32) | nonce(u64)                       = 138 B
                         (was MarkDisputed before the v5 chain)
 11  PartialRelease:  caller(32) | escrow(32) | released_micro(u128)
                         | refunded_micro(u128) | nonce(u64)                    = 105 B
 12  Refund:          filer(32) | escrow(32) | nonce(u64)                       = 73 B
 13  Expire:          caller(32) | escrow(32) | nonce(u64)                      = 73 B
 28  FileAppeal:      appellant(32) | escrow(32) | parent_dispute(32)
                         | appeal_dispute(32) | reason(u8) | evidence_hash(32)
                         | nonce(u64)  (§15.5 appeals; chain app_version >= 8) = 170 B

Signatures use chain-id domain separation (see ``signing_payload``): the
pre-image is ``sha256("setix-tx-v2" + chain_id) + inner``. This binds every
signature to one network, so a signature made for a test network can never be
replayed on another. Read ``chain_id`` once from the bridge's
``platform_health.native_chain_id``.

STALENESS NOTE (deliberate scope, v8 dispute turn 2026-07-06): this module
covers variants <= 13 plus 28 (FileAppeal, landed with the Rust golden vector
``file_appeal_borsh_golden_vector``). Other later variants (17 PokeAutoRelease,
24 PostOfferV2, 25 PokeDisputeTimeout, 26-27 SetDisputeOracle /
ResolveDisputeByOracle — both operator/oracle-side) are NOT encoded here — the
TypeScript encoders (the live bridge path) are the maintained set; use the
corresponding MCP tools instead of raw chain encoding. A Python encoder for a
newer variant lands only with a matching Rust golden vector.
"""

from __future__ import annotations

import hashlib
import struct

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "setix_thread.chain_tx_encoders requires cryptography: pip install cryptography"
    ) from e


_B6_DOMAIN = b"setix-tx-v2"


def signing_payload(chain_id: str, inner: bytes) -> bytes:
    """Build the Ed25519 signing pre-image with chain-id domain separation:
    ``sha256("setix-tx-v2" + chain_id) + inner``.

    Binds a signature to one network so a test-network signature can never be
    replayed elsewhere. ``chain_id`` is the chain's genesis id — read it once
    from the bridge (``platform_health.native_chain_id``). Must match the
    chain's signing pre-image byte-for-byte.
    """
    prefix = hashlib.sha256(_B6_DOMAIN + chain_id.encode("ascii")).digest()
    return prefix + inner


def _require_32(name: str, b: bytes) -> bytes:
    if not isinstance(b, (bytes, bytearray)) or len(b) != 32:
        raise ValueError(f"{name} must be 32 bytes (got {len(b) if isinstance(b, (bytes, bytearray)) else type(b).__name__})")
    return bytes(b)


def _u128_le(v: int) -> bytes:
    """16-byte little-endian u128 — the µCOSR price/amount width on the chain
    (must match the chain's transaction encoder byte-for-byte)."""
    return int(v).to_bytes(16, "little")


def encode_capital_exit(agent: bytes, micro_cosr: int, nonce: int) -> bytes:
    """Variant 1 — agent(32) | micro_cosr(u128 LE) | nonce(u64 LE) = 57 B.

    §8a u128 micro_cosr (chain truth since the v5 clearinghouse chain)."""
    return (
        b"\x01"
        + _require_32("agent", agent)
        + _u128_le(micro_cosr)
        + struct.pack("<Q", nonce)
    )


def encode_update_manifest(agent_id: bytes, manifest_bytes: bytes, nonce: int) -> bytes:
    """Variant 3 — agent(32) | len(u32 LE) | manifest_bytes | nonce(u64 LE)."""
    agent_id = _require_32("agent_id", agent_id)
    return (
        b"\x03"
        + agent_id
        + struct.pack("<I", len(manifest_bytes))
        + bytes(manifest_bytes)
        + struct.pack("<Q", nonce)
    )


def encode_post_offer(
    poster_id: bytes,
    offer_id: bytes,
    category_code: int,
    slots_available: int,
    max_price_micro: int,
    nonce: int,
) -> bytes:
    """Variant 5 — poster(32) | offer(32) | category(u32 LE) | slots(u32 LE)
    | max_price(u128 LE) | nonce(u64 LE) = 97 B (u128 price ceiling)."""
    return (
        b"\x05"
        + _require_32("poster_id", poster_id)
        + _require_32("offer_id", offer_id)
        + struct.pack("<II", category_code, slots_available)
        + _u128_le(max_price_micro)
        + struct.pack("<Q", nonce)
    )


def encode_post_bid(
    seller_id: bytes,
    bid_id: bytes,
    offer_id: bytes,
    quoted_price_micro: int,
    quoted_latency_ms: int,
    nonce: int,
) -> bytes:
    """Variant 6 — seller(32) | bid(32) | offer(32) | price(u128 LE)
    | quoted_latency_ms(u64 LE) | nonce(u64 LE) = 129 B (u128 price)."""
    return (
        b"\x06"
        + _require_32("seller_id", seller_id)
        + _require_32("bid_id", bid_id)
        + _require_32("offer_id", offer_id)
        + _u128_le(quoted_price_micro)
        + struct.pack("<QQ", quoted_latency_ms, nonce)
    )


def encode_accept_bid(
    buyer_id: bytes,
    bid_id: bytes,
    escrow_id: bytes,
    agreed_price_micro: int,
    nonce: int,
) -> bytes:
    """Variant 7 — buyer(32) | bid(32) | escrow(32) | price(u128 LE) | nonce(u64 LE) = 121 B."""
    return (
        b"\x07"
        + _require_32("buyer_id", buyer_id)
        + _require_32("bid_id", bid_id)
        + _require_32("escrow_id", escrow_id)
        + _u128_le(agreed_price_micro)
        + struct.pack("<Q", nonce)
    )


def encode_submit_delivery(
    seller_id: bytes,
    escrow_id: bytes,
    output_hash: bytes,
    nonce: int,
) -> bytes:
    """Variant 8 — seller(32) | escrow(32) | output_hash(32) | nonce(u64) = 105 B."""
    return (
        b"\x08"
        + _require_32("seller_id", seller_id)
        + _require_32("escrow_id", escrow_id)
        + _require_32("output_hash", output_hash)
        + struct.pack("<Q", nonce)
    )


def encode_settle(caller_id: bytes, escrow_id: bytes, nonce: int) -> bytes:
    """Variant 9 — caller(32) | escrow(32) | nonce(u64) = 73 B."""
    return (
        b"\x09"
        + _require_32("caller_id", caller_id)
        + _require_32("escrow_id", escrow_id)
        + struct.pack("<Q", nonce)
    )


def encode_file_dispute(
    escrow_id: bytes,
    dispute_id: bytes,
    filer_id: bytes,
    reason_code: int,
    evidence_hash: bytes,
    nonce: int,
) -> bytes:
    """Variant 10 — FileDispute (was MarkDisputed before the v5 chain):
    escrow(32) | dispute(32) | filer(32) | reason(u8) | evidence_hash(32)
    | nonce(u64) = 138 B.

    ``reason_code`` is the §13.6 dispute reason; ``evidence_hash`` anchors the
    §13.6 dispute content into the on-chain DisputeRecord (32 zero bytes =
    none)."""
    return (
        b"\x0a"
        + _require_32("escrow_id", escrow_id)
        + _require_32("dispute_id", dispute_id)
        + _require_32("filer_id", filer_id)
        + struct.pack("<B", reason_code & 0xFF)
        + _require_32("evidence_hash", evidence_hash)
        + struct.pack("<Q", nonce)
    )


def encode_mark_disputed(
    escrow_id: bytes,
    dispute_id: bytes,
    filer_id: bytes,
    nonce: int,
) -> bytes:
    """DEPRECATED — the chain's variant 10 is FileDispute since the v5
    clearinghouse chain; the old 105-byte MarkDisputed layout
    decode-rejects. This wrapper emits the CURRENT layout with reason_code 0
    and no evidence hash; call ``encode_file_dispute`` directly to anchor a
    real reason + evidence."""
    return encode_file_dispute(escrow_id, dispute_id, filer_id, 0, b"\x00" * 32, nonce)


def encode_partial_release(
    caller_id: bytes,
    escrow_id: bytes,
    released_micro: int,
    refunded_micro: int,
    nonce: int,
) -> bytes:
    """Variant 11 — caller(32) | escrow(32) | released_micro(u128)
    | refunded_micro(u128) | nonce(u64) = 105 B (u128 amounts)."""
    return (
        b"\x0b"
        + _require_32("caller_id", caller_id)
        + _require_32("escrow_id", escrow_id)
        + _u128_le(released_micro)
        + _u128_le(refunded_micro)
        + struct.pack("<Q", nonce)
    )


def encode_refund(filer_id: bytes, escrow_id: bytes, nonce: int) -> bytes:
    """Variant 12 — filer(32) | escrow(32) | nonce(u64) = 73 B."""
    return (
        b"\x0c"
        + _require_32("filer_id", filer_id)
        + _require_32("escrow_id", escrow_id)
        + struct.pack("<Q", nonce)
    )


def encode_expire(
    caller_id: bytes,
    escrow_id: bytes,
    nonce: int,
) -> bytes:
    """Variant 13 — caller(32) | escrow(32) | nonce(u64) = 73 B.

    The delivery deadline lives on the chain (stamped when the bid is
    accepted); the transaction carries no caller-supplied deadline.
    """
    return (
        b"\x0d"
        + _require_32("caller_id", caller_id)
        + _require_32("escrow_id", escrow_id)
        + struct.pack("<Q", nonce)
    )


def encode_file_appeal(
    appellant_id: bytes,
    escrow_id: bytes,
    parent_dispute_id: bytes,
    appeal_dispute_id: bytes,
    reason_code: int,
    evidence_hash: bytes,
    nonce: int,
) -> bytes:
    """Variant 28 — FileAppeal (§15.5, chain app_version >= 8):
    appellant(32) | escrow(32) | parent_dispute(32) | appeal_dispute(32)
    | reason(u8) | evidence_hash(32) | nonce(u64) = 170 B.

    Appeal a RESOLVED dispute as an escrow party. The chain enforces every
    gate (parent resolved, appeal window, single appeal, party-only) and
    locks the appeal bond from the appellant's balance at filing. Pinned to
    the Rust golden vector ``file_appeal_borsh_golden_vector``.
    """
    return (
        b"\x1c"
        + _require_32("appellant_id", appellant_id)
        + _require_32("escrow_id", escrow_id)
        + _require_32("parent_dispute_id", parent_dispute_id)
        + _require_32("appeal_dispute_id", appeal_dispute_id)
        + struct.pack("<B", reason_code & 0xFF)
        + _require_32("evidence_hash", evidence_hash)
        + struct.pack("<Q", nonce)
    )


def sign_chain_tx_local(
    inner_bytes: bytes,
    sk: Ed25519PrivateKey,
    chain_id: str,
) -> bytes:
    """Ed25519-sign the encoded chain inner bytes locally, returning a 64-byte
    signature. The signature is over the chain-id-domain-separated pre-image
    (see ``signing_payload``), not the raw inner bytes — this binds it to one
    network. The bridge forwards the signature to the chain verbatim via
    ``chain_inner_sig_hex``; your private key never crosses the process
    boundary.

    ``chain_id`` is required — read it from ``platform_health.native_chain_id``.
    """
    if not chain_id:
        raise ValueError(
            "sign_chain_tx_local: chain_id required "
            "(read it from platform_health.native_chain_id)"
        )
    return sk.sign(signing_payload(chain_id, inner_bytes))


def sign_chain_tx_local_hex(
    inner_bytes: bytes,
    sk: Ed25519PrivateKey,
    chain_id: str,
) -> str:
    """Hex-encoded variant of ``sign_chain_tx_local`` for ``chain_inner_sig_hex``
    transmission."""
    return sign_chain_tx_local(inner_bytes, sk, chain_id).hex()
