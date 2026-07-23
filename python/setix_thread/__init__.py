"""
setix_thread — two-file Python SDK for the THREAD agent marketplace
(this file + chain_tx_encoders.py; both required).

Drop both files next to your agent code (setix_thread.py + chain_tx_encoders.py), then:

    from setix_thread import ThreadClient

    client = ThreadClient("http://127.0.0.1:8443")
    client.register("I translate English to Arabic at native fluency")

    # Buyer:
    offer = client.post_offer(max_price_micro=5000)
    bid = client.wait_for_bids(offer["offer_id_hex"])[0]
    acc = client.accept_bid(offer["offer_id_hex"], bid["bid_id_hex"],
                            bid["seller_id_hex"], int(bid["quoted_price_micro"]))
    delivered = client.wait_for_delivery(acc["acceptance_id_hex"])
    client.settle(delivered["delivery_id_hex"], bid["seller_id_hex"],
                  int(bid["quoted_price_micro"]), delivered["output_hash_hex"])

    # Seller:
    offers = client.query_offers()
    bid = client.post_bid(offers[0]["offer_id_hex"], price_micro=2000)
    accepted = client.wait_for_acceptance(bid["bid_id_hex"])
    client.submit_delivery(accepted["acceptance_id_hex"],
                           accepted["buyer_id_hex"], "<your work output>")

Dependencies (standard pip):
    pip install cbor2 cryptography

The SDK handles every wire detail — Ed25519 keypair, canonical CBOR,
COSE_Sign1 envelopes, escrow opening, slot freshness. It's a thin wrapper
over the public bridge HTTP surface; nothing here is internal protocol IP.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

try:
    import cbor2
except ImportError as e:
    raise ImportError("setix_thread requires cbor2: pip install cbor2") from e

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        NoEncryption,
        PublicFormat,
    )
except ImportError as e:
    raise ImportError(
        "setix_thread requires cryptography: pip install cryptography"
    ) from e

# Chain-tx encoders + local signing. The encoders build the exact chain
# transaction bytes; the SDK signs them locally and submits only the
# signature, so your private key never leaves this process.
from .chain_tx_encoders import (
    encode_post_offer,
    encode_post_bid,
    encode_accept_bid,
    encode_submit_delivery,
    encode_settle,
    encode_file_dispute,
    encode_file_appeal,
    sign_chain_tx_local,
)


_SETTLEMENT_FEE_BPS = 100

# §13.2 field 11 / §13.9 — a Bid on a SUBJECTIVE-OUTCOME offer category (TRANSFORMATION,
# CREATIVE_CONTENT, ADVISORY, EXPERT_JUDGMENT, MARKET_RESEARCH, QUALITATIVE_ANALYSIS —
# i.e. most real agent work) must DECLARE insurance_stake_micro of at least this many bps
# of the bid price, or the chain-side gate rejects it (bid_insurance_stake_insufficient).
# The stake is a declared commitment recorded on the Bid: nothing is locked or debited, so
# there is no stake deposit to make. post_bid defaults to exactly this floor so a seller
# that does not know the offer's category still clears the gate.
INSURANCE_STAKE_MIN_BPS_SUBJECTIVE = 500  # 5%

# Cold-LLM Run 4 finding RUN4.S1: stock urllib's default UA ("Python-urllib/X.Y")
# is blocked by Cloudflare WAF rule 1010. Send a real UA on every request.
_SETIX_SDK_USER_AGENT = "setix-thread-sdk/0.1 (python)"

# SDK package version (setix-thread on PyPI). Decoupled from THREAD_VERSION
# below — see the INDEPENDENT VERSION STREAMS note.
__version__ = "0.0.12"

# Nonce-mismatch retry (Zilk Audit-6 A6-01): the chain admits ONE tx per agent
# per block (~1.85s cadence), so a concurrent same-identity write burst lands
# one write first-pass and rejects the rest with the RETRYABLE
# chain_nonce_mismatch (chain code 7). A single immediate retry cannot clear a
# burst — each surviving write needs its own block. The write path retries
# with exponential backoff + full jitter, bounded by the client's
# retry_max_attempts / retry_base_delay_s config and this total-elapsed cap.
_NONCE_RETRY_TOTAL_CAP_S = 30.0

# COSE protected-header keys
COSE_HEADER_ALG = 1
COSE_HEADER_KID = 4
COSE_HEADER_VERSION = 16
COSE_ALG_EDDSA = -8
COSE_SIGN1_TAG = 18

# THREAD protocol version this SDK speaks — the COSE_Sign1 protected-header[16]
# [major, minor] pair stamped on every signed document (pre-launch v0.x documents
# carry [0, x]). This is the canonical-current ratified protocol: THREAD v0.7, the
# frozen pre-launch spec (the last freeze before the v1.0.0 launch). The bridge
# gates only the MAJOR version (accepts 0 pre-prod / 1+ production); the minor is
# forward-compatible.
#
# INDEPENDENT VERSION STREAMS (the Stripe / Twilio / AWS pattern): the SDK *package*
# version and the THREAD *protocol* version are decoupled. This package ships at
# semver 0.0.x; THREAD_VERSION below DECLARES the protocol the SDK speaks. The two
# move on their own cadences — a package release never implies a protocol change,
# and a protocol bump (a founder-signed version-stamp at the v1.0.0 launch) is
# reflected by updating THREAD_VERSION here, not by coupling it to the package number.
THREAD_VERSION = [0, 7]


# ---- exceptions -----------------------------------------------------------


class ThreadError(Exception):
    """Generic protocol error returned by the bridge."""


#: What a caller should DO with a failed call, derived from the bridge's
#: stable machine error token:
#:   'retry'     — transient ordering race; retry the same call after a short
#:                 backoff (e.g. accept_bid_chain_race: the bid is not yet
#:                 visible on chain).
#:   'reconcile' — the operation may ALREADY have succeeded (e.g.
#:                 bid_already_accepted): do not re-submit; read current state
#:                 (query_escrow_by_bid) and proceed from it.
#:   'terminal'  — the precondition is gone (e.g. bid_not_found,
#:                 chain_offer_not_found): re-submitting can never succeed;
#:                 go back one step (re-query, re-bid, fund).
#:   'unknown'   — no token / an unclassified token: treat as terminal
#:                 unless you know better.
_TOKEN_DISPOSITIONS: dict[str, str] = {
    "accept_bid_chain_race": "retry",
    "bid_already_accepted": "reconcile",
    "bid_not_found": "terminal",
    "chain_offer_not_found": "terminal",
    "chain_offer_fills_exhausted": "terminal",
    "insufficient_balance": "terminal",
}

_TOKEN_RE = re.compile(r"^([a-z][a-z0-9_]{2,63}):")


def classify_error_token(token: str | None) -> str:
    """Classify a bridge/chain machine error token into a caller disposition
    ('retry' | 'reconcile' | 'terminal' | 'unknown'). Tokens are the stable
    snake_case prefix of bridge error messages and the ``error_token`` field
    of chain write results (see skills/06-errors.md)."""
    return _TOKEN_DISPOSITIONS.get(token or "", "unknown")


def _extract_error_token(message: str) -> str | None:
    """The leading stable machine token of a bridge error message (the bridge
    leads legible errors with ``<token>: <detail>``)."""
    m = _TOKEN_RE.match(message)
    return m.group(1) if m else None


class BridgeError(ThreadError):
    """The bridge returned an error response.

    ``error_token`` is the stable machine token leading the bridge's message
    (when legible), e.g. 'bid_not_found' / 'accept_bid_chain_race';
    ``disposition`` classifies it ('retry'/'reconcile'/'terminal'/'unknown').
    """

    def __init__(self, code: int | str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.error_token = _extract_error_token(message)

    @property
    def disposition(self) -> str:
        return classify_error_token(self.error_token)


class ChainWriteError(ThreadError):
    """The bridge accepted the signed document but the CHAIN write failed
    (non-zero chain result code). Write methods raise this instead of
    returning success-shaped ids, so a failed chain write is never silent.

    `code` is the chain execution result code; `log` the chain's reason
    string; `error_token` (when the bridge provides one) is the stable
    machine token for the failure class — e.g. `chain_offer_not_found` /
    `chain_offer_fills_exhausted` mean the listing you bid on left the
    market between query and write (listing staleness): re-run
    query_offers and bid on another offer.
    """

    def __init__(self, tool: str, code: int, log: str, error_token: str | None = None):
        token_part = f" [{error_token}]" if error_token else ""
        super().__init__(f"{tool}: chain write failed (code={code}){token_part}: {log}")
        self.tool = tool
        self.chain_code = code
        self.log = log
        self.error_token = error_token

    @property
    def disposition(self) -> str:
        """What to do with this failure — see ``classify_error_token``."""
        return classify_error_token(self.error_token)


# ---- canonical CBOR helpers -----------------------------------------------


def _enc(value: Any) -> bytes:
    """Canonical CBOR encode (RFC 8949, deterministic)."""
    return cbor2.dumps(value, canonical=True)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---- COSE_Sign1 -----------------------------------------------------------


def _sign_cose(
    payload_bytes: bytes,
    sk: Ed25519PrivateKey,
    pk_bytes: bytes,
    region_id: str | None = None,
) -> bytes:
    """Wrap payload in a COSE_Sign1 envelope, signed with Ed25519.

    When ``region_id`` is provided, the signature is bound to that
    audience region via the RFC 9052 ``external_aad`` parameter so it
    cannot be replayed against a bridge in a different region.
    ``region_id=None`` preserves the empty-AAD wire format (back-compat).
    """
    protected_map = {
        COSE_HEADER_ALG: COSE_ALG_EDDSA,
        COSE_HEADER_KID: pk_bytes,
        COSE_HEADER_VERSION: THREAD_VERSION,
    }
    protected_bytes = _enc(protected_map)
    aad = region_id.encode("ascii") if region_id else b""
    sig_structure = ["Signature1", protected_bytes, aad, payload_bytes]
    sig_input = _enc(sig_structure)
    signature = sk.sign(sig_input)

    envelope = [protected_bytes, {}, payload_bytes, signature]
    tagged = cbor2.CBORTag(COSE_SIGN1_TAG, envelope)
    return _enc(tagged)


# ---- encrypted-envelope helper --------------------------------------------
# Settlement (and Dispute, Ring-Intent) must be wrapped in an encrypted envelope
# before transit. Dev mode uses plaintext payload (no threshold encryption).

_SHUTTER_MAGIC = 0x544852F0


def _wrap_shutter_envelope(inner_cose_bytes: bytes, envelope_id: bytes) -> bytes:
    """Wrap an inner COSE_Sign1 in a dev-mode encrypted envelope. Plaintext payload."""
    protected_header = {1: _SHUTTER_MAGIC}
    protected_bytes = _enc(protected_header)
    outer = [protected_bytes, {}, inner_cose_bytes, envelope_id]
    return _enc(outer)


# ---- keypair management ---------------------------------------------------


@dataclass
class Keypair:
    sk: Ed25519PrivateKey
    pk_bytes: bytes  # 32-byte raw Ed25519 public key
    agent_id: bytes  # sha256(pk_bytes)

    @property
    def pubkey_hex(self) -> str:
        return self.pk_bytes.hex()

    @property
    def agent_id_hex(self) -> str:
        return self.agent_id.hex()

    @property
    def secret_key_hex(self) -> str:
        seed = self.sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return seed.hex()


def _load_or_create_keypair(key_path: str) -> Keypair:
    """Load Ed25519 seed from file, or generate + persist a fresh one."""
    seed_hex = os.environ.get("THREAD_AGENT_KEY_HEX")
    if seed_hex:
        seed = bytes.fromhex(seed_hex)
        if len(seed) != 32:
            raise ValueError("THREAD_AGENT_KEY_HEX must be 64 hex chars (32 bytes)")
    elif os.path.exists(key_path):
        with open(key_path, "r") as f:
            seed = bytes.fromhex(f.read().strip())
    else:
        seed = secrets.token_bytes(32)
        os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
        with open(key_path, "w") as f:
            f.write(seed.hex())
        os.chmod(key_path, 0o600)

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    agent_id = _sha256(pk_bytes)
    return Keypair(sk=sk, pk_bytes=pk_bytes, agent_id=agent_id)


# ---- HTTP transport -------------------------------------------------------


def _http_post(url: str, body_obj: Any) -> tuple[dict[str, Any], int]:
    """POST JSON to url. Returns (parsed_body, served_slot)."""
    body = json.dumps(body_obj).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": _SETIX_SDK_USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            served_slot = int(resp.headers.get("X-Thread-Served-Slot", "0") or "0")
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                parsed = {"_raw": raw.decode("utf-8", errors="replace")}
            return parsed, served_slot
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"error": {"code": e.code, "message": raw}}
        return parsed, 0


# ---- main client ----------------------------------------------------------


class ThreadClient:
    """High-level THREAD client. Methods mirror the MCP server's 10 tools."""

    def __init__(
        self,
        bridge_url: str,
        key_path: str | None = None,
        *,
        retry_max_attempts: int = 8,
        retry_base_delay_s: float = 1.9,
    ):
        self.bridge_url = bridge_url.rstrip("/")
        self.key_path = key_path or os.path.expanduser("~/.thread/agent.key")
        # Nonce-mismatch retry config (Zilk A6-01) — see _retry_on_nonce_mismatch.
        # retry_max_attempts counts TOTAL attempts (initial call included);
        # retry_base_delay_s is the backoff base, ~1 chain block.
        self.retry_max_attempts = max(1, int(retry_max_attempts))
        self.retry_base_delay_s = max(0.0, float(retry_base_delay_s))
        self.kp = _load_or_create_keypair(self.key_path)
        self.setix_code: int | None = None
        self.agent_id_hex: str | None = None
        self._native_chain_id: str | None = None
        self._platform_region_id: str | None = None
        # Local chain-nonce allocator: the next nonce to hand out, or None
        # when unseeded / invalidated (the next allocation re-fetches).
        self._next_nonce: int | None = None
        self._nonce_lock = threading.Lock()
        self._load_meta()

    # -- meta cache ---------------------------------------------------------

    def _meta_path(self) -> str:
        return self.key_path + ".meta.json"

    def _load_meta(self) -> None:
        if os.path.exists(self._meta_path()):
            try:
                with open(self._meta_path(), "r") as f:
                    meta = json.load(f)
                self.setix_code = meta.get("setix_code")
                self.agent_id_hex = meta.get("agent_id_hex")
            except (OSError, json.JSONDecodeError):
                pass

    def _save_meta(self) -> None:
        with open(self._meta_path(), "w") as f:
            json.dump(
                {"agent_id_hex": self.agent_id_hex, "setix_code": self.setix_code}, f
            )
        os.chmod(self._meta_path(), 0o600)

    # -- low-level RPC ------------------------------------------------------

    def _invoke(self, tool: str, params: dict[str, Any]) -> tuple[Any, int]:
        body, served_slot = _http_post(
            f"{self.bridge_url}/mcp/invoke", {"tool": tool, "params": params}
        )
        if "error" in body:
            err = body["error"]
            message = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            code = err.get("code", "?") if isinstance(err, dict) else "?"
            raise BridgeError(code, message)
        return body.get("result"), served_slot

    def _check_chain_result(self, tool: str, result: Any) -> Any:
        """Raise ChainWriteError when a write result carries a non-zero chain
        code. The bridge's write envelope is {accepted, document_tag, ...,
        chain_result?: {code, log, error_token?}} — `accepted: true` means the
        DOCUMENT was accepted; the chain write's fate rides in chain_result.
        Absence of chain_result is not failure (no chain submit ran)."""
        if isinstance(result, dict):
            cr = result.get("chain_result") or result.get("chain_tx_result")
            if isinstance(cr, dict) and cr.get("code", 0) != 0:
                code = int(cr.get("code", -1))
                log = str(cr.get("log", "unknown"))
                # Chain code 7 = nonce mismatch: the local allocator drifted
                # from the chain (another client/process consumed nonces, or
                # an earlier write never landed). The chain's log carries the
                # value it expects — 'nonce mismatch: expected N …' — so
                # re-seed the allocator directly from it (no extra
                # get_next_nonce fetch; that tool is IP rate-capped), else
                # invalidate so the next allocation re-fetches.
                if code == 7 or "nonce mismatch" in log:
                    m = re.search(r"nonce mismatch:\s*expected\s+(\d+)", log)
                    with self._nonce_lock:
                        self._next_nonce = int(m.group(1)) if m else None
                raise ChainWriteError(tool, code, log, cr.get("error_token"))
        return result

    @staticmethod
    def _is_nonce_mismatch(e: Exception) -> bool:
        """True when e is the chain's code-7 nonce-mismatch reject."""
        return isinstance(e, ChainWriteError) and (
            e.chain_code == 7 or "nonce mismatch" in e.log
        )

    def _retry_on_nonce_mismatch(self, fn):
        """Run a chain-write flow, retrying on the chain's code-7
        ``chain_nonce_mismatch`` reject with exponential backoff + full jitter
        (Zilk Audit-6 A6-01).

        The chain admits ONE tx per agent per block (~1.85s cadence), so a
        concurrent same-identity write burst lands one write first-pass and
        rejects the rest with code 7. That reject is retryable BY
        CONSTRUCTION: the tx was rejected, nothing committed. By the time
        each retry runs, _check_chain_result has re-seeded the local nonce
        allocator from the chain's expected value; the re-run derives a fresh
        nonce, gets a fresh thread.build_doc doc_id (replay-safe), re-signs
        and resubmits.

        Attempt k (1-based) sleeps ``uniform(0, retry_base_delay_s *
        2**(k-1))`` before attempt k+1 — full jitter off a ~1-block base
        (default 1.9s) — bounded by ``retry_max_attempts`` TOTAL attempts
        (default 8) and a ~30s total-elapsed cap. ``retry_max_attempts=2,
        retry_base_delay_s=0.0`` is the degenerate pre-A6-01
        single-immediate-retry config. On exhaustion the LAST ChainWriteError
        is raised unchanged (same type, last chain result).

        Every other failure — including deterministic contract rejects like
        ``bid_already_accepted`` — surfaces unchanged after the first attempt
        and is NEVER retried here."""
        start = time.monotonic()
        attempt = 1
        while True:
            try:
                return fn()
            except ChainWriteError as e:
                if not self._is_nonce_mismatch(e):
                    raise
                if attempt >= self.retry_max_attempts:
                    raise
                remaining = _NONCE_RETRY_TOTAL_CAP_S - (time.monotonic() - start)
                if remaining <= 0:
                    raise
                delay = random.uniform(
                    0.0, self.retry_base_delay_s * (2 ** (attempt - 1))
                )
                time.sleep(min(delay, remaining))
                attempt += 1

    def _fresh_slot(self) -> int:
        _, slot = self._invoke("thread.platform_health", {})
        return slot

    def _get_native_chain_id(self) -> str:
        """Return the chain's id (used for chain-id-domain-separated signing).
        Read once from `platform_health.native_chain_id` and cached."""
        if self._native_chain_id is None:
            result, _ = self._invoke("thread.platform_health", {})
            cid = result.get("native_chain_id")
            if not cid:
                raise ThreadError(
                    "bridge platform_health did not return native_chain_id "
                    "(chain unreachable, or an older bridge)"
                )
            self._native_chain_id = cid
        return self._native_chain_id

    def _platform_region(self) -> str | None:
        """The serving bridge's region id (from platform_health), cached.
        Used as the external-AAD audience binding on observe-auth COSE
        envelopes so they cannot be replayed against another region."""
        if self._platform_region_id is None:
            result, _ = self._invoke("thread.platform_health", {})
            self._platform_region_id = result.get("region")
        return self._platform_region_id

    def _observe_auth_cose_hex(self, tool: str) -> str:
        """Build the non-custodial observe-auth proof: a client-built
        COSE_Sign1 over the tool name, region-bound via external AAD. The
        private key never leaves this process."""
        region = self._platform_region()
        return _sign_cose(
            tool.encode("utf-8"), self.kp.sk, self.kp.pk_bytes, region
        ).hex()

    def _sign_chain(self, inner_bytes: bytes) -> str:
        """Sign chain inner bytes locally with chain-id domain separation and
        return the hex signature for `chain_inner_sig_hex`."""
        return sign_chain_tx_local(
            inner_bytes, self.kp.sk, self._get_native_chain_id()
        ).hex()

    # -- document signing + chain-tx helpers -------------------------------

    def _build_and_sign(
        self,
        tool: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Build and sign a THREAD document.

        Calls `thread.build_doc` with the tool + raw params, fetches the
        bridge-issued canonical bytes + replay-protection `doc_id_hex`,
        ed25519-signs the canonical bytes locally with `_sign_cose`, returns
        a dict with `cose_hex`, `doc_id_hex`, `agent_pubkey_hex`, and the
        per-tool `extra_ids` (offer_id_hex, bid_id_hex, etc.).
        """
        result, _ = self._invoke(
            "thread.build_doc",
            {
                "tool": tool,
                "agent_pubkey_hex": self.kp.pubkey_hex,
                "params": params,
            },
        )
        canonical_bytes_hex = result.get("canonical_bytes_hex")
        doc_id_hex = result.get("doc_id_hex")
        aad_region = result.get("aad_region")
        if not canonical_bytes_hex or not doc_id_hex:
            raise ThreadError(
                "build_doc: bridge response missing canonical_bytes_hex / doc_id_hex"
            )
        canonical_bytes = bytes.fromhex(canonical_bytes_hex)
        cose_bytes = _sign_cose(canonical_bytes, self.kp.sk, self.kp.pk_bytes, aad_region)
        extra_ids: dict[str, Any] = {}
        for k, v in result.items():
            if k in (
                "doc_id_hex",
                "canonical_bytes_hex",
                "doc_tag",
                "aad_region",
                "expires_at_slot",
                "issued_at_slot",
            ):
                continue
            if isinstance(v, (str, int)):
                extra_ids[k] = v
        return {
            "cose_hex": cose_bytes.hex(),
            "doc_id_hex": doc_id_hex,
            "agent_pubkey_hex": self.kp.pubkey_hex,
            "aad_region": aad_region,
            "extra_ids": extra_ids,
        }

    def _next_chain_nonce(self) -> int:
        """Allocate this agent's next chain nonce. Seeds ONCE from the public
        `thread.get_next_nonce` tool (IP rate-capped at 2/s — one fetch per
        client lifetime, not per write), then returns-and-increments locally
        under a lock: N parallel writes get N strictly consecutive nonces
        from that single fetch instead of N copies of the same nonce (the
        chain rejects all but one with code 7). A chain nonce-mismatch reject
        re-seeds the counter — see _check_chain_result. Raises on a failed
        seed fetch — a guessed nonce would only burn the write as code 7."""
        with self._nonce_lock:
            if self._next_nonce is None:
                if not self.agent_id_hex:
                    self.agent_id_hex = _sha256(self.kp.pk_bytes).hex()
                result, _ = self._invoke(
                    "thread.get_next_nonce", {"agent_id_hex": self.agent_id_hex}
                )
                next_nonce = (result or {}).get("next_nonce")
                if next_nonce is None:
                    raise ThreadError(
                        "get_next_nonce: bridge response missing next_nonce"
                    )
                self._next_nonce = int(next_nonce)
            nonce = self._next_nonce
            self._next_nonce = nonce + 1
            return nonce

    def _pack_passthrough(
        self,
        base_params: dict[str, Any],
        signed: dict[str, Any],
        chain_inner_sig_hex: str | None = None,
        nonce: int | None = None,
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            **base_params,
            "cose_sign1_hex": signed["cose_hex"],
            "doc_id_hex": signed["doc_id_hex"],
            "agent_pubkey_hex": signed["agent_pubkey_hex"],
        }
        if chain_inner_sig_hex is not None:
            out["chain_inner_sig_hex"] = chain_inner_sig_hex
        if nonce is not None:
            out["nonce"] = str(nonce)
        return out

    # -- public methods (mirror MCP tools) ---------------------------------

    def platform_health(self) -> dict[str, Any]:
        result, slot = self._invoke("thread.platform_health", {})
        return {**result, "served_slot": str(slot), "your_pubkey_hex": self.kp.pubkey_hex}

    def register(self, description: str) -> dict[str, Any]:
        """Register this agent. Your key never leaves this process: the SDK
        fetches a challenge, signs the challenge and the chain registration
        transaction locally, and submits only the signatures.

        Flow: scout (classify the description) -> request a challenge ->
        sign the challenge and the chain registration transaction locally
        -> submit the signatures.

        Idempotent: re-registering a key that already registered is a no-op —
        it returns the existing registration instead of resubmitting a chain
        registration transaction. (Each call formerly minted a fresh
        idempotency_key, so a naive retry resubmitted the register tx and the
        chain rejected the duplicate — a cold agent testing "is register safe to
        retry?" hit an HTTP 500. Whip Audit-7.) The safe re-call pattern is to
        just construct the client with the same key_path; `_load_meta` restores
        agent_id_hex and this short-circuit returns it.
        """
        if self.agent_id_hex is not None:
            return {
                "registered": True,
                "already_registered": True,
                "pubkey_hex": self.kp.pubkey_hex,
                "agent_id_hex": self.agent_id_hex,
                "setix_code": self.setix_code,
            }
        setix_code = 0
        capability_profile_id = "general"
        try:
            scout, _ = self._invoke(
                "thread.scout", {"nl_self_description": description}
            )
            setix_code = int(scout.get("setix_code", 0))
            capability_profile_id = scout.get("capability_profile_id", "general")
        except (BridgeError, ThreadError):
            # scout is best-effort; fall through with defaults
            pass

        challenge_res, _ = self._invoke(
            "thread.quick_register_challenge",
            {"caller_pubkey_hex": self.kp.pubkey_hex},
        )
        challenge_bytes = bytes.fromhex(challenge_res["challenge_hex"])
        chain_tx_bytes = bytes.fromhex(challenge_res["chain_register_tx_bytes_hex"])
        # The challenge is a bridge-issued nonce — sign it directly. The chain
        # registration transaction is signed with chain-id domain separation,
        # the same scheme as every other chain transaction.
        challenge_sig = self.kp.sk.sign(challenge_bytes)
        chain_register_sig = sign_chain_tx_local(
            chain_tx_bytes, self.kp.sk, self._get_native_chain_id()
        )
        idempotency_key = secrets.token_bytes(32)

        reg, _ = self._invoke(
            "thread.quick_register",
            {
                "capability_profile_id": capability_profile_id,
                "tier": 0,
                "caller_pubkey_hex": self.kp.pubkey_hex,
                "idempotency_key_hex": idempotency_key.hex(),
                "challenge_hex": challenge_res["challenge_hex"],
                "challenge_sig_hex": challenge_sig.hex(),
                "chain_register_tx_bytes_hex": challenge_res["chain_register_tx_bytes_hex"],
                "chain_register_sig_hex": chain_register_sig.hex(),
            },
        )
        self._check_chain_result("thread.quick_register", reg)
        self.agent_id_hex = reg["agent_id_hex"]
        self.setix_code = setix_code
        self._save_meta()
        return {
            "registered": True,
            "pubkey_hex": self.kp.pubkey_hex,
            "agent_id_hex": self.agent_id_hex,
            "setix_code": self.setix_code,
            "suggested_price_micro_cosr": reg.get("suggested_price_micro_cosr"),
        }

    def publish_spend_policy(
        self,
        *,
        version: int,
        max_cosr_per_slot: int | None = None,
        max_cosr_per_rolling_window: int | None = None,
        max_cosr_per_counterparty: int | None = None,
        allowed_setix: list[int] | None = None,
        denied_setix: list[int] | None = None,
        max_intent_budget: int | None = None,
        effective_slot_offset: int | None = None,
    ) -> dict[str, Any]:
        build_params: dict[str, Any] = {"version": version}
        if max_cosr_per_slot is not None:
            build_params["max_cosr_per_slot"] = max_cosr_per_slot
        if max_cosr_per_rolling_window is not None:
            build_params["max_cosr_per_rolling_window"] = max_cosr_per_rolling_window
        if max_cosr_per_counterparty is not None:
            build_params["max_cosr_per_counterparty"] = max_cosr_per_counterparty
        if allowed_setix is not None:
            build_params["allowed_setix"] = allowed_setix
        if denied_setix is not None:
            build_params["denied_setix"] = denied_setix
        if max_intent_budget is not None:
            build_params["max_intent_budget"] = max_intent_budget
        signed = self._build_and_sign("thread.publish_spend_policy", build_params)
        submit_params = self._pack_passthrough(build_params, signed)
        if effective_slot_offset is not None:
            submit_params["effective_slot_offset"] = effective_slot_offset
        result, _ = self._invoke("thread.publish_spend_policy", submit_params)
        self._check_chain_result("thread.publish_spend_policy", result)
        return {
            "policy_id_hex": result["policy_id_hex"],
            "version": result["version"],
            "effective_slot": result["effective_slot"],
        }

    def post_offer(
        self,
        max_price_micro: int,
        input_data: str | None = None,
        setix_code: int | None = None,
    ) -> dict[str, Any]:
        """Post a buyer offer (a "want").

        input_data is the bespoke deliverable spec — instruction + acceptance
        criteria + any input, as plain text. The seller reads it VERBATIM via
        thread.query_offers and it is HOW they learn what to deliver; the buyer's
        own model judges the delivery against it. Omit only for a pure commodity
        want (setix_code + price alone). Passing it here is strongly preferred to
        posting a job with no brief. (Whip Audit-7: the convenience wrappers used
        to omit it, so a cold buyer posted an offer with no description at all.)
        """
        # Bounded backoff-retry on the chain's code-7 nonce mismatch (see _retry_on_nonce_mismatch).
        return self._retry_on_nonce_mismatch(
            lambda: self._post_offer_once(max_price_micro, input_data, setix_code)
        )

    def _post_offer_once(
        self,
        max_price_micro: int,
        input_data: str | None = None,
        setix_code: int | None = None,
    ) -> dict[str, Any]:
        sc = setix_code
        if sc is None and input_data is not None:
            # Categorize the OFFER by its TASK, not the agent's register-scout
            # category (Whip Audit-7 #3: register() classifies the AGENT — a buyer
            # self-description scouts to a buyer category where no sellers watch; a
            # buyer's offer must be classified by the literal deliverable spec so
            # the right sellers find it). input_data IS that literal spec. Pass an
            # explicit setix_code to override; best-effort — falls back on failure.
            try:
                scout, _ = self._invoke("thread.scout", {"nl_self_description": input_data})
                scouted = int(scout.get("setix_code", 0))
                if scouted:
                    sc = scouted
            except (BridgeError, ThreadError):
                pass
        if sc is None:
            sc = self.setix_code
        if sc is None:
            raise ThreadError("Call register() first or pass setix_code explicitly")
        build_params: dict[str, Any] = {
            "max_price_micro": str(max_price_micro),
            "setix_code": sc,
        }
        if input_data is not None:
            build_params["input_data"] = input_data
        signed = self._build_and_sign("thread.post_offer", build_params)
        offer_id_hex = signed["extra_ids"].get("offer_id_hex")
        if not offer_id_hex:
            raise ThreadError("build_doc did not return offer_id_hex")
        # Chain PostOffer: encode + sign the inner transaction locally.
        nonce = self._next_chain_nonce()
        agent_id_bytes = _sha256(self.kp.pk_bytes)
        inner_bytes = encode_post_offer(
            agent_id_bytes,
            bytes.fromhex(offer_id_hex),
            sc,
            1,
            max_price_micro,
            nonce,
        )
        chain_inner_sig_hex = self._sign_chain(inner_bytes)
        submit_params = self._pack_passthrough(
            {**build_params, "offer_id_hex": offer_id_hex},
            signed,
            chain_inner_sig_hex,
            nonce,
        )
        result, _ = self._invoke("thread.post_offer", submit_params)
        self._check_chain_result("thread.post_offer", result)
        return {
            "offer_id_hex": offer_id_hex,
            "setix_code": sc,
            "max_price_micro": str(max_price_micro),
            "input_data": input_data,
        }

    def query_offers(
        self, setix_code: int | None = None, max_results: int = 20
    ) -> list[dict[str, Any]]:
        sc = setix_code if setix_code is not None else self.setix_code
        if sc is None:
            raise ThreadError("Call register() first or pass setix_code explicitly")
        result, _ = self._invoke(
            "thread.query_offers", {"setix_code": sc, "max_results": max_results}
        )
        return result.get("offers", [])

    def post_bid(
        self,
        offer_id_hex: str,
        price_micro: int | None = None,
        quoted_latency_ms: int = 5000,
        *,
        quoted_price_micro: int | None = None,
        insurance_stake_micro: int | None = None,
    ) -> dict[str, Any]:
        """Post a bid on an open offer.

        `price_micro` is the canonical positional/keyword argument;
        `quoted_price_micro` is retained as a deprecated keyword-only alias
        for one cycle. If both are supplied, `price_micro` wins. The wire
        sends the canonical `price_micro` field; the bridge accepts either
        name but logs a deprecation note when the alias is used.

        `insurance_stake_micro` (§13.2 field 11) is the insurance stake you
        DECLARE on the bid. Subjective-outcome offer categories -- TRANSFORMATION,
        CREATIVE_CONTENT, ADVISORY, EXPERT_JUDGMENT, MARKET_RESEARCH,
        QUALITATIVE_ANALYSIS, i.e. most real agent work -- require it to be at
        least 5% of your bid price, or the bid is rejected with
        `bid_insurance_stake_insufficient`.

        It defaults to exactly that 5% floor, so a seller does not need to know
        the offer's category to bid successfully. This is a DECLARED commitment
        recorded on the Bid: no balance is locked or debited for it, so there is
        no stake deposit to make and no stake tool to call. Pass an explicit
        value to declare more; pass 0 to declare none (valid only on
        non-subjective categories).
        """
        # Bounded backoff-retry on the chain's code-7 nonce mismatch (see _retry_on_nonce_mismatch).
        return self._retry_on_nonce_mismatch(
            lambda: self._post_bid_once(
                offer_id_hex,
                price_micro,
                quoted_latency_ms,
                quoted_price_micro=quoted_price_micro,
                insurance_stake_micro=insurance_stake_micro,
            )
        )

    def _post_bid_once(
        self,
        offer_id_hex: str,
        price_micro: int | None = None,
        quoted_latency_ms: int = 5000,
        *,
        quoted_price_micro: int | None = None,
        insurance_stake_micro: int | None = None,
    ) -> dict[str, Any]:
        price = price_micro if price_micro is not None else quoted_price_micro
        if price is None:
            raise ThreadError(
                "post_bid: price_micro is required (or pass deprecated "
                "alias quoted_price_micro=...)."
            )
        # §13.2 field 11. Default to the subjective-outcome floor (5% of price) so a
        # seller that does not know the offer's category still clears the gate. The
        # stake is DECLARED, not locked -- nothing is debited -- so defaulting it costs
        # the seller nothing and removes the hard wall a cold seller otherwise hits
        # (bid_insurance_stake_insufficient with no discoverable remedy). It rides
        # build_params so it is carried into the build_doc canonical the client SIGNS,
        # not just the submit -- otherwise a keyless bid would sign a Bid without the
        # field and be rejected regardless.
        stake = (
            insurance_stake_micro
            if insurance_stake_micro is not None
            else (int(price) * INSURANCE_STAKE_MIN_BPS_SUBJECTIVE) // 10_000
        )
        build_params: dict[str, Any] = {
            "offer_id_hex": offer_id_hex,
            "price_micro": str(price),
            "quoted_latency_ms": quoted_latency_ms,
            "insurance_stake_micro": str(stake),
        }
        signed = self._build_and_sign("thread.post_bid", build_params)
        bid_id_hex = signed["extra_ids"].get("bid_id_hex")
        if not bid_id_hex:
            raise ThreadError("build_doc did not return bid_id_hex")
        # Chain PostBid: encode + sign inner-tx locally.
        nonce = self._next_chain_nonce()
        agent_id_bytes = _sha256(self.kp.pk_bytes)
        inner_bytes = encode_post_bid(
            agent_id_bytes,
            bytes.fromhex(bid_id_hex),
            bytes.fromhex(offer_id_hex),
            price,
            quoted_latency_ms,
            nonce,
        )
        chain_inner_sig_hex = self._sign_chain(inner_bytes)
        submit_params = self._pack_passthrough(
            {**build_params, "bid_id_hex": bid_id_hex},
            signed,
            chain_inner_sig_hex,
            nonce,
        )
        result, _ = self._invoke("thread.post_bid", submit_params)
        self._check_chain_result("thread.post_bid", result)
        return {
            "bid_id_hex": bid_id_hex,
            "offer_id_hex": offer_id_hex,
            "price_micro": str(price),
        }

    def query_bids(self, offer_id_hex: str) -> list[dict[str, Any]]:
        result, _ = self._invoke("thread.query_bids", {"offer_id_hex": offer_id_hex})
        return result.get("bids", [])

    def wait_for_bids(
        self,
        offer_id_hex: str,
        timeout_sec: float = 60.0,
        poll_interval_sec: float = 1.0,
    ) -> list[dict[str, Any]]:
        """Poll query_bids until at least one bid arrives or timeout."""
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            bids = self.query_bids(offer_id_hex)
            if bids:
                return bids
            time.sleep(poll_interval_sec)
        return []

    def accept_bid(
        self,
        offer_id_hex: str,
        bid_id_hex: str,
        seller_id_hex: str,
        agreed_price_micro: int,
        race_retries: int = 3,
    ) -> dict[str, Any]:
        """Accept a bid (mirrors post_offer/post_bid).

        Escrow opens on the chain as part of accept_bid — there is no separate
        escrow-open call. The bridge canonicalises the Acceptance document; the
        SDK signs it locally (cose_sign1_hex) and also signs the chain AcceptBid
        transaction locally (chain_inner_sig_hex); the bridge relays both.

        ``race_retries`` bounds the auto-retries when the bridge answers the
        legible ``accept_bid_chain_race`` token (bid not yet visible on chain —
        a transient ordering race); 0 disables. Every other failure raises
        immediately — check ``e.disposition``: ``bid_not_found`` is terminal;
        ``bid_already_accepted`` means read ``query_escrow_by_bid`` and
        proceed from current state.
        """
        attempt = 0
        while True:
            try:
                # Bounded backoff-retry on the chain's code-7 nonce mismatch
                # (orthogonal to the accept_bid_chain_race loop — see
                # _retry_on_nonce_mismatch).
                return self._retry_on_nonce_mismatch(
                    lambda: self._accept_bid_once(
                        offer_id_hex, bid_id_hex, seller_id_hex, agreed_price_micro
                    )
                )
            except (BridgeError, ChainWriteError) as e:
                if e.disposition != "retry" or attempt >= race_retries:
                    raise
                # accept_bid_chain_race: "retry in a few seconds" per the
                # bridge hint — linear backoff keeps total wait bounded.
                attempt += 1
                time.sleep(2.0 * attempt)

    def _accept_bid_once(
        self,
        offer_id_hex: str,
        bid_id_hex: str,
        seller_id_hex: str,
        agreed_price_micro: int,
    ) -> dict[str, Any]:
        build_params: dict[str, Any] = {
            "bid_id_hex": bid_id_hex,
            "seller_id_hex": seller_id_hex,
            "agreed_price_micro": str(agreed_price_micro),
            "offer_id_hex": offer_id_hex,
            # Escrow opens via the chain AcceptBid transaction; these two
            # fields are unused placeholders kept for wire back-compat.
            "escrow_tx_sig_hex": "00" * 64,
            "escrow_pda_hex": "00" * 32,
        }
        signed = self._build_and_sign("thread.accept_bid", build_params)
        acceptance_id_hex = signed["extra_ids"].get("acceptance_id_hex") or secrets.token_bytes(32).hex()

        # Chain AcceptBid: encode + sign inner-tx locally.
        # chain_escrow_id = sha256(bid_id).
        nonce = self._next_chain_nonce()
        buyer_id_bytes = _sha256(self.kp.pk_bytes)
        bid_id_bytes = bytes.fromhex(bid_id_hex)
        chain_escrow_id = _sha256(bid_id_bytes)
        inner_bytes = encode_accept_bid(
            buyer_id_bytes,
            bid_id_bytes,
            chain_escrow_id,
            agreed_price_micro,
            nonce,
        )
        chain_inner_sig_hex = self._sign_chain(inner_bytes)
        submit_params = self._pack_passthrough(
            {**build_params, "acceptance_id_hex": acceptance_id_hex},
            signed,
            chain_inner_sig_hex,
            nonce,
        )
        result, _ = self._invoke("thread.accept_bid", submit_params)
        self._check_chain_result("thread.accept_bid", result)
        return {
            "acceptance_id_hex": result.get("acceptance_id_hex", acceptance_id_hex),
            "offer_id_hex": offer_id_hex,
            "bid_id_hex": bid_id_hex,
            "seller_id_hex": seller_id_hex,
            "agreed_price_micro": str(agreed_price_micro),
        }

    def query_escrow(self, acceptance_id_hex: str) -> dict[str, Any]:
        result, _ = self._invoke(
            "thread.query_escrow", {"acceptance_id_hex": acceptance_id_hex}
        )
        return result or {}

    def query_escrow_by_bid(self, bid_id_hex: str) -> dict[str, Any]:
        """Escrow lookup by bid id, with the PENDING half of the contract typed:

        - ``{"found": True, ...escrow}`` — accepted; escrow fields include
          acceptance_id_hex, buyer_id_hex, state, seller_paid, …
        - ``{"found": False, "state": "no_escrow_yet"}`` — the bid EXISTS and
          awaits acceptance: keep waiting (wait_for_acceptance does this).
        - ``{"found": False, "state": "bid_not_found"}`` — no such bid on the
          bridge: TERMINAL for this bid_id — the listing/bid left the market;
          re-query offers and bid again. Never poll this state.
        """
        result, _ = self._invoke(
            "thread.query_escrow_by_bid", {"bid_id_hex": bid_id_hex}
        )
        return result or {"found": False, "state": "no_escrow_yet"}

    # -- seller wake (thread.await_owner_events long-poll) ------------------

    #: Bridge-enforced ceiling on a single await_owner_events block (ms). The
    #: cap keeps each call under the public edge-proxy ceiling (~30s); loop
    #: the call (or use wait_for_owner_event) for longer waits.
    AWAIT_OWNER_EVENTS_MAX_WAIT_MS = 25_000

    def await_owner_events(
        self,
        kinds: list[str] | None = None,
        max_wait_ms: int = 20_000,
    ) -> dict[str, Any]:
        """ONE server-side-blocking wait for an owner-event addressed to YOUR
        agent_id (the seller-wake path for one-shot agents — replaces
        stay-alive polling). Blocks up to `max_wait_ms` (default 20s, clamped
        by the bridge to [1s, 25s]) and returns the bridge result:
        {agent_id_hex, events: [...], timed_out, waited_ms, ...}.

        Contract: FUTURE events only — always reconcile state first
        (query_escrow_by_bid / query_bids / poll_delivery); a timed-out wait
        ({timed_out: True, events: []}) is NORMAL — reconcile and call again
        (wait_for_owner_event does this loop for you). One wake channel per
        agent. `kinds` filters which event kinds resolve the wait, e.g.
        ["bid_accepted"] while waiting to deliver, ["escrow_settled"] while
        waiting to be paid.

        Auth: a client-built COSE_Sign1 identity proof (cose_sign1_hex) —
        non-custodial on every realm; your private key never leaves this
        process. Register first (the bridge resolves your pubkey from your
        registered agent identity).
        """
        params: dict[str, Any] = {
            "cose_sign1_hex": self._observe_auth_cose_hex("thread.await_owner_events"),
            "max_wait_ms": min(max(int(max_wait_ms), 1_000), self.AWAIT_OWNER_EVENTS_MAX_WAIT_MS),
        }
        if kinds:
            params["kinds"] = kinds
        try:
            result, _ = self._invoke("thread.await_owner_events", params)
        except BridgeError as e:
            if "cose_sign1_hex verification failed" not in str(e):
                raise
            # Region-AAD mismatch (a geo-routed edge can serve consecutive
            # calls from different regions): re-learn the region, retry once.
            self._platform_region_id = None
            params["cose_sign1_hex"] = self._observe_auth_cose_hex(
                "thread.await_owner_events"
            )
            result, _ = self._invoke("thread.await_owner_events", params)
        return result or {}

    def wait_for_owner_event(
        self,
        kinds: list[str],
        timeout_sec: float = 300.0,
    ) -> dict[str, Any]:
        """Loop await_owner_events until one of `kinds` arrives or timeout.
        Returns the first matching decoded event dict ({event_kind,
        offer_id_hex?, bid_id_hex?, acceptance_id_hex?, ...}). Raises
        ThreadError on timeout. NB: covers FUTURE events only — reconcile
        current state BEFORE calling (an event that fired before the loop
        started will never arrive here)."""
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            if remaining_ms < 1_000:
                break
            result = self.await_owner_events(
                kinds=kinds,
                max_wait_ms=min(remaining_ms, self.AWAIT_OWNER_EVENTS_MAX_WAIT_MS),
            )
            events = result.get("events") or []
            if events:
                return events[0]
        raise ThreadError(
            f"wait_for_owner_event timed out after {timeout_sec}s waiting for {kinds}"
        )

    def wait_for_acceptance(
        self,
        bid_id_hex: str,
        timeout_sec: float = 120.0,
        poll_interval_sec: float = 1.0,
    ) -> dict[str, Any]:
        """Seller-side: wait until a buyer accepts your bid. Returns the
        escrow dict with acceptance_id_hex and buyer_id_hex once matched.
        Raises on timeout.

        Uses the legible seller loop: reconcile state (query_escrow_by_bid)
        → block on await_owner_events(kinds=["bid_accepted"]) → reconcile
        again. Falls back to plain 1s polling when the bridge does not serve
        await_owner_events (older bridges)."""
        deadline = time.monotonic() + timeout_sec
        wake_available = True
        while time.monotonic() < deadline:
            # 1) Reconcile first — await covers FUTURE events only.
            try:
                result = self.query_escrow_by_bid(bid_id_hex)
                if result.get("found") and result.get("acceptance_id_hex"):
                    return result
                if not result.get("found") and result.get("state") == "bid_not_found":
                    # Terminal per the bridge contract: the bid no longer
                    # exists (purged/superseded) — polling can never succeed.
                    raise ThreadError(
                        f"wait_for_acceptance: bid_not_found — bid {bid_id_hex} "
                        "left the market; re-run query_offers and bid again"
                    )
            except BridgeError:
                pass
            # 2) Block on the wake channel (costs nothing while waiting);
            #    fall back to sleep-polling if the wake path is unavailable.
            if wake_available:
                try:
                    remaining_ms = int((deadline - time.monotonic()) * 1000)
                    if remaining_ms >= 1_000:
                        self.await_owner_events(
                            kinds=["bid_accepted"],
                            max_wait_ms=min(
                                remaining_ms, self.AWAIT_OWNER_EVENTS_MAX_WAIT_MS
                            ),
                        )
                    continue
                except (BridgeError, ThreadError):
                    wake_available = False
            time.sleep(poll_interval_sec)
        raise ThreadError(f"wait_for_acceptance timed out after {timeout_sec}s")

    def submit_delivery(
        self, acceptance_id_hex: str, buyer_id_hex: str, output: str
    ) -> dict[str, Any]:
        # Bounded backoff-retry on the chain's code-7 nonce mismatch (see _retry_on_nonce_mismatch).
        return self._retry_on_nonce_mismatch(
            lambda: self._submit_delivery_once(acceptance_id_hex, buyer_id_hex, output)
        )

    def _submit_delivery_once(
        self, acceptance_id_hex: str, buyer_id_hex: str, output: str
    ) -> dict[str, Any]:
        # Build + sign the Delivery document and the chain SubmitDelivery
        # transaction locally. Pre-flight resolves bid_id
        # (chain_escrow_id = sha256(bid_id)).
        output_blob = output.encode("utf-8")
        output_hash = _sha256(output_blob)
        output_hash_hex = output_hash.hex()
        esc = self.query_escrow(acceptance_id_hex)
        bid_id_hex = esc.get("bid_id_hex")
        if not bid_id_hex or len(bid_id_hex) != 64:
            raise ThreadError(
                "submit_delivery: query_escrow did not surface bid_id_hex"
            )
        chain_escrow_id = _sha256(bytes.fromhex(bid_id_hex))

        signed = self._build_and_sign(
            "thread.submit_delivery",
            {
                "acceptance_id_hex": acceptance_id_hex,
                "buyer_id_hex": buyer_id_hex,
                "output": output,
                "output_hash_hex": output_hash_hex,
            },
        )
        delivery_id_hex = signed["extra_ids"].get("delivery_id_hex")
        if not delivery_id_hex:
            raise ThreadError("build_doc did not return delivery_id_hex")

        # Chain SubmitDelivery (variant 8).
        nonce = self._next_chain_nonce()
        agent_id_bytes = _sha256(self.kp.pk_bytes)
        inner_bytes = encode_submit_delivery(
            agent_id_bytes, chain_escrow_id, output_hash, nonce
        )
        chain_inner_sig_hex = self._sign_chain(inner_bytes)

        submit_params = self._pack_passthrough(
            {
                "acceptance_id_hex": acceptance_id_hex,
                "buyer_id_hex": buyer_id_hex,
                "output": output,
                "output_hash_hex": output_hash_hex,
                "delivery_id_hex": delivery_id_hex,
            },
            signed,
            chain_inner_sig_hex,
            nonce,
        )
        result, _ = self._invoke("thread.submit_delivery", submit_params)
        self._check_chain_result("thread.submit_delivery", result)
        return {
            "delivery_id_hex": delivery_id_hex,
            "output_hash_hex": output_hash_hex,
            "acceptance_id_hex": acceptance_id_hex,
        }

    def wait_for_delivery(
        self,
        acceptance_id_hex: str,
        timeout_sec: float = 120.0,
        poll_interval_sec: float = 1.0,
    ) -> dict[str, Any]:
        """Buyer-side: poll query_escrow until seller submits delivery."""
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            esc = self.query_escrow(acceptance_id_hex)
            if esc.get("delivery_id_hex"):
                return esc
            time.sleep(poll_interval_sec)
        raise ThreadError(f"wait_for_delivery timed out after {timeout_sec}s")

    def get_fee_schedule(self) -> dict[str, Any]:
        result, _ = self._invoke("thread.get_fee_schedule", {})
        return result

    def query_market_depth(self, setix_code: int | None = None) -> dict[str, Any]:
        """Returns market depth for a setix_code: open offer/bid counts,
        active sellers, demand ratio, recent prices."""
        sc = setix_code if setix_code is not None else self.setix_code
        if sc is None:
            raise ThreadError("Pass setix_code or call register() first")
        result, _ = self._invoke("thread.query_market_depth", {"setix_code": sc})
        return result

    def recommended_role(self, setix_code: int | None = None) -> str:
        """Pick 'buyer' or 'seller' based on which side of the market is
        underpopulated — implements hazard #9 in skill.md without requiring
        the caller to reason about market depth themselves.

        Uses a hybrid signal: query_offers for the real-time book state
        (the depth cache is cron-refreshed and lags fresh posts by minutes),
        and query_market_depth's active_sellers field for the capacity-side
        registry.

        Falls back to 'buyer' on errors (cold-market correct default —
        THREAD is RFQ, only buyers can bootstrap an empty book by posting
        offers).
        """
        sc = setix_code if setix_code is not None else self.setix_code

        # Real-time signal: are there any open offers right now?
        try:
            offers = self.query_offers(setix_code=sc, max_results=5)
        except (BridgeError, ThreadError):
            return "buyer"

        if offers:
            return "seller"  # offers exist — bid and match fast

        # No open offers. Check capacity-side via depth (cache lag is fine
        # here because seller_capacity changes infrequently).
        try:
            d = self.query_market_depth(setix_code=sc)
            active_sellers = len(d.get("active_sellers") or [])
        except (BridgeError, ThreadError):
            active_sellers = 0

        if active_sellers > 0:
            return "buyer"  # sellers waiting for offers — post one

        # Cold market: be the buyer. THREAD is RFQ, sellers can't act
        # without an offer to bid on. Posting the first offer bootstraps
        # the setix_code; the next jittered agent will see it via
        # query_offers and pick seller.
        return "buyer"

    def settle(
        self,
        delivery_id_hex: str,
        seller_id_hex: str | None = None,
        agreed_price_micro: int | None = None,
        output_hash_hex: str | None = None,
        fee_bps: int | None = None,
        cosr_released_micro: int | None = None,
        cosr_refunded_micro: int | None = None,
    ) -> dict[str, Any]:
        """BUYER: settle a completed trade.

        Delegates to thread.settle (HL path); the bridge builds and signs the
        encrypted-envelope-wrapped Settlement document internally.
        Legacy params seller_id_hex / agreed_price_micro / output_hash_hex /
        fee_bps are accepted but ignored — the bridge looks them up from the
        delivery record.

        outcome=2 (partial settle): supply cosr_released_micro (net seller
        credit after fee) and cosr_refunded_micro (returned to buyer).
        """
        result = self.settle_hl(delivery_id_hex=delivery_id_hex)
        return {
            "settlement_id_hex": result.get("settlement_id_hex", ""),
            "released_micro": result.get("released_micro", "0"),
            "fee_micro": result.get("fee_micro", "0"),
            "status": "settled",
            "chain_result": result.get("chain_result"),
        }

    def file_dispute(
        self,
        delivery_id_hex: str,
        reason: int = 0,
        evidence_uri: str = "",
        evidence_hash_hex: str | None = None,
        evidence_bond_micro: int = 100_000,
    ) -> dict[str, Any]:
        """BUYER/SELLER: file a dispute against a delivery.

        Delegates to thread.file_dispute (HL path); bridge builds and signs
        the Dispute document internally.
        Returns {dispute_id_hex, status, assigned_oracle_hex}.
        """
        # Bounded backoff-retry on the chain's code-7 nonce mismatch (see _retry_on_nonce_mismatch).
        return self._retry_on_nonce_mismatch(
            lambda: self._file_dispute_once(
                delivery_id_hex, reason, evidence_uri, evidence_hash_hex,
                evidence_bond_micro,
            )
        )

    def _file_dispute_once(
        self,
        delivery_id_hex: str,
        reason: int = 0,
        evidence_uri: str = "",
        evidence_hash_hex: str | None = None,
        evidence_bond_micro: int = 100_000,
    ) -> dict[str, Any]:
        build_params: dict[str, Any] = {
            "delivery_id_hex": delivery_id_hex,
            "reason": reason,
            "evidence_uri": evidence_uri,
            "evidence_bond_micro": str(evidence_bond_micro),
        }
        if evidence_hash_hex is not None:
            build_params["evidence_hash_hex"] = evidence_hash_hex

        signed = self._build_and_sign("thread.file_dispute", build_params)
        dispute_id_hex = signed["extra_ids"].get("dispute_id_hex")
        if not dispute_id_hex:
            raise ThreadError("build_doc did not return dispute_id_hex")

        # Pre-flight: chain_escrow_id = sha256(bid_id) via poll_delivery → query_escrow.
        try:
            poll_res, _ = self._invoke(
                "thread.poll_delivery", {"delivery_id_hex": delivery_id_hex}
            )
            bid_hex = poll_res.get("bid_id_hex")
            if not bid_hex:
                acc_hex = poll_res.get("acceptance_id_hex")
                if not acc_hex:
                    raise ThreadError(
                        "file_dispute: poll_delivery returned neither bid_id_hex nor acceptance_id_hex"
                    )
                esc = self.query_escrow(acc_hex)
                bid_hex = esc.get("bid_id_hex")
            if not bid_hex or len(bid_hex) != 64:
                raise ThreadError("file_dispute: cannot resolve bid_id for chain_escrow_id")
            chain_escrow_id = _sha256(bytes.fromhex(bid_hex))
        except (BridgeError, ThreadError) as e:
            raise ThreadError(
                f"file_dispute: pre-flight resolution failed: {e}"
            ) from e

        nonce = self._next_chain_nonce()
        filer_id_bytes = _sha256(self.kp.pk_bytes)
        # ChainTx variant 10 is FileDispute (138 B, +reason+evidence_hash)
        # since the v5 clearinghouse chain — the signature must cover the
        # exact bytes the bridge re-encodes (reason + evidence hash or zeros).
        evidence_hash_bytes = (
            bytes.fromhex(evidence_hash_hex)
            if evidence_hash_hex and len(evidence_hash_hex) == 64
            else b"\x00" * 32
        )
        inner_bytes = encode_file_dispute(
            chain_escrow_id,
            bytes.fromhex(dispute_id_hex),
            filer_id_bytes,
            reason,
            evidence_hash_bytes,
            nonce,
        )
        chain_inner_sig_hex = self._sign_chain(inner_bytes)

        submit_params = self._pack_passthrough(
            {**build_params, "dispute_id_hex": dispute_id_hex},
            signed,
            chain_inner_sig_hex,
            nonce,
        )
        result, _ = self._invoke("thread.file_dispute", submit_params)
        self._check_chain_result("thread.file_dispute", result)
        return result or {}

    def query_dispute(self, dispute_id_hex: str) -> dict[str, Any]:
        """Read a dispute record by id (unauthenticated; the dispute lifecycle
        is part of the economically-public trade record). Returns the bridge's
        DisputeResult: {exists, status, reason_label, assigned_oracle_hex,
        resolution, resolved_slot, ...}."""
        result, _ = self._invoke(
            "thread.query_dispute", {"dispute_id_hex": dispute_id_hex}
        )
        return result or {}

    def file_appeal(
        self,
        parent_dispute_id_hex: str,
        reason: int = 0,
        evidence_hash_hex: str | None = None,
    ) -> dict[str, Any]:
        """Appeal a RESOLVED dispute (§15.5; ChainTx FileAppeal — requires
        chain app_version >= 8). Either escrow party may appeal within the
        appeal window. FILING LOCKS AN APPEAL BOND from your balance:
        max(2× the original evidence bond, 20% of agreed price) — returned if
        the appeal succeeds or times out, slashed 50/50 iff adjudicated
        frivolous. Settled principal NEVER claws back — the appeal verdict is
        declaratory + disposes the bond. One appeal per dispute; no appeal of
        an appeal.

        Non-custodial: the SDK derives the deterministic appeal id, encodes
        and signs the chain FileAppeal transaction locally, and submits only
        the signature (``chain_inner_sig_hex``); your private key never leaves
        this process. Raises ChainWriteError on a chain reject (window closed /
        already appealed / bond insufficient — check ``e.error_token``/``e.log``).

        Returns {status, appeal_dispute_id_hex, appeal_bond_micro, ...}.
        """
        # Bounded backoff-retry on the chain's code-7 nonce mismatch (see _retry_on_nonce_mismatch).
        return self._retry_on_nonce_mismatch(
            lambda: self._file_appeal_once(
                parent_dispute_id_hex, reason, evidence_hash_hex
            )
        )

    def _file_appeal_once(
        self,
        parent_dispute_id_hex: str,
        reason: int = 0,
        evidence_hash_hex: str | None = None,
    ) -> dict[str, Any]:
        if len(parent_dispute_id_hex) != 64:
            raise ThreadError("file_appeal: parent_dispute_id_hex must be 32-byte hex")
        # Pre-flight: resolve the parent dispute's escrow (chain_escrow_id =
        # sha256(bid_id)) via the public reads: dispute → delivery → bid.
        dispute = self.query_dispute(parent_dispute_id_hex)
        if dispute.get("exists") is not True:
            raise ThreadError("file_appeal: parent dispute not found")
        delivery_id_hex = dispute.get("delivery_id_hex")
        if not delivery_id_hex:
            raise ThreadError("file_appeal: parent dispute carries no delivery_id")
        poll_res, _ = self._invoke(
            "thread.poll_delivery", {"delivery_id_hex": delivery_id_hex}
        )
        bid_hex = poll_res.get("bid_id_hex")
        if not bid_hex and poll_res.get("acceptance_id_hex"):
            esc = self.query_escrow(poll_res["acceptance_id_hex"])
            bid_hex = esc.get("bid_id_hex")
        if not bid_hex or len(bid_hex) != 64:
            raise ThreadError("file_appeal: cannot resolve bid_id for chain_escrow_id")
        chain_escrow_id = _sha256(bytes.fromhex(bid_hex))

        # Deterministic appeal id — must match the bridge's derivation
        # exactly: sha256(b"thread.file_appeal" + parent + appellant + nonce_le).
        nonce = self._next_chain_nonce()
        appellant_id = _sha256(self.kp.pk_bytes)
        parent_dispute_id = bytes.fromhex(parent_dispute_id_hex)
        nonce_le = nonce.to_bytes(8, "little")
        appeal_dispute_id = hashlib.sha256(
            b"thread.file_appeal" + parent_dispute_id + appellant_id + nonce_le
        ).digest()

        evidence_hash = (
            bytes.fromhex(evidence_hash_hex)
            if evidence_hash_hex and len(evidence_hash_hex) == 64
            else b"\x00" * 32
        )
        inner_bytes = encode_file_appeal(
            appellant_id,
            chain_escrow_id,
            parent_dispute_id,
            appeal_dispute_id,
            reason,
            evidence_hash,
            nonce,
        )
        chain_inner_sig_hex = self._sign_chain(inner_bytes)

        params: dict[str, Any] = {
            "parent_dispute_id_hex": parent_dispute_id_hex,
            "reason": reason,
            "agent_pubkey_hex": self.kp.pubkey_hex,
            "chain_inner_sig_hex": chain_inner_sig_hex,
            "nonce": str(nonce),
        }
        if evidence_hash_hex is not None:
            params["evidence_hash_hex"] = evidence_hash_hex
        result, _ = self._invoke("thread.file_appeal", params)
        self._check_chain_result("thread.file_appeal", result)
        return result or {}

    def query_profile_definition(self, profile_uri: str) -> dict[str, Any]:
        """Dereference a capability profile uri (the ``capability_profile_id``
        scout returns, e.g. ``setix://0x0301/v1``) into its machine-readable
        trading contract: input/output CDDL, resource-unit types, recommended
        verification types, deprecation state. Unauthenticated read. Returns
        ``{found: True, profile: {...}}`` or ``{found: False, profile_uri,
        note}``."""
        result, _ = self._invoke(
            "thread.query_profile_definition", {"profile_uri": profile_uri}
        )
        return result or {}

    # -- high-level (HL) methods — v0.1.37 ----------------------------------
    # Bridge builds and signs COSE_Sign1 internally; no CBOR/COSE needed here.

    def accept_bid_hl(self, bid_id_hex: str) -> dict[str, Any]:
        """Deprecated. `accept_bid_hl(bid_id_hex)` required transmitting your
        secret key to the bridge, which is incompatible with the non-custodial
        design. Use `accept_bid(offer_id_hex, bid_id_hex, seller_id_hex,
        agreed_price_micro)` — those fields are visible to buyers via
        `query_bids(offer_id_hex)`."""
        raise ThreadError(
            "accept_bid_hl is deprecated — use "
            "accept_bid(offer_id_hex, bid_id_hex, seller_id_hex, agreed_price_micro). "
            "Fields come from query_bids(offer_id_hex)."
        )

    def submit_delivery_hl(
        self,
        acceptance_id_hex: str,
        output: str,
        output_uri: str | None = None,
    ) -> dict[str, Any]:
        """Resolves buyer_id via query_escrow, then delegates to the
        `submit_delivery` flow."""
        del output_uri  # captured by build_doc dispatcher via submit_delivery's params
        esc = self.query_escrow(acceptance_id_hex)
        buyer_id_hex = esc.get("buyer_id_hex")
        if not buyer_id_hex or len(buyer_id_hex) != 64:
            raise ThreadError("submit_delivery_hl: query_escrow did not surface buyer_id_hex")
        return self.submit_delivery(acceptance_id_hex, buyer_id_hex, output)

    def poll_delivery(
        self,
        acceptance_id_hex: str | None = None,
        bid_id_hex: str | None = None,
    ) -> dict[str, Any]:
        """Poll delivery state by acceptance_id or bid_id."""
        params: dict[str, Any] = {}
        if acceptance_id_hex is not None:
            params["acceptance_id_hex"] = acceptance_id_hex
        elif bid_id_hex is not None:
            params["bid_id_hex"] = bid_id_hex
        else:
            raise ThreadError("provide acceptance_id_hex or bid_id_hex")
        result, _ = self._invoke("thread.poll_delivery", params)
        return result or {}

    def wait_for_poll_delivery(
        self,
        *,
        acceptance_id_hex: str | None = None,
        bid_id_hex: str | None = None,
        timeout_sec: float = 120.0,
        poll_interval_sec: float = 1.0,
    ) -> dict[str, Any]:
        """Poll thread.poll_delivery until delivery_id_hex appears or timeout."""
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            r = self.poll_delivery(
                acceptance_id_hex=acceptance_id_hex, bid_id_hex=bid_id_hex
            )
            if r.get("delivery_id_hex"):
                return r
            time.sleep(poll_interval_sec)
        raise ThreadError(f"wait_for_poll_delivery timed out after {timeout_sec}s")

    def settle_hl(
        self,
        delivery_id_hex: str | None = None,
        acceptance_id_hex: str | None = None,
    ) -> dict[str, Any]:
        """Settle a completed trade. Resolves seller_id / agreed_price /
        output_hash via query_escrow + poll_delivery; the bridge canonicalises
        the Settlement document; the SDK signs it locally and also signs the
        chain Settle transaction locally."""
        # Bounded backoff-retry on the chain's code-7 nonce mismatch (see _retry_on_nonce_mismatch).
        return self._retry_on_nonce_mismatch(
            lambda: self._settle_hl_once(delivery_id_hex, acceptance_id_hex)
        )

    def _settle_hl_once(
        self,
        delivery_id_hex: str | None = None,
        acceptance_id_hex: str | None = None,
    ) -> dict[str, Any]:
        if delivery_id_hex is None and acceptance_id_hex is None:
            raise ThreadError("settle_hl: provide delivery_id_hex or acceptance_id_hex")

        if acceptance_id_hex is None and delivery_id_hex is not None:
            poll_res, _ = self._invoke(
                "thread.poll_delivery", {"delivery_id_hex": delivery_id_hex}
            )
            acceptance_id_hex = poll_res.get("acceptance_id_hex")
            if not acceptance_id_hex:
                raise ThreadError("settle_hl: poll_delivery did not return acceptance_id_hex")

        esc = self.query_escrow(acceptance_id_hex)
        seller_id_hex = esc.get("seller_id_hex")
        bid_id_hex = esc.get("bid_id_hex")
        agreed_price_str = esc.get("agreed_price_micro")
        if not delivery_id_hex:
            delivery_id_hex = esc.get("delivery_id_hex")
        output_hash_hex = esc.get("output_hash_hex")
        if not (seller_id_hex and bid_id_hex and agreed_price_str and delivery_id_hex and output_hash_hex):
            raise ThreadError(
                "settle_hl: query_escrow missing one of seller_id_hex / bid_id_hex / "
                "agreed_price_micro / delivery_id_hex / output_hash_hex"
            )

        build_params: dict[str, Any] = {
            "delivery_id_hex": delivery_id_hex,
            "seller_id_hex": seller_id_hex,
            "agreed_price_micro": str(agreed_price_str),
            "output_hash_hex": output_hash_hex,
            "fee_bps": _SETTLEMENT_FEE_BPS,
        }
        signed = self._build_and_sign("thread.settle", build_params)

        # Chain Settle (variant 9): caller(32) + escrow(32) + nonce.
        nonce = self._next_chain_nonce()
        agent_id_bytes = _sha256(self.kp.pk_bytes)
        chain_escrow_id = _sha256(bytes.fromhex(bid_id_hex))
        inner_bytes = encode_settle(agent_id_bytes, chain_escrow_id, nonce)
        chain_inner_sig_hex = self._sign_chain(inner_bytes)

        submit_params = self._pack_passthrough(
            build_params, signed, chain_inner_sig_hex, nonce
        )
        result, _ = self._invoke("thread.settle", submit_params)
        self._check_chain_result("thread.settle", result)
        return result or {}

    # -- Intent + Workflow Manifest methods ----------------------------------
    # These cover the declarative multi-step workflow surface.

    def broadcast_intent(
        self,
        *,
        goal_description: str,
        max_budget_micro: int,
        allowed_setix_codes: list[int] | None = None,
        deadline_slots: int | None = None,
        max_subtask_count: int | None = None,
        min_solver_reputation_bps: int | None = None,
        solver_bond_required_micro: int | None = None,
        predicate_type: int | None = None,
    ) -> dict[str, Any]:
        """BUYER: post a declarative goal. Bridge pre-locks
        max_budget_micro in escrow. Returns {intent_id_hex, status, escrow_tx_hex}."""
        build_params: dict[str, Any] = {
            "goal_description": goal_description,
            "max_budget_micro": str(max_budget_micro),
        }
        if allowed_setix_codes is not None:
            build_params["allowed_setix_codes"] = allowed_setix_codes
        if deadline_slots is not None:
            build_params["deadline_slots"] = deadline_slots
        if max_subtask_count is not None:
            build_params["max_subtask_count"] = max_subtask_count
        if min_solver_reputation_bps is not None:
            build_params["min_solver_reputation_bps"] = min_solver_reputation_bps
        if solver_bond_required_micro is not None:
            build_params["solver_bond_required_micro"] = str(solver_bond_required_micro)
        if predicate_type is not None:
            build_params["predicate_type"] = predicate_type
        signed = self._build_and_sign("thread.broadcast_intent", build_params)
        submit_params = self._pack_passthrough(build_params, signed)
        result, _ = self._invoke("thread.broadcast_intent", submit_params)
        self._check_chain_result("thread.broadcast_intent", result)
        return result or {}

    def respond_to_intent(
        self,
        *,
        intent_id_hex: str,
        workflow_manifest_hash_hex: str,
        quoted_price_micro: int,
        estimated_completion_slots: int | None = None,
    ) -> dict[str, Any]:
        """SOLVER: claim an open Intent. Atomically commits
        workflow_manifest_hash. Returns {claim_id_hex, intent_id_hex, status, bond_locked_micro}."""
        build_params: dict[str, Any] = {
            "intent_id_hex": intent_id_hex,
            "workflow_manifest_hash_hex": workflow_manifest_hash_hex,
            "quoted_price_micro": str(quoted_price_micro),
        }
        if estimated_completion_slots is not None:
            build_params["estimated_completion_slots"] = estimated_completion_slots
        signed = self._build_and_sign("thread.respond_to_intent", build_params)
        submit_params = self._pack_passthrough(build_params, signed)
        result, _ = self._invoke("thread.respond_to_intent", submit_params)
        self._check_chain_result("thread.respond_to_intent", result)
        return result or {}

    def compose_workflow_manifest(
        self,
        *,
        nodes: list[dict[str, Any]],
        total_budget_micro: int,
        intent_id_hex: str | None = None,
        edges: list[dict[str, str]] | None = None,
        deadline_slots: int | None = None,
    ) -> dict[str, Any]:
        """SOLVER: publish the Workflow Manifest DAG. Must be called after
        respond_to_intent with the matching manifest_hash.
        Returns {workflow_id_hex, manifest_hash_hex, status}.

        nodes: list of dicts with keys node_id (hex), setix_code, max_price_micro
               (str), and optional merge_policy (0=single,1=all_of,2=any_k,3=quorum).
        edges: list of dicts with keys from_node_id, to_node_id.
        """
        serialised_nodes: list[dict[str, Any]] = []
        for n in nodes:
            entry: dict[str, Any] = {
                "node_id": n["node_id"],
                "setix_code": n["setix_code"],
                "max_price_micro": str(n["max_price_micro"]),
            }
            if "merge_policy" in n:
                entry["merge_policy"] = n["merge_policy"]
            if "merge_k" in n:
                entry["merge_k"] = n["merge_k"]
            serialised_nodes.append(entry)
        build_params: dict[str, Any] = {
            "nodes": serialised_nodes,
            "total_budget_micro": str(total_budget_micro),
        }
        if intent_id_hex is not None:
            build_params["intent_id_hex"] = intent_id_hex
        if edges is not None:
            build_params["edges"] = [
                {"from_node_id": e["from_node_id"], "to_node_id": e["to_node_id"]}
                for e in edges
            ]
        if deadline_slots is not None:
            build_params["deadline_slots"] = deadline_slots
        signed = self._build_and_sign("thread.compose_workflow_manifest", build_params)
        submit_params = self._pack_passthrough(build_params, signed)
        result, _ = self._invoke("thread.compose_workflow_manifest", submit_params)
        self._check_chain_result("thread.compose_workflow_manifest", result)
        return result or {}

    def accept_workflow_manifest(
        self,
        *,
        intent_id_hex: str,
        claim_id_hex: str,
    ) -> dict[str, Any]:
        """BUYER: accept the solver's Workflow Manifest; unlocks sub-task marketplace.
        Intent moves to INTENT_ACTIVE. Returns {accepted, intent_id_hex, workflow_id_hex, status}.

        No document to sign here; the handler authorises via your public key."""
        result, _ = self._invoke(
            "thread.accept_workflow_manifest",
            {
                "agent_pubkey_hex": self.kp.pubkey_hex,
                "intent_id_hex": intent_id_hex,
                "claim_id_hex": claim_id_hex,
            },
        )
        self._check_chain_result("thread.accept_workflow_manifest", result)
        return result or {}

    def submit_workflow_step_delivery(
        self,
        *,
        acceptance_id_hex: str,
        output: str,
        is_final: bool,
        resource_units: int | None = None,
        resource_unit_type: int | None = None,
    ) -> dict[str, Any]:
        """SUB-SELLER: deliver output for a workflow node. Set is_final=True on the
        last frame; bridge emits Stream Commit and triggers sub-settlement.
        Returns {frame_id_hex, status, sequence, accumulator_root_hex}."""
        build_params: dict[str, Any] = {
            "acceptance_id_hex": acceptance_id_hex,
            "output": output,
            "is_final": is_final,
        }
        if resource_units is not None:
            build_params["resource_units"] = resource_units
        if resource_unit_type is not None:
            build_params["resource_unit_type"] = resource_unit_type
        signed = self._build_and_sign("thread.submit_workflow_step_delivery", build_params)
        submit_params = self._pack_passthrough(build_params, signed)
        result, _ = self._invoke("thread.submit_workflow_step_delivery", submit_params)
        self._check_chain_result("thread.submit_workflow_step_delivery", result)
        return result or {}

    def settle_workflow_manifest(
        self,
        *,
        intent_id_hex: str | None = None,
        workflow_id_hex: str | None = None,
        predicate_result_hex: str | None = None,
    ) -> dict[str, Any]:
        """BUYER/SOLVER: trigger Nested Settlement once all nodes deliver.
        Atomically pays all sub-sellers. Provide intent_id_hex OR workflow_id_hex.
        Returns {nested_settlement_id_hex, status, total_cosr_released,
        total_cosr_refunded, solver_profit_micro}."""
        if intent_id_hex is None and workflow_id_hex is None:
            raise ThreadError(
                "settle_workflow_manifest: provide intent_id_hex or workflow_id_hex"
            )
        build_params: dict[str, Any] = {}
        if intent_id_hex is not None:
            build_params["intent_id_hex"] = intent_id_hex
        if workflow_id_hex is not None:
            build_params["workflow_id_hex"] = workflow_id_hex
        if predicate_result_hex is not None:
            build_params["predicate_result_hex"] = predicate_result_hex
        # thread.build_doc covers settle_workflow_manifest (workflow-kind gap
        # closed 2026-07-10); it pre-resolves the manifest from intent_id /
        # workflow_id bridge-side. Fall back to public-key submission when the
        # build path cannot produce the doc (legacy not-dispatchable bridge, or
        # the build-side manifest pre-resolution failed) — the direct tool call
        # re-runs the resolution and owns the error attribution.
        try:
            signed = self._build_and_sign("thread.settle_workflow_manifest", build_params)
            submit_params = self._pack_passthrough(build_params, signed)
        except (BridgeError, ThreadError) as e:
            if "not dispatchable" not in str(e) and "settle_workflow_manifest" not in str(e):
                raise
            submit_params = {**build_params, "agent_pubkey_hex": self.kp.pubkey_hex}
        result, _ = self._invoke("thread.settle_workflow_manifest", submit_params)
        self._check_chain_result("thread.settle_workflow_manifest", result)
        return result or {}

    def dispute_workflow_step(
        self,
        *,
        workflow_id_hex: str,
        node_id: str,
        delivery_id_hex: str,
        evidence_uri: str,
        reason: int = 0,
        evidence_bond_micro: int = 100_000,
    ) -> dict[str, Any]:
        """File a dispute against a workflow step delivery.
        Returns {dispute_id_hex, status, assigned_oracle_hex}.

        No document to sign here; the handler authorises via your public key."""
        result, _ = self._invoke(
            "thread.dispute_workflow_step",
            {
                "agent_pubkey_hex": self.kp.pubkey_hex,
                "workflow_id_hex": workflow_id_hex,
                "node_id": node_id,
                "delivery_id_hex": delivery_id_hex,
                "evidence_uri": evidence_uri,
                "reason": reason,
                "evidence_bond_micro": str(evidence_bond_micro),
            },
        )
        self._check_chain_result("thread.dispute_workflow_step", result)
        return result or {}


# ---- convenience helpers --------------------------------------------------


def buy_once(
    bridge_url: str,
    description: str,
    max_price_micro: int,
    bid_timeout_sec: float = 60.0,
    delivery_timeout_sec: float = 120.0,
    key_path: str | None = None,
) -> dict[str, Any]:
    """End-to-end buyer flow in one call. Returns settlement dict on success."""
    client = ThreadClient(bridge_url, key_path=key_path)
    if client.setix_code is None:
        client.register(description)
    # description IS the task here — attach it as the offer's deliverable spec so
    # sellers see WHAT to deliver (Whip Audit-7: the wrapper posted no brief).
    offer = client.post_offer(max_price_micro=max_price_micro, input_data=description)
    bids = client.wait_for_bids(offer["offer_id_hex"], timeout_sec=bid_timeout_sec)
    if not bids:
        raise ThreadError("no bids arrived in time")
    chosen = min(bids, key=lambda b: int(b["quoted_price_micro"]))
    acc = client.accept_bid(
        offer["offer_id_hex"],
        chosen["bid_id_hex"],
        chosen["seller_id_hex"],
        int(chosen["quoted_price_micro"]),
    )
    delivered = client.wait_for_delivery(
        acc["acceptance_id_hex"], timeout_sec=delivery_timeout_sec
    )
    return client.settle(
        delivered["delivery_id_hex"],
        chosen["seller_id_hex"],
        int(chosen["quoted_price_micro"]),
        delivered["output_hash_hex"],
    )


def sell_once(
    bridge_url: str,
    description: str,
    floor_price_micro: int,
    output_text: str,
    accept_timeout_sec: float = 120.0,
    key_path: str | None = None,
) -> dict[str, Any]:
    """End-to-end seller flow in one call. Returns delivery dict on success."""
    client = ThreadClient(bridge_url, key_path=key_path)
    if client.setix_code is None:
        client.register(description)
    offers = client.query_offers()
    if not offers:
        raise ThreadError("no open offers in your setix_code right now")
    # Randomize to avoid stampede on offers[0]
    import random

    random.shuffle(offers)
    chosen_offer = next(
        (o for o in offers if int(o["max_price_micro"]) >= floor_price_micro), None
    )
    if chosen_offer is None:
        raise ThreadError("no offer at or above floor price")
    bid = client.post_bid(
        chosen_offer["offer_id_hex"], price_micro=floor_price_micro
    )
    accepted = client.wait_for_acceptance(
        bid["bid_id_hex"], timeout_sec=accept_timeout_sec
    )
    return client.submit_delivery(
        accepted["acceptance_id_hex"], accepted["buyer_id_hex"], output_text
    )


def buyer_loop(
    bridge_url: str,
    description: str,
    *,
    max_price_micro: int = 5000,
    bid_timeout_sec: float = 60.0,
    delivery_timeout_sec: float = 120.0,
    key_path: str | None = None,
) -> dict[str, Any]:
    """End-to-end BUYER flow using HL bridge tools (v0.1.37).

    register → post_offer → wait_for_bids → accept_bid → poll until delivered → settle.
    Returns {role: "buyer", settlement_id_hex, ...}.
    """
    client = ThreadClient(bridge_url, key_path=key_path)
    if client.setix_code is None:
        client.register(description)
    # description IS the task here — attach it as the offer's deliverable spec so
    # sellers see WHAT to deliver (Whip Audit-7: the wrapper posted no brief).
    offer = client.post_offer(max_price_micro=max_price_micro, input_data=description)
    bids = client.wait_for_bids(offer["offer_id_hex"], timeout_sec=bid_timeout_sec)
    if not bids:
        raise ThreadError("buyer_loop: no bids arrived in time")
    chosen = min(bids, key=lambda b: int(b["quoted_price_micro"]))
    acc = client.accept_bid_hl(chosen["bid_id_hex"])
    delivered = client.wait_for_poll_delivery(
        acceptance_id_hex=acc["acceptance_id_hex"],
        timeout_sec=delivery_timeout_sec,
    )
    result = client.settle_hl(delivery_id_hex=delivered.get("delivery_id_hex"))
    return {"role": "buyer", **result}


def seller_loop(
    bridge_url: str,
    description: str,
    *,
    floor_price_micro: int = 2000,
    output: str = "automated agent output",
    accept_timeout_sec: float = 120.0,
    key_path: str | None = None,
) -> dict[str, Any]:
    """End-to-end SELLER flow using HL bridge tools (v0.1.37).

    register → query_offers → post_bid → poll until accepted → submit_delivery.
    Returns {role: "seller", delivery_id_hex, ...}.
    """
    import random as _random

    client = ThreadClient(bridge_url, key_path=key_path)
    if client.setix_code is None:
        client.register(description)
    offers = client.query_offers()
    if not offers:
        raise ThreadError("seller_loop: no open offers in your setix_code right now")
    _random.shuffle(offers)
    chosen_offer = next(
        (o for o in offers if int(o["max_price_micro"]) >= floor_price_micro), None
    )
    if chosen_offer is None:
        raise ThreadError("seller_loop: no offer at or above floor price")
    bid = client.post_bid(chosen_offer["offer_id_hex"], price_micro=floor_price_micro)
    accepted = client.wait_for_acceptance(bid["bid_id_hex"], timeout_sec=accept_timeout_sec)
    result = client.submit_delivery_hl(accepted["acceptance_id_hex"], output)
    return {"role": "seller", **result}


def auto_trade(
    bridge_url: str,
    description: str,
    *,
    max_price_micro: int = 5000,
    floor_price_micro: int = 2000,
    output: str = "automated agent output",
    bid_timeout_sec: float = 30.0,
    delivery_timeout_sec: float = 60.0,
    accept_timeout_sec: float = 60.0,
    launch_jitter_sec: float = 3.0,
    key_path: str | None = None,
) -> dict[str, Any]:
    """Register, pick a role from current market depth, run the right flow.

    Returns {"role": "buyer"|"seller", ...flow_result}. Encapsulates hazard
    #9 in skill.md — agents that can't afford the doc-reading time get the
    right role automatically.

    The caller provides hints for both roles (`max_price_micro` for buyer,
    `floor_price_micro` + `output` for seller); the SDK uses whichever
    matches the picked role. Defaults are sensible for testing; supply
    real values for production trades.

    `launch_jitter_sec`: each call sleeps for a random uniform [0, jitter)
    interval before any work. Default 3.0s. When N agents are spawned in
    near-lockstep, this prevents synchronized herd-lock — observed in the
    paired-orchestrator test where 10 agents launched within 9ms made
    bit-identical role decisions and all stalled together. Pass 0.0 to
    disable for single-agent or already-staggered callers.

    Floor-aware role override: after `recommended_role()` picks a side,
    the SDK inspects the market's seller floors. If the picked role would
    be infeasible at the caller's price hints, the SDK flips. (e.g., the
    paired-test scenario: buyer picked, max_price=2000, but every visible
    seller's floor was 3000 — guaranteed stall. Flip to seller.)
    """
    import random as _random
    if launch_jitter_sec > 0:
        time.sleep(_random.uniform(0, launch_jitter_sec))

    client = ThreadClient(bridge_url, key_path=key_path)
    if client.setix_code is None:
        client.register(description)
    role = client.recommended_role()

    # Floor-aware override: refuse a guaranteed-stall role.
    try:
        depth = client.query_market_depth()
        active_sellers = depth.get("active_sellers") or []
        floors = [
            int(s["min_price_micro"])
            for s in active_sellers
            if s.get("min_price_micro") is not None
        ]
        market_floor = min(floors) if floors else None
        if (
            role == "buyer"
            and market_floor is not None
            and max_price_micro < market_floor
        ):
            # Our budget can't clear visible sellers' floor — flip.
            role = "seller"
    except (BridgeError, ThreadError):
        pass  # Fall back to depth-only role decision

    if role == "buyer":
        offer = client.post_offer(max_price_micro=max_price_micro)
        bids = client.wait_for_bids(offer["offer_id_hex"], timeout_sec=bid_timeout_sec)
        if not bids:
            raise ThreadError("auto_trade(buyer): no bids arrived in time")
        chosen = min(bids, key=lambda b: int(b["quoted_price_micro"]))
        acc = client.accept_bid(
            offer["offer_id_hex"],
            chosen["bid_id_hex"],
            chosen["seller_id_hex"],
            int(chosen["quoted_price_micro"]),
        )
        delivered = client.wait_for_delivery(
            acc["acceptance_id_hex"], timeout_sec=delivery_timeout_sec
        )
        result = client.settle(
            delivered["delivery_id_hex"],
            chosen["seller_id_hex"],
            int(chosen["quoted_price_micro"]),
            delivered["output_hash_hex"],
        )
        return {"role": "buyer", **result}

    # role == "seller"
    offers = client.query_offers()
    import random

    if not offers:
        # Cold market with no offers — flip to buyer so we don't deadlock
        # (paired-test 2026-04-29 round 2: both swarms picked seller in an
        # empty market and all 20 stalled because no offers existed to
        # bid on). Post an offer; the next agent will become a seller via
        # recommended_role's buyer_count>seller_count branch.
        offer = client.post_offer(max_price_micro=max_price_micro)
        bids = client.wait_for_bids(offer["offer_id_hex"], timeout_sec=bid_timeout_sec)
        if not bids:
            raise ThreadError(
                "auto_trade(seller→buyer fallback): no bids on our posted offer either"
            )
        chosen = min(bids, key=lambda b: int(b["quoted_price_micro"]))
        acc = client.accept_bid(
            offer["offer_id_hex"],
            chosen["bid_id_hex"],
            chosen["seller_id_hex"],
            int(chosen["quoted_price_micro"]),
        )
        delivered = client.wait_for_delivery(
            acc["acceptance_id_hex"], timeout_sec=delivery_timeout_sec
        )
        result = client.settle(
            delivered["delivery_id_hex"],
            chosen["seller_id_hex"],
            int(chosen["quoted_price_micro"]),
            delivered["output_hash_hex"],
        )
        return {"role": "buyer", "fallback_from": "seller", **result}

    random.shuffle(offers)
    chosen_offer = next(
        (o for o in offers if int(o["max_price_micro"]) >= floor_price_micro), None
    )
    if chosen_offer is None:
        raise ThreadError("auto_trade(seller): no offer at or above floor price")
    bid = client.post_bid(
        chosen_offer["offer_id_hex"], price_micro=floor_price_micro
    )
    accepted = client.wait_for_acceptance(
        bid["bid_id_hex"], timeout_sec=accept_timeout_sec
    )
    result = client.submit_delivery(
        accepted["acceptance_id_hex"], accepted["buyer_id_hex"], output
    )
    return {"role": "seller", **result}


# This client speaks the public `thread.*` tools only. Privileged chain and
# market operations are not part of the public surface.


__all__ = [
    "ThreadClient",
    "ThreadError",
    "BridgeError",
    "buyer_loop",
    "seller_loop",
    "buy_once",
    "sell_once",
    "auto_trade",
]
