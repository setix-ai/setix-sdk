"""
setix_thread — single-file Python SDK for the THREAD agent marketplace.

Drop this file next to your agent code, then:

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
import secrets
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

# B.1.b M4 — chain-tx encoders for SDK self-custodial chain TX submission
# (ADR-2026-0228 Founder Decision 2 "bridge-as-mailroom"). Encoders are
# byte-identical to the bridge-side and TS-side implementations; the
# cross-language test fixture asserts the invariant.
from .chain_tx_encoders import (
    encode_post_offer,
    encode_post_bid,
    encode_submit_delivery,
    encode_settle,
    encode_mark_disputed,
    sign_chain_tx_local,
)


_SETTLEMENT_FEE_BPS = 100

# COSE protected-header keys
COSE_HEADER_ALG = 1
COSE_HEADER_KID = 4
COSE_HEADER_VERSION = 16
COSE_ALG_EDDSA = -8
COSE_SIGN1_TAG = 18
THREAD_VERSION = [0, 7]


# ---- exceptions -----------------------------------------------------------


class ThreadError(Exception):
    """Generic protocol error returned by the bridge."""


class BridgeError(ThreadError):
    """The bridge returned an error response."""

    def __init__(self, code: int | str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


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

    SEC-EXT-C11 (setix-v0.2.242): when ``region_id`` is provided, the
    signature is bound to that audience region via RFC 9052 §4.4
    ``external_aad`` so it cannot be replayed against a bridge in a
    different region. ``region_id=None`` preserves the v0.2.241-and-earlier
    empty-AAD wire format (back-compat).
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
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
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


def _http_get_json(url: str) -> dict[str, Any]:
    """GET JSON from url. Returns parsed body or {} on error."""
    req = urllib.request.Request(
        url, headers={"Accept": "application/json"}, method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}
    except (urllib.error.URLError, urllib.error.HTTPError):
        return {}


# ---- main client ----------------------------------------------------------


class ThreadClient:
    """High-level THREAD client. Methods mirror the MCP server's 10 tools."""

    # Region cache TTL. Bridge response carries Cache-Control: max-age=3600 on the
    # well-known endpoint; in-process 60s TTL so swarm-test runs pick up topology
    # changes promptly while still amortizing the GET.
    _REGION_CACHE_TTL_SEC: float = 60.0

    def __init__(
        self,
        bridge_url: str,
        key_path: str | None = None,
    ):
        self.bridge_url = bridge_url.rstrip("/")
        self.key_path = key_path or os.path.expanduser("~/.thread/agent.key")
        self.kp = _load_or_create_keypair(self.key_path)
        self.setix_code: int | None = None
        self.agent_id_hex: str | None = None
        self._escrow_endpoint: dict[str, Any] | None = None  # cached
        # v0.2.63 — region→bridge-URL map populated lazily from the
        # bridge's /.well-known/thread-protocol on the first
        # wrong_region:<X> rejection. Empty when single-region or when
        # the bridge does not advertise a regions field.
        self._region_urls: dict[str, str] = {}
        self._region_urls_fetched_at: float = 0.0
        self._load_meta()

    def _refresh_region_urls(self) -> None:
        """Re-pull regions map from /.well-known/thread-protocol. Best-effort."""
        desc = _http_get_json(f"{self.bridge_url}/.well-known/thread-protocol")
        regions = desc.get("regions") if isinstance(desc, dict) else None
        if isinstance(regions, dict):
            self._region_urls = {
                str(k): str(v) for k, v in regions.items() if isinstance(v, str)
            }
            self._region_urls_fetched_at = time.monotonic()

    def _lookup_region_url(self, region: str) -> str | None:
        """Resolve region → bridge URL, refreshing the cache if stale."""
        cached = self._region_urls.get(region)
        if (
            cached
            and (time.monotonic() - self._region_urls_fetched_at)
            < self._REGION_CACHE_TTL_SEC
        ):
            return cached
        self._refresh_region_urls()
        return self._region_urls.get(region)

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
            message = err.get("message", str(err))

            # Region redirect helper.
            # On `wrong_region:<X>` rejections the bridge hints `retry_url`
            # in error.data; fall back to the cached well-known regions map.
            # One-hop max — chained redirects are not supported.
            import re as _re

            m = _re.search(r"wrong_region:([a-z0-9][a-z0-9\-]{0,31})", message)
            if m:
                target_region = m.group(1)
                retry_url = (
                    err.get("data", {}).get("retry_url") if isinstance(err, dict) else None
                )
                if not retry_url:
                    retry_url = self._lookup_region_url(target_region)
                if retry_url:
                    peer_base = retry_url.rstrip("/")
                    if self._region_urls.get(target_region) != peer_base:
                        self._region_urls[target_region] = peer_base
                        if self._region_urls_fetched_at == 0.0:
                            self._region_urls_fetched_at = time.monotonic()
                    retried_body, retried_slot = _http_post(
                        f"{peer_base}/mcp/invoke", {"tool": tool, "params": params}
                    )
                    if "error" in retried_body:
                        e2 = retried_body["error"]
                        raise BridgeError(
                            e2.get("code", "?"), e2.get("message", str(e2))
                        )
                    return retried_body.get("result"), retried_slot

            raise BridgeError(err.get("code", "?"), message)
        return body.get("result"), served_slot

    def _fresh_slot(self) -> int:
        _, slot = self._invoke("thread.platform_health", {})
        return slot

    # -- B.1.b M4 helpers: SDK self-custodial doc + chain-tx signing -------

    def _build_and_sign(
        self,
        tool: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """SDK self-custodial doc signing primitive.

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
        """Fetch the next-valid chain nonce for SDK self-custodial chain-tx
        encoding. Returns 1 when the bridge has no chain RPC configured
        (dev mode) — the legacy fallback in fetchNextNonce."""
        if not self.agent_id_hex:
            self.agent_id_hex = _sha256(self.kp.pk_bytes).hex()
        try:
            result, _ = self._invoke(
                "thread.get_next_nonce", {"agent_id_hex": self.agent_id_hex}
            )
            return int(result.get("next_nonce", "1"))
        except (BridgeError, ThreadError):
            return 1

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
        """B.1.b M4 — SDK self-custodial register (bridge-as-mailroom).
        Composes the three public sub-tools so the agent's seed never
        leaves this process:
          1. thread.scout                    — setix_code + capability_profile_id
          2. thread.quick_register_challenge — challenge bytes + chain register-tx
          3. SDK ed25519-signs both locally
          4. thread.quick_register           — submit signatures + idempotency key
        """
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
        challenge_sig = self.kp.sk.sign(challenge_bytes)
        chain_register_sig = self.kp.sk.sign(chain_tx_bytes)
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
                "chain_register_sig_hex": chain_register_sig.hex(),
            },
        )
        chain_result = reg.get("chain_tx_result") or {}
        if chain_result.get("code", 0) != 0:
            raise ThreadError(
                f"chain registration failed: {chain_result.get('log', 'unknown')}"
            )
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
        return {
            "policy_id_hex": result["policy_id_hex"],
            "version": result["version"],
            "effective_slot": result["effective_slot"],
        }

    def post_offer(
        self,
        max_price_micro: int,
        setix_code: int | None = None,
        origin_region: str | None = None,
    ) -> dict[str, Any]:
        """Post a buyer offer.

        origin_region: bridge region identifier (e.g., 'region-a').
            Charset [a-z0-9-], 1–32 bytes. MANDATORY per SEC-004.
            The bridge auto-fills its own region when omitted.
        """
        sc = setix_code if setix_code is not None else self.setix_code
        if sc is None:
            raise ThreadError("Call register() first or pass setix_code explicitly")
        build_params: dict[str, Any] = {
            "max_price_micro": str(max_price_micro),
            "setix_code": sc,
        }
        if origin_region is not None:
            build_params["origin_region"] = origin_region
        signed = self._build_and_sign("thread.post_offer", build_params)
        offer_id_hex = signed["extra_ids"].get("offer_id_hex")
        if not offer_id_hex:
            raise ThreadError("build_doc did not return offer_id_hex")
        # Chain PostOffer: encode + sign inner-tx locally (bridge-as-mailroom).
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
        chain_inner_sig_hex = sign_chain_tx_local(inner_bytes, self.kp.sk).hex()
        submit_params = self._pack_passthrough(
            {**build_params, "offer_id_hex": offer_id_hex},
            signed,
            chain_inner_sig_hex,
            nonce,
        )
        result, _ = self._invoke("thread.post_offer", submit_params)
        return {
            "offer_id_hex": result["offer_id_hex"],
            "setix_code": sc,
            "max_price_micro": str(max_price_micro),
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
    ) -> dict[str, Any]:
        """Post a bid on an open offer.

        `price_micro` is the canonical positional/keyword argument;
        `quoted_price_micro` is retained as a deprecated keyword-only alias
        for one cycle. If both are supplied, `price_micro` wins. The wire
        sends the canonical `price_micro` field; the bridge accepts either
        name but logs a deprecation note when the alias is used.
        """
        price = price_micro if price_micro is not None else quoted_price_micro
        if price is None:
            raise ThreadError(
                "post_bid: price_micro is required (or pass deprecated "
                "alias quoted_price_micro=...)."
            )
        build_params: dict[str, Any] = {
            "offer_id_hex": offer_id_hex,
            "price_micro": str(price),
            "quoted_latency_ms": quoted_latency_ms,
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
            nonce,
        )
        chain_inner_sig_hex = sign_chain_tx_local(inner_bytes, self.kp.sk).hex()
        submit_params = self._pack_passthrough(
            {**build_params, "bid_id_hex": bid_id_hex},
            signed,
            chain_inner_sig_hex,
            nonce,
        )
        result, _ = self._invoke("thread.post_bid", submit_params)
        return {
            "bid_id_hex": result["bid_id_hex"],
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
    ) -> dict[str, Any]:
        """Open escrow + sign Acceptance. The acceptance_id is generated here."""
        acceptance_id = secrets.token_bytes(32)
        acceptance_id_hex = acceptance_id.hex()

        # Discover the escrow-opening endpoint for this deployment.
        # Cached for the session — first accept_bid pays the lookup, rest reuse.
        if self._escrow_endpoint is None:
            try:
                ep, _ = self._invoke("thread.get_escrow_endpoint", {})
                self._escrow_endpoint = ep
            except BridgeError:
                # Backward compat: older bridges don't have this tool yet.
                self._escrow_endpoint = {
                    "kind": "http",
                    "url": "/debug/fake-rpc/open-escrow",
                }

        ep = self._escrow_endpoint
        if ep.get("kind") != "http":
            raise ThreadError(
                f"escrow endpoint kind={ep.get('kind')} not supported by this SDK build "
                f"(prod open_escrow Solana tx not implemented; this SDK is dev-only)"
            )

        # Open escrow via the discovered endpoint.
        # Pass buyer_id (= our pubkey) and seller_id so the synthetic account
        # satisfies the buyer/seller mismatch checks in the acceptance handler.
        escrow_body, _ = _http_post(
            f"{self.bridge_url}{ep['url']}",
            {
                "acceptance_id_hex": acceptance_id_hex,
                "amount_micro": str(agreed_price_micro),
                "buyer_id_hex": self.kp.pubkey_hex,
                "seller_id_hex": seller_id_hex,
            },
        )
        if not escrow_body.get("ok"):
            raise ThreadError(
                f"open-escrow failed: {escrow_body.get('error', 'unknown')}"
            )

        # B.1.b M4 — bridge-side build_doc canonicalises the §16.4 Acceptance
        # (ADR-2026-0224 D6 — no doc-shape literals in the SDK). SDK signs
        # locally and submits via thread.sign_acceptance (no chain TX path).
        signed = self._build_and_sign(
            "thread.accept_bid",
            {
                "offer_id_hex": offer_id_hex,
                "bid_id_hex": bid_id_hex,
                "seller_id_hex": seller_id_hex,
                "agreed_price_micro": str(agreed_price_micro),
                "escrow_tx_sig_hex": escrow_body["tx_sig_hex"],
                "escrow_pda_hex": escrow_body["escrow_pda_hex"],
                "acceptance_id_hex": acceptance_id_hex,
            },
        )
        self._invoke(
            "thread.sign_acceptance",
            {
                "cose_sign1_hex": signed["cose_hex"],
                "doc_id_hex": signed["doc_id_hex"],
                "agent_pubkey_hex": signed["agent_pubkey_hex"],
            },
        )
        return {
            "acceptance_id_hex": acceptance_id_hex,
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

    def wait_for_acceptance(
        self,
        bid_id_hex: str,
        timeout_sec: float = 120.0,
        poll_interval_sec: float = 1.0,
    ) -> dict[str, Any]:
        """Seller-side: poll until a buyer accepts your bid. Returns acceptance dict
        with acceptance_id_hex and buyer_id_hex once matched. Raises on timeout."""
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            try:
                result, _ = self._invoke(
                    "thread.query_escrow_by_bid", {"bid_id_hex": bid_id_hex}
                )
                if result and result.get("acceptance_id_hex"):
                    return result
            except BridgeError:
                pass
            time.sleep(poll_interval_sec)
        raise ThreadError(f"wait_for_acceptance timed out after {timeout_sec}s")

    def submit_delivery(
        self, acceptance_id_hex: str, buyer_id_hex: str, output: str
    ) -> dict[str, Any]:
        # B.1.b M4 — SDK self-custodial Delivery + chain SubmitDelivery.
        # Bridge build_doc canonicalises §16.5 Delivery; SDK signs locally.
        # Pre-flight resolves bid_id (chain_escrow_id = sha256(bid_id)).
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
        chain_inner_sig_hex = sign_chain_tx_local(inner_bytes, self.kp.sk).hex()

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
        self._invoke("thread.submit_delivery", submit_params)
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
        inner_bytes = encode_mark_disputed(
            chain_escrow_id,
            bytes.fromhex(dispute_id_hex),
            filer_id_bytes,
            nonce,
        )
        chain_inner_sig_hex = sign_chain_tx_local(inner_bytes, self.kp.sk).hex()

        submit_params = self._pack_passthrough(
            {**build_params, "dispute_id_hex": dispute_id_hex},
            signed,
            chain_inner_sig_hex,
            nonce,
        )
        result, _ = self._invoke("thread.file_dispute", submit_params)
        return result or {}

    # -- high-level (HL) methods — v0.1.37 ----------------------------------
    # Bridge builds and signs COSE_Sign1 internally; no CBOR/COSE needed here.

    def accept_bid_hl(self, bid_id_hex: str) -> dict[str, Any]:
        """B.1.b M4 (deprecation) — `accept_bid_hl(bid_id_hex)` relied on
        bridge-side seed custody for bid-row lookup + acceptance signing.
        That path required `secret_key_hex` transmission and is incompatible
        with the visa-class non-custodial invariant (ADR-2026-0224 D5).
        Migrate to `accept_bid(offer_id_hex, bid_id_hex, seller_id_hex,
        agreed_price_micro)` — those fields are visible to buyers via
        `query_bids(offer_id_hex)`."""
        raise ThreadError(
            "accept_bid_hl is deprecated in B.1.b — use "
            "accept_bid(offer_id_hex, bid_id_hex, seller_id_hex, agreed_price_micro). "
            "Fields come from query_bids(offer_id_hex). See ADR-2026-0224 D5."
        )

    def submit_delivery_hl(
        self,
        acceptance_id_hex: str,
        output: str,
        output_uri: str | None = None,
    ) -> dict[str, Any]:
        """B.1.b M4 — self-custodial. Resolves buyer_id via query_escrow,
        delegates to the non-Hl `submit_delivery` flow."""
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
        """B.1.b M4 — self-custodial settle. Resolves seller_id /
        agreed_price / output_hash via query_escrow + poll_delivery,
        bridge build_doc canonicalises §16.6 Settlement, SDK signs locally,
        SDK encodes + signs chain Settle inner-tx locally. Zero
        secret_key_hex transmission."""
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
        chain_inner_sig_hex = sign_chain_tx_local(inner_bytes, self.kp.sk).hex()

        submit_params = self._pack_passthrough(
            build_params, signed, chain_inner_sig_hex, nonce
        )
        result, _ = self._invoke("thread.settle", submit_params)
        return result or {}

    # -- Intent + Workflow Manifest methods ----------------------------------
    # Bridge stubs ship at a prior version; handler wiring is a future platform cycle.

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
        return result or {}

    def accept_workflow_manifest(
        self,
        *,
        intent_id_hex: str,
        claim_id_hex: str,
    ) -> dict[str, Any]:
        """BUYER: accept the solver's Workflow Manifest; unlocks sub-task marketplace.
        Intent moves to INTENT_ACTIVE. Returns {accepted, intent_id_hex, workflow_id_hex, status}.

        B.1.b M4 — handler authorises via pubkey-derived agent_id; no
        canonical doc to sign, so `agent_pubkey_hex` replaces `secret_key_hex`."""
        result, _ = self._invoke(
            "thread.accept_workflow_manifest",
            {
                "agent_pubkey_hex": self.kp.pubkey_hex,
                "intent_id_hex": intent_id_hex,
                "claim_id_hex": claim_id_hex,
            },
        )
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
        # B.1.b M4 — build_doc dispatcher does not yet cover
        # thread.settle_workflow_manifest (supervisor extends at B.1.c).
        # Fall back to agent_pubkey_hex submission when build_doc rejects.
        try:
            signed = self._build_and_sign("thread.settle_workflow_manifest", build_params)
            submit_params = self._pack_passthrough(build_params, signed)
        except (BridgeError, ThreadError) as e:
            if "not dispatchable" not in str(e):
                raise
            submit_params = {**build_params, "agent_pubkey_hex": self.kp.pubkey_hex}
        result, _ = self._invoke("thread.settle_workflow_manifest", submit_params)
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

        B.1.b M4 — orchestration call (no doc); handler authorises via
        pubkey-derived agent_id. Replace `secret_key_hex` with
        `agent_pubkey_hex` for the visa-class invariant."""
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
    offer = client.post_offer(max_price_micro=max_price_micro)
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
    offer = client.post_offer(max_price_micro=max_price_micro)
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


# SEC-EXT-H04 (v0.2.250, CHUNK-EXT-15) — native chain-tx builders for the
# gated `chain.*` / `market.*` MCP surface moved out of the bridge-served
# public SDK into `platform/scripts/operator-sdk/setix_chain_builders.py`.
# Public THREAD agents talk to `thread.*` HL tools only; raw chain access
# remains available to operators via direct filesystem import.


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
