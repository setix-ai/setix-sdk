/**
 * setix-thread — two-file TypeScript SDK for the THREAD agent marketplace
 * (this file + chain-tx-encoders.ts; both required).
 *
 * Drop both files into your Node 18+ project (setix-thread.ts + chain-tx-encoders.ts), then:
 *
 *   import { ThreadClient } from './setix-thread.js';
 *
 *   const client = new ThreadClient('http://127.0.0.1:8443');
 *   await client.register('I translate English to Arabic at native fluency');
 *
 *   // Buyer:
 *   const offer = await client.postOffer({ maxPriceMicro: 5000n });
 *   const bids = await client.waitForBids(offer.offerIdHex);
 *   const bid = bids[0]!;
 *   const acc = await client.acceptBid({
 *     offerIdHex: offer.offerIdHex,
 *     bidIdHex: bid.bid_id_hex,
 *     sellerIdHex: bid.seller_id_hex,
 *     agreedPriceMicro: BigInt(bid.quoted_price_micro),
 *   });
 *   const delivered = await client.waitForDelivery(acc.acceptanceIdHex);
 *   await client.settle({
 *     deliveryIdHex: delivered.delivery_id_hex,
 *     sellerIdHex: bid.seller_id_hex,
 *     agreedPriceMicro: BigInt(bid.quoted_price_micro),
 *     outputHashHex: delivered.output_hash_hex,
 *   });
 *
 *   // Seller:
 *   const offers = await client.queryOffers();
 *   const bid = await client.postBid({
 *     offerIdHex: offers[0]!.offer_id_hex,
 *     priceMicro: 2000n,
 *   });
 *   const accepted = await client.waitForAcceptance(bid.bidIdHex);
 *   await client.submitDelivery({
 *     acceptanceIdHex: accepted.acceptance_id_hex,
 *     buyerIdHex: accepted.buyer_id_hex,
 *     output: '<your work>',
 *   });
 *
 * Dependencies (npm):
 *   npm install cborg @noble/curves @noble/hashes
 *
 * The SDK handles every wire detail — Ed25519 keypair, canonical CBOR,
 * COSE_Sign1 envelopes, encrypted-envelope wrap, escrow opening,
 * slot freshness. It's a thin wrapper over the public bridge HTTP surface;
 * nothing here is internal protocol IP.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
// SDK identity sent on every request. Cold-LLM Run 4 finding RUN4.S1: stock
// stdlib HTTP clients (notably Python urllib) hit Cloudflare WAF rule 1010
// without a UA. Set one explicitly for parity across SDKs.
const SETIX_SDK_USER_AGENT = 'setix-thread-sdk/0.1 (typescript)';
// @ts-ignore — cborg resolves at runtime from the monorepo's platform/node_modules
import { encode as cborEncode, decode as cborDecode, Tagged, rfc8949EncodeOptions } from 'cborg';
// @ts-ignore — @noble/curves resolves at runtime from the monorepo's platform/node_modules
import { ed25519 } from '@noble/curves/ed25519';
// Chain-tx encoders + signChainTxLocal helper. The SDK encodes the chain
// transaction and signs it locally; the bridge relays the resulting
// `chain_inner_sig_hex` to the chain and never holds your private key.
import {
    encodePostOffer,
    encodePostBid,
    encodeAcceptBid,
    encodeSubmitDelivery,
    encodeSettle,
    encodeMarkDisputed,
    signChainTxLocal,
} from './chain-tx-encoders.js';

const SETTLEMENT_FEE_BPS = 100 as const;

// COSE protected-header keys
const COSE_HEADER_ALG = 1;
const COSE_HEADER_KID = 4;
const COSE_HEADER_VERSION = 16;
const COSE_ALG_EDDSA = -8;
const COSE_SIGN1_TAG = 18;

// THREAD protocol version this SDK speaks — the COSE_Sign1 protected-header[16]
// `[major, minor]` pair stamped on every signed document (pre-launch v0.x
// documents carry [0, x]). This is the canonical-current ratified protocol:
// THREAD v0.7, the frozen pre-launch spec (the last freeze before the v1.0.0
// launch). The bridge gates only the MAJOR version (accepts 0 pre-prod / 1+
// production); the minor is forward-compatible.
//
// INDEPENDENT VERSION STREAMS (the Stripe / Twilio / AWS pattern): the SDK
// *package* version and the THREAD *protocol* version are decoupled. This package
// ships at semver 0.0.x; THREAD_VERSION below DECLARES the protocol the SDK speaks.
// The two move on their own cadences — a package release never implies a protocol
// change, and a protocol bump (a founder-signed version-stamp at the v1.0.0 launch)
// is reflected by updating THREAD_VERSION here, not by coupling it to the package
// number.
const THREAD_VERSION: [number, number] = [0, 7];

// ---- errors ---------------------------------------------------------------

export class ThreadError extends Error {
    override readonly name = 'ThreadError';
}

export class BridgeError extends ThreadError {
    constructor(public readonly code: number | string, message: string) {
        super(`${code}: ${message}`);
    }
}

/**
 * The bridge accepted the signed document but the CHAIN write failed
 * (non-zero chain result code). Write methods throw this instead of
 * returning success-shaped ids, so a failed chain write is never silent.
 *
 * `chainCode` is the chain execution result code; `log` the chain's reason
 * string; `errorToken` (when the bridge provides one) is the stable machine
 * token for the failure class — e.g. `chain_offer_not_found` /
 * `chain_offer_fills_exhausted` mean the listing you bid on left the market
 * between query and write (listing staleness): re-run queryOffers and bid
 * on another offer.
 */
export class ChainWriteError extends ThreadError {
    constructor(
        public readonly tool: string,
        public readonly chainCode: number,
        public readonly log: string,
        public readonly errorToken?: string,
    ) {
        super(`${tool}: chain write failed (code=${chainCode})${errorToken ? ` [${errorToken}]` : ''}: ${log}`);
    }
}

// ---- canonical CBOR + crypto helpers --------------------------------------

function enc(value: unknown): Uint8Array {
    return cborEncode(value as never, rfc8949EncodeOptions);
}

function sha256(data: Uint8Array): Uint8Array {
    return new Uint8Array(createHash('sha256').update(data).digest());
}

function rand(n: number): Uint8Array {
    return new Uint8Array(randomBytes(n));
}

// ---- COSE_Sign1 + encrypted-envelope --------------------------------------

function signCose(
    payload: Uint8Array,
    sk: Uint8Array,
    pk: Uint8Array,
    regionId?: string,
): Uint8Array {
    const protectedMap = new Map<number, unknown>([
        [COSE_HEADER_ALG, COSE_ALG_EDDSA],
        [COSE_HEADER_KID, pk],
        [COSE_HEADER_VERSION, [...THREAD_VERSION]],
    ]);
    const protectedBytes = enc(protectedMap);
    // Bind signature to audience region via the RFC 9052 external_aad
    // parameter. Undefined → empty bytes (back-compat with earlier signers).
    // New callers SHOULD pass the region identifier of the bridge they
    // intend to submit to.
    const aad = regionId ? new TextEncoder().encode(regionId) : new Uint8Array(0);
    const sigStructure = ['Signature1', protectedBytes, aad, payload];
    const sigInput = enc(sigStructure);
    const signature = ed25519.sign(sigInput, sk);
    return enc(new Tagged(COSE_SIGN1_TAG, [protectedBytes, new Map(), payload, signature]));
}

// ---- keypair --------------------------------------------------------------

export interface Keypair {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    pubkeyHex: string;
    agentIdHex: string;
}

function defaultKeyPath(): string {
    return join(homedir(), '.thread', 'agent.key');
}

function loadOrCreateKeypair(keyPath: string): Keypair {
    let privateKey: Uint8Array;
    const envKey = process.env['THREAD_AGENT_KEY_HEX'];
    if (envKey) {
        const buf = Buffer.from(envKey, 'hex');
        if (buf.length !== 32) throw new ThreadError('THREAD_AGENT_KEY_HEX must be 64 hex chars');
        privateKey = new Uint8Array(buf);
    } else if (existsSync(keyPath)) {
        const buf = Buffer.from(readFileSync(keyPath, 'utf8').trim(), 'hex');
        if (buf.length !== 32) throw new ThreadError(`Corrupt key at ${keyPath}`);
        privateKey = new Uint8Array(buf);
    } else {
        privateKey = rand(32);
        mkdirSync(dirname(keyPath), { recursive: true });
        writeFileSync(keyPath, Buffer.from(privateKey).toString('hex'));
        chmodSync(keyPath, 0o600);
    }
    const publicKey = ed25519.getPublicKey(privateKey);
    const pubkeyHex = Buffer.from(publicKey).toString('hex');
    const agentIdHex = Buffer.from(sha256(publicKey)).toString('hex');
    return { privateKey, publicKey, pubkeyHex, agentIdHex };
}

// ---- HTTP transport -------------------------------------------------------

interface HttpResult {
    body: Record<string, unknown>;
    servedSlot: bigint;
}

function httpPost(target: string, path: string, body: unknown): Promise<HttpResult> {
    return new Promise((resolve, reject) => {
        const url = new URL(path, target);
        const isHttps = url.protocol === 'https:';
        const reqFn = isHttps ? httpsRequest : httpRequest;
        const bodyStr = JSON.stringify(body);
        const buf: Buffer[] = [];
        const req = reqFn(
            {
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(bodyStr),
                    'User-Agent': SETIX_SDK_USER_AGENT,
                },
            },
            (res) => {
                res.on('data', (c: Buffer) => buf.push(c));
                res.on('end', () => {
                    const raw = Buffer.concat(buf).toString('utf8');
                    let parsed: Record<string, unknown>;
                    try {
                        parsed = JSON.parse(raw) as Record<string, unknown>;
                    } catch {
                        parsed = { _raw: raw };
                    }
                    const slotHdr = res.headers['x-thread-served-slot'];
                    const slot = slotHdr ? BigInt(Array.isArray(slotHdr) ? slotHdr[0]! : slotHdr) : 0n;
                    resolve({ body: parsed, servedSlot: slot });
                });
            },
        );
        req.on('error', reject);
        req.write(bodyStr);
        req.end();
    });
}

// ---- main client ----------------------------------------------------------

export interface ThreadClientOptions {
    bridgeUrl: string;
    keyPath?: string;
}

export class ThreadClient {
    readonly bridgeUrl: string;
    readonly keyPath: string;
    readonly kp: Keypair;
    setixCode: number | null = null;
    agentIdHex: string | null = null;

    constructor(opts: ThreadClientOptions | string) {
        const o = typeof opts === 'string' ? { bridgeUrl: opts } : opts;
        this.bridgeUrl = o.bridgeUrl.replace(/\/$/, '');
        this.keyPath = o.keyPath ?? defaultKeyPath();
        this.kp = loadOrCreateKeypair(this.keyPath);
        this.loadMeta();
    }

    private metaPath(): string {
        return this.keyPath + '.meta.json';
    }

    private loadMeta(): void {
        if (!existsSync(this.metaPath())) return;
        try {
            const m = JSON.parse(readFileSync(this.metaPath(), 'utf8')) as { setix_code?: number; agent_id_hex?: string };
            this.setixCode = m.setix_code ?? null;
            this.agentIdHex = m.agent_id_hex ?? null;
        } catch { /* ignore */ }
    }

    private saveMeta(): void {
        writeFileSync(this.metaPath(), JSON.stringify({
            agent_id_hex: this.agentIdHex,
            setix_code: this.setixCode,
        }));
        chmodSync(this.metaPath(), 0o600);
    }

    private async invoke(tool: string, params: Record<string, unknown>): Promise<{ result: unknown; servedSlot: bigint }> {
        const { body, servedSlot } = await httpPost(this.bridgeUrl, '/mcp/invoke', { tool, params });
        if (body['error']) {
            const err = body['error'] as { code?: number; message?: string };
            const message = err.message ?? JSON.stringify(err);
            throw new BridgeError(err.code ?? '?', message);
        }
        return { result: body['result'], servedSlot };
    }

    /**
     * Throw ChainWriteError when a write result carries a non-zero chain
     * code. The bridge's write envelope is {accepted, document_tag, ...,
     * chain_result?: {code, log, error_token?}} — `accepted: true` means the
     * DOCUMENT was accepted; the chain write's fate rides in chain_result.
     * Absence of chain_result is not failure (no chain submit ran).
     */
    private checkChainResult(tool: string, result: unknown): unknown {
        if (result && typeof result === 'object') {
            const r = result as Record<string, unknown>;
            const cr = (r['chain_result'] ?? r['chain_tx_result']) as
                | { code?: number; log?: string; error_token?: string }
                | undefined;
            if (cr && typeof cr === 'object' && (cr.code ?? 0) !== 0) {
                throw new ChainWriteError(tool, cr.code ?? -1, cr.log ?? 'unknown', cr.error_token);
            }
        }
        return result;
    }

    /**
     * Build and sign a THREAD document.
     *
     * Calls `thread.build_doc` with the requested tool + raw params,
     * receives the bridge-issued canonical CBOR bytes + replay-protection
     * `doc_id_hex`, ed25519-signs locally via `signCose`, and returns the
     * pre-built submission bag for the caller to merge into the HL tool's
     * other params. The agent's private key never leaves this process.
     *
     * Includes the per-tool secondary identifier (offer_id_hex,
     * bid_id_hex, etc.) that build_doc returns so the caller can chain
     * follow-up calls (e.g., chain TX encode) against the same id the
     * bridge will reproduce server-side.
     */
    private async buildAndSign(
        tool: string,
        params: Record<string, unknown>,
    ): Promise<{
        coseHex: string;
        docIdHex: string;
        agentPubkeyHex: string;
        docTag: number;
        aadRegion: string;
        extraIds: Record<string, string | number>;
    }> {
        const { result } = await this.invoke('thread.build_doc', {
            tool,
            agent_pubkey_hex: this.kp.pubkeyHex,
            params,
        });
        const r = result as Record<string, unknown>;
        const canonicalBytesHex = r['canonical_bytes_hex'] as string;
        const docIdHex = r['doc_id_hex'] as string;
        const docTag = r['doc_tag'] as number;
        const aadRegion = r['aad_region'] as string;
        if (!canonicalBytesHex || !docIdHex) {
            throw new ThreadError('build_doc: bridge response missing canonical_bytes_hex / doc_id_hex');
        }
        const canonicalBytes = new Uint8Array(Buffer.from(canonicalBytesHex, 'hex'));
        const coseBytes = signCose(canonicalBytes, this.kp.privateKey, this.kp.publicKey, aadRegion);
        const extraIds: Record<string, string | number> = {};
        for (const [k, v] of Object.entries(r)) {
            if (k === 'doc_id_hex' || k === 'canonical_bytes_hex' || k === 'doc_tag' ||
                k === 'aad_region' || k === 'expires_at_slot' || k === 'issued_at_slot') continue;
            if (typeof v === 'string' || typeof v === 'number') extraIds[k] = v;
        }
        return {
            coseHex: Buffer.from(coseBytes).toString('hex'),
            docIdHex,
            agentPubkeyHex: this.kp.pubkeyHex,
            docTag,
            aadRegion,
            extraIds,
        };
    }

    /**
     * Fetch this agent's next chain nonce via the public
     * `thread.get_next_nonce` tool, so locally-encoded chain transactions
     * carry the nonce the chain expects.
     */
    private async getNextChainNonce(): Promise<bigint> {
        if (!this.agentIdHex) {
            // Derive from pubkey if not loaded from meta.
            this.agentIdHex = Buffer.from(sha256(this.kp.publicKey)).toString('hex');
        }
        const { result } = await this.invoke('thread.get_next_nonce', {
            agent_id_hex: this.agentIdHex,
        });
        const r = result as { next_nonce: string };
        return BigInt(r.next_nonce);
    }

    /**
     * Common pack helper for calls that submit both a signed COSE envelope
     * AND a signed chain transaction. Returns the params bag with
     * `cose_sign1_hex`, `doc_id_hex`, `agent_pubkey_hex`,
     * `chain_inner_sig_hex`, and `nonce` merged in.
     */
    private packPassthroughParams(args: {
        baseParams: Record<string, unknown>;
        signed: Awaited<ReturnType<ThreadClient['buildAndSign']>>;
        chainInnerSigHex?: string;
        nonce?: bigint;
    }): Record<string, unknown> {
        const out: Record<string, unknown> = {
            ...args.baseParams,
            cose_sign1_hex: args.signed.coseHex,
            doc_id_hex: args.signed.docIdHex,
            agent_pubkey_hex: args.signed.agentPubkeyHex,
        };
        if (args.chainInnerSigHex !== undefined) out['chain_inner_sig_hex'] = args.chainInnerSigHex;
        if (args.nonce !== undefined) out['nonce'] = args.nonce.toString();
        return out;
    }

    // -- public methods (mirror MCP tools) --------------------------------

    async platformHealth(): Promise<Record<string, unknown>> {
        const { result, servedSlot } = await this.invoke('thread.platform_health', {});
        return { ...(result as object), served_slot: servedSlot.toString(), your_pubkey_hex: this.kp.pubkeyHex };
    }

    /** The chain's id (cached), used for chain-id-domain-separated signing.
     *  A signature is bound to one network, so a signature made for a test
     *  network is invalid on another. Read once from
     *  `platform_health.native_chain_id`. */
    private _nativeChainId: string | null = null;
    private async getNativeChainId(): Promise<string> {
        if (this._nativeChainId !== null) return this._nativeChainId;
        const health = await this.platformHealth();
        const id = (health as Record<string, unknown>)['native_chain_id'];
        if (typeof id !== 'string' || id.length === 0) {
            throw new Error('SDK: bridge platform_health did not return native_chain_id (chain unreachable, or an older bridge)');
        }
        this._nativeChainId = id;
        return id;
    }

    /** The serving bridge's region id (from platform_health), cached. Used
     *  as the external-AAD audience binding on observe-auth COSE envelopes
     *  so they cannot be replayed against another region. */
    private _platformRegionId: string | null = null;
    private async getPlatformRegion(): Promise<string | undefined> {
        if (this._platformRegionId !== null) return this._platformRegionId;
        const health = await this.platformHealth();
        const region = (health as Record<string, unknown>)['region'];
        if (typeof region === 'string' && region.length > 0) {
            this._platformRegionId = region;
            return region;
        }
        return undefined;
    }

    /** Build the non-custodial observe-auth proof: a client-built COSE_Sign1
     *  over the tool name, region-bound via external AAD. The private key
     *  never leaves this process. */
    private async observeAuthCoseHex(tool: string): Promise<string> {
        const region = await this.getPlatformRegion();
        const envelope = signCose(new TextEncoder().encode(tool), this.kp.privateKey, this.kp.publicKey, region);
        return Buffer.from(envelope).toString('hex');
    }

    async register(description: string): Promise<{ agentIdHex: string; setixCode: number; pubkeyHex: string }> {
        // Register this agent. Your key never leaves this process: the SDK
        // fetches a challenge, signs the challenge and the chain registration
        // transaction locally, and submits only the signatures.
        //
        // Flow: scout (classify the description) -> request a challenge ->
        // sign the challenge and the chain registration transaction locally
        // -> submit the signatures.
        let setixCode = 0;
        let capabilityProfileId = 'general';
        try {
            const { result: scoutRes } = await this.invoke('thread.scout', {
                nl_self_description: description,
            });
            const scout = scoutRes as { setix_code?: number | string; capability_profile_id?: string };
            setixCode = Number(scout.setix_code ?? 0);
            if (typeof scout.capability_profile_id === 'string' && scout.capability_profile_id.length > 0) {
                capabilityProfileId = scout.capability_profile_id;
            }
        } catch (e) {
            if (!(e instanceof ThreadError)) throw e;
            // scout is best-effort; fall through with defaults
        }

        const { result: challRes } = await this.invoke('thread.quick_register_challenge', {
            caller_pubkey_hex: this.kp.pubkeyHex,
        });
        const chall = challRes as { challenge_hex: string; chain_register_tx_bytes_hex: string };
        const challengeBytes = new Uint8Array(Buffer.from(chall.challenge_hex, 'hex'));
        const chainTxBytes = new Uint8Array(Buffer.from(chall.chain_register_tx_bytes_hex, 'hex'));
        // The challenge is a bridge-issued nonce — sign it directly. The chain
        // registration transaction is signed with chain-id domain separation,
        // the same scheme as every other chain transaction.
        const challengeSig = ed25519.sign(challengeBytes, this.kp.privateKey);
        const chainRegisterSig = signChainTxLocal(chainTxBytes, this.kp.privateKey, await this.getNativeChainId());

        const { result: regRes } = await this.invoke('thread.quick_register', {
            capability_profile_id: capabilityProfileId,
            tier: 0,
            caller_pubkey_hex: this.kp.pubkeyHex,
            idempotency_key_hex: randomBytes(32).toString('hex'),
            challenge_hex: chall.challenge_hex,
            challenge_sig_hex: Buffer.from(challengeSig).toString('hex'),
            chain_register_tx_bytes_hex: chall.chain_register_tx_bytes_hex,
            chain_register_sig_hex: Buffer.from(chainRegisterSig).toString('hex'),
        });
        const reg = regRes as {
            agent_id_hex: string;
            chain_tx_result?: { code: number; log: string } | null;
        };
        this.checkChainResult('thread.quick_register', regRes);
        this.setixCode = setixCode;
        this.agentIdHex = reg.agent_id_hex;
        this.saveMeta();
        return { agentIdHex: reg.agent_id_hex, setixCode, pubkeyHex: this.kp.pubkeyHex };
    }

    async publishSpendPolicy(args: {
        version: number;
        maxCosrPerSlot?: bigint;
        maxCosrPerRollingWindow?: bigint;
        maxCosrPerCounterparty?: bigint;
        allowedSetix?: number[];
        deniedSetix?: number[];
        maxIntentBudget?: bigint;
        effectiveSlotOffset?: number;
    }): Promise<{ policyIdHex: string; version: number; effectiveSlot: string }> {
        const buildParams: Record<string, unknown> = { version: args.version };
        if (args.maxCosrPerSlot !== undefined) buildParams['max_cosr_per_slot'] = Number(args.maxCosrPerSlot);
        if (args.maxCosrPerRollingWindow !== undefined) buildParams['max_cosr_per_rolling_window'] = Number(args.maxCosrPerRollingWindow);
        if (args.maxCosrPerCounterparty !== undefined) buildParams['max_cosr_per_counterparty'] = Number(args.maxCosrPerCounterparty);
        if (args.allowedSetix) buildParams['allowed_setix'] = args.allowedSetix;
        if (args.deniedSetix) buildParams['denied_setix'] = args.deniedSetix;
        if (args.maxIntentBudget !== undefined) buildParams['max_intent_budget'] = Number(args.maxIntentBudget);
        const signed = await this.buildAndSign('thread.publish_spend_policy', buildParams);
        const submitParams = this.packPassthroughParams({ baseParams: buildParams, signed });
        if (args.effectiveSlotOffset !== undefined) submitParams['effective_slot_offset'] = args.effectiveSlotOffset;
        const { result } = await this.invoke('thread.publish_spend_policy', submitParams);
        this.checkChainResult('thread.publish_spend_policy', result);
        const r = result as { policy_id_hex: string; version: number; effective_slot: string };
        return { policyIdHex: r.policy_id_hex, version: r.version, effectiveSlot: r.effective_slot };
    }

    async postOffer(args: {
        maxPriceMicro: bigint;
        setixCode?: number;
    }): Promise<{ offerIdHex: string }> {
        const sc = args.setixCode ?? this.setixCode;
        if (sc === null) throw new ThreadError('Call register() first or pass setixCode');
        const buildParams: Record<string, unknown> = {
            max_price_micro: args.maxPriceMicro.toString(),
            setix_code: sc,
        };
        const signed = await this.buildAndSign('thread.post_offer', buildParams);
        const offerIdHex = signed.extraIds['offer_id_hex'] as string;
        if (!offerIdHex) throw new ThreadError('build_doc did not return offer_id_hex');
        // Chain PostOffer: encode + sign the inner transaction locally.
        const nonce = await this.getNextChainNonce();
        const agentIdBytes = sha256(this.kp.publicKey);
        const offerIdBytes = new Uint8Array(Buffer.from(offerIdHex, 'hex'));
        const innerBytes = encodePostOffer(
            agentIdBytes,
            offerIdBytes,
            sc,
            1,
            args.maxPriceMicro,
            nonce,
        );
        const chainInnerSigHex = Buffer.from(signChainTxLocal(innerBytes, this.kp.privateKey, await this.getNativeChainId())).toString('hex');
        const submitParams = this.packPassthroughParams({
            baseParams: { ...buildParams, offer_id_hex: offerIdHex },
            signed,
            chainInnerSigHex,
            nonce,
        });
        const { result: postOfferRes } = await this.invoke('thread.post_offer', submitParams);
        this.checkChainResult('thread.post_offer', postOfferRes);
        return { offerIdHex };
    }

    async queryOffers(args: { setixCode?: number; maxResults?: number } = {}): Promise<Record<string, unknown>[]> {
        const sc = args.setixCode ?? this.setixCode;
        if (sc === null) throw new ThreadError('Call register() first or pass setixCode');
        const { result } = await this.invoke('thread.query_offers', {
            setix_code: sc, max_results: args.maxResults ?? 20,
        });
        return ((result as { offers?: Record<string, unknown>[] }).offers) ?? [];
    }

    /**
     * Post a bid on an open offer.
     *
     * `priceMicro` is the canonical input; `quotedPriceMicro` is retained for
     * one cycle as a deprecated alias (caller picks one; canonical wins if both
     * supplied). The wire sends the canonical `price_micro` field; the bridge
     * accepts either but logs a deprecation note when the alias name is used.
     */
    async postBid(args: {
        offerIdHex: string;
        /** Canonical bid-price field (v0.2.75+). Must equal the parent offer's max_price_micro exactly. */
        priceMicro?: bigint;
        /** @deprecated Pass `priceMicro` instead. */
        quotedPriceMicro?: bigint;
        quotedLatencyMs?: number;
    }): Promise<{ bidIdHex: string }> {
        const price = args.priceMicro ?? args.quotedPriceMicro;
        if (price === undefined) {
            throw new ThreadError('postBid: priceMicro is required (or pass deprecated alias quotedPriceMicro)');
        }
        const buildParams: Record<string, unknown> = {
            offer_id_hex: args.offerIdHex,
            price_micro: price.toString(),
            quoted_latency_ms: args.quotedLatencyMs ?? 5000,
        };
        const signed = await this.buildAndSign('thread.post_bid', buildParams);
        const bidIdHex = signed.extraIds['bid_id_hex'] as string;
        if (!bidIdHex) throw new ThreadError('build_doc did not return bid_id_hex');
        // Chain PostBid: encode + sign inner-tx locally.
        const nonce = await this.getNextChainNonce();
        const agentIdBytes = sha256(this.kp.publicKey);
        const innerBytes = encodePostBid(
            agentIdBytes,
            new Uint8Array(Buffer.from(bidIdHex, 'hex')),
            new Uint8Array(Buffer.from(args.offerIdHex, 'hex')),
            price,
            BigInt(args.quotedLatencyMs ?? 5000),
            nonce,
        );
        const chainInnerSigHex = Buffer.from(signChainTxLocal(innerBytes, this.kp.privateKey, await this.getNativeChainId())).toString('hex');
        const submitParams = this.packPassthroughParams({
            baseParams: { ...buildParams, bid_id_hex: bidIdHex },
            signed,
            chainInnerSigHex,
            nonce,
        });
        const { result: postBidRes } = await this.invoke('thread.post_bid', submitParams);
        this.checkChainResult('thread.post_bid', postBidRes);
        return { bidIdHex };
    }

    async queryBids(offerIdHex: string): Promise<Record<string, unknown>[]> {
        const { result } = await this.invoke('thread.query_bids', { offer_id_hex: offerIdHex });
        return ((result as { bids?: Record<string, unknown>[] }).bids) ?? [];
    }

    async waitForBids(offerIdHex: string, opts: { timeoutMs?: number; pollMs?: number } = {}): Promise<Record<string, unknown>[]> {
        const deadline = Date.now() + (opts.timeoutMs ?? 60_000);
        const poll = opts.pollMs ?? 1000;
        while (Date.now() < deadline) {
            const bids = await this.queryBids(offerIdHex);
            if (bids.length > 0) return bids;
            await new Promise<void>((r) => setTimeout(r, poll));
        }
        return [];
    }

    async acceptBid(args: {
        offerIdHex: string; bidIdHex: string; sellerIdHex: string; agreedPriceMicro: bigint;
    }): Promise<{ acceptanceIdHex: string }> {
        // Accept a bid (mirrors postOffer/postBid). Escrow opens on the chain
        // as part of accept_bid — there is no separate escrow-open call. The
        // bridge canonicalises the Acceptance document; the SDK signs it
        // locally (cose_sign1_hex) and also signs the chain AcceptBid
        // transaction locally (chain_inner_sig_hex); the bridge relays both.
        //
        // Pre-flight: thread.build_doc returns the canonical Acceptance
        // document and the acceptance_id_hex (which both the canonical
        // document and the chain escrow_id derivation depend on).
        const buildParams: Record<string, unknown> = {
            bid_id_hex: args.bidIdHex,
            seller_id_hex: args.sellerIdHex,
            agreed_price_micro: args.agreedPriceMicro.toString(),
            offer_id_hex: args.offerIdHex,
            // Escrow opens via the chain AcceptBid transaction; these two
            // fields are unused placeholders kept for wire back-compat.
            escrow_tx_sig_hex: '00'.repeat(64),
            escrow_pda_hex: '00'.repeat(32),
        };
        const signed = await this.buildAndSign('thread.accept_bid', buildParams);
        const acceptanceIdHex = (signed.extraIds['acceptance_id_hex'] as string)
            ?? Buffer.from(rand(32)).toString('hex');

        // Chain AcceptBid: encode + sign inner-tx locally.
        // chain_escrow_id = sha256(bid_id).
        const nonce = await this.getNextChainNonce();
        const buyerIdBytes = sha256(this.kp.publicKey);
        const bidIdBytes = new Uint8Array(Buffer.from(args.bidIdHex, 'hex'));
        const chainEscrowId = sha256(bidIdBytes);
        const innerBytes = encodeAcceptBid(
            buyerIdBytes,
            bidIdBytes,
            chainEscrowId,
            args.agreedPriceMicro,
            nonce,
        );
        const chainInnerSigHex = Buffer.from(signChainTxLocal(innerBytes, this.kp.privateKey, await this.getNativeChainId())).toString('hex');

        const submitParams = this.packPassthroughParams({
            baseParams: { ...buildParams, acceptance_id_hex: acceptanceIdHex },
            signed,
            chainInnerSigHex,
            nonce,
        });
        const { result } = await this.invoke('thread.accept_bid', submitParams);
        this.checkChainResult('thread.accept_bid', result);
        const r = result as { acceptance_id_hex?: string };
        return { acceptanceIdHex: r.acceptance_id_hex ?? acceptanceIdHex };
    }

    async queryEscrow(acceptanceIdHex: string): Promise<Record<string, unknown>> {
        try {
            const { result } = await this.invoke('thread.query_escrow', { acceptance_id_hex: acceptanceIdHex });
            return (result as Record<string, unknown>) ?? {};
        } catch {
            return {};
        }
    }

    // -- seller wake (thread.await_owner_events long-poll) ------------------

    /** Bridge-enforced ceiling on a single awaitOwnerEvents block (ms). The
     *  cap keeps each call under the public edge-proxy ceiling (~30s); loop
     *  the call (or use waitForOwnerEvent) for longer waits. */
    static readonly AWAIT_OWNER_EVENTS_MAX_WAIT_MS = 25_000;

    /**
     * ONE server-side-blocking wait for an owner-event addressed to YOUR
     * agent_id (the seller-wake path for one-shot agents — replaces
     * stay-alive polling). Blocks up to maxWaitMs (default 20s, clamped by
     * the bridge to [1s, 25s]) and returns the bridge result:
     * {agent_id_hex, events: [...], timed_out, waited_ms, ...}.
     *
     * Contract: FUTURE events only — always reconcile state first
     * (query_escrow_by_bid / query_bids / poll_delivery); a timed-out wait
     * ({timed_out: true, events: []}) is NORMAL — reconcile and call again
     * (waitForOwnerEvent does this loop for you). One wake channel per
     * agent. `kinds` filters which event kinds resolve the wait, e.g.
     * ['bid_accepted'] while waiting to deliver, ['escrow_settled'] while
     * waiting to be paid.
     *
     * Auth: a client-built COSE_Sign1 identity proof (cose_sign1_hex) —
     * non-custodial on every realm; your private key never leaves this
     * process. Register first (the bridge resolves your pubkey from your
     * registered agent identity).
     */
    async awaitOwnerEvents(opts: { kinds?: string[]; maxWaitMs?: number } = {}): Promise<Record<string, unknown>> {
        const raw = opts.maxWaitMs ?? 20_000;
        const params: Record<string, unknown> = {
            cose_sign1_hex: await this.observeAuthCoseHex('thread.await_owner_events'),
            max_wait_ms: Math.min(Math.max(Math.floor(raw), 1_000), ThreadClient.AWAIT_OWNER_EVENTS_MAX_WAIT_MS),
        };
        if (opts.kinds && opts.kinds.length > 0) params['kinds'] = opts.kinds;
        try {
            const { result } = await this.invoke('thread.await_owner_events', params);
            return (result ?? {}) as Record<string, unknown>;
        } catch (e) {
            if (!(e instanceof BridgeError) || !String(e.message).includes('cose_sign1_hex verification failed')) throw e;
            // Region-AAD mismatch (a geo-routed edge can serve consecutive
            // calls from different regions): re-learn the region, retry once.
            this._platformRegionId = null;
            params['cose_sign1_hex'] = await this.observeAuthCoseHex('thread.await_owner_events');
            const { result } = await this.invoke('thread.await_owner_events', params);
            return (result ?? {}) as Record<string, unknown>;
        }
    }

    /**
     * Loop awaitOwnerEvents until one of `kinds` arrives or timeout. Returns
     * the first matching decoded event ({event_kind, offer_id_hex?,
     * bid_id_hex?, acceptance_id_hex?, ...}). Throws ThreadError on timeout.
     * NB: covers FUTURE events only — reconcile current state BEFORE calling
     * (an event that fired before the loop started will never arrive here).
     */
    async waitForOwnerEvent(kinds: string[], opts: { timeoutMs?: number } = {}): Promise<Record<string, unknown>> {
        const timeoutMs = opts.timeoutMs ?? 300_000;
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            const remainingMs = deadline - Date.now();
            if (remainingMs < 1_000) break;
            const result = await this.awaitOwnerEvents({
                kinds,
                maxWaitMs: Math.min(remainingMs, ThreadClient.AWAIT_OWNER_EVENTS_MAX_WAIT_MS),
            });
            const events = (result['events'] ?? []) as Record<string, unknown>[];
            if (events.length > 0) return events[0]!;
        }
        throw new ThreadError(`waitForOwnerEvent timed out after ${timeoutMs}ms waiting for ${kinds.join(',')}`);
    }

    /**
     * Seller-side: wait until a buyer accepts your bid. Returns the escrow
     * record with acceptance_id_hex and buyer_id_hex once matched. Throws on
     * timeout.
     *
     * Uses the legible seller loop: reconcile state (query_escrow_by_bid) →
     * block on awaitOwnerEvents({kinds: ['bid_accepted']}) → reconcile again.
     * Falls back to plain 1s polling when the bridge does not serve
     * await_owner_events (older bridges).
     */
    async waitForAcceptance(bidIdHex: string, opts: { timeoutMs?: number; pollMs?: number } = {}): Promise<Record<string, unknown>> {
        const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
        const poll = opts.pollMs ?? 1000;
        let wakeAvailable = true;
        while (Date.now() < deadline) {
            // 1) Reconcile first — await covers FUTURE events only.
            try {
                const { result } = await this.invoke('thread.query_escrow_by_bid', { bid_id_hex: bidIdHex });
                const r = result as { acceptance_id_hex?: string };
                if (r && r.acceptance_id_hex) return result as Record<string, unknown>;
            } catch { /* reconcile again next cycle */ }
            // 2) Block on the wake channel (costs nothing while waiting);
            //    fall back to sleep-polling if the wake path is unavailable.
            if (wakeAvailable) {
                try {
                    const remainingMs = deadline - Date.now();
                    if (remainingMs >= 1_000) {
                        await this.awaitOwnerEvents({
                            kinds: ['bid_accepted'],
                            maxWaitMs: Math.min(remainingMs, ThreadClient.AWAIT_OWNER_EVENTS_MAX_WAIT_MS),
                        });
                    }
                    continue;
                } catch {
                    wakeAvailable = false;
                }
            }
            await new Promise<void>((r) => setTimeout(r, poll));
        }
        throw new ThreadError(`waitForAcceptance timed out after ${opts.timeoutMs ?? 120000}ms`);
    }

    async submitDelivery(args: {
        acceptanceIdHex: string; buyerIdHex: string; output: string;
        // encrypted delivery store: for a setix-store:// delivery,
        // pass output:"" + outputUri=setix-store://<hash> + the SELLER-ASSERTED
        // outputHashHex (sha256 of the PLAINTEXT) + outputKeyWrapHex (the sealed key
        // from encryptDeliveryArtifact in ./delivery-crypto). The bridge stores them
        // opaquely; it never sees plaintext. Omit all three for a normal delivery.
        outputUri?: string; outputHashHex?: string; outputKeyWrapHex?: string;
    }): Promise<{ deliveryIdHex: string; outputHashHex: string }> {
        // The bridge `thread.build_doc` canonicalises the Delivery document;
        // the SDK signs the canonical bytes locally and also encodes + signs
        // the chain SubmitDelivery transaction locally.
        const isStore = typeof args.outputUri === 'string' && args.outputUri.startsWith('setix-store://');
        const outputHash = args.outputHashHex
            ? new Uint8Array(Buffer.from(args.outputHashHex, 'hex'))
            : sha256(new TextEncoder().encode(args.output));
        const outputHashHex = Buffer.from(outputHash).toString('hex');

        // Pre-flight: resolve bid_id (needed for chain_escrow_id = sha256(bid_id)).
        const esc = await this.queryEscrow(args.acceptanceIdHex);
        const bidIdHex = esc['bid_id_hex'] as string | undefined;
        if (!bidIdHex || bidIdHex.length !== 64) {
            throw new ThreadError('submitDelivery: query_escrow did not surface bid_id_hex');
        }
        const bidIdBytes = new Uint8Array(Buffer.from(bidIdHex, 'hex'));
        const chainEscrowId = sha256(bidIdBytes);

        const signed = await this.buildAndSign('thread.submit_delivery', {
            acceptance_id_hex: args.acceptanceIdHex,
            buyer_id_hex: args.buyerIdHex,
            output: isStore ? '' : args.output,
            output_hash_hex: outputHashHex,
            ...(isStore ? { output_uri: args.outputUri, output_key_wrap_hex: args.outputKeyWrapHex } : {}),
        });
        const deliveryIdHex = signed.extraIds['delivery_id_hex'] as string;
        if (!deliveryIdHex) throw new ThreadError('build_doc did not return delivery_id_hex');

        // Chain SubmitDelivery (variant 8): agent(32) + escrow(32) + output_hash(32) + nonce.
        const nonce = await this.getNextChainNonce();
        const agentIdBytes = sha256(this.kp.publicKey);
        const innerBytes = encodeSubmitDelivery(agentIdBytes, chainEscrowId, outputHash, nonce);
        const chainInnerSigHex = Buffer.from(signChainTxLocal(innerBytes, this.kp.privateKey, await this.getNativeChainId())).toString('hex');

        const submitParams = this.packPassthroughParams({
            baseParams: {
                acceptance_id_hex: args.acceptanceIdHex,
                buyer_id_hex: args.buyerIdHex,
                output: isStore ? '' : args.output,
                output_hash_hex: outputHashHex,
                delivery_id_hex: deliveryIdHex,
                ...(isStore ? { output_uri: args.outputUri, output_key_wrap_hex: args.outputKeyWrapHex } : {}),
            },
            signed,
            chainInnerSigHex,
            nonce,
        });
        const { result: submitDeliveryRes } = await this.invoke('thread.submit_delivery', submitParams);
        this.checkChainResult('thread.submit_delivery', submitDeliveryRes);
        return { deliveryIdHex, outputHashHex };
    }

    async waitForDelivery(acceptanceIdHex: string, opts: { timeoutMs?: number; pollMs?: number } = {}): Promise<Record<string, unknown>> {
        const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
        const poll = opts.pollMs ?? 1000;
        while (Date.now() < deadline) {
            const esc = await this.queryEscrow(acceptanceIdHex);
            if (esc['delivery_id_hex']) return esc;
            await new Promise<void>((r) => setTimeout(r, poll));
        }
        throw new ThreadError(`waitForDelivery timed out after ${opts.timeoutMs ?? 120000}ms`);
    }

    async getFeeSchedule(): Promise<Record<string, unknown>> {
        const { result } = await this.invoke('thread.get_fee_schedule', {});
        return result as Record<string, unknown>;
    }

    /** Returns market depth for a setix_code: open offer/bid counts,
     * active sellers, demand ratio, recent prices. */
    async queryMarketDepth(setixCode?: number): Promise<Record<string, unknown>> {
        const sc = setixCode ?? this.setixCode;
        if (sc === null || sc === undefined) {
            throw new ThreadError('Pass setixCode or call register() first');
        }
        const { result } = await this.invoke('thread.query_market_depth', { setix_code: sc });
        return result as Record<string, unknown>;
    }

    /** Pick 'buyer' or 'seller' based on which side of the market is
     * underpopulated. Uses query_offers for the real-time book state
     * (depth cache is cron-refreshed and lags fresh posts) and depth's
     * active_sellers field for the slower-moving capacity-side signal.
     * Falls back to 'buyer' on errors — cold-market correct default
     * because only buyers can bootstrap an empty THREAD (RFQ) book. */
    async recommendedRole(setixCode?: number): Promise<'buyer' | 'seller'> {
        const sc = setixCode ?? this.setixCode ?? undefined;

        // Real-time signal: any open offers right now?
        let offers: Record<string, unknown>[] = [];
        try {
            offers = await this.queryOffers({ ...(sc !== undefined ? { setixCode: sc } : {}), maxResults: 5 });
        } catch {
            return 'buyer';
        }
        if (offers.length > 0) return 'seller';

        // No open offers. Check capacity-side via depth.
        let activeSellers = 0;
        try {
            const d = await this.queryMarketDepth(sc);
            activeSellers = Array.isArray(d['active_sellers'])
                ? (d['active_sellers'] as unknown[]).length
                : 0;
        } catch { /* fall through */ }

        if (activeSellers > 0) return 'buyer';

        // Cold market: bootstrap as buyer.
        return 'buyer';
    }

    /**
     * Settle a completed trade. Delegates to thread.settle (HL path); the bridge
     * builds and signs the encrypted-envelope-wrapped Settlement document internally.
     * Legacy params sellerIdHex / agreedPriceMicro / outputHashHex /
     * feeBps are accepted but ignored — the bridge looks them up from the delivery.
     *
     * outcome=2 (partial settle): supply cosr_released_micro and cosr_refunded_micro.
     * The SDK validates the implied fee and sum invariant before sending to the bridge.
     * fee = floor(releasedGross * SETTLEMENT_FEE_BPS / 10_000) where releasedGross =
     * agreedPriceMicro - cosr_refunded_micro (requires agreedPriceMicro for outcome=2).
     */
    async settle(args: {
        deliveryIdHex: string;
        sellerIdHex?: string;
        agreedPriceMicro?: bigint;
        outputHashHex?: string;
        feeBps?: number;
        /** outcome=2 partial settle: net seller credit (after fee). */
        cosrReleasedMicro?: bigint;
        /** outcome=2 partial settle: amount returned to buyer. */
        cosrRefundedMicro?: bigint;
    }): Promise<{ settlementIdHex: string; releasedMicro: bigint; feeMicro: bigint; feeBps: number }> {
        const r = await this.settleHl({ deliveryIdHex: args.deliveryIdHex });
        return {
            settlementIdHex: r['settlement_id_hex'] as string ?? '',
            releasedMicro: BigInt(r['released_micro'] as string ?? '0'),
            feeMicro: BigInt(r['fee_micro'] as string ?? '0'),
            feeBps: SETTLEMENT_FEE_BPS,
        };
    }

    async fileDispute(args: {
        deliveryIdHex: string;
        reason?: number;
        evidenceUri: string;
        evidenceHashHex?: string;
        evidenceBondMicro?: bigint;
    }): Promise<{ disputeIdHex: string; status: string; assignedOracleHex: string | null }> {
        // The bridge `thread.build_doc` canonicalises the Dispute document;
        // the SDK signs it locally and also encodes + signs the chain
        // MarkDisputed transaction locally. Pre-flight resolves the bid_id
        // (chain_escrow_id = sha256(bid_id)).
        const buildParams: Record<string, unknown> = {
            delivery_id_hex: args.deliveryIdHex,
            reason: args.reason ?? 0,
            evidence_uri: args.evidenceUri,
            evidence_bond_micro: (args.evidenceBondMicro ?? 100_000n).toString(),
        };
        if (args.evidenceHashHex !== undefined) buildParams['evidence_hash_hex'] = args.evidenceHashHex;

        const signed = await this.buildAndSign('thread.file_dispute', buildParams);
        const disputeIdHex = signed.extraIds['dispute_id_hex'] as string;
        if (!disputeIdHex) throw new ThreadError('build_doc did not return dispute_id_hex');

        // Pre-flight: derive chain_escrow_id from delivery → acceptance → bid.
        // The poll_delivery surface returns acceptance_id_hex + bid_id_hex when
        // present; we route through it to keep the SDK strictly thin.
        let chainEscrowId: Uint8Array;
        try {
            const { result: poll } = await this.invoke('thread.poll_delivery', {
                delivery_id_hex: args.deliveryIdHex,
            });
            const p = poll as { bid_id_hex?: string; acceptance_id_hex?: string };
            if (p.bid_id_hex && p.bid_id_hex.length === 64) {
                chainEscrowId = sha256(new Uint8Array(Buffer.from(p.bid_id_hex, 'hex')));
            } else if (p.acceptance_id_hex) {
                const esc = await this.queryEscrow(p.acceptance_id_hex);
                const bidHex = esc['bid_id_hex'] as string | undefined;
                if (!bidHex || bidHex.length !== 64) {
                    throw new ThreadError('fileDispute: cannot resolve bid_id for chain_escrow_id');
                }
                chainEscrowId = sha256(new Uint8Array(Buffer.from(bidHex, 'hex')));
            } else {
                throw new ThreadError('fileDispute: poll_delivery returned neither bid_id_hex nor acceptance_id_hex');
            }
        } catch (e) {
            // Bridge may not expose poll_delivery in stub mode; surface as a
            // typed error so the caller can fall back to a different flow.
            if (e instanceof ThreadError) throw e;
            throw new ThreadError(`fileDispute: pre-flight resolution failed: ${(e as Error).message}`);
        }

        const nonce = await this.getNextChainNonce();
        const filerIdBytes = sha256(this.kp.publicKey);
        const disputeIdBytes = new Uint8Array(Buffer.from(disputeIdHex, 'hex'));
        const innerBytes = encodeMarkDisputed(chainEscrowId, disputeIdBytes, filerIdBytes, nonce);
        const chainInnerSigHex = Buffer.from(signChainTxLocal(innerBytes, this.kp.privateKey, await this.getNativeChainId())).toString('hex');

        const submitParams = this.packPassthroughParams({
            baseParams: { ...buildParams, dispute_id_hex: disputeIdHex },
            signed,
            chainInnerSigHex,
            nonce,
        });
        const { result } = await this.invoke('thread.file_dispute', submitParams);
        this.checkChainResult('thread.file_dispute', result);
        const r = result as { dispute_id_hex: string; status: string; assigned_oracle_hex: string | null };
        return {
            disputeIdHex: r.dispute_id_hex,
            status: r.status,
            assignedOracleHex: r.assigned_oracle_hex ?? null,
        };
    }

    // -- high-level (HL) methods — v0.1.37 ----------------------------------
    // Bridge builds and signs COSE_Sign1 internally; no CBOR/COSE needed here.

    get secretKeyHex(): string {
        return Buffer.from(this.kp.privateKey).toString('hex');
    }

    /**
     * Deprecated. `acceptBidHl(bid_id_hex)` required transmitting your secret
     * key to the bridge, which is incompatible with the non-custodial design.
     * Use the full `acceptBid`, which accepts the offer / seller / price
     * explicitly — those fields are visible to buyers via `queryBids(offerIdHex)`.
     *
     * Retained as a throwing stub so older code surfaces the migration clearly
     * rather than silently breaking.
     */
    async acceptBidHl(bidIdHex: string): Promise<Record<string, unknown>> {
        void bidIdHex;
        throw new ThreadError(
            'acceptBidHl is deprecated — use acceptBid({ offerIdHex, bidIdHex, sellerIdHex, agreedPriceMicro }). ' +
            'Fields come from queryBids(offerIdHex).',
        );
    }

    /**
     * Resolves buyer_id from the escrow row, then delegates to the
     * `submitDelivery` flow.
     */
    async submitDeliveryHl(opts: {
        acceptanceIdHex: string;
        output: string;
        outputUri?: string;
    }): Promise<Record<string, unknown>> {
        void opts.outputUri;
        const esc = await this.queryEscrow(opts.acceptanceIdHex);
        const buyerIdHex = esc['buyer_id_hex'] as string | undefined;
        if (!buyerIdHex || buyerIdHex.length !== 64) {
            throw new ThreadError('submitDeliveryHl: queryEscrow did not surface buyer_id_hex');
        }
        const res = await this.submitDelivery({
            acceptanceIdHex: opts.acceptanceIdHex,
            buyerIdHex,
            output: opts.output,
        });
        return { delivery_id_hex: res.deliveryIdHex, output_hash_hex: res.outputHashHex };
    }

    async pollDelivery(opts: {
        acceptanceIdHex?: string;
        bidIdHex?: string;
    }): Promise<Record<string, unknown>> {
        const params: Record<string, unknown> = {};
        if (opts.acceptanceIdHex !== undefined) params['acceptance_id_hex'] = opts.acceptanceIdHex;
        else if (opts.bidIdHex !== undefined) params['bid_id_hex'] = opts.bidIdHex;
        else throw new ThreadError('provide acceptanceIdHex or bidIdHex');
        const { result } = await this.invoke('thread.poll_delivery', params);
        return result as Record<string, unknown>;
    }

    async waitForPollDelivery(opts: {
        acceptanceIdHex?: string;
        bidIdHex?: string;
        timeoutMs?: number;
        pollIntervalMs?: number;
    }): Promise<Record<string, unknown>> {
        const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
        const interval = opts.pollIntervalMs ?? 1_000;
        while (Date.now() < deadline) {
            const r = await this.pollDelivery({
                ...(opts.acceptanceIdHex !== undefined ? { acceptanceIdHex: opts.acceptanceIdHex } : {}),
                ...(opts.bidIdHex !== undefined ? { bidIdHex: opts.bidIdHex } : {}),
            });
            if (r['delivery_id_hex']) return r;
            await new Promise((resolve) => setTimeout(resolve, interval));
        }
        throw new ThreadError('waitForPollDelivery timed out');
    }

    /**
     * Settle a completed trade. Resolves seller / agreed_price / output_hash
     * via `thread.query_escrow_by_bid` (or `thread.query_escrow` when
     * acceptance_id_hex is supplied); the bridge canonicalises the Settlement
     * document; the SDK signs the canonical bytes locally and also encodes +
     * signs the chain Settle transaction locally.
     */
    async settleHl(opts: {
        deliveryIdHex?: string;
        acceptanceIdHex?: string;
    }): Promise<Record<string, unknown>> {
        if (!opts.deliveryIdHex && !opts.acceptanceIdHex) {
            throw new ThreadError('settleHl: provide deliveryIdHex or acceptanceIdHex');
        }

        // Pre-flight: resolve all build_doc fields the bridge expects for
        // thread.settle — seller_id, agreed_price, output_hash + chain
        // escrow id (sha256(bid_id)).
        let acceptanceIdHex = opts.acceptanceIdHex;
        let deliveryIdHex = opts.deliveryIdHex;
        if (!acceptanceIdHex && deliveryIdHex) {
            const { result: pollResult } = await this.invoke('thread.poll_delivery', {
                delivery_id_hex: deliveryIdHex,
            });
            const p = pollResult as { acceptance_id_hex?: string; output_hash_hex?: string };
            if (!p.acceptance_id_hex) {
                throw new ThreadError('settleHl: poll_delivery did not return acceptance_id_hex');
            }
            acceptanceIdHex = p.acceptance_id_hex;
        }
        const esc = await this.queryEscrow(acceptanceIdHex!);
        const sellerIdHex = esc['seller_id_hex'] as string | undefined;
        const bidIdHex = esc['bid_id_hex'] as string | undefined;
        const agreedPriceStr = esc['agreed_price_micro'] as string | undefined;
        if (!deliveryIdHex) deliveryIdHex = esc['delivery_id_hex'] as string | undefined;
        const outputHashHex = esc['output_hash_hex'] as string | undefined;
        if (!sellerIdHex || !bidIdHex || !agreedPriceStr || !deliveryIdHex || !outputHashHex) {
            throw new ThreadError(
                'settleHl: query_escrow missing one of seller_id_hex / bid_id_hex / agreed_price_micro / delivery_id_hex / output_hash_hex',
            );
        }

        const signed = await this.buildAndSign('thread.settle', {
            delivery_id_hex: deliveryIdHex,
            seller_id_hex: sellerIdHex,
            agreed_price_micro: agreedPriceStr,
            output_hash_hex: outputHashHex,
            fee_bps: SETTLEMENT_FEE_BPS,
        });

        // Chain Settle: caller(32) + escrow(32) + nonce(u64 LE) where
        // escrow_id = sha256(bid_id).
        const nonce = await this.getNextChainNonce();
        const agentIdBytes = sha256(this.kp.publicKey);
        const chainEscrowId = sha256(new Uint8Array(Buffer.from(bidIdHex, 'hex')));
        const innerBytes = encodeSettle(agentIdBytes, chainEscrowId, nonce);
        const chainInnerSigHex = Buffer.from(signChainTxLocal(innerBytes, this.kp.privateKey, await this.getNativeChainId())).toString('hex');

        const submitParams = this.packPassthroughParams({
            baseParams: {
                delivery_id_hex: deliveryIdHex,
                seller_id_hex: sellerIdHex,
                agreed_price_micro: agreedPriceStr,
                output_hash_hex: outputHashHex,
                fee_bps: SETTLEMENT_FEE_BPS,
            },
            signed,
            chainInnerSigHex,
            nonce,
        });
        const { result } = await this.invoke('thread.settle', submitParams);
        this.checkChainResult('thread.settle', result);
        return result as Record<string, unknown>;
    }

    // -- Intent + Workflow Manifest methods ----------------------------------
    // Bridge stubs ship at a prior version; handler wiring is a future platform cycle.

    /** Buyer: post a declarative goal. Bridge pre-locks
     *  max_budget_micro in escrow. Returns {intent_id_hex, status, escrow_tx_hex}. */
    async broadcastIntent(args: {
        goalDescription: string;
        maxBudgetMicro: bigint;
        allowedSetixCodes?: number[];
        deadlineSlots?: number;
        maxSubtaskCount?: number;
        minSolverReputationBps?: number;
        solverBondRequiredMicro?: bigint;
        predicateType?: number;
    }): Promise<{ intentIdHex: string; status: string; escrowTxHex: string }> {
        const buildParams: Record<string, unknown> = {
            goal_description: args.goalDescription,
            max_budget_micro: args.maxBudgetMicro.toString(),
        };
        if (args.allowedSetixCodes !== undefined) buildParams['allowed_setix_codes'] = args.allowedSetixCodes;
        if (args.deadlineSlots !== undefined) buildParams['deadline_slots'] = args.deadlineSlots;
        if (args.maxSubtaskCount !== undefined) buildParams['max_subtask_count'] = args.maxSubtaskCount;
        if (args.minSolverReputationBps !== undefined) buildParams['min_solver_reputation_bps'] = args.minSolverReputationBps;
        if (args.solverBondRequiredMicro !== undefined) buildParams['solver_bond_required_micro'] = args.solverBondRequiredMicro.toString();
        if (args.predicateType !== undefined) buildParams['predicate_type'] = args.predicateType;
        const signed = await this.buildAndSign('thread.broadcast_intent', buildParams);
        const submitParams = this.packPassthroughParams({ baseParams: buildParams, signed });
        const { result } = await this.invoke('thread.broadcast_intent', submitParams);
        this.checkChainResult('thread.broadcast_intent', result);
        const r = result as { intent_id_hex: string; status: string; escrow_tx_hex: string };
        return { intentIdHex: r.intent_id_hex, status: r.status, escrowTxHex: r.escrow_tx_hex };
    }

    /** Solver: claim an open Intent. Atomically commits
     *  workflow_manifest_hash. Returns {claim_id_hex, intent_id_hex, status, bond_locked_micro}. */
    async respondToIntent(args: {
        intentIdHex: string;
        workflowManifestHashHex: string;
        quotedPriceMicro: bigint;
        estimatedCompletionSlots?: number;
    }): Promise<{ claimIdHex: string; intentIdHex: string; status: string; bondLockedMicro: string }> {
        const buildParams: Record<string, unknown> = {
            intent_id_hex: args.intentIdHex,
            workflow_manifest_hash_hex: args.workflowManifestHashHex,
            quoted_price_micro: args.quotedPriceMicro.toString(),
        };
        if (args.estimatedCompletionSlots !== undefined) buildParams['estimated_completion_slots'] = args.estimatedCompletionSlots;
        const signed = await this.buildAndSign('thread.respond_to_intent', buildParams);
        const submitParams = this.packPassthroughParams({ baseParams: buildParams, signed });
        const { result } = await this.invoke('thread.respond_to_intent', submitParams);
        this.checkChainResult('thread.respond_to_intent', result);
        const r = result as { claim_id_hex: string; intent_id_hex: string; status: string; bond_locked_micro: string };
        return { claimIdHex: r.claim_id_hex, intentIdHex: r.intent_id_hex, status: r.status, bondLockedMicro: r.bond_locked_micro };
    }

    /** Solver: publish the Workflow Manifest DAG. Must be called after
     *  respondToIntent with the matching manifest_hash. Returns {workflow_id_hex, manifest_hash_hex, status}. */
    async composeWorkflowManifest(args: {
        nodes: Array<{ nodeId: string; setixCode: number; maxPriceMicro: bigint; mergePolicy?: number; mergeK?: number }>;
        totalBudgetMicro: bigint;
        intentIdHex?: string;
        edges?: Array<{ fromNodeId: string; toNodeId: string }>;
        deadlineSlots?: number;
    }): Promise<{ workflowIdHex: string; manifestHashHex: string; status: string }> {
        const buildParams: Record<string, unknown> = {
            nodes: args.nodes.map(n => ({
                node_id: n.nodeId,
                setix_code: n.setixCode,
                max_price_micro: n.maxPriceMicro.toString(),
                ...(n.mergePolicy !== undefined ? { merge_policy: n.mergePolicy } : {}),
                ...(n.mergeK !== undefined ? { merge_k: n.mergeK } : {}),
            })),
            total_budget_micro: args.totalBudgetMicro.toString(),
        };
        if (args.intentIdHex !== undefined) buildParams['intent_id_hex'] = args.intentIdHex;
        if (args.edges !== undefined) buildParams['edges'] = args.edges.map(e => ({ from_node_id: e.fromNodeId, to_node_id: e.toNodeId }));
        if (args.deadlineSlots !== undefined) buildParams['deadline_slots'] = args.deadlineSlots;
        const signed = await this.buildAndSign('thread.compose_workflow_manifest', buildParams);
        const submitParams = this.packPassthroughParams({ baseParams: buildParams, signed });
        const { result } = await this.invoke('thread.compose_workflow_manifest', submitParams);
        this.checkChainResult('thread.compose_workflow_manifest', result);
        const r = result as { workflow_id_hex: string; manifest_hash_hex: string; status: string };
        return { workflowIdHex: r.workflow_id_hex, manifestHashHex: r.manifest_hash_hex, status: r.status };
    }

    /** Buyer: accept the solver's Workflow Manifest; unlocks sub-task marketplace.
     *  Intent moves to INTENT_ACTIVE. Returns {accepted, intent_id_hex, workflow_id_hex, status}. */
    async acceptWorkflowManifest(args: {
        intentIdHex: string;
        claimIdHex: string;
    }): Promise<{ accepted: boolean; intentIdHex: string; workflowIdHex: string; status: string }> {
        // No document to sign here; the handler authorises via your public
        // key (agent_pubkey_hex).
        const { result } = await this.invoke('thread.accept_workflow_manifest', {
            agent_pubkey_hex: this.kp.pubkeyHex,
            intent_id_hex: args.intentIdHex,
            claim_id_hex: args.claimIdHex,
        });
        this.checkChainResult('thread.accept_workflow_manifest', result);
        const r = result as { accepted: boolean; intent_id_hex: string; workflow_id_hex: string; status: string };
        return { accepted: r.accepted, intentIdHex: r.intent_id_hex, workflowIdHex: r.workflow_id_hex, status: r.status };
    }

    /** Sub-seller: deliver output for a workflow node. Set isFinal=true on the last frame;
     *  bridge emits Stream Commit and triggers sub-settlement.
     *  Returns {frame_id_hex, status, sequence, accumulator_root_hex}. */
    async submitWorkflowStepDelivery(args: {
        acceptanceIdHex: string;
        output: string;
        isFinal: boolean;
        resourceUnits?: number;
        resourceUnitType?: number;
    }): Promise<{ frameIdHex: string; status: string; sequence: number; accumulatorRootHex: string }> {
        const buildParams: Record<string, unknown> = {
            acceptance_id_hex: args.acceptanceIdHex,
            output: args.output,
            is_final: args.isFinal,
        };
        if (args.resourceUnits !== undefined) buildParams['resource_units'] = args.resourceUnits;
        if (args.resourceUnitType !== undefined) buildParams['resource_unit_type'] = args.resourceUnitType;
        const signed = await this.buildAndSign('thread.submit_workflow_step_delivery', buildParams);
        const submitParams = this.packPassthroughParams({ baseParams: buildParams, signed });
        const { result } = await this.invoke('thread.submit_workflow_step_delivery', submitParams);
        this.checkChainResult('thread.submit_workflow_step_delivery', result);
        const r = result as { frame_id_hex: string; status: string; sequence: number; accumulator_root_hex: string };
        return { frameIdHex: r.frame_id_hex, status: r.status, sequence: r.sequence, accumulatorRootHex: r.accumulator_root_hex };
    }

    /** Buyer/solver: trigger Nested Settlement after all nodes deliver.
     *  Atomically pays all sub-sellers. Returns {nested_settlement_id_hex, status,
     *  total_cosr_released, total_cosr_refunded, solver_profit_micro}. */
    async settleWorkflowManifest(args: {
        intentIdHex?: string;
        workflowIdHex?: string;
        predicateResultHex?: string;
    } = {}): Promise<{ nestedSettlementIdHex: string; status: string; totalCosrReleased: string; totalCosrRefunded: string; solverProfitMicro: string }> {
        if (!args.intentIdHex && !args.workflowIdHex) {
            throw new ThreadError('settleWorkflowManifest: provide intentIdHex or workflowIdHex');
        }
        const buildParams: Record<string, unknown> = {};
        if (args.intentIdHex !== undefined) buildParams['intent_id_hex'] = args.intentIdHex;
        if (args.workflowIdHex !== undefined) buildParams['workflow_id_hex'] = args.workflowIdHex;
        if (args.predicateResultHex !== undefined) buildParams['predicate_result_hex'] = args.predicateResultHex;
        // The bridge builds the Nested Settlement document internally; route
        // through the build_doc path. build_doc does not cover
        // thread.settle_workflow_manifest yet — fall back to submitting the
        // public key only when build_doc reports the tool is not dispatchable.
        let submitParams: Record<string, unknown>;
        try {
            const signed = await this.buildAndSign('thread.settle_workflow_manifest', buildParams);
            submitParams = this.packPassthroughParams({ baseParams: buildParams, signed });
        } catch (e) {
            const msg = (e as Error).message ?? '';
            if (!/not dispatchable/.test(msg)) throw e;
            // Fallback: pass identity only (public key, no secret key).
            submitParams = { ...buildParams, agent_pubkey_hex: this.kp.pubkeyHex };
        }
        const { result } = await this.invoke('thread.settle_workflow_manifest', submitParams);
        this.checkChainResult('thread.settle_workflow_manifest', result);
        const r = result as {
            nested_settlement_id_hex: string; status: string;
            total_cosr_released: string; total_cosr_refunded: string; solver_profit_micro: string;
        };
        return {
            nestedSettlementIdHex: r.nested_settlement_id_hex,
            status: r.status,
            totalCosrReleased: r.total_cosr_released,
            totalCosrRefunded: r.total_cosr_refunded,
            solverProfitMicro: r.solver_profit_micro,
        };
    }

    /** File a dispute against a workflow step delivery.
     *  Returns {dispute_id_hex, status, assigned_oracle_hex}. */
    async disputeWorkflowStep(args: {
        workflowIdHex: string;
        nodeId: string;
        deliveryIdHex: string;
        reason?: number;
        evidenceUri: string;
        evidenceBondMicro?: bigint;
    }): Promise<{ disputeIdHex: string; status: string; assignedOracleHex: string | null }> {
        // No document to sign here; the handler authorises via your public
        // key (agent_pubkey_hex).
        const params: Record<string, unknown> = {
            agent_pubkey_hex: this.kp.pubkeyHex,
            workflow_id_hex: args.workflowIdHex,
            node_id: args.nodeId,
            delivery_id_hex: args.deliveryIdHex,
            evidence_uri: args.evidenceUri,
            reason: args.reason ?? 0,
            evidence_bond_micro: (args.evidenceBondMicro ?? 100_000n).toString(),
        };
        const { result } = await this.invoke('thread.dispute_workflow_step', params);
        this.checkChainResult('thread.dispute_workflow_step', result);
        const r = result as { dispute_id_hex: string; status: string; assigned_oracle_hex: string | null };
        return { disputeIdHex: r.dispute_id_hex, status: r.status, assignedOracleHex: r.assigned_oracle_hex ?? null };
    }
}

// ---- one-shot convenience helpers -----------------------------------------

export async function buyOnce(opts: {
    bridgeUrl: string;
    description: string;
    maxPriceMicro: bigint;
    bidTimeoutMs?: number;
    deliveryTimeoutMs?: number;
    keyPath?: string;
}): Promise<{ settlementIdHex: string; releasedMicro: bigint; feeMicro: bigint }> {
    const client = new ThreadClient({ bridgeUrl: opts.bridgeUrl, ...(opts.keyPath !== undefined ? { keyPath: opts.keyPath } : {}) });
    if (client.setixCode === null) await client.register(opts.description);
    const offer = await client.postOffer({ maxPriceMicro: opts.maxPriceMicro });
    const bids = await client.waitForBids(offer.offerIdHex, { timeoutMs: opts.bidTimeoutMs ?? 60_000 });
    if (bids.length === 0) throw new ThreadError('no bids arrived in time');
    const chosen = bids.reduce((a, b) =>
        BigInt(a['quoted_price_micro'] as string) < BigInt(b['quoted_price_micro'] as string) ? a : b
    );
    const sellerIdHex = chosen['seller_id_hex'] as string;
    const agreed = BigInt(chosen['quoted_price_micro'] as string);
    const acc = await client.acceptBid({
        offerIdHex: offer.offerIdHex,
        bidIdHex: chosen['bid_id_hex'] as string,
        sellerIdHex, agreedPriceMicro: agreed,
    });
    const delivered = await client.waitForDelivery(acc.acceptanceIdHex, { timeoutMs: opts.deliveryTimeoutMs ?? 120_000 });
    return await client.settle({
        deliveryIdHex: delivered['delivery_id_hex'] as string,
        sellerIdHex, agreedPriceMicro: agreed,
        outputHashHex: delivered['output_hash_hex'] as string,
    });
}

export async function sellOnce(opts: {
    bridgeUrl: string;
    description: string;
    floorPriceMicro: bigint;
    output: string;
    acceptTimeoutMs?: number;
    keyPath?: string;
}): Promise<{ deliveryIdHex: string; outputHashHex: string }> {
    const client = new ThreadClient({ bridgeUrl: opts.bridgeUrl, ...(opts.keyPath !== undefined ? { keyPath: opts.keyPath } : {}) });
    if (client.setixCode === null) await client.register(opts.description);
    const offers = await client.queryOffers();
    if (offers.length === 0) throw new ThreadError('no open offers in your setix_code');
    const shuffled = [...offers].sort(() => Math.random() - 0.5);
    const chosen = shuffled.find((o) => BigInt(o['max_price_micro'] as string) >= opts.floorPriceMicro);
    if (!chosen) throw new ThreadError('no offer at or above floor price');
    const bid = await client.postBid({
        offerIdHex: chosen['offer_id_hex'] as string,
        priceMicro: opts.floorPriceMicro,
    });
    const accepted = await client.waitForAcceptance(bid.bidIdHex, { timeoutMs: opts.acceptTimeoutMs ?? 120_000 });
    return await client.submitDelivery({
        acceptanceIdHex: accepted['acceptance_id_hex'] as string,
        buyerIdHex: accepted['buyer_id_hex'] as string,
        output: opts.output,
    });
}

/** End-to-end BUYER flow using HL bridge tools (v0.1.37).
 * register → post_offer → wait_for_bids → accept_bid → poll until delivered → settle.
 * Returns {role: "buyer", settlementIdHex, ...}. */
export async function buyerLoop(opts: {
    bridgeUrl: string;
    description: string;
    maxPriceMicro?: bigint;
    bidTimeoutMs?: number;
    deliveryTimeoutMs?: number;
    keyPath?: string;
}): Promise<Record<string, unknown>> {
    const client = new ThreadClient({ bridgeUrl: opts.bridgeUrl, ...(opts.keyPath !== undefined ? { keyPath: opts.keyPath } : {}) });
    if (client.setixCode === null) await client.register(opts.description);
    const offer = await client.postOffer({ maxPriceMicro: opts.maxPriceMicro ?? 5000n });
    const bids = await client.waitForBids(offer.offerIdHex, { timeoutMs: opts.bidTimeoutMs ?? 60_000 });
    if (bids.length === 0) throw new ThreadError('buyerLoop: no bids arrived in time');
    const chosen = bids.reduce((a, b) =>
        BigInt(a['quoted_price_micro'] as string) < BigInt(b['quoted_price_micro'] as string) ? a : b
    );
    // Use the full acceptBid flow with the bid row's published fields.
    const acc = await client.acceptBid({
        offerIdHex: chosen['offer_id_hex'] as string,
        bidIdHex: chosen['bid_id_hex'] as string,
        sellerIdHex: chosen['seller_id_hex'] as string,
        agreedPriceMicro: BigInt(chosen['quoted_price_micro'] as string),
    });
    const delivered = await client.waitForPollDelivery({
        acceptanceIdHex: acc.acceptanceIdHex,
        timeoutMs: opts.deliveryTimeoutMs ?? 120_000,
    });
    const result = await client.settleHl({ deliveryIdHex: delivered['delivery_id_hex'] as string });
    return { role: 'buyer', ...result };
}

/** End-to-end SELLER flow using HL bridge tools (v0.1.37).
 * register → query_offers → post_bid → poll until accepted → submit_delivery.
 * Returns {role: "seller", deliveryIdHex, ...}. */
export async function sellerLoop(opts: {
    bridgeUrl: string;
    description: string;
    floorPriceMicro?: bigint;
    output: string;
    acceptTimeoutMs?: number;
    keyPath?: string;
}): Promise<Record<string, unknown>> {
    const client = new ThreadClient({ bridgeUrl: opts.bridgeUrl, ...(opts.keyPath !== undefined ? { keyPath: opts.keyPath } : {}) });
    if (client.setixCode === null) await client.register(opts.description);
    const offers = await client.queryOffers();
    if (offers.length === 0) throw new ThreadError('sellerLoop: no open offers in your setix_code');
    const floor = opts.floorPriceMicro ?? 2000n;
    const shuffled = [...offers].sort(() => Math.random() - 0.5);
    const chosen = shuffled.find((o) => BigInt(o['max_price_micro'] as string) >= floor);
    if (!chosen) throw new ThreadError('sellerLoop: no offer at or above floor price');
    const bid = await client.postBid({
        offerIdHex: chosen['offer_id_hex'] as string,
        priceMicro: floor,
    });
    const accepted = await client.waitForAcceptance(bid.bidIdHex, {
        timeoutMs: opts.acceptTimeoutMs ?? 120_000,
    });
    const result = await client.submitDeliveryHl({
        acceptanceIdHex: accepted['acceptance_id_hex'] as string,
        output: opts.output,
    });
    return { role: 'seller', ...result };
}

/** Register, pick a role from current market depth, run the right flow.
 * Returns `{role, ...flowResult}`. Encapsulates hazard #9 in skill.md —
 * agents that can't afford the doc-reading time get the right role
 * automatically. Caller provides hints for both roles; SDK uses whichever
 * matches the picked role. */
export async function autoTrade(opts: {
    bridgeUrl: string;
    description: string;
    maxPriceMicro?: bigint;        // used if buyer
    floorPriceMicro?: bigint;      // used if seller
    output?: string;               // used if seller
    bidTimeoutMs?: number;         // default 30_000
    deliveryTimeoutMs?: number;    // default 60_000
    acceptTimeoutMs?: number;      // default 60_000
    launchJitterMs?: number;       // default 3000 — random delay 0..N before any work
    keyPath?: string;
}): Promise<{ role: 'buyer' | 'seller'; [k: string]: unknown }> {
    // Stagger swarm launches so N near-simultaneous agents don't herd-lock
    // on identical recommended_role() decisions.
    const jitter = opts.launchJitterMs ?? 3000;
    if (jitter > 0) {
        await new Promise<void>((r) => setTimeout(r, Math.random() * jitter));
    }

    const client = new ThreadClient({ bridgeUrl: opts.bridgeUrl, ...(opts.keyPath !== undefined ? { keyPath: opts.keyPath } : {}) });
    if (client.setixCode === null) {
        await client.register(opts.description);
    }
    let role = await client.recommendedRole();

    // Floor-aware override: refuse a guaranteed-stall role.
    try {
        const depth = await client.queryMarketDepth();
        const activeSellers = (depth['active_sellers'] as Array<Record<string, unknown>> | undefined) ?? [];
        const floors = activeSellers
            .map((s) => s['min_price_micro'])
            .filter((v): v is string | number => v !== null && v !== undefined)
            .map((v) => BigInt(v as string | number));
        const marketFloor = floors.length > 0
            ? floors.reduce((a, b) => (a < b ? a : b))
            : null;
        const maxPriceMicro = opts.maxPriceMicro ?? 5000n;
        if (role === 'buyer' && marketFloor !== null && maxPriceMicro < marketFloor) {
            // Our budget can't clear visible sellers' floor — flip.
            role = 'seller';
        }
    } catch { /* fall back to depth-only role */ }

    if (role === 'buyer') {
        const maxPriceMicro = opts.maxPriceMicro ?? 5000n;
        const offer = await client.postOffer({ maxPriceMicro });
        const bids = await client.waitForBids(offer.offerIdHex, {
            timeoutMs: opts.bidTimeoutMs ?? 30_000,
        });
        if (bids.length === 0) {
            throw new ThreadError('autoTrade(buyer): no bids arrived in time');
        }
        const chosen = bids.reduce((a, b) =>
            BigInt(a['quoted_price_micro'] as string) < BigInt(b['quoted_price_micro'] as string) ? a : b
        );
        const sellerIdHex = chosen['seller_id_hex'] as string;
        const agreed = BigInt(chosen['quoted_price_micro'] as string);
        const acc = await client.acceptBid({
            offerIdHex: offer.offerIdHex,
            bidIdHex: chosen['bid_id_hex'] as string,
            sellerIdHex,
            agreedPriceMicro: agreed,
        });
        const delivered = await client.waitForDelivery(acc.acceptanceIdHex, {
            timeoutMs: opts.deliveryTimeoutMs ?? 60_000,
        });
        const settled = await client.settle({
            deliveryIdHex: delivered['delivery_id_hex'] as string,
            sellerIdHex,
            agreedPriceMicro: agreed,
            outputHashHex: delivered['output_hash_hex'] as string,
        });
        return { role: 'buyer', ...settled };
    }

    // role === 'seller'
    const floorPriceMicro = opts.floorPriceMicro ?? 2000n;
    const output = opts.output ?? 'automated agent output';
    const offers = await client.queryOffers();
    if (offers.length === 0) {
        // Cold market with no offers — flip to buyer so we don't deadlock
        // (paired-test round 2: both swarms picked seller in an empty
        // market and all 20 stalled). Post an offer; the next agent will
        // become a seller via recommended_role's buyer_count>seller_count
        // branch.
        const maxPriceMicro = opts.maxPriceMicro ?? 5000n;
        const offer = await client.postOffer({ maxPriceMicro });
        const bids = await client.waitForBids(offer.offerIdHex, {
            timeoutMs: opts.bidTimeoutMs ?? 30_000,
        });
        if (bids.length === 0) {
            throw new ThreadError(
                'autoTrade(seller→buyer fallback): no bids on our posted offer either'
            );
        }
        const chosen = bids.reduce((a, b) =>
            BigInt(a['quoted_price_micro'] as string) < BigInt(b['quoted_price_micro'] as string) ? a : b
        );
        const sellerIdHex = chosen['seller_id_hex'] as string;
        const agreed = BigInt(chosen['quoted_price_micro'] as string);
        const acc = await client.acceptBid({
            offerIdHex: offer.offerIdHex,
            bidIdHex: chosen['bid_id_hex'] as string,
            sellerIdHex,
            agreedPriceMicro: agreed,
        });
        const delivered = await client.waitForDelivery(acc.acceptanceIdHex, {
            timeoutMs: opts.deliveryTimeoutMs ?? 60_000,
        });
        const settled = await client.settle({
            deliveryIdHex: delivered['delivery_id_hex'] as string,
            sellerIdHex,
            agreedPriceMicro: agreed,
            outputHashHex: delivered['output_hash_hex'] as string,
        });
        return { role: 'buyer', fallback_from: 'seller', ...settled };
    }
    const shuffled = [...offers].sort(() => Math.random() - 0.5);
    const chosenOffer = shuffled.find(
        (o) => BigInt(o['max_price_micro'] as string) >= floorPriceMicro
    );
    if (!chosenOffer) {
        throw new ThreadError('autoTrade(seller): no offer at or above floor price');
    }
    const bid = await client.postBid({
        offerIdHex: chosenOffer['offer_id_hex'] as string,
        priceMicro: floorPriceMicro,
    });
    const accepted = await client.waitForAcceptance(bid.bidIdHex, {
        timeoutMs: opts.acceptTimeoutMs ?? 60_000,
    });
    const delivery = await client.submitDelivery({
        acceptanceIdHex: accepted['acceptance_id_hex'] as string,
        buyerIdHex: accepted['buyer_id_hex'] as string,
        output,
    });
    return { role: 'seller', ...delivery };
}

// This client speaks the public `thread.*` tools only. Privileged chain and
// market operations are not part of the public surface.

// Silence unused-import warnings on cborDecode if downstream tools strip it.
void cborDecode;
