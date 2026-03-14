/**
 * Shadow — Double Ratchet Algorithm (TypeScript)
 *
 * A complete implementation of the Signal Double Ratchet Algorithm:
 *   https://signal.org/docs/specifications/doubleratchet/
 *
 * Primitives:
 *   X25519       — Diffie-Hellman (@noble/curves/x25519)
 *   HKDF-SHA256  — KDF root chain (@noble/hashes/hkdf)
 *   HMAC-SHA256  — KDF chain keys (@noble/hashes/hmac)
 *   AES-256-GCM  — AEAD message encryption (Web Crypto SubtleCrypto)
 *
 * Public API:
 *   generateDH()
 *   dh(privHex, pubHex)
 *   kdfRk(rootKey, dhOut)            → [newRk, chainKey]
 *   kdfCk(chainKey)                  → [newCk, messageKey]
 *   aeadEncrypt(mk, pt, aad)         → Promise<Uint8Array>   (IV || ciphertext)
 *   aeadDecrypt(mk, ct, aad)         → Promise<Uint8Array>   (plaintext)
 *   serializeHeader / deserializeHeader
 *   ratchetInitAlice(sk, bobDhPub)   → RatchetState
 *   ratchetInitBob(sk, spkPriv, spkPub) → RatchetState
 *   ratchetEncrypt(state, plaintext, ad)
 *   ratchetDecrypt(state, header, ct, ad)
 */

import { x25519 }    from '@noble/curves/x25519';
import { sha256 }    from '@noble/hashes/sha256';
import { hkdf }      from '@noble/hashes/hkdf';
import { hmac }      from '@noble/hashes/hmac';
import { randomBytes } from '@noble/hashes/utils';
import { fromHex, toHex } from './identity';

// ─── Constants ────────────────────────────────────────────────────────────────

/** Maximum number of skipped message keys to keep. Prevents DoS. */
const MAX_SKIP = 1000;

const HKDF_INFO_RK  = new TextEncoder().encode('ShadowRootKey');
const HMAC_CK_CONST = new Uint8Array([0x01]);  // constant for chain key KDF
const HMAC_MK_CONST = new Uint8Array([0x02]);  // constant for message key KDF

/** AES-GCM nonce size (bytes) */
const GCM_NONCE_LEN = 12;

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Complete state of a Double Ratchet session.
 * All keys are stored as lowercase hex for JSON serialisability.
 */
export interface RatchetState {
  /** Sending DH keypair — private key (hex) */
  dhsPriv:   string;
  /** Sending DH keypair — public key (hex) */
  dhsPub:    string;
  /** Receiving DH public key, or null before any message received */
  dhr:       string | null;
  /** Root key (32 bytes, hex) */
  rk:        string;
  /** Sending chain key (hex), or null if no sending chain yet */
  cks:       string | null;
  /** Receiving chain key (hex), or null if no receiving chain yet */
  ckr:       string | null;
  /** Send message number */
  ns:        number;
  /** Receive message number */
  nr:        number;
  /** Number of messages in previous sending chain */
  pn:        number;
  /**
   * Skipped message keys, keyed as "<dh_pub_hex>:<message_number>".
   * Values are message keys (hex).
   */
  mkSkipped: Record<string, string>;
}

export interface Header {
  /** Sender's current DH ratchet public key */
  dh: Uint8Array;
  /** Number of messages in previous sending chain */
  pn: number;
  /** Message number in current sending chain */
  n:  number;
}

export interface EncryptResult {
  /** Serialised 40-byte header */
  header:     Uint8Array;
  /** Promise resolving to (IV || GCM ciphertext) */
  ciphertext: Promise<Uint8Array>;
  /** Updated ratchet state (must be persisted before next operation) */
  newState:   RatchetState;
}

export interface DecryptResult {
  plaintext: string;
  newState:  RatchetState;
}

// ─── DH primitives ────────────────────────────────────────────────────────────

/**
 * Generate a fresh X25519 DH keypair.
 * Returns [privHex, pubHex].
 */
export function generateDH(): [string, string] {
  const priv = randomBytes(32);
  const pub  = x25519.getPublicKey(priv);
  return [toHex(priv), toHex(pub)];
}

/**
 * Perform X25519 Diffie-Hellman.
 * Returns the 32-byte shared secret.
 */
export function dh(privHex: string, pubHex: string): Uint8Array {
  return x25519.getSharedSecret(fromHex(privHex), fromHex(pubHex));
}

// ─── KDF functions ────────────────────────────────────────────────────────────

/**
 * Root key KDF. Derives a new root key and chain key from a DH output.
 *
 * RK', CK = HKDF-SHA256(RK, dh_out, 'ShadowRootKey', L=64)
 * Returns [newRootKey (32 bytes), chainKey (32 bytes)].
 */
export function kdfRk(
  rootKey: Uint8Array,
  dhOut:   Uint8Array,
): [Uint8Array, Uint8Array] {
  // HKDF: IKM=dhOut, salt=rootKey, info=HKDF_INFO_RK, length=64
  const out = hkdf(sha256, dhOut, rootKey, HKDF_INFO_RK, 64);
  return [out.slice(0, 32), out.slice(32, 64)];
}

/**
 * Chain key KDF. Derives a new chain key and message key.
 *
 * newCK = HMAC-SHA256(CK, 0x01)
 * MK    = HMAC-SHA256(CK, 0x02)
 *
 * Returns [newChainKey (32 bytes), messageKey (32 bytes)].
 */
export function kdfCk(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const newCk = hmac(sha256, chainKey, HMAC_CK_CONST);
  const mk    = hmac(sha256, chainKey, HMAC_MK_CONST);
  return [newCk, mk];
}

// ─── AEAD: AES-256-GCM ───────────────────────────────────────────────────────

/**
 * Encrypt plaintext with AES-256-GCM.
 *
 * Output format: [12-byte IV] || [GCM ciphertext + 16-byte auth tag]
 *
 * @param messageKey — 32-byte AES key
 * @param plaintext  — plaintext bytes
 * @param aad        — additional authenticated data (not encrypted)
 */
export async function aeadEncrypt(
  messageKey: Uint8Array,
  plaintext:  Uint8Array,
  aad:        Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    messageKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );
  const iv = randomBytes(GCM_NONCE_LEN);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    plaintext,
  );
  // Prepend IV so receiver can extract it
  const result = new Uint8Array(GCM_NONCE_LEN + ct.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ct), GCM_NONCE_LEN);
  return result;
}

/**
 * Decrypt AES-256-GCM ciphertext.
 *
 * @param messageKey — 32-byte AES key
 * @param ciphertext — [12-byte IV] || [GCM ciphertext]
 * @param aad        — additional authenticated data (must match encrypt call)
 * @throws           DecryptionError if authentication fails
 */
export async function aeadDecrypt(
  messageKey: Uint8Array,
  ciphertext: Uint8Array,
  aad:        Uint8Array,
): Promise<Uint8Array> {
  if (ciphertext.length < GCM_NONCE_LEN + 16) {
    throw new Error('aeadDecrypt: ciphertext too short');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    messageKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const iv = ciphertext.slice(0, GCM_NONCE_LEN);
  const ct = ciphertext.slice(GCM_NONCE_LEN);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    ct,
  );
  return new Uint8Array(pt);
}

// ─── Header serialisation ─────────────────────────────────────────────────────

/**
 * Serialise a ratchet header to a fixed 40-byte representation:
 *   bytes  0–31 : DH public key (32 bytes)
 *   bytes 32–35 : pn (uint32 big-endian)
 *   bytes 36–39 : n  (uint32 big-endian)
 */
export function serializeHeader(h: Header): Uint8Array {
  const out = new Uint8Array(40);
  out.set(h.dh, 0);
  const view = new DataView(out.buffer);
  view.setUint32(32, h.pn, false);  // big-endian
  view.setUint32(36, h.n,  false);
  return out;
}

/** Deserialise a 40-byte header. */
export function deserializeHeader(data: Uint8Array): Header {
  if (data.length < 40) {
    throw new RangeError(`deserializeHeader: expected 40 bytes, got ${data.length}`);
  }
  const dh   = data.slice(0, 32);
  const view = new DataView(data.buffer, data.byteOffset);
  const pn   = view.getUint32(32, false);
  const n    = view.getUint32(36, false);
  return { dh, pn, n };
}

/**
 * Build the AEAD additional data: AD || 4-byte header-length || header-bytes.
 * This binds ciphertexts to a specific header, preventing splice attacks.
 */
export function concatAD(ad: Uint8Array, header: Header): Uint8Array {
  const hdrBytes = serializeHeader(header);
  const lenBuf   = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, hdrBytes.length, false);
  const out = new Uint8Array(ad.length + 4 + hdrBytes.length);
  out.set(ad,       0);
  out.set(lenBuf,   ad.length);
  out.set(hdrBytes, ad.length + 4);
  return out;
}

// ─── Ratchet initialisation ───────────────────────────────────────────────────

/**
 * Initialise Alice's (sender's) ratchet state after a completed X3DH exchange.
 *
 * @param sk       — 32-byte shared secret from X3DH
 * @param bobDhPub — Bob's signed prekey public (hex); Alice uses it as dhr
 */
export function ratchetInitAlice(
  sk:       Uint8Array,
  bobDhPub: string,
): RatchetState {
  const [dhsPriv, dhsPub] = generateDH();
  const dhOut             = dh(dhsPriv, bobDhPub);
  const [rk, cks]         = kdfRk(sk, dhOut);

  return {
    dhsPriv, dhsPub,
    dhr: bobDhPub,
    rk:  toHex(rk),
    cks: toHex(cks),
    ckr: null,
    ns: 0, nr: 0, pn: 0,
    mkSkipped: {},
  };
}

/**
 * Initialise Bob's (receiver's) ratchet state after receiving an X3DH message.
 *
 * @param sk      — 32-byte shared secret from X3DH
 * @param spkPriv — Bob's signed prekey private key (hex)
 * @param spkPub  — Bob's signed prekey public key (hex)
 */
export function ratchetInitBob(
  sk:      Uint8Array,
  spkPriv: string,
  spkPub:  string,
): RatchetState {
  return {
    dhsPriv: spkPriv,
    dhsPub:  spkPub,
    dhr:     null,
    rk:      toHex(sk),
    cks:     null,
    ckr:     null,
    ns: 0, nr: 0, pn: 0,
    mkSkipped: {},
  };
}

// ─── Encrypt ──────────────────────────────────────────────────────────────────

/**
 * Encrypt a plaintext message using the current sending chain.
 *
 * The header and updated state are returned synchronously (important: the
 * caller MUST persist `newState` before awaiting `ciphertext`).
 * The ciphertext is returned as a Promise because AES-GCM is async.
 *
 * @throws if there is no active sending chain (cks is null)
 */
export function ratchetEncrypt(
  state:     RatchetState,
  plaintext: string,
  ad:        Uint8Array,
): EncryptResult {
  if (!state.cks) {
    throw new Error('ratchetEncrypt: no sending chain key (session not initialised)');
  }

  // Deep-clone state so caller's original is not mutated
  const s: RatchetState = {
    ...state,
    mkSkipped: { ...state.mkSkipped },
  };

  // Advance the sending chain
  const [newCk, mk] = kdfCk(fromHex(s.cks!));
  s.cks = toHex(newCk);

  const header: Header = { dh: fromHex(s.dhsPub), pn: s.pn, n: s.ns };
  s.ns += 1;

  const aad        = concatAD(ad, header);
  const ptBytes    = new TextEncoder().encode(plaintext);
  const ciphertext = aeadEncrypt(mk, ptBytes, aad);

  return { header: serializeHeader(header), ciphertext, newState: s };
}

// ─── Decrypt ──────────────────────────────────────────────────────────────────

/**
 * Decrypt a received message, advancing the ratchet as needed.
 *
 * Handles:
 *   - Skipped messages (out-of-order delivery)
 *   - DH ratchet steps (new sender ratchet key)
 *
 * @throws if decryption fails (wrong key, tampered ciphertext, etc.)
 */
export async function ratchetDecrypt(
  state:       RatchetState,
  headerBytes: Uint8Array,
  ciphertext:  Uint8Array,
  ad:          Uint8Array,
): Promise<DecryptResult> {
  // Deep-clone state
  const s: RatchetState = {
    ...state,
    mkSkipped: { ...state.mkSkipped },
  };

  const header = deserializeHeader(headerBytes);
  const dhHex  = toHex(header.dh);

  // ── Try previously skipped message keys ────────────────────────────────
  const skippedKey = `${dhHex}:${header.n}`;
  if (s.mkSkipped[skippedKey]) {
    const mk = fromHex(s.mkSkipped[skippedKey]);
    delete s.mkSkipped[skippedKey];
    const aad = concatAD(ad, header);
    const pt  = await aeadDecrypt(mk, ciphertext, aad);
    return { plaintext: new TextDecoder().decode(pt), newState: s };
  }

  // ── DH ratchet step if needed ──────────────────────────────────────────
  if (s.dhr === null || dhHex !== s.dhr) {
    skipMessageKeys(s, header.pn);
    dhRatchetStep(s, header);
  }

  // ── Advance receive chain ──────────────────────────────────────────────
  skipMessageKeys(s, header.n);

  if (!s.ckr) {
    throw new Error('ratchetDecrypt: no receiving chain key after DH ratchet');
  }

  const [newCk, mk] = kdfCk(fromHex(s.ckr));
  s.ckr  = toHex(newCk);
  s.nr  += 1;

  const aad = concatAD(ad, header);
  const pt  = await aeadDecrypt(mk, ciphertext, aad);
  return { plaintext: new TextDecoder().decode(pt), newState: s };
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/**
 * Store message keys for all skipped messages up to `until`.
 * Mutates `s` in place.
 */
function skipMessageKeys(s: RatchetState, until: number): void {
  if (s.nr + MAX_SKIP < until) {
    throw new Error(
      `ratchetDecrypt: too many skipped messages (${until - s.nr} > ${MAX_SKIP})`,
    );
  }
  while (s.ckr && s.nr < until) {
    const [newCk, mk] = kdfCk(fromHex(s.ckr));
    s.ckr = toHex(newCk);
    s.mkSkipped[`${s.dhr}:${s.nr}`] = toHex(mk);
    s.nr += 1;
  }
}

/**
 * Perform a DH ratchet step on receiving a new sender DH key.
 * Derives a new receiving chain key, then a new sending chain key.
 * Mutates `s` in place.
 */
function dhRatchetStep(s: RatchetState, header: Header): void {
  s.pn  = s.ns;
  s.ns  = 0;
  s.nr  = 0;
  s.dhr = toHex(header.dh);

  // Receiving ratchet: DH(ours, their new key) → new RK + CKr
  const out1      = dh(s.dhsPriv, s.dhr);
  const [rk1, ckr] = kdfRk(fromHex(s.rk), out1);
  s.rk  = toHex(rk1);
  s.ckr = toHex(ckr);

  // Generate a new sending DH keypair
  const [newPriv, newPub] = generateDH();
  s.dhsPriv = newPriv;
  s.dhsPub  = newPub;

  // Sending ratchet: DH(new ours, their new key) → new RK + CKs
  const out2      = dh(s.dhsPriv, s.dhr);
  const [rk2, cks] = kdfRk(fromHex(s.rk), out2);
  s.rk  = toHex(rk2);
  s.cks = toHex(cks);
}
