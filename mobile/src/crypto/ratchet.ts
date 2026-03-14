/**
 * Shadow — Double Ratchet (TypeScript)
 *
 * Primitives:
 *   X25519       — @noble/curves/x25519
 *   HKDF-SHA256  — @noble/hashes/hkdf
 *   HMAC-SHA256  — @noble/hashes/hmac
 *   AES-256-GCM  — Web Crypto SubtleCrypto
 */

import { x25519 }    from '@noble/curves/x25519';
import { sha256 }    from '@noble/hashes/sha256';
import { hkdf }      from '@noble/hashes/hkdf';
import { hmac }      from '@noble/hashes/hmac';
import { randomBytes } from '@noble/hashes/utils';
import { fromHex, toHex } from './identity';

const MAX_SKIP = 1000;
const HKDF_INFO_RK  = new TextEncoder().encode('ShadowRootKey');
const HMAC_CK_CONST = new Uint8Array([0x01]);
const HMAC_MK_CONST = new Uint8Array([0x02]);

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export interface RatchetState {
  dhsPriv:    string;   // hex
  dhsPub:     string;
  dhr:        string | null;
  rk:         string;
  cks:        string | null;
  ckr:        string | null;
  ns:         number;
  nr:         number;
  pn:         number;
  mkSkipped:  Record<string, string>;  // "{dh_pub}:{n}" -> mk_hex
}

export interface EncryptResult {
  header:     Uint8Array;
  ciphertext: Uint8Array;
  newState:   RatchetState;
}

// ─────────────────────────────────────────────────────────────
// DH primitives
// ─────────────────────────────────────────────────────────────

export function generateDH(): [string, string] {
  const priv = randomBytes(32);
  const pub  = x25519.getPublicKey(priv);
  return [toHex(priv), toHex(pub)];
}

export function dh(privHex: string, pubHex: string): Uint8Array {
  return x25519.getSharedSecret(fromHex(privHex), fromHex(pubHex));
}

// ─────────────────────────────────────────────────────────────
// KDF
// ─────────────────────────────────────────────────────────────

export function kdfRk(rootKey: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const out = hkdf(sha256, dhOut, rootKey, HKDF_INFO_RK, 64);
  return [out.slice(0, 32), out.slice(32)];
}

export function kdfCk(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const newCk = hmac(sha256, chainKey, HMAC_CK_CONST);
  const mk    = hmac(sha256, chainKey, HMAC_MK_CONST);
  return [newCk, mk];
}

// ─────────────────────────────────────────────────────────────
// AEAD: AES-256-GCM via SubtleCrypto
// ─────────────────────────────────────────────────────────────

export async function aeadEncrypt(
  messageKey: Uint8Array,
  plaintext:  Uint8Array,
  aad:        Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', messageKey, 'AES-GCM', false, ['encrypt']);
  const iv  = randomBytes(12);
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return out;
}

export async function aeadDecrypt(
  messageKey: Uint8Array,
  ciphertext: Uint8Array,
  aad:        Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', messageKey, 'AES-GCM', false, ['decrypt']);
  const iv  = ciphertext.slice(0, 12);
  const ct  = ciphertext.slice(12);
  const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct);
  return new Uint8Array(pt);
}

// ─────────────────────────────────────────────────────────────
// Header
// ─────────────────────────────────────────────────────────────

export interface Header {
  dh: Uint8Array;
  pn: number;
  n:  number;
}

export function serializeHeader(h: Header): Uint8Array {
  const out = new Uint8Array(40);
  out.set(h.dh, 0);
  new DataView(out.buffer).setUint32(32, h.pn, false);
  new DataView(out.buffer).setUint32(36, h.n,  false);
  return out;
}

export function deserializeHeader(data: Uint8Array): Header {
  const dh = data.slice(0, 32);
  const pn = new DataView(data.buffer, data.byteOffset).getUint32(32, false);
  const n  = new DataView(data.buffer, data.byteOffset).getUint32(36, false);
  return { dh, pn, n };
}

export function concatAD(ad: Uint8Array, header: Header): Uint8Array {
  const hdr = serializeHeader(header);
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, hdr.length, false);
  const out = new Uint8Array(ad.length + 4 + hdr.length);
  out.set(ad, 0);
  out.set(lenBuf, ad.length);
  out.set(hdr, ad.length + 4);
  return out;
}

// ─────────────────────────────────────────────────────────────
// Ratchet init
// ─────────────────────────────────────────────────────────────

export function ratchetInitAlice(sk: Uint8Array, bobDhPub: string): RatchetState {
  const [dhsPriv, dhsPub] = generateDH();
  const dhOut = dh(dhsPriv, bobDhPub);
  const [rk, cks] = kdfRk(sk, dhOut);
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

export function ratchetInitBob(sk: Uint8Array, spkPriv: string, spkPub: string): RatchetState {
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

// ─────────────────────────────────────────────────────────────
// Encrypt (sync header, async AEAD)
// ─────────────────────────────────────────────────────────────

export function ratchetEncrypt(
  state:     RatchetState,
  plaintext: string,
  ad:        Uint8Array,
): { header: Uint8Array; ciphertext: Promise<Uint8Array>; newState: RatchetState } {
  if (!state.cks) throw new Error('No sending chain key');
  const s = { ...state, mkSkipped: { ...state.mkSkipped } };

  const ck = fromHex(s.cks!);
  const [newCk, mk] = kdfCk(ck);
  s.cks = toHex(newCk);

  const header: Header = { dh: fromHex(s.dhsPub), pn: s.pn, n: s.ns };
  s.ns += 1;

  const aad        = concatAD(ad, header);
  const ptBytes    = new TextEncoder().encode(plaintext);
  const ciphertext = aeadEncrypt(mk, ptBytes, aad);

  return { header: serializeHeader(header), ciphertext, newState: s };
}

export async function ratchetDecrypt(
  state:      RatchetState,
  headerBytes: Uint8Array,
  ciphertext:  Uint8Array,
  ad:          Uint8Array,
): Promise<{ plaintext: string; newState: RatchetState }> {
  const s = { ...state, mkSkipped: { ...state.mkSkipped } };
  const header = deserializeHeader(headerBytes);
  const dhHex  = toHex(header.dh);

  // Try skipped keys
  const skippedKey = `${dhHex}:${header.n}`;
  if (s.mkSkipped[skippedKey]) {
    const mk = fromHex(s.mkSkipped[skippedKey]);
    delete s.mkSkipped[skippedKey];
    const aad = concatAD(ad, header);
    const pt  = await aeadDecrypt(mk, ciphertext, aad);
    return { plaintext: new TextDecoder().decode(pt), newState: s };
  }

  // DH ratchet if new sender key
  if (s.dhr === null || dhHex !== s.dhr) {
    skipMessageKeys(s, header.pn);
    dhRatchet(s, header);
  }

  skipMessageKeys(s, header.n);

  const ck = fromHex(s.ckr!);
  const [newCk, mk] = kdfCk(ck);
  s.ckr = toHex(newCk);
  s.nr += 1;

  const aad = concatAD(ad, header);
  const pt  = await aeadDecrypt(mk, ciphertext, aad);
  return { plaintext: new TextDecoder().decode(pt), newState: s };
}

function skipMessageKeys(s: RatchetState, until: number): void {
  if (s.nr + MAX_SKIP < until) throw new Error('Too many skipped messages');
  while (s.nr < until && s.ckr) {
    const ck = fromHex(s.ckr);
    const [newCk, mk] = kdfCk(ck);
    s.ckr = toHex(newCk);
    s.mkSkipped[`${s.dhr}:${s.nr}`] = toHex(mk);
    s.nr += 1;
  }
}

function dhRatchet(s: RatchetState, header: Header): void {
  s.pn  = s.ns;
  s.ns  = 0;
  s.nr  = 0;
  s.dhr = toHex(header.dh);

  const out1 = dh(s.dhsPriv, s.dhr);
  const [rk1, ckr] = kdfRk(fromHex(s.rk), out1);
  s.rk  = toHex(rk1);
  s.ckr = toHex(ckr);

  const [newPriv, newPub] = generateDH();
  s.dhsPriv = newPriv;
  s.dhsPub  = newPub;

  const out2 = dh(s.dhsPriv, s.dhr);
  const [rk2, cks] = kdfRk(fromHex(s.rk), out2);
  s.rk  = toHex(rk2);
  s.cks = toHex(cks);
}
