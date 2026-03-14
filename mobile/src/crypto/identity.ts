/**
 * Shadow — Device Identity
 *
 * Manages the device's long-lived cryptographic identity:
 *   - X25519 keypair  (ikDh*)    for Diffie-Hellman in X3DH and ratchet
 *   - ed25519 keypair (ikSign*)  for signing the Signed PreKey (SPK)
 *
 * All key material is represented as lowercase hex strings for safe
 * JSON serialisation. Binary operations use Uint8Array throughout.
 *
 * Exports:
 *   generateDeviceIdentity()          → DeviceIdentity
 *   generateSignedPreKey(id, identity) → SignedPreKey
 *   generateOneTimePreKey(id)          → OneTimePreKey
 *   signData(identity, data)           → Uint8Array  (ed25519 signature)
 *   verifySignature(pubHex, data, sig) → boolean
 *   verifyBundle(identitySignPub, spkPub, spkSig) → boolean
 *   toHex(bytes)   / fromHex(hex)
 */

import { x25519 }     from '@noble/curves/x25519';
import { ed25519 }    from '@noble/curves/ed25519';
import { randomBytes } from '@noble/hashes/utils';

// ─── Public types ─────────────────────────────────────────────────────────────

/**
 * A device's long-lived cryptographic identity.
 * MUST be stored in hardware-backed secure storage (expo-secure-store).
 */
export interface DeviceIdentity {
  /** X25519 private scalar (32 bytes, hex) — used in X3DH and ratchet DH */
  ikDhPriv:   string;
  /** X25519 public key (32 bytes, hex) — shared with contacts */
  ikDhPub:    string;
  /** ed25519 private key seed (32 bytes, hex) — used to sign SPK */
  ikSignPriv: string;
  /** ed25519 public key (32 bytes, hex) — shared with contacts for SPK verification */
  ikSignPub:  string;
}

/**
 * A Signed PreKey: a fresh X25519 keypair signed by the identity signing key.
 * Rotated periodically (recommended: weekly).
 */
export interface SignedPreKey {
  /** Monotonically increasing ID (used to match Alice's bundle reference) */
  id:        number;
  /** X25519 private key (32 bytes, hex) */
  privKey:   string;
  /** X25519 public key (32 bytes, hex) */
  pubKey:    string;
  /** ed25519 signature of pubKey, produced by ikSignPriv (64 bytes, hex) */
  signature: string;
}

/**
 * A One-Time PreKey: a single-use X25519 keypair.
 * Consumed during X3DH; the private key is deleted after use.
 */
export interface OneTimePreKey {
  /** Unique ID (used to match Alice's bundle reference) */
  id:      number;
  /** X25519 private key (32 bytes, hex) */
  privKey: string;
  /** X25519 public key (32 bytes, hex) */
  pubKey:  string;
}

// ─── Key generation ───────────────────────────────────────────────────────────

/**
 * Generate a fresh device identity.
 * Should only be called once per device installation.
 */
export function generateDeviceIdentity(): DeviceIdentity {
  const dhPrivBytes   = randomBytes(32);
  const dhPubBytes    = x25519.getPublicKey(dhPrivBytes);
  const signPrivBytes = ed25519.utils.randomPrivateKey();
  const signPubBytes  = ed25519.getPublicKey(signPrivBytes);

  return {
    ikDhPriv:   toHex(dhPrivBytes),
    ikDhPub:    toHex(dhPubBytes),
    ikSignPriv: toHex(signPrivBytes),
    ikSignPub:  toHex(signPubBytes),
  };
}

/**
 * Generate a new Signed PreKey, signed by the device identity.
 *
 * @param identity — device identity (needs ikSignPriv)
 * @param id       — monotonically increasing SPK id
 */
export function generateSignedPreKey(
  identity: DeviceIdentity,
  id: number,
): SignedPreKey {
  const privBytes = randomBytes(32);
  const pubBytes  = x25519.getPublicKey(privBytes);
  const sigBytes  = ed25519.sign(pubBytes, fromHex(identity.ikSignPriv));

  return {
    id,
    privKey:   toHex(privBytes),
    pubKey:    toHex(pubBytes),
    signature: toHex(sigBytes),
  };
}

/**
 * Generate a fresh One-Time PreKey.
 *
 * @param id — unique identifier for this OPK
 */
export function generateOneTimePreKey(id: number): OneTimePreKey {
  const privBytes = randomBytes(32);
  const pubBytes  = x25519.getPublicKey(privBytes);

  return {
    id,
    privKey: toHex(privBytes),
    pubKey:  toHex(pubBytes),
  };
}

// ─── Signing ──────────────────────────────────────────────────────────────────

/**
 * Sign arbitrary data using the device's ed25519 identity signing key.
 * Returns a 64-byte signature.
 */
export function signData(
  identity: DeviceIdentity,
  data:     Uint8Array,
): Uint8Array {
  return ed25519.sign(data, fromHex(identity.ikSignPriv));
}

/**
 * Verify an ed25519 signature against a known public key.
 *
 * @param signPubHex — signer's ed25519 public key (hex)
 * @param data       — original data that was signed
 * @param signature  — 64-byte signature
 */
export function verifySignature(
  signPubHex: string,
  data:       Uint8Array,
  signature:  Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, data, fromHex(signPubHex));
  } catch {
    return false;
  }
}

/**
 * Verify that an SPK was signed by a given identity signing key.
 * Used by Alice when processing Bob's PreKeyBundle.
 *
 * @param identitySignPubHex — Bob's ikSignPub (hex)
 * @param spkPubHex          — Bob's SPK public key (hex)
 * @param spkSignatureHex    — signature of spkPub by identitySignPriv (hex)
 */
export function verifyBundle(
  identitySignPubHex: string,
  spkPubHex:          string,
  spkSignatureHex:    string,
): boolean {
  try {
    return ed25519.verify(
      fromHex(spkSignatureHex),
      fromHex(spkPubHex),
      fromHex(identitySignPubHex),
    );
  } catch {
    return false;
  }
}

// ─── Encoding helpers ─────────────────────────────────────────────────────────

/** Convert a Uint8Array to a lowercase hex string */
export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** Convert a lowercase hex string to a Uint8Array */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new RangeError(`fromHex: odd-length hex string (${hex.length} chars)`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i >>> 1] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}
