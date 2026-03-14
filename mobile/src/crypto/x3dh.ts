/**
 * Shadow — X3DH Key Agreement (TypeScript)
 *
 * Implements the Extended Triple Diffie-Hellman key agreement protocol
 * as specified in the Signal specification:
 *   https://signal.org/docs/specifications/x3dh/
 *
 * Roles:
 *   Alice (sender)   — initiates the session, sends InitialMessage
 *   Bob   (receiver) — derives the same session key from the initial message
 *
 * Primitives:
 *   DH  : X25519       via @noble/curves/x25519
 *   Hash: SHA-256      via @noble/hashes/sha256
 *   HKDF: HKDF-SHA-256 via @noble/hashes/hkdf
 *   Sign: ed25519      via @noble/curves/ed25519 (SPK verification)
 */

import { x25519 }     from '@noble/curves/x25519';
import { ed25519 }    from '@noble/curves/ed25519';
import { sha256 }     from '@noble/hashes/sha256';
import { hkdf }       from '@noble/hashes/hkdf';
import { randomBytes } from '@noble/hashes/utils';

import {
  fromHex,
  toHex,
  type DeviceIdentity,
  type SignedPreKey,
  type OneTimePreKey,
} from './identity';
import {
  ratchetInitAlice,
  ratchetInitBob,
  type RatchetState,
} from './ratchet';

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * The 32-byte constant 0xFF...FF prepended to the KDF input per the X3DH spec.
 * This ensures the KDF input space is distinct from DH output space.
 */
const X3DH_F    = new Uint8Array(32).fill(0xff);
const X3DH_INFO = new TextEncoder().encode('ShadowX3DH');
/** Per RFC 5869: empty salt → all-zero salt of hash length */
const X3DH_SALT = new Uint8Array(32);

// ─── Public types ─────────────────────────────────────────────────────────────

/**
 * Bob's public key bundle. Transmitted out-of-band (QR code, server, etc.).
 * Alice uses this to initiate a session.
 */
export interface PreKeyBundle {
  /** Bob's X25519 identity key public (used in DH) */
  identityKey:     string;   // hex, 64 chars
  /** Bob's ed25519 identity key public (used to verify SPK sig) */
  identitySignKey: string;   // hex, 64 chars
  /** ID of the signed prekey used */
  spkId:           number;
  /** Bob's SPK public key */
  spkPublic:       string;   // hex, 64 chars
  /** ed25519 signature of spkPublic by identitySignKey */
  spkSignature:    string;   // hex, 128 chars (64 bytes)
  /** Optional one-time prekey ID; null if no OPK is being used */
  opkId:           number | null;
  /** Optional one-time prekey public; null if no OPK is being used */
  opkPublic:       string | null;  // hex, 64 chars
}

/**
 * Alice's initial message to Bob. Sent alongside the first ciphertext so Bob
 * can reconstruct the shared secret and initialise his ratchet state.
 */
export interface InitialMessage {
  /** Alice's X25519 identity key public */
  ikPub:       string;   // hex
  /** Alice's ephemeral key public */
  ekPub:       string;   // hex
  /** SPK ID Alice used from Bob's bundle */
  spkId:       number;
  /** OPK ID Alice used, or null */
  opkId:       number | null;
  /** Serialised ratchet header bytes for the first encrypted message (hex) */
  headerBytes: string;   // hex
  /** First encrypted message ciphertext (hex); filled by caller after await */
  ciphertext:  string;   // hex
}

/**
 * The result of Alice running x3dhSend. Contains her initial ratchet state
 * and the partially-constructed InitialMessage (ciphertext is '' until
 * the caller resolves the async aeadEncrypt and fills it in).
 */
export interface X3DHSendResult {
  /** Alice's ratchet state, ready to call ratchetEncrypt on subsequent messages */
  aliceState: RatchetState;
  /** Partially-filled InitialMessage; caller must fill in .ciphertext after encrypt */
  initMsg: InitialMessage;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function dhRaw(privHex: string, pubHex: string): Uint8Array {
  return x25519.getSharedSecret(fromHex(privHex), fromHex(pubHex));
}

/**
 * KDF: HKDF-SHA256(IKM = F||DH1||…||DH4, salt=0x00*32, info='ShadowX3DH')
 * Returns a 32-byte session key.
 */
function kdfX3DH(dhOutputs: Uint8Array[]): Uint8Array {
  // IKM = F (32 bytes of 0xFF) || DH1 || DH2 || DH3 [|| DH4]
  const ikmLen = X3DH_F.length + dhOutputs.reduce((n, d) => n + d.length, 0);
  const ikm = new Uint8Array(ikmLen);
  ikm.set(X3DH_F, 0);
  let offset = X3DH_F.length;
  for (const d of dhOutputs) {
    ikm.set(d, offset);
    offset += d.length;
  }
  return hkdf(sha256, ikm, X3DH_SALT, X3DH_INFO, 32);
}

// ─── Bundle verification ──────────────────────────────────────────────────────

/**
 * Verify the SPK signature in a PreKeyBundle.
 * Returns true iff the ed25519 signature is valid.
 */
export function verifyBundle(bundle: PreKeyBundle): boolean {
  try {
    return ed25519.verify(
      fromHex(bundle.spkSignature),
      fromHex(bundle.spkPublic),
      fromHex(bundle.identitySignKey),
    );
  } catch {
    return false;
  }
}

// ─── Alice (sender) ───────────────────────────────────────────────────────────

/**
 * Alice initiates a session using Bob's PreKeyBundle.
 *
 * The returned `initMsg.ciphertext` is empty string — the caller MUST:
 *   1. Call `ratchetEncrypt(aliceState, plaintext, ad)` to get the first
 *      ciphertext Promise.
 *   2. Await it and set `initMsg.ciphertext = toHex(ciphertext)`.
 *   3. Send `initMsg` to Bob alongside the encrypted payload.
 *
 * @throws If the SPK signature in the bundle is invalid.
 */
export function x3dhSend(
  alice:  DeviceIdentity,
  bundle: PreKeyBundle,
): X3DHSendResult {
  if (!verifyBundle(bundle)) {
    throw new Error('X3DH: SPK signature verification failed — bundle is invalid');
  }

  // Generate Alice's ephemeral keypair
  const ekPrivBytes = randomBytes(32);
  const ekPubBytes  = x25519.getPublicKey(ekPrivBytes);
  const ekPrivHex   = toHex(ekPrivBytes);
  const ekPubHex    = toHex(ekPubBytes);

  // DH1 = DH(IK_A,  SPK_B)
  const dh1 = dhRaw(alice.ikDhPriv, bundle.spkPublic);
  // DH2 = DH(EK_A,  IK_B)
  const dh2 = dhRaw(ekPrivHex,      bundle.identityKey);
  // DH3 = DH(EK_A,  SPK_B)
  const dh3 = dhRaw(ekPrivHex,      bundle.spkPublic);

  const outputs: Uint8Array[] = [dh1, dh2, dh3];

  if (bundle.opkPublic !== null) {
    // DH4 = DH(EK_A, OPK_B)
    outputs.push(dhRaw(ekPrivHex, bundle.opkPublic));
  }

  const sk          = kdfX3DH(outputs);
  const aliceState  = ratchetInitAlice(sk, bundle.spkPublic);

  const initMsg: InitialMessage = {
    ikPub:       alice.ikDhPub,
    ekPub:       ekPubHex,
    spkId:       bundle.spkId,
    opkId:       bundle.opkId,
    headerBytes: '',   // not yet used — caller performs first ratchetEncrypt
    ciphertext:  '',   // filled in by caller after ratchetEncrypt
  };

  return { aliceState, initMsg };
}

// ─── Bob (receiver) ───────────────────────────────────────────────────────────

/**
 * Bob derives the session key from Alice's InitialMessage.
 *
 * @param bob         Bob's device identity
 * @param bobSpk      Bob's signed prekey (must match initMsg.spkId)
 * @param bobOpk      Bob's one-time prekey (required iff initMsg.opkId !== null)
 * @param initMsg     Alice's initial message
 * @returns           Bob's initial RatchetState, ready to call ratchetDecrypt
 * @throws            If SPK ID mismatches or a required OPK is missing
 */
export function x3dhReceive(
  bob:      DeviceIdentity,
  bobSpk:   SignedPreKey,
  bobOpk:   OneTimePreKey | null,
  initMsg:  InitialMessage,
): RatchetState {
  if (bobSpk.id !== initMsg.spkId) {
    throw new Error(
      `X3DH: SPK ID mismatch — message uses ${initMsg.spkId}, ` +
      `but provided SPK has id ${bobSpk.id}`,
    );
  }
  if (initMsg.opkId !== null && bobOpk === null) {
    throw new Error(
      `X3DH: message requires OPK id=${initMsg.opkId} but none was provided`,
    );
  }

  // DH1 = DH(SPK_B,  IK_A)
  const dh1 = dhRaw(bobSpk.privKey,  initMsg.ikPub);
  // DH2 = DH(IK_B,   EK_A)
  const dh2 = dhRaw(bob.ikDhPriv,   initMsg.ekPub);
  // DH3 = DH(SPK_B,  EK_A)
  const dh3 = dhRaw(bobSpk.privKey,  initMsg.ekPub);

  const outputs: Uint8Array[] = [dh1, dh2, dh3];

  if (initMsg.opkId !== null && bobOpk !== null) {
    // DH4 = DH(OPK_B, EK_A)
    outputs.push(dhRaw(bobOpk.privKey, initMsg.ekPub));
  }

  const sk = kdfX3DH(outputs);
  return ratchetInitBob(sk, bobSpk.privKey, bobSpk.pubKey);
}

// ─── Utility ──────────────────────────────────────────────────────────────────

/**
 * Build a PreKeyBundle from locally held key material.
 * Useful for serialising own bundle for QR code display or server upload.
 */
export function buildPreKeyBundle(
  identity: DeviceIdentity,
  spk:      SignedPreKey,
  opk?:     OneTimePreKey,
): PreKeyBundle {
  return {
    identityKey:     identity.ikDhPub,
    identitySignKey: identity.ikSignPub,
    spkId:           spk.id,
    spkPublic:       spk.pubKey,
    spkSignature:    spk.signature,
    opkId:           opk?.id   ?? null,
    opkPublic:       opk?.pubKey ?? null,
  };
}
