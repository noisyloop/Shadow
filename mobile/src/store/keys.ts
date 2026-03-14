/**
 * Shadow — Key Store
 *
 * Zustand store for:
 *   - Own device identity (IK: X25519 + ed25519 keypair)
 *   - Signed prekey (SPK)
 *   - One-time prekeys (OPKs)
 *   - Per-contact Double Ratchet sessions
 *
 * All private key material is persisted to expo-secure-store (hardware-backed
 * on devices that support it). Sessions are also stored securely.
 *
 * Public API:
 *   identity            — DeviceIdentity | null
 *   spk                 — SignedPreKey | null
 *   opks                — OneTimePreKey[]
 *   initializeIdentity()— generate & persist new identity on first run (no-op if exists)
 *   loadKeys()          — re-hydrate from storage (call on app focus if needed)
 *   rotateSpk()         — generate a new SPK and persist
 *   consumeOpk(id)      — remove a used OPK and persist
 *   replenishOpks(n)    — generate n new OPKs and persist
 *   getSession(cId)     — load or return a per-contact ratchet session
 *   saveSession(cId, s) — persist an updated ratchet session
 *   deleteSession(cId)  — wipe a session (e.g., after contact removal)
 */

import { create } from 'zustand';
import * as SecureStore from 'expo-secure-store';
import {
  generateDeviceIdentity,
  generateSignedPreKey,
  generateOneTimePreKey,
  type DeviceIdentity,
  type SignedPreKey,
  type OneTimePreKey,
} from '@/crypto/identity';
import type { RatchetState } from '@/crypto/ratchet';

// ─── Types ────────────────────────────────────────────────────────────────────

/** A per-contact Double Ratchet session */
export interface Session {
  /** The ratchet state */
  state: RatchetState;
  /** The contact's X25519 identity key public (hex) */
  contactIkPub: string;
  /** Unix timestamp (ms) when the session was established */
  createdAt: number;
  /** Unix timestamp (ms) of last message */
  lastActiveAt: number;
}

interface KeyState {
  identity: DeviceIdentity | null;
  spk:      SignedPreKey   | null;
  opks:     OneTimePreKey[];
  /** In-memory cache of loaded sessions */
  sessions: Record<string, Session>;

  initializeIdentity: ()                                         => Promise<void>;
  loadKeys:           ()                                         => Promise<void>;
  rotateSpk:          ()                                         => Promise<void>;
  consumeOpk:         (id: number)                              => Promise<void>;
  replenishOpks:      (count?: number)                          => Promise<void>;
  getSession:         (contactId: string)                        => Promise<Session | null>;
  saveSession:        (contactId: string, state: RatchetState)  => Promise<void>;
  deleteSession:      (contactId: string)                        => Promise<void>;
}

// ─── Storage keys ─────────────────────────────────────────────────────────────

const KEY_IDENTITY  = 'shadow_identity_v1';
const KEY_SPK       = 'shadow_spk_v1';
const KEY_OPKS      = 'shadow_opks_v1';
const DEFAULT_OPK_BATCH = 10;

function sessionStorageKey(contactId: string): string {
  // Use 24-char hex prefix to stay within SecureStore key length limits
  return `shadow_session_v1_${contactId.slice(0, 24)}`;
}

// ─── Store ────────────────────────────────────────────────────────────────────

export const useKeysStore = create<KeyState>((set, get) => ({
  identity: null,
  spk:      null,
  opks:     [],
  sessions: {},

  /**
   * Initialise device identity on first launch.
   * If an identity already exists in SecureStore, loads it instead.
   * Generates SPK and 10 OPKs on first run.
   */
  initializeIdentity: async () => {
    const existing = await SecureStore.getItemAsync(KEY_IDENTITY);
    if (existing) {
      // Hydrate existing keys
      const identity: DeviceIdentity = JSON.parse(existing);
      const [spkRaw, opksRaw] = await Promise.all([
        SecureStore.getItemAsync(KEY_SPK),
        SecureStore.getItemAsync(KEY_OPKS),
      ]);
      set({
        identity,
        spk:  spkRaw  ? (JSON.parse(spkRaw)  as SignedPreKey)    : null,
        opks: opksRaw ? (JSON.parse(opksRaw) as OneTimePreKey[]) : [],
      });
      return;
    }

    // Generate fresh identity
    const identity = generateDeviceIdentity();
    const spk      = generateSignedPreKey(identity, 1);
    const opks     = Array.from(
      { length: DEFAULT_OPK_BATCH },
      (_, i) => generateOneTimePreKey(i + 1),
    );

    await Promise.all([
      SecureStore.setItemAsync(KEY_IDENTITY, JSON.stringify(identity)),
      SecureStore.setItemAsync(KEY_SPK,      JSON.stringify(spk)),
      SecureStore.setItemAsync(KEY_OPKS,     JSON.stringify(opks)),
    ]);

    set({ identity, spk, opks });
  },

  /**
   * Re-hydrate all key material from SecureStore.
   * Useful after an app resume or when the store was cleared.
   */
  loadKeys: async () => {
    const [idRaw, spkRaw, opksRaw] = await Promise.all([
      SecureStore.getItemAsync(KEY_IDENTITY),
      SecureStore.getItemAsync(KEY_SPK),
      SecureStore.getItemAsync(KEY_OPKS),
    ]);
    set({
      identity: idRaw   ? (JSON.parse(idRaw)   as DeviceIdentity)  : null,
      spk:      spkRaw  ? (JSON.parse(spkRaw)  as SignedPreKey)     : null,
      opks:     opksRaw ? (JSON.parse(opksRaw) as OneTimePreKey[])  : [],
    });
  },

  /**
   * Generate a new SPK (signed by the current identity key) and persist.
   * The old SPK is silently discarded — real deployments should keep it for
   * a grace period to decrypt in-flight messages.
   */
  rotateSpk: async () => {
    const { identity, spk } = get();
    if (!identity) throw new Error('KeyStore: identity not initialised');
    const newSpk = generateSignedPreKey(identity, (spk?.id ?? 0) + 1);
    await SecureStore.setItemAsync(KEY_SPK, JSON.stringify(newSpk));
    set({ spk: newSpk });
  },

  /**
   * Remove a one-time prekey that has been used (to prevent reuse).
   * Automatically triggers replenishment when the pool drops below 5 keys.
   */
  consumeOpk: async (id: number) => {
    const next = get().opks.filter((k) => k.id !== id);
    set({ opks: next });
    await SecureStore.setItemAsync(KEY_OPKS, JSON.stringify(next));

    // Auto-replenish when the pool falls below the low-water mark
    if (next.length < 5) {
      await get().replenishOpks(DEFAULT_OPK_BATCH);
    }
  },

  /**
   * Generate `count` new OPKs and append them to the existing set.
   *
   * Steps:
   *   1. Generates `count` new OPKs using generateOneTimePreKey().
   *   2. Assigns sequential IDs starting from max(existing IDs) + 1.
   *   3. Persists the updated pool to SecureStore.
   *
   * TODO: In a real deployment this should also publish the new OPK public
   *       keys to the prekey server so other users can initiate X3DH sessions.
   */
  replenishOpks: async (count: number = DEFAULT_OPK_BATCH) => {
    const existing = get().opks;
    const maxId    = existing.reduce((m, k) => Math.max(m, k.id), 0);
    const newKeys  = Array.from(
      { length: count },
      (_, i) => generateOneTimePreKey(maxId + i + 1),
    );
    const next = [...existing, ...newKeys];
    set({ opks: next });
    await SecureStore.setItemAsync(KEY_OPKS, JSON.stringify(next));
  },

  /**
   * Return a contact's ratchet session.
   * Checks in-memory cache first, then SecureStore.
   * Returns null if no session exists yet (key exchange not completed).
   */
  getSession: async (contactId: string): Promise<Session | null> => {
    const cached = get().sessions[contactId];
    if (cached) return cached;

    try {
      const raw = await SecureStore.getItemAsync(sessionStorageKey(contactId));
      if (raw) {
        const session: Session = JSON.parse(raw);
        set((s) => ({ sessions: { ...s.sessions, [contactId]: session } }));
        return session;
      }
    } catch (err) {
      console.warn(`[KeyStore] Failed to load session for ${contactId.slice(0, 8)}:`, err);
    }
    return null;
  },

  /**
   * Persist an updated ratchet state for a contact.
   * Updates the in-memory cache and SecureStore.
   */
  saveSession: async (contactId: string, state: RatchetState) => {
    const existing = get().sessions[contactId];
    const session: Session = {
      state,
      contactIkPub:  contactId,
      createdAt:     existing?.createdAt ?? Date.now(),
      lastActiveAt:  Date.now(),
    };
    set((s) => ({ sessions: { ...s.sessions, [contactId]: session } }));
    await SecureStore.setItemAsync(
      sessionStorageKey(contactId),
      JSON.stringify(session),
    );
  },

  /**
   * Delete a ratchet session (e.g. when removing a contact).
   * Wipes both the in-memory cache and SecureStore entry.
   */
  deleteSession: async (contactId: string) => {
    set((s) => {
      const sessions = { ...s.sessions };
      delete sessions[contactId];
      return { sessions };
    });
    await SecureStore.deleteItemAsync(sessionStorageKey(contactId));
  },
}));

// ─── Backwards-compatible alias ───────────────────────────────────────────────
// HomeScreen and ChatScreen import `useKeyStore` (singular); keep both names.
export const useKeyStore = useKeysStore;
