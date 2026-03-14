/**
 * Shadow — Contact Store
 *
 * Zustand store for the contact list, persisted to expo-secure-store.
 * Each contact is identified by their X25519 identity key (ikDhPub, hex).
 *
 * Public API:
 *   contacts          — reactive array of Contact objects
 *   addContact(c)     — upsert a contact (deduplicates by id)
 *   removeContact(id) — remove by id
 *   loadContacts()    — hydrate from SecureStore on app start
 */

import { create } from 'zustand';
import * as SecureStore from 'expo-secure-store';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Contact {
  /** Primary key — equals ikDhPub (lowercase hex, 64 chars) */
  id:       string;
  /** Human-readable display name */
  name:     string;
  /** X25519 identity DH public key (hex, 64 chars) */
  ikDhPub:  string;
  /** Unix timestamp (ms) when contact was added */
  addedAt:  number;
}

/** Parameter type for addContact — id and addedAt are derived automatically */
export type NewContact = Omit<Contact, 'id' | 'addedAt'>;

interface ContactState {
  contacts:      Contact[];
  loaded:        boolean;
  addContact:    (c: NewContact) => Promise<void>;
  removeContact: (id: string)    => Promise<void>;
  loadContacts:  ()              => Promise<void>;
}

// ─── Storage key ──────────────────────────────────────────────────────────────

const STORAGE_KEY = 'shadow_contacts_v1';

// ─── Persistence helpers ──────────────────────────────────────────────────────

async function persist(contacts: Contact[]): Promise<void> {
  await SecureStore.setItemAsync(STORAGE_KEY, JSON.stringify(contacts));
}

// ─── Store ────────────────────────────────────────────────────────────────────

export const useContactStore = create<ContactState>((set, get) => ({
  contacts: [],
  loaded:   false,

  /**
   * Hydrate the contacts list from SecureStore.
   * Safe to call multiple times — subsequent calls are no-ops if already loaded.
   */
  loadContacts: async () => {
    if (get().loaded) return;
    try {
      const raw = await SecureStore.getItemAsync(STORAGE_KEY);
      if (raw) {
        const parsed: unknown = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          set({ contacts: parsed as Contact[], loaded: true });
          return;
        }
      }
    } catch (err) {
      console.warn('[ContactStore] Failed to load contacts:', err);
    }
    set({ loaded: true });
  },

  /**
   * Add or update a contact. If a contact with the same ikDhPub already
   * exists, it is replaced (preserving its original addedAt timestamp).
   */
  addContact: async (c: NewContact) => {
    const id = c.ikDhPub.toLowerCase();
    const existing = get().contacts.find((x) => x.id === id);
    const contact: Contact = {
      id,
      name:     c.name,
      ikDhPub:  id,
      addedAt:  existing?.addedAt ?? Date.now(),
    };
    const next = [
      ...get().contacts.filter((x) => x.id !== id),
      contact,
    ].sort((a, b) => a.name.localeCompare(b.name));
    set({ contacts: next });
    await persist(next);
  },

  /**
   * Remove a contact by id (= ikDhPub).
   * Silently ignores unknown ids.
   */
  removeContact: async (id: string) => {
    const next = get().contacts.filter((c) => c.id !== id);
    set({ contacts: next });
    await persist(next);
  },
}));
