/**
 * Shadow — Message Store
 *
 * Zustand store for per-contact message threads, persisted to expo-secure-store.
 *
 * Design notes:
 * - Messages are keyed by contactId (= ikDhPub hex).
 * - Each contact's thread is stored in a separate SecureStore entry to avoid
 *   hitting the 2 KB item limit on some platforms; we use a key derived from
 *   a SHA-1-like prefix of the contactId.
 * - The store does NOT decrypt messages — it stores plaintext for display.
 *   Encryption/decryption happens in ChatScreen via the ratchet.
 * - `headerHex` and `ctHex` are the raw encrypted bytes for future key export.
 *
 * Public API:
 *   getMessages(contactId)       — reactive selector (returns [] if not loaded)
 *   addMessage(msg)              — append and persist
 *   loadMessages(contactId)      — hydrate a thread from storage
 *   markDelivered(contactId, id) — flip msg.delivered = true and persist
 */

import { create } from 'zustand';
import * as SecureStore from 'expo-secure-store';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Message {
  /** Unique message ID (UUID or timestamp-based string) */
  id:          string;
  /** Contact's ikDhPub (= store key) */
  contactId:   string;
  /** true = sent by us, false = received */
  fromMe:      boolean;
  /** Plaintext content for display */
  text:        string;
  /** Unix timestamp (ms) */
  timestamp:   number;
  /** Whether the remote party has acknowledged receipt */
  delivered:   boolean;
  /** Raw ratchet header bytes, hex (for audit / re-key) */
  headerHex?:  string;
  /** Raw AES-GCM ciphertext bytes, hex (for audit / re-key) */
  ctHex?:      string;
}

interface MessageState {
  /** Loaded message threads, keyed by contactId */
  messagesByContact: Record<string, Message[]>;
  /** Set of contactIds whose threads have been loaded from storage */
  loadedContacts:    Set<string>;

  getMessages:    (contactId: string) => Message[];
  addMessage:     (msg: Message) => Promise<void>;
  loadMessages:   (contactId: string) => Promise<void>;
  markDelivered:  (contactId: string, messageId: string) => Promise<void>;
}

// ─── Storage helpers ──────────────────────────────────────────────────────────

/**
 * SecureStore key for a contact's message thread.
 * We use a 24-char hex prefix to stay well within the 240-char key limit.
 */
function storageKey(contactId: string): string {
  return `shadow_msgs_v1_${contactId.slice(0, 24)}`;
}

async function persistThread(contactId: string, msgs: Message[]): Promise<void> {
  try {
    await SecureStore.setItemAsync(storageKey(contactId), JSON.stringify(msgs));
  } catch (err) {
    console.warn(`[MessageStore] Failed to persist thread ${contactId.slice(0, 8)}:`, err);
  }
}

// ─── Store ────────────────────────────────────────────────────────────────────

export const useMessageStore = create<MessageState>((set, get) => ({
  messagesByContact: {},
  loadedContacts:    new Set(),

  getMessages: (contactId: string): Message[] =>
    get().messagesByContact[contactId] ?? [],

  /**
   * Append a message to the in-memory store and persist asynchronously.
   * Messages are sorted by timestamp ascending.
   */
  addMessage: async (msg: Message) => {
    const prev = get().messagesByContact[msg.contactId] ?? [];
    const next = [...prev, msg].sort((a, b) => a.timestamp - b.timestamp);
    set((s) => ({
      messagesByContact: {
        ...s.messagesByContact,
        [msg.contactId]: next,
      },
    }));
    await persistThread(msg.contactId, next);
  },

  /**
   * Load a contact's message thread from SecureStore.
   * No-op if already loaded.
   */
  loadMessages: async (contactId: string) => {
    if (get().loadedContacts.has(contactId)) return;
    try {
      const raw = await SecureStore.getItemAsync(storageKey(contactId));
      if (raw) {
        const parsed: unknown = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          const msgs = (parsed as Message[]).sort(
            (a, b) => a.timestamp - b.timestamp,
          );
          set((s) => {
            const loadedContacts = new Set(s.loadedContacts);
            loadedContacts.add(contactId);
            return {
              messagesByContact: {
                ...s.messagesByContact,
                [contactId]: msgs,
              },
              loadedContacts,
            };
          });
          return;
        }
      }
    } catch (err) {
      console.warn(`[MessageStore] Failed to load thread ${contactId.slice(0, 8)}:`, err);
    }
    // Mark as loaded even if empty
    set((s) => {
      const loadedContacts = new Set(s.loadedContacts);
      loadedContacts.add(contactId);
      return { loadedContacts };
    });
  },

  /**
   * Flip a message's `delivered` flag to true and re-persist the thread.
   */
  markDelivered: async (contactId: string, messageId: string) => {
    const msgs = get().messagesByContact[contactId];
    if (!msgs) return;
    const updated = msgs.map((m) =>
      m.id === messageId ? { ...m, delivered: true } : m,
    );
    set((s) => ({
      messagesByContact: {
        ...s.messagesByContact,
        [contactId]: updated,
      },
    }));
    await persistThread(contactId, updated);
  },
}));
