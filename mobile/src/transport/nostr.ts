/**
 * Shadow — Nostr relay client for React Native (mobile/src/transport/nostr.ts)
 *
 * Provides a WebSocket-based Nostr relay client compatible with React Native's
 * built-in WebSocket API. Handles event publishing, subscriptions, and
 * auto-reconnect with exponential backoff.
 *
 * Note on event signing
 * ---------------------
 * Nostr events must be signed with a secp256k1 Schnorr signature (BIP340).
 * Signing is intentionally NOT implemented here — it belongs in a dedicated
 * secp256k1 module once a suitable React Native native module is available.
 * See the TODO comment in `createSignedEvent` below.
 */

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

export const DEFAULT_RELAY = "wss://relay.damus.io";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface NostrFilter {
  kinds?: number[];
  authors?: string[];
  /** p-tag filter — events tagged with these recipient pubkeys */
  "#p"?: string[];
  since?: number;
  until?: number;
  limit?: number;
}

export interface NostrRelayClient {
  /** Open the WebSocket connection. Resolves once the connection is open. */
  connect(): Promise<void>;
  /** Close the WebSocket connection immediately. */
  disconnect(): void;
  /**
   * Publish a pre-signed Nostr event to the relay.
   * Resolves once the message is dispatched (does not wait for relay ACK).
   */
  publish(event: NostrEvent): Promise<void>;
  /**
   * Subscribe to events matching `filter`. Calls `onEvent` for each matching
   * event received from the relay.
   *
   * Returns an unsubscribe function that sends a CLOSE message and removes the
   * local handler.
   */
  subscribe(filter: NostrFilter, onEvent: (event: NostrEvent) => void): () => void;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

type SubscriptionEntry = {
  filter: NostrFilter;
  onEvent: (event: NostrEvent) => void;
};

type ConnectionState = "disconnected" | "connecting" | "connected" | "closing";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a random hex subscription ID. */
function randomSubId(): string {
  const bytes = new Uint8Array(8);
  // React Native's crypto.getRandomValues may not be available everywhere.
  // Fall back to Math.random when it is not.
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// TODO: secp256k1 Schnorr signing stub
// ---------------------------------------------------------------------------

/**
 * Build and sign a Nostr event.
 *
 * TODO: Replace the stub body with a real secp256k1 Schnorr (BIP340) signing
 * implementation once a suitable React Native native module for secp256k1 is
 * integrated into the project dependencies. For now this function throws so
 * that callers are not silently publishing unsigned/invalid events.
 *
 * @param unsignedEvent - Event fields without id / sig.
 * @param _privateKeyHex - 32-byte secp256k1 private key (hex).
 */
export function createSignedEvent(
  _unsignedEvent: Omit<NostrEvent, "id" | "sig">,
  _privateKeyHex: string,
): NostrEvent {
  // TODO: implement BIP340 Schnorr signing via a secp256k1 native module.
  throw new Error(
    "createSignedEvent is not yet implemented. " +
      "Add a secp256k1 native module and implement BIP340 Schnorr signing."
  );
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Create a Nostr relay client that connects to `relayUrl`.
 *
 * Auto-reconnect behaviour:
 *   - On unexpected disconnection the client retries up to 3 times with
 *     exponential backoff: 1 s → 2 s → 4 s.
 *   - After 3 failed retries the client stops attempting to reconnect and
 *     leaves itself in the "disconnected" state.
 *   - Calling `disconnect()` explicitly cancels any pending reconnect.
 */
export function createNostrClient(relayUrl: string): NostrRelayClient {
  const MAX_RETRIES = 3;
  const BASE_BACKOFF_MS = 1000;

  let ws: WebSocket | null = null;
  let state: ConnectionState = "disconnected";
  let retryCount = 0;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  // Active subscriptions: subId → entry
  const subscriptions = new Map<string, SubscriptionEntry>();

  // ── Internal helpers ───────────────────────────────────────────────── //

  function clearReconnectTimer(): void {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  }

  function send(data: string): void {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  }

  function resubscribeAll(): void {
    subscriptions.forEach((entry, subId) => {
      send(JSON.stringify(["REQ", subId, entry.filter]));
    });
  }

  function handleMessage(raw: string): void {
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }
    if (!Array.isArray(msg) || msg.length < 2) return;

    const msgType = msg[0];

    if (msgType === "EVENT" && msg.length >= 3) {
      const subId = msg[1] as string;
      const eventData = msg[2] as NostrEvent;
      const entry = subscriptions.get(subId);
      if (entry) {
        entry.onEvent(eventData);
      }
    } else if (msgType === "EOSE") {
      // End of stored events — nothing to do here; streaming continues.
    } else if (msgType === "NOTICE") {
      const notice = msg[1] as string;
      // Relay notice — log in development builds.
      if (__DEV__) {
        console.log(`[NostrRelay] NOTICE from ${relayUrl}: ${notice}`);
      }
    }
    // OK messages (publish acknowledgements) are silently ignored.
  }

  function scheduleReconnect(): void {
    if (retryCount >= MAX_RETRIES) {
      if (__DEV__) {
        console.warn(
          `[NostrRelay] Gave up reconnecting to ${relayUrl} after ${MAX_RETRIES} retries.`
        );
      }
      state = "disconnected";
      return;
    }
    const delayMs = BASE_BACKOFF_MS * Math.pow(2, retryCount);
    retryCount += 1;
    if (__DEV__) {
      console.log(
        `[NostrRelay] Reconnecting to ${relayUrl} in ${delayMs}ms (attempt ${retryCount}/${MAX_RETRIES}) …`
      );
    }
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      openWebSocket().catch(() => {
        // openWebSocket handles its own error → scheduleReconnect chain.
      });
    }, delayMs);
  }

  function openWebSocket(): Promise<void> {
    return new Promise((resolve, reject) => {
      state = "connecting";
      const socket = new WebSocket(relayUrl);

      socket.onopen = () => {
        ws = socket;
        state = "connected";
        retryCount = 0; // reset backoff on successful connection
        resubscribeAll();
        resolve();
      };

      socket.onmessage = (event: MessageEvent) => {
        if (typeof event.data === "string") {
          handleMessage(event.data);
        }
      };

      socket.onerror = (err: Event) => {
        if (state === "connecting") {
          reject(err);
        }
        // onerror is always followed by onclose; handle reconnect there.
      };

      socket.onclose = () => {
        ws = null;
        if (state === "closing") {
          state = "disconnected";
          return;
        }
        // Unexpected close — try to reconnect.
        state = "disconnected";
        scheduleReconnect();
      };
    });
  }

  // ── Public interface ───────────────────────────────────────────────── //

  const client: NostrRelayClient = {
    connect(): Promise<void> {
      if (state === "connected" || state === "connecting") {
        return Promise.resolve();
      }
      clearReconnectTimer();
      retryCount = 0;
      return openWebSocket();
    },

    disconnect(): void {
      clearReconnectTimer();
      state = "closing";
      if (ws) {
        ws.close();
        ws = null;
      } else {
        state = "disconnected";
      }
    },

    publish(event: NostrEvent): Promise<void> {
      if (state !== "connected") {
        return Promise.reject(new Error("Not connected to relay."));
      }
      send(JSON.stringify(["EVENT", event]));
      return Promise.resolve();
    },

    subscribe(filter: NostrFilter, onEvent: (event: NostrEvent) => void): () => void {
      const subId = randomSubId();
      subscriptions.set(subId, { filter, onEvent });

      // Send REQ immediately if already connected; otherwise it will be sent
      // by resubscribeAll() once the connection opens.
      if (state === "connected") {
        send(JSON.stringify(["REQ", subId, filter]));
      }

      return function unsubscribe(): void {
        subscriptions.delete(subId);
        if (state === "connected") {
          send(JSON.stringify(["CLOSE", subId]));
        }
      };
    },
  };

  return client;
}
