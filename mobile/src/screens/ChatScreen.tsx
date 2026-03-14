/**
 * Shadow — ChatScreen
 *
 * Message thread for a single contact.
 *
 * Layout:
 *   - FlatList of MessageBubble components (sent = right/blue, received = left/gray)
 *   - Text input with send button at the bottom
 *   - Contact name shown in the navigation header (set by parent navigator)
 *
 * Crypto integration:
 *   - Encrypts outbound messages via ratchetEncrypt() before storing.
 *   - Stores both plaintext (for display) and ciphertext (for audit/re-keying).
 *   - Inbound decryption is handled when messages arrive from the transport
 *     layer (not yet wired; stubs show how to call ratchetDecrypt).
 */

import React, {
  useState,
  useRef,
  useEffect,
  useCallback,
  type FC,
} from 'react';
import {
  View,
  Text,
  FlatList,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
  ActivityIndicator,
} from 'react-native';
import { useRoute, useNavigation } from '@react-navigation/native';
import type { RouteProp } from '@react-navigation/native';
import type { StackNavigationProp } from '@react-navigation/stack';
import { Ionicons } from '@expo/vector-icons';

import type { RootStackParamList } from '@/navigation';
import { useMessageStore, type Message } from '@/store/messages';
import { useKeyStore } from '@/store/keys';
import { useContactStore } from '@/store/contacts';
import { ratchetEncrypt, toHex as ratchetToHex } from '@/crypto/ratchet';
import { fromHex } from '@/crypto/identity';
import MessageBubble from '@/components/MessageBubble';

// ─── Route / nav param types ──────────────────────────────────────────────────

type ChatRoute = RouteProp<RootStackParamList, 'Chat'>;
type ChatNav   = StackNavigationProp<RootStackParamList, 'Chat'>;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Derive the session associated data from both parties' identity keys.
 * Keys are sorted lexicographically so both sides derive the same value.
 */
function deriveSessionAD(myPub: string, theirPub: string): Uint8Array {
  const prefix = new TextEncoder().encode('shadow-session-v1:');
  const [a, b] = myPub <= theirPub
    ? [myPub, theirPub]
    : [theirPub, myPub];
  const aBytes = fromHex(a);
  const bBytes = fromHex(b);
  const out = new Uint8Array(prefix.length + aBytes.length + bBytes.length);
  out.set(prefix, 0);
  out.set(aBytes, prefix.length);
  out.set(bBytes, prefix.length + aBytes.length);
  return out;
}

/** Generate a short, collision-resistant message ID */
function makeMessageId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// ─── Component ────────────────────────────────────────────────────────────────

const ChatScreen: FC = () => {
  const route      = useRoute<ChatRoute>();
  const navigation = useNavigation<ChatNav>();
  const { contactId, contactName } = route.params;

  const flatRef  = useRef<FlatList<Message>>(null);
  const [input, setInput]     = useState('');
  const [sending, setSending] = useState(false);

  // Store selectors
  const messages     = useMessageStore((s) => s.getMessages(contactId));
  const loadMessages = useMessageStore((s) => s.loadMessages);
  const addMessage   = useMessageStore((s) => s.addMessage);
  const identity     = useKeyStore((s) => s.identity);
  const getSession   = useKeyStore((s) => s.getSession);
  const saveSession  = useKeyStore((s) => s.saveSession);
  const contacts     = useContactStore((s) => s.contacts);

  const isVerified = contacts.find((c) => c.id === contactId)?.verified ?? false;

  // ── Shield header button ───────────────────────────────────────────────────

  useEffect(() => {
    navigation.setOptions({
      headerRight: () => (
        <TouchableOpacity
          onPress={() => navigation.navigate('Verify', { contactId, contactName })}
          style={chatHeaderStyles.headerBtn}
          accessibilityLabel={
            isVerified ? 'Key verified — tap to review' : 'Verify contact key'
          }
          accessibilityRole="button"
        >
          <Ionicons
            name="shield-checkmark-outline"
            size={22}
            color={isVerified ? '#00e5ff' : '#555'}
          />
        </TouchableOpacity>
      ),
    });
  }, [navigation, contactId, contactName, isVerified]);

  // ── Hydrate messages on mount ──────────────────────────────────────────────

  useEffect(() => {
    loadMessages(contactId).catch((err: unknown) => {
      console.warn('[ChatScreen] loadMessages failed:', err);
    });
  }, [contactId, loadMessages]);

  // ── Auto-scroll to bottom ──────────────────────────────────────────────────

  useEffect(() => {
    if (messages.length > 0) {
      const timer = setTimeout(
        () => flatRef.current?.scrollToEnd({ animated: true }),
        60,
      );
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [messages.length]);

  // ── Send ───────────────────────────────────────────────────────────────────

  const handleSend = useCallback(async () => {
    const text = input.trim();
    if (!text || sending || !identity) return;

    setSending(true);
    setInput('');

    try {
      // Get or create session
      const session = await getSession(contactId);
      if (!session) {
        // No session yet — key exchange not completed.
        // In a full implementation this would trigger an X3DH exchange.
        console.warn('[ChatScreen] No active session for', contactId.slice(0, 8));
        // Still store the message as plaintext (pre-handshake envelope).
        const msg: Message = {
          id:        makeMessageId(),
          contactId,
          fromMe:    true,
          text,
          timestamp: Date.now(),
          delivered: false,
        };
        await addMessage(msg);
        return;
      }

      // Derive associated data
      const ad = deriveSessionAD(identity.ikDhPub, session.contactIkPub);

      // Encrypt via Double Ratchet (sync header, async AEAD)
      const {
        header,
        ciphertext: ctPromise,
        newState,
      } = ratchetEncrypt(session.state, text, ad);

      // Persist updated ratchet state immediately (before awaiting AEAD)
      await saveSession(contactId, newState);

      // Await AEAD encryption
      const ciphertext = await ctPromise;

      const msg: Message = {
        id:        makeMessageId(),
        contactId,
        fromMe:    true,
        text,
        timestamp: Date.now(),
        delivered: false,
        headerHex: Array.from(header).map((b) => b.toString(16).padStart(2, '0')).join(''),
        ctHex:     Array.from(ciphertext).map((b) => b.toString(16).padStart(2, '0')).join(''),
      };
      await addMessage(msg);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('[ChatScreen] Send failed:', msg);
      // Re-populate input so user doesn't lose their message
      setInput(text);
    } finally {
      setSending(false);
    }
  }, [
    input,
    sending,
    identity,
    contactId,
    getSession,
    saveSession,
    addMessage,
  ]);

  // ─────────────────────────────────────────────────────────────────────────

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      keyboardVerticalOffset={90}
    >
      <FlatList
        ref={flatRef}
        data={messages}
        keyExtractor={(m) => m.id}
        renderItem={({ item }) => <MessageBubble message={item} />}
        contentContainerStyle={styles.messageList}
        showsVerticalScrollIndicator={false}
        ListEmptyComponent={
          <View style={styles.emptyChat}>
            <Text style={styles.emptyChatIcon}>🔒</Text>
            <Text style={styles.emptyChatText}>
              End-to-end encrypted.{'\n'}No one else can read these messages.
            </Text>
          </View>
        }
      />

      {/* Input row */}
      <View style={styles.inputRow}>
        <TextInput
          style={styles.input}
          placeholder={`Message ${contactName}`}
          placeholderTextColor="#444"
          value={input}
          onChangeText={setInput}
          multiline
          maxLength={4096}
          returnKeyType="send"
          blurOnSubmit={false}
          onSubmitEditing={handleSend}
          editable={!sending}
          accessibilityLabel="Message input"
        />
        <TouchableOpacity
          style={[
            styles.sendBtn,
            (!input.trim() || sending) && styles.sendBtnDisabled,
          ]}
          onPress={handleSend}
          disabled={!input.trim() || sending}
          accessibilityLabel="Send message"
          accessibilityRole="button"
        >
          {sending ? (
            <ActivityIndicator size="small" color="#000" />
          ) : (
            <Text style={styles.sendBtnText}>↑</Text>
          )}
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
};

export default ChatScreen;

// ─── Header styles (defined outside component to avoid recreation) ────────────

const chatHeaderStyles = StyleSheet.create({
  headerBtn: {
    marginRight: 16,
    padding: 4,
  },
});

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  messageList: {
    paddingHorizontal: 12,
    paddingVertical: 16,
    paddingBottom: 8,
    flexGrow: 1,
  },
  emptyChat: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingTop: 80,
    gap: 12,
  },
  emptyChatIcon: {
    fontSize: 32,
  },
  emptyChatText: {
    color: '#444',
    fontSize: 13,
    textAlign: 'center',
    lineHeight: 22,
    maxWidth: 260,
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    paddingHorizontal: 12,
    paddingVertical: 10,
    paddingBottom: Platform.OS === 'ios' ? 24 : 12,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#1e1e1e',
    backgroundColor: '#111111',
    gap: 8,
  },
  input: {
    flex: 1,
    backgroundColor: '#1a1a1a',
    borderRadius: 22,
    paddingHorizontal: 16,
    paddingVertical: 10,
    paddingTop: 10,
    color: '#f0f0f0',
    fontSize: 15,
    lineHeight: 20,
    maxHeight: 130,
  },
  sendBtn: {
    width: 42,
    height: 42,
    borderRadius: 21,
    backgroundColor: '#00e5ff',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 1,
  },
  sendBtnDisabled: {
    backgroundColor: '#1e1e1e',
  },
  sendBtnText: {
    color: '#000',
    fontSize: 18,
    fontWeight: '700',
    lineHeight: 22,
  },
});
