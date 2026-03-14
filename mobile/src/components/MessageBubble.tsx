/**
 * Shadow — MessageBubble
 *
 * Renders a single chat message in Signal-style bubble layout:
 *   sent    → right-aligned, blue (#0a3a5a)
 *   received → left-aligned, dark gray (#1a1a1a)
 *
 * Props:
 *   message  — Message from the message store
 */

import React, { memo } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import type { Message } from '@/store/messages';

// ─── Props ────────────────────────────────────────────────────────────────────

interface Props {
  message: Message;
}

// ─── Component ────────────────────────────────────────────────────────────────

const MessageBubble: React.FC<Props> = memo(({ message }) => {
  const { fromMe, text, timestamp, delivered } = message;
  const timeStr = formatTime(timestamp);

  return (
    <View style={[styles.row, fromMe ? styles.rowSent : styles.rowReceived]}>
      <View
        style={[
          styles.bubble,
          fromMe ? styles.bubbleSent : styles.bubbleReceived,
        ]}
        // Allow text selection for copy-paste
        accessible
        accessibilityLabel={`${fromMe ? 'You' : 'Contact'}: ${text}`}
      >
        <Text
          style={[styles.messageText, fromMe ? styles.textSent : styles.textReceived]}
          selectable
        >
          {text}
        </Text>

        {/* Timestamp + delivery indicator */}
        <View style={[styles.meta, fromMe ? styles.metaSent : styles.metaReceived]}>
          <Text style={styles.timeText}>{timeStr}</Text>
          {fromMe && (
            <Text
              style={[styles.tick, delivered && styles.tickDelivered]}
              accessibilityLabel={delivered ? 'Delivered' : 'Sent'}
            >
              {delivered ? '✓✓' : '✓'}
            </Text>
          )}
        </View>
      </View>
    </View>
  );
});

MessageBubble.displayName = 'MessageBubble';
export default MessageBubble;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTime(ts: number): string {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${hh}:${mm}`;
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  row: {
    flexDirection: 'row',
    marginVertical: 3,
    paddingHorizontal: 4,
  },
  rowSent: {
    justifyContent: 'flex-end',
  },
  rowReceived: {
    justifyContent: 'flex-start',
  },

  bubble: {
    maxWidth: '78%',
    borderRadius: 18,
    paddingHorizontal: 14,
    paddingTop: 9,
    paddingBottom: 7,
  },
  bubbleSent: {
    backgroundColor: '#1d4e89',   // blue — sent messages (right)
    borderBottomRightRadius: 4,
  },
  bubbleReceived: {
    backgroundColor: '#1e1e1e',   // dark gray — received messages (left)
    borderBottomLeftRadius: 4,
  },

  messageText: {
    fontSize: 15,
    lineHeight: 21,
  },
  textSent: {
    color: '#f0f0f0',
  },
  textReceived: {
    color: '#e0e0e0',
  },

  meta: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 4,
    gap: 4,
  },
  metaSent: {
    justifyContent: 'flex-end',
  },
  metaReceived: {
    justifyContent: 'flex-start',
  },

  timeText: {
    color: '#7a8a9a',
    fontSize: 11,
  },
  tick: {
    color: '#7a8a9a',
    fontSize: 11,
  },
  tickDelivered: {
    color: '#00e5ff',
  },
});
