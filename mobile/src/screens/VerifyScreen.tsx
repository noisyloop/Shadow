/**
 * Shadow — VerifyScreen (Key Verification)
 *
 * Displays both parties' X25519 identity DH public keys side-by-side so the
 * user can compare them with their contact via a voice call or in person.
 *
 * Route params: { contactId: string, contactName: string }
 *
 * Actions:
 *   Mark as Verified    — sets verified=true, persists, navigates back
 *   Remove Verification — sets verified=false, persists, navigates back
 */

import React, { memo, useCallback, useEffect } from 'react';
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
} from 'react-native';
import { useNavigation, useRoute } from '@react-navigation/native';
import type { RouteProp } from '@react-navigation/native';
import type { StackNavigationProp } from '@react-navigation/stack';

import type { RootStackParamList } from '@/navigation';
import { useContactStore } from '@/store/contacts';
import { useKeysStore } from '@/store/keys';
import QRDisplay from '@/components/QRDisplay';

// ─── Route / nav types ────────────────────────────────────────────────────────

type VerifyRoute = RouteProp<RootStackParamList, 'Verify'>;
type VerifyNav   = StackNavigationProp<RootStackParamList, 'Verify'>;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Shortened hex: first 16 chars + ellipsis + last 8 chars */
function shortHex(hex: string): string {
  return `${hex.slice(0, 16)}…${hex.slice(-8)}`;
}

/** Format hex as space-separated 8-char groups for readability */
function formatHex(hex: string): string {
  return (hex.match(/.{1,8}/g) ?? []).join(' ');
}

// ─── Component ────────────────────────────────────────────────────────────────

const VerifyScreen: React.FC = memo(() => {
  const navigation    = useNavigation<VerifyNav>();
  const route         = useRoute<VerifyRoute>();
  const { contactId, contactName } = route.params;

  const identity      = useKeysStore((s) => s.identity);
  const contacts      = useContactStore((s) => s.contacts);
  const verifyContact = useContactStore((s) => s.verifyContact);

  const contact    = contacts.find((c) => c.id === contactId);
  const isVerified = contact?.verified ?? false;

  // Update header title with contact name
  useEffect(() => {
    navigation.setOptions({ title: `Verify ${contactName}` });
  }, [navigation, contactName]);

  const handleMarkVerified = useCallback(async () => {
    await verifyContact(contactId, true);
    navigation.goBack();
  }, [verifyContact, contactId, navigation]);

  const handleRemoveVerification = useCallback(async () => {
    await verifyContact(contactId, false);
    navigation.goBack();
  }, [verifyContact, contactId, navigation]);

  // ── Loading / error states ─────────────────────────────────────────────────

  if (!identity) {
    return (
      <View style={styles.loading}>
        <ActivityIndicator color="#00e5ff" size="large" />
        <Text style={styles.loadingText}>Loading identity…</Text>
      </View>
    );
  }

  if (!contact) {
    return (
      <View style={styles.loading}>
        <Text style={styles.loadingText}>Contact not found.</Text>
      </View>
    );
  }

  const myKey        = identity.ikDhPub;
  const theirKey     = contact.ikDhPub;
  const myQrValue    = `shadow://key/${myKey}`;
  const theirQrValue = `shadow://key/${theirKey}`;

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      {/* Status badge */}
      {isVerified ? (
        <View style={styles.verifiedBadge}>
          <Text style={styles.verifiedBadgeText}>✓ Verified</Text>
        </View>
      ) : (
        <View style={styles.unverifiedBadge}>
          <Text style={styles.unverifiedBadgeText}>Not Verified</Text>
        </View>
      )}

      {/* Instruction / warning */}
      <View style={styles.warningBox}>
        <Text style={styles.warningText}>
          Compare these keys with your contact via a voice call or in person.
          Verification confirms you are communicating with the right person
          and that no one has tampered with their key.
        </Text>
      </View>

      {/* QR codes side-by-side */}
      <View style={styles.keysRow}>
        <View style={styles.keyCard}>
          <Text style={styles.keyCardTitle}>You</Text>
          <QRDisplay value={myQrValue} size={160} ecl="M" />
          <Text style={styles.keyHexLabel} selectable numberOfLines={2}>
            {shortHex(myKey)}
          </Text>
        </View>

        <View style={styles.keyCard}>
          <Text style={styles.keyCardTitle} numberOfLines={1}>
            {contactName}
          </Text>
          <QRDisplay value={theirQrValue} size={160} ecl="M" />
          <Text style={styles.keyHexLabel} selectable numberOfLines={2}>
            {shortHex(theirKey)}
          </Text>
        </View>
      </View>

      {/* Full hex for manual comparison */}
      <View style={styles.hexBlock}>
        <Text style={styles.hexBlockLabel}>Your IK DH Public Key</Text>
        <Text style={styles.hexBlockValue} selectable>
          {formatHex(myKey)}
        </Text>
      </View>

      <View style={styles.hexBlock}>
        <Text style={styles.hexBlockLabel}>{contactName}'s IK DH Public Key</Text>
        <Text style={styles.hexBlockValue} selectable>
          {formatHex(theirKey)}
        </Text>
      </View>

      {/* Action button */}
      {isVerified ? (
        <TouchableOpacity
          style={styles.btnRemove}
          onPress={handleRemoveVerification}
          accessibilityLabel="Remove key verification for this contact"
          accessibilityRole="button"
        >
          <Text style={styles.btnRemoveText}>Remove Verification</Text>
        </TouchableOpacity>
      ) : (
        <TouchableOpacity
          style={styles.btnVerify}
          onPress={handleMarkVerified}
          accessibilityLabel="Mark this contact's key as verified"
          accessibilityRole="button"
        >
          <Text style={styles.btnVerifyText}>Mark as Verified</Text>
        </TouchableOpacity>
      )}

      <Text style={styles.footer}>
        Verification is stored locally on your device only.{'\n'}
        It does not affect message encryption.
      </Text>
    </ScrollView>
  );
});

VerifyScreen.displayName = 'VerifyScreen';
export default VerifyScreen;

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  content: {
    padding: 20,
    alignItems: 'center',
    gap: 20,
    paddingBottom: 48,
  },
  loading: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    gap: 16,
    backgroundColor: '#0a0a0a',
  },
  loadingText: {
    color: '#555',
    fontSize: 14,
  },
  // Status badges
  verifiedBadge: {
    backgroundColor: '#0d2e1a',
    borderColor: '#00c853',
    borderWidth: 1,
    borderRadius: 20,
    paddingHorizontal: 18,
    paddingVertical: 7,
  },
  verifiedBadgeText: {
    color: '#00c853',
    fontSize: 14,
    fontWeight: '600',
  },
  unverifiedBadge: {
    backgroundColor: '#2a1a00',
    borderColor: '#ff9800',
    borderWidth: 1,
    borderRadius: 20,
    paddingHorizontal: 18,
    paddingVertical: 7,
  },
  unverifiedBadgeText: {
    color: '#ff9800',
    fontSize: 14,
    fontWeight: '600',
  },
  // Warning / instruction box
  warningBox: {
    backgroundColor: '#141414',
    borderLeftWidth: 3,
    borderLeftColor: '#ff9800',
    borderRadius: 8,
    padding: 14,
    width: '100%',
  },
  warningText: {
    color: '#aaa',
    fontSize: 13,
    lineHeight: 20,
  },
  // QR cards row
  keysRow: {
    flexDirection: 'row',
    gap: 12,
    width: '100%',
  },
  keyCard: {
    flex: 1,
    backgroundColor: '#111111',
    borderRadius: 14,
    padding: 12,
    alignItems: 'center',
    gap: 10,
  },
  keyCardTitle: {
    color: '#f0f0f0',
    fontSize: 13,
    fontWeight: '600',
  },
  keyHexLabel: {
    color: '#00e5ff',
    fontFamily: 'monospace',
    fontSize: 10,
    textAlign: 'center',
    lineHeight: 15,
  },
  // Full hex blocks
  hexBlock: {
    backgroundColor: '#111111',
    borderRadius: 12,
    padding: 14,
    width: '100%',
  },
  hexBlockLabel: {
    color: '#555',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: 0.8,
    marginBottom: 8,
  },
  hexBlockValue: {
    color: '#00e5ff',
    fontFamily: 'monospace',
    fontSize: 12,
    lineHeight: 20,
    letterSpacing: 0.3,
  },
  // Buttons
  btnVerify: {
    backgroundColor: '#00e5ff',
    borderRadius: 12,
    paddingVertical: 15,
    width: '100%',
    alignItems: 'center',
  },
  btnVerifyText: {
    color: '#000',
    fontWeight: '700',
    fontSize: 15,
  },
  btnRemove: {
    backgroundColor: '#1a1a1a',
    borderColor: '#333',
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 15,
    width: '100%',
    alignItems: 'center',
  },
  btnRemoveText: {
    color: '#f0f0f0',
    fontWeight: '600',
    fontSize: 15,
  },
  footer: {
    color: '#333',
    fontSize: 12,
    textAlign: 'center',
    lineHeight: 20,
  },
});
