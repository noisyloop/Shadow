/**
 * Shadow — KeyScreen (Identity Key Display)
 *
 * Shows the user's own public identity key in two forms:
 *   1. QR code (value = "shadow://key/<hex>")
 *   2. Hex string with 8-char grouping for readability
 *
 * Actions:
 *   Copy  — writes raw hex to clipboard
 *   Share — native share sheet with the shadow:// URI
 *
 * Also shows signed prekey metadata (ID, creation timestamp) for reference.
 */

import React, { useCallback, useEffect, type FC } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Share,
  ScrollView,
  Alert,
  ActivityIndicator,
} from 'react-native';
import * as Clipboard from 'expo-clipboard';

import { useKeysStore } from '@/store/keys';
import QRDisplay from '@/components/QRDisplay';

// ─── Component ────────────────────────────────────────────────────────────────

const KeyScreen: FC = () => {
  const identity           = useKeysStore((s) => s.identity);
  const spk                = useKeysStore((s) => s.spk);
  const initializeIdentity = useKeysStore((s) => s.initializeIdentity);

  // Ensure identity is initialised if this screen is opened cold
  useEffect(() => {
    if (!identity) {
      initializeIdentity().catch((err: unknown) => {
        console.error('[KeyScreen] initializeIdentity failed:', err);
      });
    }
  }, [identity, initializeIdentity]);

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleCopy = useCallback(async () => {
    if (!identity) return;
    await Clipboard.setStringAsync(identity.ikDhPub);
    Alert.alert('Copied', 'Identity key copied to clipboard.');
  }, [identity]);

  const handleShare = useCallback(async () => {
    if (!identity) return;
    const uri = `shadow://key/${identity.ikDhPub}`;
    await Share.share(
      {
        message: `Add me on Shadow:\n${uri}`,
        title:   'Shadow Identity Key',
      },
      { dialogTitle: 'Share My Shadow Key' },
    );
  }, [identity]);

  // ── Loading state ──────────────────────────────────────────────────────────

  if (!identity) {
    return (
      <View style={styles.loading} accessibilityLiveRegion="polite">
        <ActivityIndicator color="#00e5ff" size="large" />
        <Text style={styles.loadingText}>Initialising identity…</Text>
      </View>
    );
  }

  const { ikDhPub, ikSignPub } = identity;
  const qrValue  = `shadow://key/${ikDhPub}`;

  // Format hex with space-separated 8-char groups (4 groups per line)
  const hexGroups   = ikDhPub.match(/.{1,8}/g) ?? [];
  const hexFormatted = hexGroups.join(' ');

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      showsVerticalScrollIndicator={false}
    >
      <Text style={styles.hint}>
        Share this QR code or key with anyone who wants to message you.
        Your identity key never changes unless you reinstall Shadow.
      </Text>

      {/* QR Code */}
      <View style={styles.qrWrapper} accessibilityLabel="Identity key QR code">
        <QRDisplay value={qrValue} size={240} ecl="M" />
      </View>

      {/* Hex key — DH */}
      <View style={styles.keyBox}>
        <Text style={styles.keyLabel}>X25519 Identity Key (DH)</Text>
        <Text style={styles.keyHex} selectable accessibilityLabel="Hex identity key">
          {hexFormatted}
        </Text>
      </View>

      {/* Hex key — signing */}
      <View style={styles.keyBox}>
        <Text style={styles.keyLabel}>ed25519 Identity Key (Signing)</Text>
        <Text style={styles.keyHexSmall} selectable>
          {(ikSignPub.match(/.{1,8}/g) ?? []).join(' ')}
        </Text>
      </View>

      {/* SPK metadata */}
      {spk && (
        <View style={styles.metaBox}>
          <View style={styles.metaRow}>
            <Text style={styles.metaLabel}>Signed Prekey ID</Text>
            <Text style={styles.metaValue}>{spk.id}</Text>
          </View>
          <View style={[styles.metaRow, styles.metaRowLast]}>
            <Text style={styles.metaLabel}>SPK Public</Text>
            <Text style={styles.metaValue} numberOfLines={1} ellipsizeMode="middle">
              {spk.pubKey.slice(0, 16)}…{spk.pubKey.slice(-8)}
            </Text>
          </View>
        </View>
      )}

      {/* Action buttons */}
      <View style={styles.actions}>
        <TouchableOpacity
          style={styles.btnSecondary}
          onPress={handleCopy}
          accessibilityLabel="Copy identity key to clipboard"
          accessibilityRole="button"
        >
          <Text style={styles.btnSecondaryText}>Copy Key</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.btnPrimary}
          onPress={handleShare}
          accessibilityLabel="Share identity key"
          accessibilityRole="button"
        >
          <Text style={styles.btnPrimaryText}>Share</Text>
        </TouchableOpacity>
      </View>

      {/* Footer note */}
      <Text style={styles.footer}>
        Shadow uses device-generated keypairs as sole identity.{'\n'}
        No phone number. No server account. No cloud backup.
      </Text>
    </ScrollView>
  );
};

export default KeyScreen;

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  content: {
    padding: 24,
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
  hint: {
    color: '#555',
    fontSize: 13,
    textAlign: 'center',
    lineHeight: 20,
  },
  qrWrapper: {
    borderRadius: 20,
    overflow: 'hidden',
  },
  keyBox: {
    backgroundColor: '#111111',
    borderRadius: 12,
    padding: 16,
    width: '100%',
  },
  keyLabel: {
    color: '#555',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: 0.9,
    marginBottom: 8,
  },
  keyHex: {
    color: '#00e5ff',
    fontFamily: 'monospace',
    fontSize: 14,
    lineHeight: 24,
    letterSpacing: 0.4,
  },
  keyHexSmall: {
    color: '#4a8a9a',
    fontFamily: 'monospace',
    fontSize: 12,
    lineHeight: 22,
    letterSpacing: 0.2,
  },
  metaBox: {
    backgroundColor: '#111111',
    borderRadius: 12,
    width: '100%',
    overflow: 'hidden',
  },
  metaRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#1e1e1e',
  },
  metaRowLast: {
    borderBottomWidth: 0,
  },
  metaLabel: {
    color: '#555',
    fontSize: 12,
  },
  metaValue: {
    color: '#888',
    fontFamily: 'monospace',
    fontSize: 12,
    maxWidth: '60%',
    textAlign: 'right',
  },
  actions: {
    flexDirection: 'row',
    gap: 12,
    width: '100%',
  },
  btnSecondary: {
    flex: 1,
    backgroundColor: '#1a1a1a',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  btnSecondaryText: {
    color: '#f0f0f0',
    fontWeight: '600',
    fontSize: 15,
  },
  btnPrimary: {
    flex: 1,
    backgroundColor: '#00e5ff',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  btnPrimaryText: {
    color: '#000',
    fontWeight: '600',
    fontSize: 15,
  },
  footer: {
    color: '#2e2e2e',
    fontSize: 12,
    textAlign: 'center',
    lineHeight: 20,
  },
});
