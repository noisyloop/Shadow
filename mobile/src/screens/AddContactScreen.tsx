/**
 * Shadow — AddContactScreen
 *
 * Two-tab screen for adding a new contact:
 *
 *   Tab 1: "Scan QR"   — live camera view, decodes a Shadow identity QR code.
 *   Tab 2: "Paste Key" — manual 64-char hex text entry with live validation.
 *
 * Both tabs share a "Display name" text field at the top.
 *
 * A valid identity key is 64 lowercase hex characters (32 bytes, X25519 pub).
 * The QR value can be either the raw 64-char hex or a shadow://key/<hex> URI.
 *
 * On success the contact is saved to the contact store and the screen pops.
 */

import React, {
  useState,
  useCallback,
  useRef,
  type FC,
} from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ScrollView,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import {
  CameraView,
  useCameraPermissions,
  type BarcodeScanningResult,
} from 'expo-camera';

import type { RootStackParamList } from '@/navigation';
import { useContactStore } from '@/store/contacts';
import type { StackNavigationProp } from '@react-navigation/stack';

// ─── Types ────────────────────────────────────────────────────────────────────

type Nav = StackNavigationProp<RootStackParamList, 'AddContact'>;
type Tab = 'scan' | 'paste';

// ─── Constants ────────────────────────────────────────────────────────────────

const HEX_KEY_RE = /^[0-9a-f]{64}$/i;
const SHADOW_URI_RE = /^shadow:\/\/key\/([0-9a-f]{64})$/i;

function isValidKey(key: string): boolean {
  return HEX_KEY_RE.test(key.trim());
}

/** Extract raw 64-char hex from either a bare key or a shadow:// URI */
function parseKeyFromQR(data: string): string | null {
  const trimmed = data.trim();
  if (isValidKey(trimmed)) return trimmed.toLowerCase();
  const match = trimmed.match(SHADOW_URI_RE);
  if (match) return match[1].toLowerCase();
  return null;
}

// ─── Component ────────────────────────────────────────────────────────────────

const AddContactScreen: FC = () => {
  const navigation = useNavigation<Nav>();
  const addContact = useContactStore((s) => s.addContact);

  const [activeTab, setActiveTab] = useState<Tab>('scan');
  const [name, setName]           = useState('');
  const [pasteKey, setPasteKey]   = useState('');
  const [saving, setSaving]       = useState(false);
  const [scanned, setScanned]     = useState(false);

  const [permission, requestPermission] = useCameraPermissions();
  const nameInputRef = useRef<TextInput>(null);

  // ── Save validated contact ──────────────────────────────────────────────

  const saveContact = useCallback(
    async (hexKey: string) => {
      const displayName = name.trim();
      if (!displayName) {
        Alert.alert(
          'Name required',
          'Please enter a display name for this contact.',
          [{ text: 'OK', onPress: () => nameInputRef.current?.focus() }],
        );
        return;
      }
      setSaving(true);
      try {
        await addContact({
          name:    displayName,
          ikDhPub: hexKey,
        });
        navigation.goBack();
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        Alert.alert('Error adding contact', msg);
      } finally {
        setSaving(false);
      }
    },
    [name, addContact, navigation],
  );

  // ── QR scan ─────────────────────────────────────────────────────────────

  const handleBarcodeScan = useCallback(
    ({ data }: BarcodeScanningResult) => {
      if (scanned) return;

      const hexKey = parseKeyFromQR(data);
      if (!hexKey) {
        Alert.alert(
          'Invalid QR code',
          'The scanned code does not contain a valid Shadow identity key.\n\n' +
            'Expected a 64-character hex string or shadow://key/<hex> URI.',
          [{ text: 'Try Again', onPress: () => setScanned(false) }],
        );
        return;
      }
      setScanned(true);
      setPasteKey(hexKey); // mirror into paste field so user can review
      saveContact(hexKey);
    },
    [scanned, saveContact],
  );

  // ── Paste submit ─────────────────────────────────────────────────────────

  const handlePasteSubmit = useCallback(async () => {
    const key = pasteKey.trim().toLowerCase();
    if (!isValidKey(key)) {
      Alert.alert(
        'Invalid key',
        `An identity key must be exactly 64 hexadecimal characters.\n` +
          `You entered ${pasteKey.trim().length} characters.`,
      );
      return;
    }
    await saveContact(key);
  }, [pasteKey, saveContact]);

  // ────────────────────────────────────────────────────────────────────────

  return (
    <KeyboardAvoidingView
      style={styles.root}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
    >
      {/* ── Shared: Display name ── */}
      <View style={styles.nameSection}>
        <Text style={styles.label}>Display name</Text>
        <TextInput
          ref={nameInputRef}
          style={styles.nameInput}
          placeholder="e.g. Alice"
          placeholderTextColor="#444"
          value={name}
          onChangeText={setName}
          autoCapitalize="words"
          autoCorrect={false}
          returnKeyType="next"
          maxLength={64}
          accessibilityLabel="Contact display name"
        />
      </View>

      {/* ── Tab bar ── */}
      <View style={styles.tabBar}>
        {(['scan', 'paste'] as Tab[]).map((tab) => (
          <TouchableOpacity
            key={tab}
            style={[styles.tab, activeTab === tab && styles.tabActive]}
            onPress={() => {
              setActiveTab(tab);
              setScanned(false);
            }}
            accessibilityRole="tab"
            accessibilityState={{ selected: activeTab === tab }}
          >
            <Text
              style={[
                styles.tabText,
                activeTab === tab && styles.tabTextActive,
              ]}
            >
              {tab === 'scan' ? 'Scan QR' : 'Paste Key'}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      {/* ── Tab content ── */}
      {activeTab === 'scan' ? (
        <ScanTab
          permission={permission}
          requestPermission={requestPermission}
          scanned={scanned}
          onScan={handleBarcodeScan}
          onReset={() => setScanned(false)}
        />
      ) : (
        <PasteTab
          value={pasteKey}
          onChange={setPasteKey}
          onSubmit={handlePasteSubmit}
          saving={saving}
        />
      )}
    </KeyboardAvoidingView>
  );
};

export default AddContactScreen;

// ─── Sub-component: ScanTab ───────────────────────────────────────────────────

interface ScanTabProps {
  permission:        ReturnType<typeof useCameraPermissions>[0];
  requestPermission: ReturnType<typeof useCameraPermissions>[1];
  scanned:           boolean;
  onScan:            (result: BarcodeScanningResult) => void;
  onReset:           () => void;
}

const ScanTab: FC<ScanTabProps> = ({
  permission,
  requestPermission,
  scanned,
  onScan,
  onReset,
}) => {
  if (!permission) {
    return (
      <View style={styles.centre}>
        <ActivityIndicator color="#00e5ff" />
      </View>
    );
  }

  if (!permission.granted) {
    return (
      <View style={styles.centre}>
        <Text style={styles.permText}>
          Camera access is required to scan QR codes.
        </Text>
        <TouchableOpacity style={styles.primaryBtn} onPress={requestPermission}>
          <Text style={styles.primaryBtnText}>Grant Permission</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (scanned) {
    return (
      <View style={styles.centre}>
        <Text style={styles.scannedText}>QR code scanned!</Text>
        <TouchableOpacity style={styles.primaryBtn} onPress={onReset}>
          <Text style={styles.primaryBtnText}>Scan Again</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={styles.cameraWrapper}>
      <CameraView
        style={styles.camera}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={onScan}
      >
        {/* Framing overlay */}
        <View style={styles.scanOverlay}>
          <View style={styles.scanFrame} />
          <Text style={styles.scanHint}>
            Point at a Shadow identity QR code
          </Text>
        </View>
      </CameraView>
    </View>
  );
};

// ─── Sub-component: PasteTab ──────────────────────────────────────────────────

interface PasteTabProps {
  value:    string;
  onChange: (v: string) => void;
  onSubmit: () => void | Promise<void>;
  saving:   boolean;
}

const PasteTab: FC<PasteTabProps> = ({ value, onChange, onSubmit, saving }) => {
  const trimmed  = value.trim();
  const isValid  = isValidKey(trimmed);
  const hasInput = trimmed.length > 0;

  return (
    <ScrollView
      style={styles.pasteScroll}
      contentContainerStyle={styles.pasteContent}
      keyboardShouldPersistTaps="handled"
    >
      <Text style={styles.label}>Identity key (64 hex characters)</Text>
      <TextInput
        style={[
          styles.keyInput,
          hasInput && !isValid && styles.keyInputInvalid,
          isValid && styles.keyInputValid,
        ]}
        placeholder="a1b2c3d4…  (64 characters)"
        placeholderTextColor="#333"
        value={value}
        onChangeText={onChange}
        autoCapitalize="none"
        autoCorrect={false}
        spellCheck={false}
        multiline
        maxLength={64}
        accessibilityLabel="Identity key input"
      />

      {hasInput && (
        <Text
          style={[styles.validationMsg, isValid ? styles.validMsg : styles.invalidMsg]}
        >
          {isValid
            ? `Valid key (${trimmed.length}/64)`
            : `${trimmed.length}/64 characters — must be exactly 64 hex chars`}
        </Text>
      )}

      <TouchableOpacity
        style={[
          styles.primaryBtn,
          styles.primaryBtnFull,
          (!isValid || saving) && styles.primaryBtnDisabled,
        ]}
        onPress={onSubmit}
        disabled={!isValid || saving}
        accessibilityLabel="Add contact"
        accessibilityRole="button"
      >
        {saving ? (
          <ActivityIndicator color="#000" size="small" />
        ) : (
          <Text style={styles.primaryBtnText}>Add Contact</Text>
        )}
      </TouchableOpacity>
    </ScrollView>
  );
};

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  // Name section
  nameSection: {
    paddingHorizontal: 16,
    paddingTop: 16,
    paddingBottom: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#1e1e1e',
  },
  label: {
    color: '#777',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: 0.9,
    marginBottom: 7,
  },
  nameInput: {
    backgroundColor: '#1a1a1a',
    borderRadius: 10,
    paddingHorizontal: 14,
    paddingVertical: 11,
    color: '#f0f0f0',
    fontSize: 16,
  },
  // Tab bar
  tabBar: {
    flexDirection: 'row',
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#1e1e1e',
  },
  tab: {
    flex: 1,
    paddingVertical: 14,
    alignItems: 'center',
  },
  tabActive: {
    borderBottomWidth: 2,
    borderBottomColor: '#00e5ff',
  },
  tabText: {
    color: '#555',
    fontSize: 14,
    fontWeight: '500',
  },
  tabTextActive: {
    color: '#00e5ff',
  },
  // Camera
  cameraWrapper: {
    flex: 1,
    overflow: 'hidden',
  },
  camera: {
    flex: 1,
  },
  scanOverlay: {
    ...StyleSheet.absoluteFillObject,
    justifyContent: 'center',
    alignItems: 'center',
    gap: 20,
  },
  scanFrame: {
    width: 220,
    height: 220,
    borderWidth: 2,
    borderColor: '#00e5ff',
    borderRadius: 16,
    backgroundColor: 'transparent',
  },
  scanHint: {
    color: '#fff',
    fontSize: 13,
    textAlign: 'center',
    textShadowColor: 'rgba(0,0,0,0.8)',
    textShadowOffset: { width: 0, height: 1 },
    textShadowRadius: 4,
  },
  // Paste
  pasteScroll: {
    flex: 1,
  },
  pasteContent: {
    padding: 16,
    gap: 12,
  },
  keyInput: {
    backgroundColor: '#111',
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#2a2a2a',
    paddingHorizontal: 14,
    paddingVertical: 12,
    color: '#00e5ff',
    fontSize: 13,
    fontFamily: 'monospace',
    minHeight: 80,
    textAlignVertical: 'top',
  },
  keyInputValid: {
    borderColor: '#00cc66',
  },
  keyInputInvalid: {
    borderColor: '#cc3333',
  },
  validationMsg: {
    fontSize: 12,
    fontFamily: 'monospace',
  },
  validMsg: {
    color: '#00cc66',
  },
  invalidMsg: {
    color: '#cc4444',
  },
  // Shared
  centre: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 32,
    gap: 16,
  },
  permText: {
    color: '#777',
    textAlign: 'center',
    fontSize: 14,
    lineHeight: 22,
  },
  scannedText: {
    color: '#00e5ff',
    fontSize: 18,
    fontWeight: '600',
  },
  primaryBtn: {
    backgroundColor: '#00e5ff',
    borderRadius: 12,
    paddingVertical: 13,
    paddingHorizontal: 28,
    alignItems: 'center',
    minWidth: 160,
  },
  primaryBtnFull: {
    marginTop: 4,
  },
  primaryBtnDisabled: {
    backgroundColor: '#1a1a1a',
  },
  primaryBtnText: {
    color: '#000',
    fontWeight: '600',
    fontSize: 15,
  },
});
