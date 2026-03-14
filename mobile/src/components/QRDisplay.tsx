/**
 * Shadow — QRDisplay
 *
 * A thin, typed wrapper around react-native-qrcode-svg that ensures:
 *   - Consistent white background (required for QR scanners)
 *   - Error correction level M (balanced: ~15% damage tolerance)
 *   - Optional label shown below the QR code
 *   - Graceful error state if the value is empty
 */

import React, { memo } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import QRCode from 'react-native-qrcode-svg';

// ─── Props ────────────────────────────────────────────────────────────────────

interface QRDisplayProps {
  /** The string to encode in the QR code */
  value: string;
  /** Pixel size of the QR code square (default: 200) */
  size?: number;
  /** Optional label rendered below the QR code in monospace */
  label?: string;
  /** Error correction level (default: 'M') */
  ecl?: 'L' | 'M' | 'Q' | 'H';
}

// ─── Component ────────────────────────────────────────────────────────────────

const QRDisplay: React.FC<QRDisplayProps> = memo(
  ({ value, size = 200, label, ecl = 'M' }) => {
    if (!value) {
      return (
        <View style={[styles.container, { width: size, height: size }]}>
          <Text style={styles.errorText}>No key to display</Text>
        </View>
      );
    }

    return (
      <View style={styles.wrapper}>
        <View style={[styles.container, { padding: Math.round(size * 0.05) }]}>
          <QRCode
            value={value}
            size={size}
            color="#000000"
            backgroundColor="#ffffff"
            ecl={ecl}
          />
        </View>
        {label !== undefined && label.length > 0 && (
          <Text style={styles.label} numberOfLines={1} ellipsizeMode="middle">
            {label}
          </Text>
        )}
      </View>
    );
  },
);

QRDisplay.displayName = 'QRDisplay';
export default QRDisplay;

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  wrapper: {
    alignItems: 'center',
    gap: 10,
  },
  container: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  label: {
    color: '#00e5ff',
    fontFamily: 'monospace',
    fontSize: 11,
    maxWidth: 280,
    textAlign: 'center',
  },
  errorText: {
    color: '#888888',
    fontSize: 13,
    textAlign: 'center',
  },
});
