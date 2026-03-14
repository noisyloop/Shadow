/**
 * Shadow – Root Application Entry Point
 *
 * Uses a custom NavigationContainer so we can inject our dark theme
 * and initialise the key store on first launch.
 */

import 'react-native-gesture-handler';
import React, { useEffect } from 'react';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { StyleSheet } from 'react-native';
import { useKeysStore } from '@/store/keys';
import Navigation from '@/navigation';

export default function App(): React.JSX.Element {
  const initializeIdentity = useKeysStore((s) => s.initializeIdentity);

  useEffect(() => {
    // Ensure a device identity exists on first launch.
    // This is a no-op if the identity is already persisted.
    initializeIdentity().catch((err: unknown) => {
      console.error('[App] Failed to initialize identity:', err);
    });
  }, [initializeIdentity]);

  return (
    <GestureHandlerRootView style={styles.root}>
      <SafeAreaProvider>
        <StatusBar style="light" />
        <Navigation />
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
});
