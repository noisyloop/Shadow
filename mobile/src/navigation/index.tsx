/**
 * Shadow – Stack Navigator
 *
 * Screens:
 *   Home        – contact list
 *   Chat        – message thread for a contact
 *   AddContact  – scan QR or paste hex public key
 *   KeyDisplay  – show own public key as QR + hex
 */

import React from 'react';
import { NavigationContainer, DefaultTheme } from '@react-navigation/native';
import {
  createStackNavigator,
  type StackNavigationOptions,
} from '@react-navigation/stack';
import { TouchableOpacity, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';

import HomeScreen from '@/screens/HomeScreen';
import ChatScreen from '@/screens/ChatScreen';
import AddContactScreen from '@/screens/AddContactScreen';
import KeyScreen from '@/screens/KeyScreen';
import VerifyScreen from '@/screens/VerifyScreen';

// ─── Route param types ────────────────────────────────────────────────────────

export type RootStackParamList = {
  Home: undefined;
  Chat: { contactId: string; contactName: string };
  AddContact: undefined;
  /** Aliased as both 'Key' (legacy) and 'KeyDisplay' */
  Key: undefined;
  KeyDisplay: undefined;
  Verify: { contactId: string; contactName: string };
};

// ─── Theme ────────────────────────────────────────────────────────────────────

const ShadowTheme = {
  ...DefaultTheme,
  dark: true,
  colors: {
    ...DefaultTheme.colors,
    primary: '#00e5ff',
    background: '#0a0a0a',
    card: '#111111',
    text: '#f0f0f0',
    border: '#222222',
    notification: '#00e5ff',
  },
};

// ─── Stack ────────────────────────────────────────────────────────────────────

const Stack = createStackNavigator<RootStackParamList>();

const screenOptions: StackNavigationOptions = {
  headerStyle: {
    backgroundColor: '#111111',
  } as StackNavigationOptions['headerStyle'],
  headerTintColor: '#f0f0f0',
  headerTitleStyle: {
    fontWeight: '600' as const,
    fontSize: 17,
  },
  cardStyle: { backgroundColor: '#0a0a0a' },
};

export default function Navigation(): React.JSX.Element {
  return (
    <NavigationContainer theme={ShadowTheme}>
      <Stack.Navigator
        initialRouteName="Home"
        screenOptions={screenOptions}
      >
        {/* ── Home ── */}
        <Stack.Screen
          name="Home"
          component={HomeScreen}
          options={({ navigation }) => ({
            title: 'Shadow',
            headerRight: () => (
              <TouchableOpacity
                onPress={() => navigation.navigate('KeyDisplay')}
                style={styles.headerBtn}
                accessibilityLabel="View my public key"
              >
                <Ionicons name="key-outline" size={22} color="#00e5ff" />
              </TouchableOpacity>
            ),
          })}
        />

        {/* ── Chat ── */}
        <Stack.Screen
          name="Chat"
          component={ChatScreen}
          options={({ route }) => ({
            title: route.params.contactName,
            headerBackTitleVisible: false,
          })}
        />

        {/* ── Add Contact ── */}
        <Stack.Screen
          name="AddContact"
          component={AddContactScreen}
          options={{ title: 'Add Contact', presentation: 'modal' }}
        />

        {/* ── Key Display (legacy route name: 'Key') ── */}
        <Stack.Screen
          name="Key"
          component={KeyScreen}
          options={{ title: 'My Identity Key' }}
        />
        <Stack.Screen
          name="KeyDisplay"
          component={KeyScreen}
          options={{ title: 'My Identity Key', presentation: 'modal' }}
        />

        {/* ── Verify ── */}
        <Stack.Screen
          name="Verify"
          component={VerifyScreen}
          options={({ route }) => ({
            title: `Verify ${route.params.contactName}`,
            headerBackTitleVisible: false,
          })}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  headerBtn: {
    marginRight: 16,
    padding: 4,
  },
});
