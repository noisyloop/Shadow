/**
 * Shadow — HomeScreen
 *
 * Contact list with:
 *   - FlatList of contacts (tap → Chat)
 *   - Empty state with call-to-action
 *   - FAB (+) to navigate to AddContact
 *   - "My Key" shortcut showing truncated own identity key
 *
 * Loads contacts from the contact store on mount.
 */

import React, { useCallback, useEffect } from 'react';
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  Pressable,
  StyleSheet,
  type ListRenderItem,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import type { StackNavigationProp } from '@react-navigation/stack';

import type { RootStackParamList } from '@/navigation';
import { useContactStore, type Contact } from '@/store/contacts';
import { useKeyStore } from '@/store/keys';

// ─── Types ────────────────────────────────────────────────────────────────────

type Nav = StackNavigationProp<RootStackParamList, 'Home'>;

// ─── Component ────────────────────────────────────────────────────────────────

export default function HomeScreen(): React.JSX.Element {
  const navigation   = useNavigation<Nav>();
  const contacts     = useContactStore((s) => s.contacts);
  const loadContacts = useContactStore((s) => s.loadContacts);
  const identity     = useKeyStore((s) => s.identity);

  useEffect(() => {
    loadContacts().catch((err: unknown) => {
      console.warn('[HomeScreen] loadContacts failed:', err);
    });
  }, [loadContacts]);

  const handleAdd = useCallback(
    () => navigation.navigate('AddContact'),
    [navigation],
  );

  const handleKey = useCallback(
    () => navigation.navigate('Key'),
    [navigation],
  );

  const handleContactPress = useCallback(
    (contact: Contact) => {
      navigation.navigate('Chat', {
        contactId:   contact.id,
        contactName: contact.name,
      });
    },
    [navigation],
  );

  const renderContact: ListRenderItem<Contact> = useCallback(
    ({ item }) => (
      <TouchableOpacity
        style={styles.contactRow}
        onPress={() => handleContactPress(item)}
        activeOpacity={0.7}
        accessibilityLabel={`Open chat with ${item.name}`}
        accessibilityRole="button"
      >
        <View style={styles.avatar} accessibilityElementsHidden>
          <Text style={styles.avatarText}>
            {item.name.charAt(0).toUpperCase()}
          </Text>
        </View>
        <View style={styles.contactInfo}>
          <Text style={styles.contactName} numberOfLines={1}>
            {item.name}
          </Text>
          <Text style={styles.contactKey} numberOfLines={1}>
            {item.ikDhPub.slice(0, 16)}…
          </Text>
        </View>
        <Text style={styles.chevron} accessibilityElementsHidden>
          ›
        </Text>
      </TouchableOpacity>
    ),
    [handleContactPress],
  );

  const keyExtractor = useCallback((item: Contact) => item.id, []);

  const ItemSeparator = useCallback(
    () => <View style={styles.separator} />,
    [],
  );

  return (
    <View style={styles.container}>
      {/* Identity peek bar */}
      <View style={styles.topBar}>
        <Text style={styles.subtitle} numberOfLines={1}>
          {identity
            ? `IK: ${identity.ikDhPub.slice(0, 8)}…`
            : 'Initialising…'}
        </Text>
        <Pressable
          onPress={handleKey}
          style={styles.keyBtn}
          accessibilityLabel="View my public key"
          accessibilityRole="button"
        >
          <Text style={styles.keyBtnText}>My Key</Text>
        </Pressable>
      </View>

      {/* Contact list / empty state */}
      {contacts.length === 0 ? (
        <View style={styles.empty} accessibilityLiveRegion="polite">
          <Text style={styles.emptyTitle}>No contacts yet</Text>
          <Text style={styles.emptySubtitle}>
            Add a contact by scanning their QR code or pasting their identity
            key. Tap the{' '}
            <Text style={styles.emptyHighlight}>+</Text> button below.
          </Text>
        </View>
      ) : (
        <FlatList
          data={contacts}
          keyExtractor={keyExtractor}
          renderItem={renderContact}
          ItemSeparatorComponent={ItemSeparator}
          contentContainerStyle={styles.listContent}
          showsVerticalScrollIndicator={false}
        />
      )}

      {/* FAB */}
      <Pressable
        style={({ pressed }) => [styles.fab, pressed && styles.fabPressed]}
        onPress={handleAdd}
        accessibilityLabel="Add contact"
        accessibilityRole="button"
      >
        <Text style={styles.fabText}>+</Text>
      </Pressable>
    </View>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0a0a',
  },
  topBar: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#1e1e1e',
  },
  subtitle: {
    color: '#555',
    fontSize: 12,
    fontFamily: 'monospace',
    flex: 1,
    marginRight: 8,
  },
  keyBtn: {
    backgroundColor: '#1a1a1a',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 6,
  },
  keyBtnText: {
    color: '#00e5ff',
    fontSize: 13,
    fontWeight: '500',
  },
  listContent: {
    paddingBottom: 100,
  },
  contactRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 14,
    backgroundColor: '#111111',
  },
  avatar: {
    width: 46,
    height: 46,
    borderRadius: 23,
    backgroundColor: '#0d2137',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 14,
  },
  avatarText: {
    color: '#00e5ff',
    fontSize: 19,
    fontWeight: '600',
  },
  contactInfo: {
    flex: 1,
    minWidth: 0,
  },
  contactName: {
    color: '#f0f0f0',
    fontSize: 16,
    fontWeight: '500',
  },
  contactKey: {
    color: '#555',
    fontSize: 11,
    fontFamily: 'monospace',
    marginTop: 2,
  },
  chevron: {
    color: '#444',
    fontSize: 24,
    marginLeft: 8,
  },
  separator: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: '#1a1a1a',
    marginLeft: 76,
  },
  // Empty state
  empty: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 40,
    paddingBottom: 80,
  },
  emptyTitle: {
    color: '#f0f0f0',
    fontSize: 20,
    fontWeight: '600',
    marginBottom: 12,
  },
  emptySubtitle: {
    color: '#555',
    fontSize: 14,
    textAlign: 'center',
    lineHeight: 22,
  },
  emptyHighlight: {
    color: '#00e5ff',
    fontWeight: '700',
  },
  // FAB
  fab: {
    position: 'absolute',
    bottom: 36,
    right: 24,
    width: 58,
    height: 58,
    borderRadius: 29,
    backgroundColor: '#00e5ff',
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#00e5ff',
    shadowOpacity: 0.45,
    shadowRadius: 14,
    shadowOffset: { width: 0, height: 4 },
    elevation: 8,
  },
  fabPressed: {
    opacity: 0.85,
    transform: [{ scale: 0.96 }],
  },
  fabText: {
    color: '#000',
    fontSize: 30,
    fontWeight: '300',
    lineHeight: 33,
    marginTop: -2,
  },
});
