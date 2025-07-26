import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Switch,
  Alert,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Bell, Moon, Image as ImageIcon, Shield, CircleHelp as HelpCircle, FileText, Trash2, ChevronRight } from 'lucide-react-native';
import { useAuth } from '@/hooks/use_auth';
import { router } from 'expo-router';
import { deleteAccount } from '@/services/accountService';
import * as WebBrowser from 'expo-web-browser';

export default function SettingsScreen() {
  const { user } = useAuth();
  const [notifications, setNotifications] = useState(true);
  const [autoSave, setAutoSave] = useState(true);
  const [highQuality, setHighQuality] = useState(true);

  const openContact = () => {
    WebBrowser.openBrowserAsync('https://www.remove.help/contact');
  };

  const openPrivacy = () => {
    WebBrowser.openBrowserAsync('https://www.remove.help/privacy');
  };

  const openTerms = () => {
    WebBrowser.openBrowserAsync('https://www.remove.help/terms');
  };

  const handleDeleteAccount = () => {
    Alert.alert(
      'Delete Account',
      'This action cannot be undone. All your data will be permanently deleted.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              const result = await deleteAccount();

              if (!result.success) {
                throw new Error(result.error);
              }

              Alert.alert(
                'Account Deleted',
                'Your account has been successfully deleted.',
                [
                  {
                    text: 'OK',
                    onPress: () => {
                      // Navigate to login or home screen
                      router.replace('/auth/login');
                    },
                  },
                ]
              );
            } catch (error) {
              Alert.alert(
                'Error',
                error instanceof Error ? error.message : 'Failed to delete account. Please try again.',
                [{ text: 'OK' }]
              );
            }
          },
        },
      ]
    );
  };

  const SettingItem = ({
    icon,
    title,
    subtitle,
    value,
    onToggle,
    onPress,
    showArrow = false,
    isSwitch = false,
    danger = false,
  }: {
    icon: React.ReactNode;
    title: string;
    subtitle?: string;
    value?: boolean;
    onToggle?: (value: boolean) => void;
    onPress?: () => void;
    showArrow?: boolean;
    isSwitch?: boolean;
    danger?: boolean;
  }) => (
    <TouchableOpacity
      style={styles.settingItem}
      onPress={onPress}
      disabled={isSwitch}
    >
      <View style={styles.settingLeft}>
        <View style={[styles.settingIcon, danger && styles.dangerIcon]}>
          {icon}
        </View>
        <View>
          <Text style={[styles.settingTitle, danger && styles.dangerText]}>
            {title}
          </Text>
          {subtitle && (
            <Text style={styles.settingSubtitle}>{subtitle}</Text>
          )}
        </View>
      </View>
      <View style={styles.settingRight}>
        {isSwitch && onToggle && (
          <Switch
            value={value}
            onValueChange={onToggle}
            trackColor={{ false: '#E5E7EB', true: '#facc15' }}
            thumbColor="#FFFFFF"
          />
        )}
        {showArrow && <ChevronRight size={20} color="#9CA3AF" />}
      </View>
    </TouchableOpacity>
  );

  if (!user) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.authRequired}>
          <Text style={styles.authTitle}>Authentication Required</Text>
          <Text style={styles.authSubtitle}>
            Please sign in to access settings
          </Text>
          <TouchableOpacity
            style={styles.authButton}
            onPress={() => router.push('/auth/login')}
          >
            <Text style={styles.authButtonText}>Sign In</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView showsVerticalScrollIndicator={false}>
        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.headerTitle}>Settings</Text>
        </View>

        {/* App Settings */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>App Settings</Text>
          
          <SettingItem
            icon={<Bell size={20} color="#6B7280" />}
            title="Notifications"
            subtitle="Get notified when processing is complete"
            value={notifications}
            onToggle={setNotifications}
            isSwitch
          />

          <SettingItem
            icon={<ImageIcon size={20} color="#6B7280" />}
            title="Auto Save"
            subtitle="Automatically save processed images"
            value={autoSave}
            onToggle={setAutoSave}
            isSwitch
          />

          <SettingItem
            icon={<ImageIcon size={20} color="#6B7280" />}
            title="High Quality"
            subtitle="Process images in highest quality"
            value={highQuality}
            onToggle={setHighQuality}
            isSwitch
          />
        </View>

        {/* Privacy & Security */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Privacy & Security</Text>
          
          <SettingItem
            icon={<Shield size={20} color="#6B7280" />}
            title="Privacy Policy"
            onPress={openPrivacy}
            showArrow
          />

          <SettingItem
            icon={<FileText size={20} color="#6B7280" />}
            title="Data Export"
            subtitle="Download your data"
            onPress={() => Alert.alert('Export', 'Data export started')}
            showArrow
          />
        </View>

        {/* Support */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Support</Text>
          
          <SettingItem
            icon={<HelpCircle size={20} color="#6B7280" />}
            title="Contact Us"
            subtitle="Get help or contact support"
            onPress={openContact}
            showArrow
          />

          <SettingItem
            icon={<FileText size={20} color="#6B7280" />}
            title="Terms of Service"
            onPress={openTerms}
            showArrow
          />

          <SettingItem
            icon={<FileText size={20} color="#6B7280" />}
            title="Privacy Policy"
            onPress={openPrivacy}
            showArrow
          />
        </View>

        {/* Danger Zone */}
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Danger Zone</Text>
          
          <SettingItem
            icon={<Trash2 size={20} color="#EF4444" />}
            title="Delete Account"
            subtitle="Permanently delete your account and data"
            onPress={handleDeleteAccount}
            showArrow
            danger
          />
        </View>

        {/* App Version */}
        <View style={styles.versionContainer}>
          <Text style={styles.versionText}>Remove.Help v1.0.0</Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
  },
  header: {
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
  },
  headerTitle: {
    fontSize: 28,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
  },
  section: {
    paddingHorizontal: 20,
    paddingTop: 24,
  },
  sectionTitle: {
    fontSize: 18,
    fontFamily: 'Inter-SemiBold',
    color: '#1F2937',
    marginBottom: 16,
  },
  settingItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
  },
  settingLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  settingIcon: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#F3F4F6',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12,
  },
  dangerIcon: {
    backgroundColor: '#FEE2E2',
  },
  settingTitle: {
    fontSize: 16,
    fontFamily: 'Inter-Medium',
    color: '#1F2937',
  },
  dangerText: {
    color: '#EF4444',
  },
  settingSubtitle: {
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    marginTop: 2,
  },
  settingRight: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  versionContainer: {
    alignItems: 'center',
    paddingVertical: 32,
  },
  versionText: {
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#9CA3AF',
  },
  authRequired: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 40,
  },
  authTitle: {
    fontSize: 24,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    marginBottom: 8,
  },
  authSubtitle: {
    fontSize: 16,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
    marginBottom: 24,
  },
  authButton: {
    backgroundColor: '#facc15',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 24,
  },
  authButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
});