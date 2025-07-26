import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Alert,
  Image,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import {
  User,
  Crown,
  Star,
  Calendar,
  Mail,
  Settings,
  CreditCard,
  LogOut,
} from 'lucide-react-native';
import { LinearGradient } from 'expo-linear-gradient';
import { useAuth } from '@/hooks/use_auth';
import { router } from 'expo-router';
import { supabase } from '@/lib/supabase';

export default function ProfileScreen() {
  const { user, signOut, refreshProfile } = useAuth();
  const [userStats, setUserStats] = useState({
    totalImages: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) {
      console.log('No user detected, attempting to redirect to login.');
      router.push('/auth/login');
      return;
    }
    console.log('User detected, loading user stats.');
    loadUserStats();
  }, [user]);

  const loadUserStats = async () => {
    try {
      // Get user's generated images count
      const { data: images } = await supabase
        .from('generated_images')
        .select('id')
        .eq('user_id', user?.id);
      
      setUserStats({
        totalImages: images?.length || 0,
      });
    } catch (error) {
      console.error('Error loading user stats:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = () => {
    Alert.alert(
      'Sign Out',
      'Are you sure you want to sign out?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Sign Out',
          style: 'destructive',
          onPress: () => {
            signOut();
            router.replace('/auth/login');
          },
        },
      ]
    );
  };

  const handleSubscription = () => {
    router.push('/subscription');
  };

  if (!user) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.authRequired}>
          <Text style={styles.authTitle}>Authentication Required</Text>
          <Text style={styles.authSubtitle}>
            Please sign in to view your profile
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
          <Text style={styles.headerTitle}>Profile</Text>
        </View>

        {/* Profile Card */}
        <View style={styles.profileCard}>
          <View style={styles.avatarContainer}>
            {user.photoURL ? (
              <Image source={{ uri: user.photoURL }} style={styles.avatar} />
            ) : (
              <View style={styles.avatarPlaceholder}>
                <User size={40} color="#6B7280" />
              </View>
            )}
            {user.isPro && (
              <View style={styles.crownBadge}>
                <Crown size={16} color="#FACC15" fill="#FACC15" />
              </View>
            )}
          </View>

          <Text style={styles.userName}>{user.displayName || 'User'}</Text>
          <Text style={styles.userEmail}>{user.email}</Text>

          {user.isPro ? (
            <LinearGradient
              colors={['#FACC15', '#FF8C00']}
              style={styles.proStatusBadge}
            >
              <Crown size={16} color="#FFFFFF" />
              <Text style={styles.proStatusText}>Pro Member</Text>
            </LinearGradient>
          ) : (
            <TouchableOpacity
              style={styles.upgradeButton}
              onPress={handleSubscription}
            >
              <Text style={styles.upgradeButtonText}>Upgrade to Pro</Text>
            </TouchableOpacity>
          )}
        </View>

        {/* Stats */}
        <View style={styles.statsContainer}>
          <View style={styles.statCard}>
            <Text style={styles.statNumber}>{userStats.totalImages}</Text>
            <Text style={styles.statLabel}>Images Created</Text>
          </View>
          <View style={styles.statCard}>
            <Text style={styles.statNumber}>{user?.credits || 0}</Text>
            <Text style={styles.statLabel}>Credits Left</Text>
          </View>
        </View>

        {/* Menu Items */}
        <View style={styles.menuContainer}>
          <TouchableOpacity style={styles.menuItem}>
            <View style={styles.menuItemLeft}>
              <Mail size={20} color="#6B7280" />
              <Text style={styles.menuItemText}>Email</Text>
            </View>
            <Text style={styles.menuItemValue}>{user.email}</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.menuItem}
            onPress={handleSubscription}
          >
            <View style={styles.menuItemLeft}>
              <CreditCard size={20} color="#6B7280" />
              <Text style={styles.menuItemText}>Subscription</Text>
            </View>
            <Text style={styles.menuItemValue}>
              {user.isPro ? 'Pro' : 'Free'}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.menuItem}
            onPress={() => router.push('/(tabs)/settings')}
          >
            <View style={styles.menuItemLeft}>
              <Settings size={20} color="#6B7280" />
              <Text style={styles.menuItemText}>Settings</Text>
            </View>
          </TouchableOpacity>
        </View>

        {/* Sign Out */}
        <TouchableOpacity style={styles.signOutButton} onPress={handleSignOut}>
          <LogOut size={20} color="#EF4444" />
          <Text style={styles.signOutText}>Sign Out</Text>
        </TouchableOpacity>
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
  profileCard: {
    alignItems: 'center',
    paddingVertical: 32,
    paddingHorizontal: 20,
  },
  avatarContainer: {
    position: 'relative',
    marginBottom: 16,
  },
  avatar: {
    width: 80,
    height: 80,
    borderRadius: 40,
  },
  avatarPlaceholder: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: '#F3F4F6',
    justifyContent: 'center',
    alignItems: 'center',
  },
  crownBadge: {
    position: 'absolute',
    top: -4,
    right: -4,
    width: 24,
    height: 24,
    borderRadius: 12,
    backgroundColor: '#FFF5E6',
    justifyContent: 'center',
    alignItems: 'center',
    borderWidth: 2,
    borderColor: '#FFFFFF',
  },
  userName: {
    fontSize: 24,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    marginBottom: 4,
  },
  userEmail: {
    fontSize: 16,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    marginBottom: 16,
  },
  proStatusBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    gap: 6,
  },
  proStatusText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontFamily: 'Inter-Medium',
  },
  upgradeButton: {
    backgroundColor: '#FACC15',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 24,
  },
  upgradeButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
  statsContainer: {
    flexDirection: 'row',
    paddingHorizontal: 20,
    gap: 20,
    marginBottom: 32,
  },
  statCard: {
    flex: 1,
    backgroundColor: '#F9FAFB',
    paddingVertical: 20,
    paddingHorizontal: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  statNumber: {
    fontSize: 24,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    marginBottom: 4,
  },
  statLabel: {
    fontSize: 12,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
  },
  menuContainer: {
    paddingHorizontal: 20,
    marginBottom: 32,
  },
  menuItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
  },
  menuItemLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  menuItemText: {
    fontSize: 16,
    fontFamily: 'Inter-Regular',
    color: '#1F2937',
  },
  menuItemValue: {
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
  },
  signOutButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginHorizontal: 20,
    paddingVertical: 16,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: '#FEE2E2',
    backgroundColor: '#FEF2F2',
    gap: 8,
    marginBottom: 32,
  },
  signOutText: {
    color: '#EF4444',
    fontSize: 16,
    fontFamily: 'Inter-Medium',
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
    backgroundColor: '#FACC15',
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