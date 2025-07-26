import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Alert,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Crown, Check, X, ArrowLeft } from 'lucide-react-native';
import { LinearGradient } from 'expo-linear-gradient';
import { router } from 'expo-router';
import { useAuth } from '@/hooks/use_auth';
import * as WebBrowser from 'expo-web-browser';
import * as Linking from 'expo-linking';
import { supabase } from '@/lib/supabase'; // adjust import if needed

export default function SubscriptionScreen() {
  const { user } = useAuth();
  const [loading, setLoading] = useState(false);

  const handleUpgrade = async () => {
    setLoading(true);
    try {
      // Get the current session/access token
      const { data: { session } } = await supabase.auth.getSession();
      const accessToken = session?.access_token;

      if (!accessToken) {
        Alert.alert('Authentication Required', 'Please sign in to upgrade.');
        setLoading(false);
        return;
      }

      // Call your Supabase Edge Function to create a Stripe Checkout session
      const response = await fetch('https://kpzpsljkpvalemxgzsis.supabase.co/functions/v1/stripe-checkout?platform=mobile', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });

      const data = await response.json();

      if (data.checkout_url) {
        // Use your app's custom URL scheme for the redirect
        const redirectUrl = 'myapp://payment-return';
        const result = await WebBrowser.openAuthSessionAsync(
          data.checkout_url,
          redirectUrl,
          {
            showInRecents: true,
            dismissButtonStyle: 'close'
          }
        );
        
        if (result.type === 'success') {
          // Wait a moment for webhook to process
          await new Promise(resolve => setTimeout(resolve, 1000));
          
          // Refresh the user's session to get updated pro status
          const { data: { user: updatedUser }, error } = await supabase.auth.refreshSession();
          
          if (!error && updatedUser) {
            // Show success message
            Alert.alert(
              'Welcome to Pro! 🎉',
              'You now have unlimited background removal and premium features.',
              [
                {
                  text: 'Start Using Pro',
                  onPress: () => {
                    // Navigate back to home screen or profile
                    router.replace('/(tabs)');
                  },
                },
              ]
            );
          }
        } else if (result.type === 'cancel') {
          // User cancelled the payment
          Alert.alert('Payment Cancelled', 'You can upgrade to Pro anytime.');
        }
      } else {
        Alert.alert('Error', data.error || 'Failed to start checkout. Please try again.');
      }
    } catch (error) {
      Alert.alert('Error', 'Failed to process payment. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const features = [
    { name: 'Background Removal', free: '5 per month', pro: 'Unlimited' },
    { name: 'High Quality Processing', free: false, pro: true },
    { name: 'Priority Processing', free: false, pro: true },
    { name: 'Batch Processing', free: false, pro: true },
    { name: 'Advanced Editing Tools', free: false, pro: true },
    { name: 'Cloud Storage', free: '100MB', pro: '10GB' },
    { name: 'Customer Support', free: 'Email', pro: 'Priority' },
  ];

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView showsVerticalScrollIndicator={false}>
        {/* Header */}
        <View style={styles.header}>
          <TouchableOpacity style={styles.backButton} onPress={() => router.back()}>
            <ArrowLeft size={24} color="#1F2937" />
          </TouchableOpacity>
          <Text style={styles.headerTitle}>Upgrade to Pro</Text>
          <View style={styles.headerRight} />
        </View>

        {/* Hero Section */}
        <LinearGradient
          colors={['#FFA500', '#FF8C00']}
          style={styles.heroSection}
        >
          <Crown size={48} color="#FFFFFF" />
          <Text style={styles.heroTitle}>Unlock the Full Power</Text>
          <Text style={styles.heroSubtitle}>
            Get unlimited background removal and premium features
          </Text>
        </LinearGradient>

        {/* Pricing */}
        <View style={styles.pricingSection}>
          <View style={styles.priceContainer}>
            <Text style={styles.price}>$4.99</Text>
            <Text style={styles.pricePeriod}>/month</Text>
          </View>
          <Text style={styles.priceDescription}>
            Cancel anytime • No hidden fees
          </Text>
        </View>

        {/* Features Comparison */}
        <View style={styles.featuresSection}>
          <Text style={styles.featuresTitle}>What's Included</Text>
          
          <View style={styles.comparisonTable}>
            <View style={styles.tableHeader}>
              <Text style={styles.featureColumnHeader}>Features</Text>
              <Text style={styles.planColumnHeader}>Free</Text>
              <Text style={styles.planColumnHeader}>Pro</Text>
            </View>

            {features.map((feature, index) => (
              <View key={index} style={styles.featureRow}>
                <Text style={styles.featureName}>{feature.name}</Text>
                
                <View style={styles.featureValue}>
                  {typeof feature.free === 'string' ? (
                    <Text style={styles.featureValueText}>{feature.free}</Text>
                  ) : feature.free ? (
                    <Check size={16} color="#10B981" />
                  ) : (
                    <X size={16} color="#EF4444" />
                  )}
                </View>
                
                <View style={styles.featureValue}>
                  {typeof feature.pro === 'string' ? (
                    <Text style={[styles.featureValueText, styles.proValue]}>
                      {feature.pro}
                    </Text>
                  ) : feature.pro ? (
                    <Check size={16} color="#FFA500" />
                  ) : (
                    <X size={16} color="#EF4444" />
                  )}
                </View>
              </View>
            ))}
          </View>
        </View>

        {/* Current Plan */}
        {user?.isPro && (
          <View style={styles.currentPlanSection}>
            <LinearGradient
              colors={['#10B981', '#059669']}
              style={styles.currentPlanBadge}
            >
              <Crown size={20} color="#FFFFFF" />
              <Text style={styles.currentPlanText}>Current Plan: Pro</Text>
            </LinearGradient>
            
            <TouchableOpacity style={styles.managePlanButton}>
              <Text style={styles.managePlanButtonText}>Manage Subscription</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* Upgrade Button */}
        {!user?.isPro && (
          <View style={styles.upgradeSection}>
            <TouchableOpacity
              style={[styles.upgradeButton, loading && styles.upgradeButtonDisabled]}
              onPress={handleUpgrade}
              disabled={loading}
            >
              <LinearGradient
                colors={['#FFA500', '#FF8C00']}
                style={styles.upgradeGradient}
              >
                <Crown size={20} color="#FFFFFF" />
                <Text style={styles.upgradeButtonText}>
                  {loading ? 'Processing...' : 'Upgrade for $4.99/month'}
                </Text>
              </LinearGradient>
            </TouchableOpacity>
            {/* Removed free trial disclaimer */}
          </View>
        )}

        {/* Benefits */}
        <View style={styles.benefitsSection}>
          <Text style={styles.benefitsTitle}>Why Upgrade?</Text>
          
          <View style={styles.benefit}>
            <View style={styles.benefitIcon}>
              <Check size={20} color="#FFA500" />
            </View>
            <View style={styles.benefitContent}>
              <Text style={styles.benefitTitle}>Unlimited Processing</Text>
              <Text style={styles.benefitDescription}>
                Remove backgrounds from unlimited images every month
              </Text>
            </View>
          </View>

          <View style={styles.benefit}>
            <View style={styles.benefitIcon}>
              <Check size={20} color="#FFA500" />
            </View>
            <View style={styles.benefitContent}>
              <Text style={styles.benefitTitle}>Premium Quality</Text>
              <Text style={styles.benefitDescription}>
                Higher resolution outputs with better edge detection
              </Text>
            </View>
          </View>

          <View style={styles.benefit}>
            <View style={styles.benefitIcon}>
              <Check size={20} color="#FFA500" />
            </View>
            <View style={styles.benefitContent}>
              <Text style={styles.benefitTitle}>Priority Support</Text>
              <Text style={styles.benefitDescription}>
                Get help faster with dedicated customer support
              </Text>
            </View>
          </View>
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
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#F3F4F6',
  },
  backButton: {
    padding: 4,
  },
  headerTitle: {
    fontSize: 18,
    fontFamily: 'Inter-SemiBold',
    color: '#1F2937',
  },
  headerRight: {
    width: 32,
  },
  heroSection: {
    alignItems: 'center',
    paddingVertical: 40,
    paddingHorizontal: 20,
    margin: 20,
    borderRadius: 16,
  },
  heroTitle: {
    fontSize: 24,
    fontFamily: 'Inter-Bold',
    color: '#FFFFFF',
    marginTop: 16,
    marginBottom: 8,
  },
  heroSubtitle: {
    fontSize: 16,
    fontFamily: 'Inter-Regular',
    color: '#FFFFFF',
    textAlign: 'center',
    opacity: 0.9,
  },
  pricingSection: {
    alignItems: 'center',
    paddingHorizontal: 20,
    marginBottom: 32,
  },
  priceContainer: {
    flexDirection: 'row',
    alignItems: 'baseline',
    marginBottom: 8,
  },
  price: {
    fontSize: 48,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
  },
  pricePeriod: {
    fontSize: 18,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    marginLeft: 4,
  },
  priceDescription: {
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
  },
  featuresSection: {
    paddingHorizontal: 20,
    marginBottom: 32,
  },
  featuresTitle: {
    fontSize: 20,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    marginBottom: 20,
    textAlign: 'center',
  },
  comparisonTable: {
    backgroundColor: '#F9FAFB',
    borderRadius: 12,
    overflow: 'hidden',
  },
  tableHeader: {
    flexDirection: 'row',
    backgroundColor: '#F3F4F6',
    paddingVertical: 12,
    paddingHorizontal: 16,
  },
  featureColumnHeader: {
    flex: 2,
    fontSize: 14,
    fontFamily: 'Inter-SemiBold',
    color: '#1F2937',
  },
  planColumnHeader: {
    flex: 1,
    fontSize: 14,
    fontFamily: 'Inter-SemiBold',
    color: '#1F2937',
    textAlign: 'center',
  },
  featureRow: {
    flexDirection: 'row',
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#E5E7EB',
  },
  featureName: {
    flex: 2,
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#1F2937',
  },
  featureValue: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  featureValueText: {
    fontSize: 12,
    fontFamily: 'Inter-Medium',
    color: '#6B7280',
    textAlign: 'center',
  },
  proValue: {
    color: '#FFA500',
  },
  currentPlanSection: {
    paddingHorizontal: 20,
    marginBottom: 32,
    alignItems: 'center',
  },
  currentPlanBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    marginBottom: 16,
    gap: 6,
  },
  currentPlanText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontFamily: 'Inter-SemiBold',
  },
  managePlanButton: {
    backgroundColor: '#F9FAFB',
    borderWidth: 1,
    borderColor: '#E5E7EB',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 24,
  },
  managePlanButtonText: {
    color: '#1F2937',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
  upgradeSection: {
    paddingHorizontal: 20,
    marginBottom: 32,
  },
  upgradeButton: {
    borderRadius: 12,
    overflow: 'hidden',
    marginBottom: 12,
  },
  upgradeButtonDisabled: {
    opacity: 0.6,
  },
  upgradeGradient: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 16,
    gap: 8,
  },
  upgradeButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
  upgradeDisclaimer: {
    fontSize: 12,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
    lineHeight: 18,
  },
  benefitsSection: {
    paddingHorizontal: 20,
    paddingBottom: 40,
  },
  benefitsTitle: {
    fontSize: 20,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    marginBottom: 20,
    textAlign: 'center',
  },
  benefit: {
    flexDirection: 'row',
    marginBottom: 20,
  },
  benefitIcon: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#fef9c3',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 16,
  },
  benefitContent: {
    flex: 1,
  },
  benefitTitle: {
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
    color: '#1F2937',
    marginBottom: 4,
  },
  benefitDescription: {
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    lineHeight: 20,
  },
});