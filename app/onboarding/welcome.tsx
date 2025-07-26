import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Dimensions,
  Image,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { LinearGradient } from 'expo-linear-gradient';
import { Star, Zap, Shield } from 'lucide-react-native';
import { router } from 'expo-router';
import AsyncStorage from '@react-native-async-storage/async-storage';

const { width } = Dimensions.get('window');

export default function OnboardingWelcome() {
  return (
    <SafeAreaView style={styles.container}>
      <LinearGradient
        colors={['#FFF5E6', '#FFFFFF']}
        style={styles.gradient}
      >
        <View style={styles.content}>
          {/* Header */}
          <View style={styles.header}>
            <Text style={styles.title}>Ready to Get{'\n'}Started?</Text>
            <Text style={styles.subtitle}>
              Sign up for free and get 5 credits to start removing backgrounds instantly
            </Text>
          </View>

          {/* Features */}
          <View style={styles.featuresContainer}>
            <View style={styles.feature}>
              <View style={styles.featureIcon}>
                <Star size={24} color="#facc15" />
              </View>
              <Text style={styles.featureText}>5 free credits to start</Text>
            </View>

            <View style={styles.feature}>
              <View style={styles.featureIcon}>
                <Zap size={24} color="#facc15" />
              </View>
              <Text style={styles.featureText}>Lightning fast processing</Text>
            </View>

            <View style={styles.feature}>
              <View style={styles.featureIcon}>
                <Shield size={24} color="#facc15" />
              </View>
              <Text style={styles.featureText}>Your images stay private</Text>
            </View>
          </View>

          {/* Illustration */}
          <View style={styles.illustrationContainer}>
            <LinearGradient
              colors={['#facc15', '#facc15']}
              style={styles.illustration}
            >
              <Image
                source={require('../../assets/images/icon.png')}
                style={styles.logoImage}
                resizeMode="contain"
              />
            </LinearGradient>
          </View>

          {/* Navigation */}
          <View style={styles.navigation}>
            <View style={styles.pagination}>
              <View style={styles.dot} />
              <View style={styles.dot} />
              <View style={[styles.dot, styles.activeDot]} />
            </View>

            <View style={styles.buttonContainer}>
              <TouchableOpacity
                style={styles.skipButton}
                onPress={async () => {
                  try {
                    await AsyncStorage.setItem('hasSeenOnboarding', 'true');
                    router.replace('/(tabs)');
                  } catch (error) {
                    console.error('Error saving onboarding status:', error);
                    router.replace('/(tabs)');
                  }
                }}
              >
                <Text style={styles.skipButtonText}>Skip</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={styles.getStartedButton}
                onPress={async () => {
                  try {
                    await AsyncStorage.setItem('hasSeenOnboarding', 'true');
                    router.replace('/(tabs)');
                  } catch (error) {
                    console.error('Error saving onboarding status:', error);
                    router.replace('/(tabs)');
                  }
                }}
              >
                <Text style={styles.getStartedButtonText}>Get Started</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </LinearGradient>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  gradient: {
    flex: 1,
  },
  content: {
    flex: 1,
    paddingHorizontal: 20,
    justifyContent: 'space-between',
    paddingTop: 60,
  },
  header: {
    alignItems: 'center',
    paddingTop: 20,
  },
  title: {
    fontSize: 32,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    textAlign: 'center',
    marginBottom: 16,
  },
  subtitle: {
    fontSize: 16,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
    lineHeight: 24,
    paddingHorizontal: 20,
  },
  featuresContainer: {
    paddingVertical: 40,
  },
  feature: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 20,
    paddingHorizontal: 20,
  },
  featureIcon: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#fef9c3',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 16,
  },
  featureText: {
    fontSize: 16,
    fontFamily: 'Inter-Medium',
    color: '#1F2937',
  },
  illustrationContainer: {
    alignItems: 'center',
    paddingVertical: 20,
  },
  illustration: {
    width: width * 0.4,
    height: width * 0.4,
    borderRadius: (width * 0.4) / 2,
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#facc15',
    shadowOffset: { width: 0, height: 10 },
    shadowOpacity: 0.3,
    shadowRadius: 20,
    elevation: 10,
  },
  logoImage: {
    width: width * 0.25,
    height: width * 0.25,
  },
  navigation: {
    paddingBottom: 40,
  },
  pagination: {
    flexDirection: 'row',
    justifyContent: 'center',
    marginBottom: 32,
    gap: 8,
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: '#E5E7EB',
  },
  activeDot: {
    backgroundColor: '#facc15',
    width: 24,
  },
  buttonContainer: {
    flexDirection: 'row',
    gap: 12,
  },
  skipButton: {
    flex: 1,
    backgroundColor: '#F9FAFB',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#E5E7EB',
  },
  skipButtonText: {
    color: '#6B7280',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
  getStartedButton: {
    flex: 2,
    backgroundColor: '#facc15',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  getStartedButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
});