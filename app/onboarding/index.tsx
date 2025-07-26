import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Image,
  Dimensions,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { LinearGradient } from 'expo-linear-gradient';
import { router } from 'expo-router';

const { width } = Dimensions.get('window');

export default function OnboardingWelcome() {
  return (
    <SafeAreaView style={styles.container}>
      <LinearGradient
        colors={['#FFF5E6', '#FFFFFF']}
        style={styles.gradient}
      >
        <View style={styles.content}>
          {/* Hero Illustration */}
          <View style={styles.heroContainer}>
            <View style={styles.heroCircle}>
              <Image
                source={{
                  uri: 'https://images.pexels.com/photos/1040881/pexels-photo-1040881.jpeg',
                }}
                style={styles.heroImage}
              />
            </View>
          </View>

          {/* Content */}
          <View style={styles.textContainer}>
            <Text style={styles.title}>Welcome to Remove.Help</Text>
            <Text style={styles.subtitle}>
              AI-Powered Background Removal{'\n'}
              Remove backgrounds from any image instantly with professional results
            </Text>
          </View>

          {/* Navigation */}
          <View style={styles.navigation}>
            <View style={styles.pagination}>
              <View style={[styles.dot, styles.activeDot]} />
              <View style={styles.dot} />
              <View style={styles.dot} />
            </View>

            <TouchableOpacity
              style={styles.nextButton}
              onPress={() => router.push('/onboarding/features')}
            >
              <Text style={styles.nextButtonText}>Next</Text>
            </TouchableOpacity>
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
  },
  heroContainer: {
    alignItems: 'center',
    paddingVertical: 60, // Increased padding to compensate for removed logo
  },
  heroCircle: {
    width: width * 0.6,
    height: width * 0.6,
    borderRadius: (width * 0.6) / 2,
    backgroundColor: '#facc15',
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#facc15',
    shadowOffset: { width: 0, height: 10 },
    shadowOpacity: 0.3,
    shadowRadius: 20,
    elevation: 10,
  },
  heroImage: {
    width: width * 0.5,
    height: width * 0.5,
    borderRadius: (width * 0.5) / 2,
  },
  textContainer: {
    alignItems: 'center',
    paddingHorizontal: 20,
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
  nextButton: {
    backgroundColor: '#facc15',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
  },
  nextButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
});