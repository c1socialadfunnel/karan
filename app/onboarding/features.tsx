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

export default function OnboardingFeatures() {
  return (
    <SafeAreaView style={styles.container}>
      <LinearGradient
        colors={['#FFF5E6', '#FFFFFF']}
        style={styles.gradient}
      >
        <View style={styles.content}>
          {/* Feature Showcase */}
          <View style={styles.featureContainer}>
            <Text style={styles.featureTitle}>Remove Backgrounds{'\n'}Instantly</Text>
            
            {/* Before/After Example */}
            <View style={styles.beforeAfterContainer}>
              <View style={styles.imageContainer}>
                <Text style={styles.imageLabel}>Before</Text>
                <Image
                  source={{
                    uri: 'https://images.pexels.com/photos/774909/pexels-photo-774909.jpeg',
                  }}
                  style={styles.beforeImage}
                />
              </View>
              
              <View style={styles.arrow}>
                <Text style={styles.arrowText}>→</Text>
              </View>
              
              <View style={styles.imageContainer}>
                <Text style={styles.imageLabel}>After</Text>
                <View style={styles.afterImageContainer}>
                  <Image
                    source={require('../../assets/images/after.png')}
                    style={styles.afterImage}
                  />
                </View>
              </View>
            </View>

            <Text style={styles.subtitle}>
              Upload any image and get professional results in seconds with our advanced AI technology
            </Text>
          </View>

          {/* Navigation */}
          <View style={styles.navigation}>
            <View style={styles.pagination}>
              <View style={styles.dot} />
              <View style={[styles.dot, styles.activeDot]} />
              <View style={styles.dot} />
            </View>

            <View style={styles.buttonContainer}>
              <TouchableOpacity
                style={styles.backButton}
                onPress={() => router.back()}
              >
                <Text style={styles.backButtonText}>Back</Text>
              </TouchableOpacity>

              <TouchableOpacity
                style={styles.nextButton}
                onPress={() => router.push('/onboarding/welcome')}
              >
                <Text style={styles.nextButtonText}>Next</Text>
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
  featureContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  featureTitle: {
    fontSize: 32,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    textAlign: 'center',
    marginBottom: 40,
  },
  beforeAfterContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    width: '100%',
    marginBottom: 40,
  },
  imageContainer: {
    alignItems: 'center',
    flex: 1,
  },
  imageLabel: {
    fontSize: 14,
    fontFamily: 'Inter-Medium',
    color: '#6B7280',
    marginBottom: 12,
  },
  beforeImage: {
    width: width * 0.3,
    height: width * 0.3,
    borderRadius: 12,
  },
  arrow: {
    paddingHorizontal: 20,
  },
  arrowText: {
    fontSize: 24,
    color: '#FFA500',
    fontFamily: 'Inter-Bold',
  },
  afterImageContainer: {
    position: 'relative',
    width: width * 0.3,
    height: width * 0.3,
  },
  afterImage: {
    width: '100%',
    height: '100%',
    borderRadius: 12,
  },
  subtitle: {
    fontSize: 16,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
    lineHeight: 24,
    paddingHorizontal: 20,
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
    backgroundColor: '#FFA500',
    width: 24,
  },
  buttonContainer: {
    flexDirection: 'row',
    gap: 12,
  },
  backButton: {
    flex: 1,
    backgroundColor: '#F9FAFB',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#E5E7EB',
  },
  backButtonText: {
    color: '#6B7280',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
  nextButton: {
    flex: 1,
    backgroundColor: '#FFA500',
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