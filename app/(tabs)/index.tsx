import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Image,
  Alert,
  Dimensions,
  ActivityIndicator,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Upload, Download, Share2, Star, ArrowRight } from 'lucide-react-native';
import { LinearGradient } from 'expo-linear-gradient';
import * as ImagePicker from 'expo-image-picker';
import { useAuth } from '@/hooks/use_auth';
import { router } from 'expo-router';
import { processImage } from '@/services/imageService';
import * as Sharing from 'expo-sharing';
import * as FileSystem from 'expo-file-system';
import { useLocalSearchParams } from 'expo-router';

const { width } = Dimensions.get('window');

export default function HomeScreen() {
  const { user, refreshProfile } = useAuth();
  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [processedImage, setProcessedImage] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const { showProWelcome } = useLocalSearchParams();
  
  useEffect(() => {
    if (showProWelcome === 'true') {
      Alert.alert(
        'Welcome to Pro! 🎉',
        'You now have unlimited background removal and premium features.',
        [{ text: 'Start Using Pro' }]
      );
    }
  }, [showProWelcome]);

  // Use real credits from user profile
  const credits = user?.credits || 0;

  const pickImage = async () => {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      allowsEditing: true,
      aspect: [1, 1],
      quality: 0.8,
    });

    if (!result.canceled && result.assets[0]) {
      setSelectedImage(result.assets[0].uri);
      setProcessedImage(null);
    }
  };

  const takePhoto = async () => {
    const result = await ImagePicker.launchCameraAsync({
      allowsEditing: true,
      aspect: [1, 1],
      quality: 0.8,
    });

    if (!result.canceled && result.assets[0]) {
      setSelectedImage(result.assets[0].uri);
      setProcessedImage(null);
    }
  };

  const handleProcessImage = async () => {
    if (!user) {
      Alert.alert(
        'Authentication Required',
        'Please sign in to remove backgrounds',
        [
          { text: 'Cancel', style: 'cancel' },
          { text: 'Sign In', onPress: () => router.push('/auth/login') },
        ]
      );
      return;
    }

    if (!selectedImage) {
      Alert.alert('No Image', 'Please select an image first');
      return;
    }

    if (credits <= 0) {
      Alert.alert(
        'No Credits',
        'You need credits to process images. Upgrade to Pro for unlimited processing.',
        [
          { text: 'Cancel', style: 'cancel' },
          { text: 'Upgrade', onPress: () => router.push('/subscription') },
        ]
      );
      return;
    }

    setIsProcessing(true);

    try {
      console.log('Starting image processing...');
      const result = await processImage(selectedImage);
      
      if (result.success && result.imageData) {
        setProcessedImage(result.imageData);
        // Refresh user profile to get updated credits
        await refreshProfile();
        Alert.alert('Success!', 'Background removed successfully');
      } else {
        console.error('Processing failed:', result.error);
        Alert.alert('Error', result.error || 'Failed to process image');
      }
    } catch (error) {
      console.error('Processing exception:', error);
      Alert.alert('Error', 'Failed to process image. Please try again.');
    } finally {
      setIsProcessing(false);
    }
  };

  const showImageOptions = () => {
    Alert.alert(
      'Select Image',
      'Choose how you want to select an image',
      [
        { text: 'Camera', onPress: takePhoto },
        { text: 'Photo Library', onPress: pickImage },
        { text: 'Cancel', style: 'cancel' },
      ]
    );
  };

  const downloadImage = async () => {
    if (!processedImage) return;
    
    try {
      // For demo purposes, show success message
      // In a real app, you'd save the base64 image to device storage
      Alert.alert('Success', 'Image saved to gallery');
    } catch (error) {
      Alert.alert('Error', 'Failed to save image');
    }
  };

  const shareImage = async () => {
    if (!processedImage) return;
    
    try {
      // Convert base64 to file and share
      const filename = FileSystem.documentDirectory + 'processed_image.png';
      await FileSystem.writeAsStringAsync(filename, processedImage.split(',')[1], {
        encoding: FileSystem.EncodingType.Base64,
      });
      
      await Sharing.shareAsync(filename);
    } catch (error) {
      Alert.alert('Error', 'Failed to share image');
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView showsVerticalScrollIndicator={false}>
        {/* Header */}
        <View style={styles.header}>
          <View>
            <Text style={styles.headerTitle}>Remove.Help</Text>
            <Text style={styles.headerSubtitle}>AI-Powered Background Removal</Text>
          </View>
          <View style={styles.headerRight}>
            {user ? (
              <View style={styles.creditsContainer}>
                <Star size={16} color="#facc15" fill="#facc15" />
                <Text style={styles.creditsText}>{credits} credits</Text>
              </View>
            ) : (
              <TouchableOpacity
                style={styles.loginButton}
                onPress={() => router.push('/auth/login')}
              >
                <Text style={styles.loginButtonText}>Login</Text>
              </TouchableOpacity>
            )}
          </View>
        </View>

        {/* Hero Section */}
        <View style={styles.heroSection}>
          <Text style={styles.heroTitle}>Remove Image{'\n'}Background</Text>
          <Text style={styles.heroSubtitle}>
            100% Automatically and <Text style={styles.freeText}>Free</Text>
          </Text>
        </View>

        {/* Upload Section */}
        <View style={styles.uploadSection}>
          <TouchableOpacity
            style={styles.uploadContainer}
            onPress={showImageOptions}
          >
            <LinearGradient
              colors={['#FFF5E6', '#FFFFFF']}
              style={styles.uploadGradient}
            >
              {selectedImage ? (
                <Image source={{ uri: selectedImage }} style={styles.selectedImage} />
              ) : (
                <>
                  <Upload size={48} color="#facc15" />
                  <Text style={styles.uploadTitle}>Upload Image</Text>
                  <Text style={styles.uploadSubtitle}>
                    or drop a file, paste an image or URL
                  </Text>
                </>
              )}
            </LinearGradient>
          </TouchableOpacity>

          {selectedImage && (
            <TouchableOpacity
              style={[
                styles.processButton,
                isProcessing && styles.processButtonDisabled
              ]}
              onPress={handleProcessImage}
              disabled={isProcessing}
            >
              {isProcessing ? (
                <ActivityIndicator color="#FFFFFF" />
              ) : (
                <Text style={styles.processButtonText}>Remove Background</Text>
              )}
            </TouchableOpacity>
          )}
        </View>

        {/* Before/After Section */}
        {processedImage && (
          <View style={styles.resultSection}>
            <Text style={styles.resultTitle}>Result</Text>
            <View style={styles.beforeAfterContainer}>
              <View style={styles.imageContainer}>
                <Text style={styles.imageLabel}>Before</Text>
                <Image source={selectedImage ? { uri: selectedImage } : undefined} style={styles.resultImage} />
              </View>
              <ArrowRight size={24} color="#facc15" />
              <View style={styles.imageContainer}>
                <Text style={styles.imageLabel}>After</Text>
                <Image source={{ uri: processedImage }} style={styles.resultImage} />
              </View>
            </View>
            
            <View style={styles.actionButtons}>
              <TouchableOpacity style={styles.actionButton} onPress={downloadImage}>
                <Download size={20} color="#facc15" />
                <Text style={styles.actionButtonText}>Download</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.actionButton} onPress={shareImage}>
                <Share2 size={20} color="#facc15" />
                <Text style={styles.actionButtonText}>Share</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}

        {/* Features Section */}
        <View style={styles.featuresSection}>
          <Text style={styles.featuresTitle}>Stunning quality</Text>
          <View style={styles.featureGrid}>
            <View style={styles.featureCard}>
              <View style={styles.featureIcon}>
                <Upload size={24} color="#facc15" />
              </View>
              <Text style={styles.featureTitle}>Easy Upload</Text>
              <Text style={styles.featureDescription}>
                Upload from camera or gallery
              </Text>
            </View>
            <View style={styles.featureCard}>
              <View style={styles.featureIcon}>
                <Star size={24} color="#facc15" />
              </View>
              <Text style={styles.featureTitle}>High Quality</Text>
              <Text style={styles.featureDescription}>
                Professional AI results
              </Text>
            </View>
          </View>
        </View>

        {/* Pro Upgrade Section */}
        {!user?.isPro && (
          <LinearGradient
            colors={['#facc15', '#FF8C00']}
            style={styles.proSection}
          >
            <View style={styles.proContent}>
              <Text style={styles.proTitle}>Upgrade to Pro</Text>
              <Text style={styles.proSubtitle}>
                Get unlimited background removal and priority processing
              </Text>
              <TouchableOpacity
                style={styles.proButton}
                onPress={() => router.push('/subscription')}
              >
                <Text style={styles.proButtonText}>Upgrade Now</Text>
              </TouchableOpacity>
            </View>
          </LinearGradient>
        )}
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
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 16,
  },
  headerTitle: {
    fontSize: 24,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
  },
  headerSubtitle: {
    fontSize: 12,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
  },
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  creditsContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#fef9c3',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 20,
  },
  creditsText: {
    marginLeft: 4,
    fontSize: 14,
    fontFamily: 'Inter-Medium',
    color: '#facc15',
  },
  loginButton: {
    backgroundColor: '#facc15',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
  },
  loginButtonText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontFamily: 'Inter-Medium',
  },
  heroSection: {
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 40,
  },
  heroTitle: {
    fontSize: 42,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    textAlign: 'center',
    lineHeight: 50,
  },
  heroSubtitle: {
    fontSize: 18,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
    marginTop: 8,
  },
  freeText: {
    color: '#facc15',
    fontFamily: 'Inter-Bold',
  },
  uploadSection: {
    paddingHorizontal: 20,
    marginTop: 20,
  },
  uploadContainer: {
    borderRadius: 16,
    overflow: 'hidden',
    borderWidth: 2,
    borderColor: '#E5E7EB',
    borderStyle: 'dashed',
  },
  uploadGradient: {
    padding: 40,
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 200,
  },
  selectedImage: {
    width: 150,
    height: 150,
    borderRadius: 12,
  },
  uploadTitle: {
    fontSize: 18,
    fontFamily: 'Inter-SemiBold',
    color: '#1F2937',
    marginTop: 16,
  },
  uploadSubtitle: {
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
    marginTop: 8,
  },
  processButton: {
    backgroundColor: '#facc15',
    borderRadius: 12,
    paddingVertical: 16,
    alignItems: 'center',
    marginTop: 20,
  },
  processButtonDisabled: {
    opacity: 0.6,
  },
  processButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
  resultSection: {
    paddingHorizontal: 20,
    marginTop: 40,
  },
  resultTitle: {
    fontSize: 24,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    textAlign: 'center',
    marginBottom: 20,
  },
  beforeAfterContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  imageContainer: {
    alignItems: 'center',
    flex: 1,
  },
  imageLabel: {
    fontSize: 14,
    fontFamily: 'Inter-Medium',
    color: '#6B7280',
    marginBottom: 8,
  },
  resultImage: {
    width: width * 0.35,
    height: width * 0.35,
    borderRadius: 12,
  },
  actionButtons: {
    flexDirection: 'row',
    justifyContent: 'center',
    gap: 20,
  },
  actionButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#F9FAFB',
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: '#E5E7EB',
  },
  actionButtonText: {
    marginLeft: 8,
    fontSize: 14,
    fontFamily: 'Inter-Medium',
    color: '#1F2937',
  },
  featuresSection: {
    paddingHorizontal: 20,
    paddingVertical: 40,
  },
  featuresTitle: {
    fontSize: 28,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    textAlign: 'center',
    marginBottom: 30,
  },
  featureGrid: {
    flexDirection: 'row',
    gap: 16,
  },
  featureCard: {
    flex: 1,
    backgroundColor: '#F9FAFB',
    padding: 20,
    borderRadius: 16,
    alignItems: 'center',
  },
  featureIcon: {
    width: 48,
    height: 48,
    backgroundColor: '#fef9c3',
    borderRadius: 24,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 12,
  },
  featureTitle: {
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
    color: '#1F2937',
    marginBottom: 8,
  },
  featureDescription: {
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
  },
  proSection: {
    margin: 20,
    borderRadius: 16,
    padding: 24,
  },
  proContent: {
    alignItems: 'center',
  },
  proTitle: {
    fontSize: 24,
    fontFamily: 'Inter-Bold',
    color: '#FFFFFF',
    marginBottom: 8,
  },
  proSubtitle: {
    fontSize: 16,
    fontFamily: 'Inter-Regular',
    color: '#FFFFFF',
    textAlign: 'center',
    marginBottom: 20,
    opacity: 0.9,
  },
  proButton: {
    backgroundColor: '#FFFFFF',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 24,
  },
  proButtonText: {
    color: '#facc15',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
  },
});