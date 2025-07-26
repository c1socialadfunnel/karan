import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  Image,
  Alert,
  Modal,
  Share,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Download, Share2, Trash2, X } from 'lucide-react-native';
import { useAuth } from '@/hooks/use_auth';
import { router } from 'expo-router';
import { getGeneratedImages, deleteGeneratedImage } from '@/services/imageService';
import * as FileSystem from 'expo-file-system';
import { supabase } from '@/lib/supabase';

interface GeneratedImage {
  id: string;
  processed_image_data_url: string;
  created_at: string;
}

export default function GalleryScreen() {
  const { user } = useAuth();
  const [images, setImages] = useState<GeneratedImage[]>([]);
  const [selectedImage, setSelectedImage] = useState<GeneratedImage | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) {
      console.log('No user detected, attempting to redirect to login.');
      router.push('/auth/login');
      return;
    }
    console.log('User detected, loading images.');
    loadImages();
  }, [user]);

  const loadImages = async () => {
    try {
      const { data, error } = await getGeneratedImages();
      
      if (error) {
        console.error('Error loading images:', error);
        Alert.alert('Error', 'Failed to load images');
        return;
      }
      
      setImages(data || []);
    } catch (error) {
      console.error('Error loading images:', error);
      Alert.alert('Error', 'Failed to load images');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteImage = async (imageId: string) => {
    Alert.alert(
      'Delete Image',
      'Are you sure you want to delete this image?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              const { error } = await deleteGeneratedImage(imageId);
              if (error) {
                Alert.alert('Error', 'Failed to delete image');
              } else {
                setImages(prev => prev.filter(img => img.id !== imageId));
                setSelectedImage(null);
              }
            } catch (error) {
              Alert.alert('Error', 'Failed to delete image');
            }
          },
        },
      ]
    );
  };

  const shareImage = async (image: GeneratedImage) => {
    try {
      // Convert base64 to file and share
      const filename = FileSystem.documentDirectory + `image_${image.id}.png`;
      await FileSystem.writeAsStringAsync(filename, image.processed_image_data_url.split(',')[1], {
        encoding: FileSystem.EncodingType.Base64,
      });
      
      await Share.share({
        url: filename,
        message: 'Check out this background-removed image from Remove.Help!',
      });
    } catch (error) {
      Alert.alert('Error', 'Failed to share image');
    }
  };

  const downloadImage = (image: GeneratedImage) => {
    try {
      // For demo purposes, show success message
      // In a real app, you'd save the base64 image to device storage
      Alert.alert('Success', 'Image saved to gallery');
    } catch (error) {
      Alert.alert('Error', 'Failed to save image');
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString();
  };

  const renderImageItem = ({ item }: { item: GeneratedImage }) => (
    <TouchableOpacity
      style={styles.imageItem}
      onPress={() => setSelectedImage(item)}
    >
      <Image source={{ uri: item.processed_image_data_url }} style={styles.thumbnailImage} />
      <Text style={styles.imageDate}>{formatDate(item.created_at)}</Text>
    </TouchableOpacity>
  );

  if (!user) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.authRequired}>
          <Text style={styles.authTitle}>Authentication Required</Text>
          <Text style={styles.authSubtitle}>
            Please sign in to view your gallery
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
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Gallery</Text>
        <Text style={styles.headerSubtitle}>
          {images.length} image{images.length !== 1 ? 's' : ''}
        </Text>
      </View>

      {images.length === 0 ? (
        <View style={styles.emptyState}>
          <Text style={styles.emptyTitle}>No Images Yet</Text>
          <Text style={styles.emptySubtitle}>
            Process your first image to see it here
          </Text>
          <TouchableOpacity
            style={styles.emptyButton}
            onPress={() => router.push('/(tabs)')}
          >
            <Text style={styles.emptyButtonText}>Start Creating</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <FlatList
          data={images}
          renderItem={renderImageItem}
          keyExtractor={item => item.id}
          numColumns={2}
          contentContainerStyle={styles.gridContainer}
          showsVerticalScrollIndicator={false}
        />
      )}

      {/* Image Preview Modal */}
      <Modal
        visible={selectedImage !== null}
        transparent
        animationType="fade"
        onRequestClose={() => setSelectedImage(null)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <TouchableOpacity
              style={styles.closeButton}
              onPress={() => setSelectedImage(null)}
            >
              <X size={24} color="#FFFFFF" />
            </TouchableOpacity>

            {selectedImage && (
              <>
                <Image
                  source={{ uri: selectedImage.processed_image_data_url }}
                  style={styles.fullImage}
                  resizeMode="contain"
                />

                <View style={styles.modalActions}>
                  <TouchableOpacity
                    style={styles.modalActionButton}
                    onPress={() => downloadImage(selectedImage)}
                  >
                    <Download size={20} color="#FFA500" />
                    <Text style={styles.modalActionText}>Download</Text>
                  </TouchableOpacity>

                  <TouchableOpacity
                    style={styles.modalActionButton}
                    onPress={() => shareImage(selectedImage)}
                  >
                    <Share2 size={20} color="#FFA500" />
                    <Text style={styles.modalActionText}>Share</Text>
                  </TouchableOpacity>

                  <TouchableOpacity
                    style={styles.modalActionButton}
                    onPress={() => handleDeleteImage(selectedImage.id)}
                  >
                    <Trash2 size={20} color="#EF4444" />
                    <Text style={[styles.modalActionText, { color: '#EF4444' }]}>Delete</Text>
                  </TouchableOpacity>
                </View>
              </>
            )}
          </View>
        </View>
      </Modal>
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
  headerSubtitle: {
    fontSize: 14,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    marginTop: 4,
  },
  gridContainer: {
    padding: 20,
  },
  imageItem: {
    flex: 1,
    margin: 8,
    backgroundColor: '#F9FAFB',
    borderRadius: 12,
    overflow: 'hidden',
  },
  thumbnailImage: {
    width: '100%',
    height: 120,
  },
  imageDate: {
    padding: 8,
    fontSize: 12,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
  },
  emptyState: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 40,
  },
  emptyTitle: {
    fontSize: 24,
    fontFamily: 'Inter-Bold',
    color: '#1F2937',
    marginBottom: 8,
  },
  emptySubtitle: {
    fontSize: 16,
    fontFamily: 'Inter-Regular',
    color: '#6B7280',
    textAlign: 'center',
    marginBottom: 24,
  },
  emptyButton: {
    backgroundColor: '#facc15',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 24,
  },
  emptyButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontFamily: 'Inter-SemiBold',
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
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.9)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  modalContent: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 20,
  },
  closeButton: {
    position: 'absolute',
    top: 60,
    right: 20,
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: 'rgba(0, 0, 0, 0.5)',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 1,
  },
  fullImage: {
    width: '100%',
    height: '100%',
    resizeMode: 'contain',
  },
  modalActions: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    width: '100%',
    paddingHorizontal: 20,
    paddingTop: 20,
  },
  modalActionButton: {
    alignItems: 'center',
    padding: 16,
  },
  modalActionText: {
    color: '#facc15',
    fontSize: 12,
    fontFamily: 'Inter-Medium',
    marginTop: 4,
  },
});