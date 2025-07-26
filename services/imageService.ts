import { supabase } from '@/lib/supabase';
import { Platform } from 'react-native';

export interface ProcessImageResult {
  success: boolean;
  imageData?: string;
  error?: string;
}

export const processImage = async (imageUri: string): Promise<ProcessImageResult> => {
  try {
    // Validate environment variables
    if (!process.env.EXPO_PUBLIC_SUPABASE_URL) {
      console.error('Missing EXPO_PUBLIC_SUPABASE_URL');
      return {
        success: false,
        error: 'App configuration error. Please contact support.',
      };
    }

    if (__DEV__) {
      console.log('Processing image:', imageUri);
    }
    
    // Get current user
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user) {
      return {
        success: false,
        error: 'Please sign in to process images',
      };
    }

    if (__DEV__) {
      console.log('User authenticated:', user.id);
    }

    // Get the current session for the auth token
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      return {
        success: false,
        error: 'Session expired. Please sign in again.',
      };
    }

    if (__DEV__) {
      console.log('Session found, making API call...');
    }

    // Create FormData for React Native
    const formData = new FormData();
    formData.append('image_file', {
      uri: imageUri,
      type: 'image/jpeg',
      name: 'image.jpg',
    } as any);

    const functionUrl = `${process.env.EXPO_PUBLIC_SUPABASE_URL}/functions/v1/remove-background`;
    
    if (__DEV__) {
      console.log('Calling function:', functionUrl);
    }

    // Make direct fetch call to the edge function with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    let response;
    try {
      response = await fetch(functionUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session.access_token}`,
        },
        body: formData,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (__DEV__) {
      console.log('Response status:', response.status);
    }

    if (!response.ok) {
      const errorText = await response.text();
      if (__DEV__) {
        console.error('Edge function error:', response.status, errorText);
      }
      
      // Handle specific error cases
      if (response.status === 402) {
        return {
          success: false,
          error: 'Insufficient credits. Please upgrade to Pro or wait for monthly reset.',
        };
      } else if (response.status === 401) {
        return {
          success: false,
          error: 'Authentication failed. Please sign in again.',
        };
      } else {
        return {
          success: false,
          error: 'Failed to process image. Please try again.',
        };
      }
    }

    const data = await response.json();
    
    if (__DEV__) {
      console.log('Response data received');
    }

    return {
      success: true,
      imageData: data.image,
    };
  } catch (error) {
    if (__DEV__) {
      console.error('Image processing error:', error);
    }
    
    // Handle specific error types
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return {
          success: false,
          error: 'Request timed out. Please check your internet connection and try again.',
        };
      }
      if (error.message.includes('Network request failed')) {
        return {
          success: false,
          error: 'Network error. Please check your internet connection.',
        };
      }
    }
    
    return {
      success: false,
      error: 'An unexpected error occurred. Please try again.',
    };
  }
};

export const getGeneratedImages = async (limit = 20, offset = 0) => {
  try {
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user) {
      throw new Error('User not authenticated');
    }

    const { data, error } = await supabase
      .from('generated_images')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) throw error;

    return { data, error: null };
  } catch (error) {
    console.error('Error fetching generated images:', error);
    return { data: null, error };
  }
};

export const deleteGeneratedImage = async (imageId: string) => {
  try {
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user) {
      throw new Error('User not authenticated');
    }

    const { error } = await supabase
      .from('generated_images')
      .delete()
      .eq('id', imageId)
      .eq('user_id', user.id); // Ensure user can only delete their own images

    if (error) throw error;

    return { error: null };
  } catch (error) {
    console.error('Error deleting image:', error);
    return { error };
  }
};