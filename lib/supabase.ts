import { createClient } from '@supabase/supabase-js';
import * as SecureStore from 'expo-secure-store';
import * as aesjs from 'aes-js';
import 'react-native-get-random-values';
import 'react-native-url-polyfill/auto';

// As Expo's SecureStore does not support values larger than 2048
// bytes, an AES-256-CBC encryption is used to store session data.
class LargeSecureStore {
  private async _encrypt(key: string, value: string) {
    const encryptionKey = crypto.getRandomValues(new Uint8Array(256 / 8));

    const cipher = new aesjs.ModeOfOperation.ctr(encryptionKey, new aesjs.Counter(1));
    const encryptedBytes = cipher.encrypt(aesjs.utils.utf8.toBytes(value));

    await SecureStore.setItemAsync(key, aesjs.utils.hex.fromBytes(encryptionKey));

    return aesjs.utils.hex.fromBytes(encryptedBytes);
  }

  private async _decrypt(key: string, value: string) {
    const encryptionKeyHex = await SecureStore.getItemAsync(key);
    if (!encryptionKeyHex) {
      return encryptionKeyHex;
    }

    const cipher = new aesjs.ModeOfOperation.ctr(
      aesjs.utils.hex.toBytes(encryptionKeyHex),
      new aesjs.Counter(1)
    );
    const decryptedBytes = cipher.decrypt(aesjs.utils.hex.toBytes(value));

    return aesjs.utils.utf8.fromBytes(decryptedBytes);
  }

  async getItem(key: string) {
    const encrypted = await SecureStore.getItemAsync(key);
    if (!encrypted) {
      return encrypted;
    }

    try {
      return await this._decrypt(key, encrypted);
    } catch (e) {
      // if the decrypt fails, we should remove the key
      await this.removeItem(key);
      return null;
    }
  }

  async removeItem(key: string) {
    await SecureStore.deleteItemAsync(key);
  }

  async setItem(key: string, value: string) {
    const encrypted = await this._encrypt(key, value);

    await SecureStore.setItemAsync(key, encrypted);
  }
}


// Get environment variables with fallbacks
const supabaseUrl = process.env.EXPO_PUBLIC_SUPABASE_URL || '';
const supabaseAnonKey = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY || '';

// Validate required environment variables
if (!supabaseUrl) {
  console.error('EXPO_PUBLIC_SUPABASE_URL is required');
  throw new Error('Missing Supabase URL configuration');
}

if (!supabaseAnonKey) {
  console.error('EXPO_PUBLIC_SUPABASE_ANON_KEY is required');
  throw new Error('Missing Supabase Anon Key configuration');
}

// Validate URL format
try {
  new URL(supabaseUrl);
} catch (error) {
  console.error('Invalid Supabase URL format:', supabaseUrl);
  throw new Error('Invalid Supabase URL configuration');
}

// Only log in development
if (__DEV__) {
  console.log('Supabase URL:', supabaseUrl);
  console.log('Supabase Anon Key:', supabaseAnonKey ? 'Present' : 'Missing');
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    storage: new LargeSecureStore(),
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: false,
    flowType: 'pkce',
  },
  global: {
    headers: {
      'X-Client-Info': 'remove-help-mobile',
    },
  },
  realtime: {
    params: {
      eventsPerSecond: 10,
    },
  },
});
