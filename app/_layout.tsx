import { useEffect, useState } from 'react';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { Platform, LogBox, View, Text } from 'react-native';
import { useFonts, Inter_400Regular, Inter_500Medium, Inter_600SemiBold, Inter_700Bold } from '@expo-google-fonts/inter';
import * as SplashScreen from 'expo-splash-screen';
import { useFrameworkReady } from '@/hooks/useFrameworkReady';
import { AuthProvider } from '@/hooks/use_auth';
import 'react-native-url-polyfill/auto';

// Ignore specific warnings that can cause crashes in production
LogBox.ignoreLogs([
  'Warning: AsyncStorage has been extracted from react-native',
  'Setting a timer for a long period of time',
  'VirtualizedLists should never be nested',
  'Non-serializable values were found in the navigation state',
  'Constants.platform.ios.model has been deprecated',
  'Require cycle:',
]);

// Prevent splash screen from auto-hiding
SplashScreen.preventAutoHideAsync().catch(() => {
  // Ignore errors if splash screen is already hidden
});

export default function RootLayout() {
  useFrameworkReady();
  const [appIsReady, setAppIsReady] = useState(false);

  const [fontsLoaded, fontError] = useFonts({
    'Inter-Regular': Inter_400Regular,
    'Inter-Medium': Inter_500Medium,
    'Inter-SemiBold': Inter_600SemiBold,
    'Inter-Bold': Inter_700Bold,
  });

  useEffect(() => {
    async function prepare() {
      try {
        // Wait for fonts to load
        if (fontsLoaded || fontError) {
          // Add a small delay to ensure everything is loaded
          await new Promise(resolve => setTimeout(resolve, 500));
          setAppIsReady(true);
        }
      } catch (e) {
        console.warn('Error during app preparation:', e);
        // Even if there's an error, mark app as ready to prevent infinite loading
        setAppIsReady(true);
      }
    }

    prepare();
  }, [fontsLoaded, fontError]);

  useEffect(() => {
    if (appIsReady) {
      // Hide splash screen when app is ready
      SplashScreen.hideAsync().catch(() => {
        // Ignore errors if splash screen is already hidden
      });
    }
  }, [appIsReady]);

  // Show loading screen while fonts are loading
  if (!appIsReady) {
    return (
      <View style={{ flex: 1, backgroundColor: '#facc15', justifyContent: 'center', alignItems: 'center' }}>
        <Text style={{ color: '#FFFFFF', fontSize: 18, fontWeight: 'bold' }}>Loading...</Text>
      </View>
    );
  }

  return (
    <AuthProvider>
      <>
        <Stack screenOptions={{ headerShown: false }}>
          <Stack.Screen name="index" />
          <Stack.Screen name="onboarding" />
          <Stack.Screen name="auth" />
          <Stack.Screen name="(tabs)" />
          <Stack.Screen name="subscription" />
          <Stack.Screen name="payment-return" />
          <Stack.Screen name="+not-found" />
        </Stack>
        <StatusBar style="auto" />
      </>
    </AuthProvider>
  );
}