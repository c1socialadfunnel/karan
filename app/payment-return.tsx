import { useEffect } from 'react';
import { View, ActivityIndicator } from 'react-native';
import { router } from 'expo-router';
import { supabase } from '@/lib/supabase';
import { useAuth } from '@/hooks/use_auth';

export default function PaymentReturnScreen() {
  const { refreshProfile } = useAuth();

  useEffect(() => {
    const handlePaymentReturn = async () => {
      try {
        // Wait a moment for webhook to process
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Refresh the session to get updated pro status
        const { data: { session }, error } = await supabase.auth.getSession();
        
        if (!error && session) {
          // Refresh user profile
          await refreshProfile();
          
          // Show success message and redirect
          router.replace({
            pathname: '/(tabs)',
            params: { 
              showProWelcome: 'true'
            }
          });
        }
      } catch (error) {
        console.error('Payment return error:', error);
        router.replace('/(tabs)');
      }
    };

    handlePaymentReturn();
  }, []);

  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <ActivityIndicator size="large" color="#facc15" />
    </View>
  );
} 