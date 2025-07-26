import { supabase } from '@/lib/supabase';
import { Linking } from 'react-native';

export interface CheckoutResult {
  success: boolean;
  checkoutUrl?: string;
  error?: string;
}

export const createCheckoutSession = async (): Promise<CheckoutResult> => {
  try {
    const { data, error } = await supabase.functions.invoke('stripe-checkout', {
      body: {},
    });

    if (error) {
      throw new Error(error.message);
    }

    return {
      success: true,
      checkoutUrl: data.checkout_url,
    };
  } catch (error) {
    console.error('Checkout session error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to create checkout session',
    };
  }
};

export const openCheckoutUrl = async (url: string) => {
  try {
    const supported = await Linking.canOpenURL(url);
    if (supported) {
      await Linking.openURL(url);
    } else {
      throw new Error('Cannot open checkout URL');
    }
  } catch (error) {
    console.error('Error opening checkout URL:', error);
    throw error;
  }
};

export const getSubscriptionStatus = async () => {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    
    if (!user) {
      throw new Error('User not authenticated');
    }

    const { data, error } = await supabase
      .from('stripe_user_subscriptions')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(1);

    if (error) throw error;

    return { data: data?.[0] || null, error: null };
  } catch (error) {
    console.error('Error fetching subscription status:', error);
    return { data: null, error };
  }
};