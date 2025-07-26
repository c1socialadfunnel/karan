import { supabase } from '@/lib/supabase';

export interface DeleteAccountResult {
  success: boolean;
  error?: string;
}

export const deleteAccount = async (): Promise<DeleteAccountResult> => {
  try {
    // Get current user
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user) {
      throw new Error('User not authenticated');
    }

    // Call the delete account edge function
    const { data, error } = await supabase.functions.invoke('delete-account', {
      body: {},
    });

    if (error) {
      throw new Error(error.message);
    }

    return {
      success: true,
    };
  } catch (error) {
    console.error('Delete account error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to delete account',
    };
  }
};