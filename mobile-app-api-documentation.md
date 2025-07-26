# IMG-AI Mobile App - API Documentation

## Base URL
```
https://kpzpsljkpvalemxgzsis.supabase.co
```

## Authentication
All authenticated endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <jwt_token>
```

---

## 1. Authentication Endpoints

### 1.1 Sign Up with Email
**Endpoint:** `POST /auth/v1/signup`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (201):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

### 1.2 Sign In with Email
**Endpoint:** `POST /auth/v1/token?grant_type=password`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "user": {
    "id": "uuid",
    "email": "user@example.com"
  }
}
```

### 1.3 Sign In with Google
**Endpoint:** `POST /auth/v1/token?grant_type=id_token`

**Request Body:**
```json
{
  "provider": "google",
  "id_token": "google_id_token_here"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "user_metadata": {
      "provider": "google",
      "name": "John Doe",
      "picture": "https://..."
    }
  }
}
```

### 1.4 Sign In with Apple
**Endpoint:** `POST /auth/v1/token?grant_type=id_token`

**Request Body:**
```json
{
  "provider": "apple",
  "id_token": "apple_id_token_here"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "user_metadata": {
      "provider": "apple",
      "name": "John Doe"
    }
  }
}
```

### 1.5 Refresh Token
**Endpoint:** `POST /auth/v1/token?grant_type=refresh_token`

**Request Body:**
```json
{
  "refresh_token": "refresh_token_here"
}
```

**Response (200):**
```json
{
  "access_token": "new_access_token",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "new_refresh_token"
}
```

### 1.6 Sign Out
**Endpoint:** `POST /auth/v1/logout`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (204):** No content

### 1.7 Get Current User
**Endpoint:** `GET /auth/v1/user`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "created_at": "2024-01-01T00:00:00Z",
  "user_metadata": {
    "name": "John Doe",
    "picture": "https://..."
  }
}
```

---

## 2. User Profile Endpoints

### 2.1 Get User Profile
**Endpoint:** `GET /rest/v1/profiles?id=eq.{user_id}`

**Headers:**
```
Authorization: Bearer <access_token>
apikey: <supabase_anon_key>
```

**Response (200):**
```json
[
  {
    "id": "uuid",
    "credits": 5,
    "is_pro": false,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
    "credits_reset_date": null
  }
]
```

### 2.2 Update User Profile
**Endpoint:** `PATCH /rest/v1/profiles?id=eq.{user_id}`

**Headers:**
```
Authorization: Bearer <access_token>
apikey: <supabase_anon_key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "updated_at": "2024-01-01T00:00:00Z"
}
```

**Response (200):**
```json
[
  {
    "id": "uuid",
    "credits": 5,
    "is_pro": false,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
    "credits_reset_date": null
  }
]
```

---

## 3. Image Processing Endpoints

### 3.1 Remove Background (Supabase Edge Function)
**Endpoint:** `POST /functions/v1/remove-background`
**Full URL:** `https://kpzpsljkpvalemxgzsis.supabase.co/functions/v1/remove-background`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body (Form Data):**
```
image_file: <binary_image_data>
```

**Success Response (200):**
```json
{
  "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
}
```

**Error Responses:**

**Insufficient Credits (402):**
```json
{
  "error": "Insufficient credits"
}
```

**Authentication Failed (401):**
```json
{
  "error": "Authentication failed"
}
```

**Invalid File (400):**
```json
{
  "error": "A valid image file with key 'image_file' is required."
}
```

**User Profile Not Found (404):**
```json
{
  "error": "User profile not found."
}
```

**External API Error (502):**
```json
{
  "error": "Failed to process image via external API."
}
```

**Server Configuration Error (500):**
```json
{
  "error": "Server configuration error: Missing API key."
}
```

**Internal Server Error (500):**
```json
{
  "error": "An internal server error occurred."
}
```

**Function Details:**
- Automatically decrements user credits after successful processing
- Stores generated image in database for history
- Supports PNG, JPG, WEBP formats
- Maximum file size: 10MB
- Pro users have unlimited processing (credits still decremented but replenished monthly)

---

## 4. Generated Images Endpoints

### 4.1 Get Generated Images
**Endpoint:** `GET /rest/v1/generated_images?user_id=eq.{user_id}&order=created_at.desc`

**Headers:**
```
Authorization: Bearer <access_token>
apikey: <supabase_anon_key>
```

**Query Parameters:**
- `limit`: Number of images to return (default: 20)
- `offset`: Number of images to skip (for pagination)

**Response (200):**
```json
[
  {
    "id": "uuid",
    "user_id": "uuid",
    "processed_image_data_url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "created_at": "2024-01-01T00:00:00Z",
    "status": "success"
  }
]
```

### 4.2 Delete Generated Image
**Endpoint:** `DELETE /rest/v1/generated_images?id=eq.{image_id}&user_id=eq.{user_id}`

**Headers:**
```
Authorization: Bearer <access_token>
apikey: <supabase_anon_key>
```

**Response (204):** No content

---

## 5. Subscription Endpoints

### 5.1 Create Stripe Checkout Session (Supabase Edge Function)
**Endpoint:** `POST /functions/v1/stripe-checkout`
**Full URL:** `https://kpzpsljkpvalemxgzsis.supabase.co/functions/v1/stripe-checkout`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:** Empty JSON object `{}`

**Success Response (200):**
```json
{
  "checkout_url": "https://checkout.stripe.com/pay/cs_test_..."
}
```

**Error Responses:**

**Unauthorized (401):**
```json
{
  "error": "Unauthorized"
}
```

**Customer Creation Failed (500):**
```json
{
  "error": "Failed to save customer information."
}
```

**Checkout Session Failed (500):**
```json
{
  "error": "Failed to create checkout session"
}
```

**Function Details:**
- Creates or retrieves existing Stripe customer
- Links Stripe customer to Supabase user
- Handles subscription creation
- Returns checkout URL for mobile app to open

### 5.2 Get Subscription Status
**Endpoint:** `GET /rest/v1/stripe_user_subscriptions?user_id=eq.{user_id}`

**Headers:**
```
Authorization: Bearer <access_token>
apikey: <supabase_anon_key>
```

**Response (200):**
```json
[
  {
    "id": "uuid",
    "customer_id": "cus_...",
    "subscription_id": "sub_...",
    "price_id": "price_...",
    "status": "active",
    "current_period_start": "2024-01-01T00:00:00Z",
    "current_period_end": "2024-02-01T00:00:00Z",
    "cancel_at_period_end": false,
    "payment_method_brand": "visa",
    "payment_method_last4": "4242",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
    "user_id": "uuid"
  }
]
```

### 5.3 Stripe Webhook (Background Process)
**Endpoint:** `POST /functions/v1/stripe-webhook`
**Full URL:** `https://kpzpsljkpvalemxgzsis.supabase.co/functions/v1/stripe-webhook`

**Note:** This endpoint is called by Stripe, not directly by the mobile app.

**Handled Events:**
- `checkout.session.completed`: Updates user to Pro status
- `customer.subscription.updated`: Syncs subscription changes
- `customer.subscription.deleted`: Removes Pro status
- `invoice.payment_succeeded`: Confirms payment and maintains Pro status

**Function Details:**
- Automatically updates user profile (`is_pro` status)
- Manages credit replenishment for Pro users
- Handles subscription lifecycle events
- Maintains sync between Stripe and Supabase

---

## 6. Account Management Endpoints

### 6.1 Update Password
**Endpoint:** `PUT /auth/v1/user`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "password": "new_secure_password"
}
```

**Response (200):**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

### 6.2 Update Email
**Endpoint:** `PUT /auth/v1/user`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "newemail@example.com"
}
```

**Response (200):**
```json
{
  "id": "uuid",
  "email": "newemail@example.com",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

### 6.3 Delete Account
**Endpoint:** `DELETE /auth/v1/user`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (204):** No content

**Note:** This will cascade delete all user data including:
- Profile information
- Generated images
- Stripe customer data
- Subscription information

### 6.4 Delete Account (Complete) - Supabase Edge Function
**Endpoint:** `POST /functions/v1/delete-account`
**Full URL:** `https://kpzpsljkpvalemxgzsis.supabase.co/functions/v1/delete-account`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:** Empty JSON object `{}`

**Success Response (200):**
```json
{
  "success": true,
  "message": "Account deleted successfully"
}
```

**Error Responses:**

**Unauthorized (401):**
```json
{
  "error": "Unauthorized"
}
```

**Method Not Allowed (405):**
```json
{
  "error": "Method not allowed"
}
```

**Internal Server Error (500):**
```json
{
  "error": "Failed to delete account"
}
```

**Function Details:**
- Cancels all active Stripe subscriptions
- Deletes all user-generated images
- Removes user profile and related data
- Deletes user from authentication system
- Handles cleanup of all associated data
- Process is irreversible

**Data Deletion Process:**
1. Retrieves user's Stripe customer information
2. Cancels all active Stripe subscriptions
3. Deletes generated images from database
4. Removes user profile information
5. Deletes user from authentication system
6. All related data is cascade deleted automatically
---

## 7. Real-time Subscriptions

### 7.1 Profile Changes
```javascript
const subscription = supabase
  .channel('profile-changes')
  .on('postgres_changes', {
    event: 'UPDATE',
    schema: 'public',
    table: 'profiles',
    filter: `id=eq.${userId}`
  }, (payload) => {
    // Handle profile updates (credits, pro status)
    console.log('Profile updated:', payload.new)
  })
  .subscribe()
```

### 7.2 Generated Images Changes
```javascript
const subscription = supabase
  .channel('generated-images-changes')
  .on('postgres_changes', {
    event: '*',
    schema: 'public',
    table: 'generated_images',
    filter: `user_id=eq.${userId}`
  }, (payload) => {
    // Handle new images, deletions
    console.log('Images updated:', payload)
  })
  .subscribe()
```

---

## 8. Error Handling

### Standard Error Response Format
```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": "Additional error details"
}
```

### Common HTTP Status Codes
- **200**: Success
- **201**: Created
- **204**: No Content
- **400**: Bad Request
- **401**: Unauthorized
- **402**: Payment Required (Insufficient credits)
- **403**: Forbidden
- **404**: Not Found
- **422**: Unprocessable Entity
- **500**: Internal Server Error
- **502**: Bad Gateway (External API error)

---

## 9. Rate Limiting

### Limits
- **Authentication endpoints**: 10 requests per minute per IP
- **Image processing**: 5 requests per minute per user (Pro users: 20/minute)
- **General API**: 100 requests per minute per user

### Rate Limit Headers
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

---

## 10. Environment Variables

### Required for Mobile App
```javascript
const SUPABASE_URL = 'https://kpzpsljkpvalemxgzsis.supabase.co'
const SUPABASE_ANON_KEY = 'your_supabase_anon_key'
```

### Edge Function Environment Variables (Server-side)
- `CLIPDROP_API_KEY`: For background removal processing
- `STRIPE_SECRET_KEY`: For payment processing
- `STRIPE_WEBHOOK_SECRET`: For webhook verification
- `STRIPE_PRICE_ID`: For subscription pricing

---

## 11. SDK Integration Examples

### 11.1 React Native Supabase Setup
```javascript
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = 'https://kpzpsljkpvalemxgzsis.supabase.co'
const supabaseAnonKey = 'your_anon_key_here'

export const supabase = createClient(supabaseUrl, supabaseAnonKey)
```

### 11.2 Authentication Examples

**Email/Password Sign Up:**
```javascript
const signUp = async (email, password) => {
  const { data, error } = await supabase.auth.signUp({
    email,
    password
  })
  return { data, error }
}
```

**Email/Password Sign In:**
```javascript
const signIn = async (email, password) => {
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password
  })
  return { data, error }
}
```

**Google Sign In:**
```javascript
import { GoogleSignin } from '@react-native-google-signin/google-signin'

const signInWithGoogle = async () => {
  try {
    await GoogleSignin.hasPlayServices()
    const userInfo = await GoogleSignin.signIn()
    
    const { data, error } = await supabase.auth.signInWithIdToken({
      provider: 'google',
      token: userInfo.idToken
    })
    
    return { data, error }
  } catch (error) {
    return { data: null, error }
  }
}
```

**Apple Sign In:**
```javascript
import { appleAuth } from '@invertase/react-native-apple-authentication'

const signInWithApple = async () => {
  try {
    const appleAuthRequestResponse = await appleAuth.performRequest({
      requestedOperation: appleAuth.Operation.LOGIN,
      requestedScopes: [appleAuth.Scope.EMAIL, appleAuth.Scope.FULL_NAME]
    })
    
    const { data, error } = await supabase.auth.signInWithIdToken({
      provider: 'apple',
      token: appleAuthRequestResponse.identityToken
    })
    
    return { data, error }
  } catch (error) {
    return { data: null, error }
  }
}
```

### 11.3 Image Processing Example
```javascript
const processImage = async (imageUri) => {
  try {
    // Create FormData
    const formData = new FormData()
    formData.append('image_file', {
      uri: imageUri,
      type: 'image/jpeg',
      name: 'image.jpg'
    })
    
    // Call edge function
    const { data, error } = await supabase.functions.invoke('remove-background', {
      body: formData
    })
    
    if (error) throw error
    
    return { success: true, imageData: data.image }
  } catch (error) {
    return { success: false, error: error.message }
  }
}
```

### 11.4 Subscription Management Example
```javascript
const createCheckoutSession = async () => {
  try {
    const { data, error } = await supabase.functions.invoke('stripe-checkout', {
      body: {}
    })
    
    if (error) throw error
    
    // Open checkout URL in browser or WebView
    return { success: true, checkoutUrl: data.checkout_url }
  } catch (error) {
    return { success: false, error: error.message }
  }
}
```

### 11.5 Gallery Management Example
```javascript
const getGeneratedImages = async (limit = 20, offset = 0) => {
  const { data, error } = await supabase
    .from('generated_images')
    .select('*')
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1)
  
  return { data, error }
}

const deleteImage = async (imageId) => {
  const { error } = await supabase
    .from('generated_images')
    .delete()
    .eq('id', imageId)
  
  return { error }
}
```

### 11.6 Profile Management Example
```javascript
const getUserProfile = async () => {
  const { data: { user } } = await supabase.auth.getUser()
  
  if (!user) return { data: null, error: 'Not authenticated' }
  
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', user.id)
    .single()
  
  return { data, error }
}
```

### 11.7 Account Deletion Example
```javascript
const deleteAccount = async () => {
  try {
    const { data, error } = await supabase.functions.invoke('delete-account', {
      body: {}
    });
    
    if (error) throw error;
    
    // Account deleted successfully
    // Navigate user to landing page or login screen
    return { success: true, message: data.message };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Usage in React Native component
const handleDeleteAccount = async () => {
  Alert.alert(
    "Delete Account",
    "This action cannot be undone. Are you sure you want to delete your account?",
    [
      { text: "Cancel", style: "cancel" },
      { 
        text: "Delete", 
        style: "destructive",
        onPress: async () => {
          const result = await deleteAccount();
          if (result.success) {
            // Navigate to login screen
            navigation.reset({
              index: 0,
              routes: [{ name: 'Auth' }],
            });
          } else {
            Alert.alert("Error", result.error);
          }
        }
      }
    ]
  );
};
```
---

## 12. Testing

### 12.1 Test Environment
- **Base URL**: `https://kpzpsljkpvalemxgzsis.supabase.co`
- **Test Mode**: All Stripe operations are in test mode

### 12.2 Test Credentials
```
Email: test@example.com
Password: testpassword123
```

### 12.3 Stripe Test Cards
- **Success**: 4242424242424242
- **Decline**: 4000000000000002
- **Insufficient Funds**: 4000000000009995

### 12.4 Test Image Processing
Use small test images (< 1MB) for faster testing. The function supports:
- PNG, JPG, WEBP formats
- Maximum 10MB file size
- Automatic base64 encoding in response

---

## 13. Security Considerations

### 13.1 Authentication
- JWT tokens expire in 1 hour
- Refresh tokens for seamless re-authentication
- Secure token storage in device keychain

### 13.2 API Security
- All endpoints use HTTPS
- Row Level Security (RLS) enabled on all tables
- User can only access their own data

### 13.3 File Upload Security
- File type validation on client and server
- File size limits enforced
- Malicious file detection

### 13.4 Payment Security
- PCI DSS compliant through Stripe
- No sensitive payment data stored locally
- Webhook signature verification

---

## 14. Performance Optimization

### 14.1 Image Handling
- Compress images before upload
- Cache processed images locally
- Lazy loading for gallery
- Progressive image loading

### 14.2 API Optimization
- Request batching where possible
- Implement retry logic with exponential backoff
- Cache user profile data
- Optimize database queries with proper indexing

### 14.3 Real-time Updates
- Use Supabase real-time for instant updates
- Minimize subscription overhead
- Efficient state management

---

## 15. Monitoring and Analytics

### 15.1 Error Tracking
- Log all API errors with context
- Track function execution times
- Monitor success/failure rates

### 15.2 Usage Analytics
- Track feature usage
- Monitor conversion rates
- Performance metrics

### 15.3 Business Metrics
- Credit usage patterns
- Subscription conversion rates
- User retention metrics