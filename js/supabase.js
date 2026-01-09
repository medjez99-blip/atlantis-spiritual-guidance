// Supabase configuration
const SUPABASE_URL = 'https://revdnghkdjfxuxiqjddk.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJldmRuZ2hrZGpmeHV4aXFqZGRrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njc3NjkzMTcsImV4cCI6MjA4MzM0NTMxN30.ytyzor-EvXbZ67NkC_o9Jaj5CH4dk3iVqxM411Xf5X4';

// Initialize Supabase client only once
if (!window.supabaseClient) {
    // Check if supabase library is loaded
    if (!window.supabase) {
        console.error('Supabase library not loaded. Make sure @supabase/supabase-js is loaded first.');
    } else {
        const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
        
        // Test connection
        async function testSupabaseConnection() {
            try {
                const { data, error } = await supabase.auth.getSession();
                if (error) {
                    console.error(window.t('supabase_connection_error') + ':', error);
                    return false;
                }
                console.log('Supabase connected successfully');
                return true;
            } catch (error) {
                console.error('Supabase connection failed:', error);
                return false;
            }
        }
        
        // Initialize on page load
        document.addEventListener('DOMContentLoaded', () => {
            testSupabaseConnection();
        });
        
        // Export supabase client
        window.supabaseClient = supabase;
        console.log('Supabase client initialized');
    }
}

// Global access - this won't redeclare if already defined
if (!window.supabaseClient) {
    console.warn('Supabase client not initialized. Creating dummy client.');
    window.supabaseClient = {
        auth: {
            getSession: () => Promise.resolve({ data: { session: null }, error: null }),
            signUp: () => Promise.reject(new Error('Supabase not initialized')),
            signInWithPassword: () => Promise.reject(new Error('Supabase not initialized')),
            signOut: () => Promise.reject(new Error('Supabase not initialized')),
            resetPasswordForEmail: () => Promise.reject(new Error('Supabase not initialized')),
            updateUser: () => Promise.reject(new Error('Supabase not initialized')),
            onAuthStateChange: () => ({})
        },
        from: () => ({
            insert: () => ({ select: () => ({ single: () => Promise.reject(new Error('Supabase not initialized')) }) }),
            select: () => ({ eq: () => ({ single: () => Promise.reject(new Error('Supabase not initialized')) }) }),
            update: () => ({ eq: () => Promise.reject(new Error('Supabase not initialized')) })
        })
    };
}