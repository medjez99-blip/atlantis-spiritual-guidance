
// Initialize everything in correct order
document.addEventListener('DOMContentLoaded', async () => {
    console.log('Initializing Atlantis...');
    
    // Wait for Supabase to initialize
    await new Promise(resolve => setTimeout(resolve, 100));
    
    if (!window.supabaseClient) {
        console.error('❌ Supabase not initialized!');
        // Show error to user
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.innerHTML = `
            <strong>Connection Error</strong>
            <p>Unable to connect to the server. Please refresh the page.</p>
        `;
        document.body.prepend(errorDiv);
    } else {
        console.log('✅ Supabase initialized successfully');
        
        // Initialize auth
        if (window.auth) {
            await window.auth.init();
        }
        
        // Initialize i18n
        if (window.i18n) {
            window.i18n.init();
        }
        
        console.log('✅ Atlantis initialized successfully');
    }
});