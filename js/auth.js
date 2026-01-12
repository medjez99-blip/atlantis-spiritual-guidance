// Authentication functions
if (!window.supabaseClient || !window.supabaseClient.auth) {
    console.error('Supabase is not properly initialized.');
}
if (!window.redirectInProgress) {
    window.redirectInProgress = false;
}

// Mobile detection helper
function isMobileDevice() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

class AuthManager {
    constructor() {
    this.currentUser = null;
    this.supabase = window.supabaseClient;
    this.isRedirecting = false;
    this.init();
	}
	
    async init() {
    // First, check for session from URL fragment (for password reset)
    const hash = window.location.hash;
    const params = new URLSearchParams(hash.substring(1));
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');
    
    if (accessToken && refreshToken) {
        try {
            const { data, error } = await this.supabase.auth.setSession({
                access_token: accessToken,
                refresh_token: refreshToken
            });
            if (error) throw error;
            // Clear URL fragment
            window.history.replaceState({}, document.title, 
                window.location.pathname + window.location.search);
        } catch (error) {
            console.error('Error setting session from URL:', error);
        }
    }
    
    // Check existing session - MAKE SURE THIS COMPLETES
    const { data: { session } } = await this.supabase.auth.getSession();
    this.currentUser = session?.user || null;
    
    // Set a flag to indicate auth is initialized
    this.initialized = true;
    
    // Update UI immediately
    this.updateAuthUI();
    
    // Listen for auth changes
    this.supabase.auth.onAuthStateChange(async (event, session) => {
        console.log('Auth state changed:', event, session?.user?.email);
        this.currentUser = session?.user || null;
        this.updateAuthUI();
        
        // Prevent multiple redirects
        if (window.redirectInProgress) return;
        
        if (event === 'SIGNED_IN') {
            console.log('User signed in:', session?.user?.email);
            this.showSuccessMessage(this.translate('welcome_back'));
            
            // ONLY redirect if we're on login page
            const currentPath = window.location.pathname;
            const isLoginPage = currentPath.includes('login.html');
            
            if (isLoginPage && !window.location.hash.includes('access_token')) {
                window.redirectInProgress = true;
                // Use consistent timeout for both mobile and desktop
                setTimeout(() => {
                    if (window.location.pathname.includes('login.html')) {
                        console.log('Redirecting to dashboard from login page');
                        window.location.href = '../pages/dashboard.html';
                    }
                }, 1000); // Increased timeout for mobile
            }
        }
    });
}
	
	// translation helper
	translate(key, defaultText = '') {
		if (window.i18n && window.i18n.translate) {
			return window.i18n.translate(key, defaultText);
		}
		return defaultText || key;
	}
	
    // Sign up new user - NO EMAIL CONFIRMATION NEEDED
    async signUp(email, password, name) {
        try {
            console.log('Starting signup for:', email);
            
            // Sign up with Supabase Auth WITHOUT email confirmation
            const { data, error } = await this.supabase.auth.signUp({
                email,
                password,
                options: {
                    data: {
                        name: name,
                        created_at: new Date().toISOString()
					}
                    // REMOVED emailRedirectTo - no confirmation needed
				}
			});
            
            if (error) {
                console.error('Auth signup error:', error);
                throw error;
			}
            
            console.log('Auth signup successful, user:', data.user);
            
            // Auto sign in after signup
            const { data: signInData, error: signInError } = await this.supabase.auth.signInWithPassword({
                email,
                password
			});
            
            if (signInError) {
                console.error('Auto signin error:', signInError);
                return { 
                    success: false, 
                    error: signInError.message 
				};
			}
            
            console.log('Auto signin successful');
            this.currentUser = signInData.user;
            
            return { 
                success: true, 
                data: signInData,
                message: 'Account created successfully!'
			};
            
			} catch (error) {
            console.error('Sign up error:', error);
            return { 
                success: false, 
                error: error.message,
                code: error.code
			};
		}
	}
	
    // Sign in user - Improved with consistent redirect
async signIn(email, password) {
    try {
        console.log('Signing in...');
        
        const { data, error } = await this.supabase.auth.signInWithPassword({
            email,
            password
        });
        
        if (error) throw error;
        
        // Show success message
        this.showSuccessMessage(this.translate('welcome_back'));
        
        // Wait a moment for session to settle
        await new Promise(resolve => setTimeout(resolve, 300));
        
        // ALWAYS redirect to dashboard after successful login
        // No conditions, just redirect
        window.location.href = '../pages/dashboard.html';
        
        return { success: true, data };
    } catch (error) {
        console.error('Sign in error:', error);
        return { success: false, error: error.message };
    }
}
	
    // Sign out user
    async signOut() {
    try {
        // First check if we have a valid session
        const { data: sessionData } = await this.supabase.auth.getSession();
        
        // Only call signOut if we have an active session
        if (sessionData?.session) {
            const { error } = await this.supabase.auth.signOut();
            if (error) throw error;
        }
        
        // Clear local user data
        this.currentUser = null;
        localStorage.removeItem('selectedIntention');
        
        // Show logout message
        this.showSuccessMessage(this.translate('logout_success'));
        
        // Wait a moment before redirecting to show the message
        setTimeout(() => {
            // Redirect based on current page
            if (window.location.pathname.includes('dashboard.html') || 
                window.location.pathname.includes('admin.html')) {
                window.location.href = '../index.html';
            } else {
                window.location.reload();
            }
        }, 1000);
        
    } catch (error) {
        console.warn('Sign out warning:', error);
        // Even if there's an error, still redirect to home
        this.currentUser = null;
        window.location.href = '../index.html';
    }
}
	
    // Reset password
    async resetPassword(email) {
    try {
        // Get the current origin (domain)
        const currentOrigin = window.location.origin;
        
        const { error } = await this.supabase.auth.resetPasswordForEmail(email, {
            redirectTo: `${currentOrigin}/pages/reset-password.html`,
        });
        
        if (error) {
            console.error('Password reset request error:', error);
            throw error;
        }
        
        return { success: true };
    } catch (error) {
        console.error('Password reset request failed:', error);
        return { 
            success: false, 
            error: error.message || 'Failed to send reset email' 
        };
    }
}
	
    // Check if user is admin
    async isAdmin() {
        if (!this.currentUser) return false;
        
        try {
            const { data, error } = await this.supabase
			.from('users')
			.select('role')
			.eq('id', this.currentUser.id)
			.single();
			
            if (error || !data) return false;
            return data.role === 'admin';
			} catch (error) {
            console.error('Admin check error:', error);
            return false;
		}
	}
	
    // Get user data
    async getUserData() {
        if (!this.currentUser) return null;
        
        try {
            const { data, error } = await this.supabase
			.from('users')
			.select('*')
			.eq('id', this.currentUser.id)
			.single();
			
            if (error) {
                // If user doesn't exist in users table, create it
                console.log('Creating user profile...');
                await this.createUserProfile(this.currentUser);
                return {
                    id: this.currentUser.id,
                    email: this.currentUser.email,
                    name: this.currentUser.user_metadata?.name || this.currentUser.email.split('@')[0],
                    role: 'user',
                    meditation_streak: 0,
                    total_meditations: 0,
                    journal_entries: 0
				};
			}
            return data;
			} catch (error) {
            console.error('Get user data error:', error);
            return null;
		}
	}
	
    // Create user profile if missing
    async createUserProfile(user) {
        try {
            const { error } = await this.supabase
			.from('users')
			.insert([
				{
					id: user.id,
					email: user.email,
					name: user.user_metadata?.name || user.email.split('@')[0],
					created_at: new Date().toISOString(),
					role: 'user'
				}
			]);
            
            if (error && error.code !== '23505') { // Ignore duplicate key errors
                console.error('Profile creation error:', error);
			}
			} catch (error) {
            console.error('Error creating profile:', error);
		}
	}
async updateAdminUI() {
    if (!this.currentUser) {
        // Hide all admin elements
        document.querySelectorAll('.nav-admin, .admin-link, .admin-header-btn, .admin-badge').forEach(el => {
            if (el) el.style.display = 'none';
        });
        return;
    }
    
    // Check if user is admin
    const isAdmin = await this.isAdmin();
    
    // Show/hide admin links
    document.querySelectorAll('.nav-admin, .admin-link, .admin-header-btn').forEach(el => {
        if (el) {
            el.style.display = isAdmin ? 'block' : 'none';
        }
    });
    
    // Add admin badge to user info (optional)
    const adminBadge = document.getElementById('admin-badge');
    if (adminBadge) {
        adminBadge.style.display = isAdmin ? 'inline-block' : 'none';
    }
}
	
    // Update auth UI
    updateAuthUI() {
    const loginBtn = document.querySelector('.nav-auth a[href*="login"]');
    const logoutBtn = document.getElementById('logout-btn');
    const userStatus = document.getElementById('user-status');
    
    if (this.currentUser) {
        if (loginBtn) loginBtn.style.display = 'none';
        if (logoutBtn) logoutBtn.style.display = 'inline-block';
        if (userStatus) {
            const welcomeMessage = window.t('welcome_user', 'Welcome back, ') + this.currentUser.email;
            userStatus.innerHTML = `<p>${welcomeMessage}</p>`;
        }
        // Also update admin UI
        this.updateAdminUI();
    } else {
        if (loginBtn) loginBtn.style.display = 'inline-block';
        if (logoutBtn) logoutBtn.style.display = 'none';
        if (userStatus) {
            userStatus.innerHTML = `<p>${window.t('guest_message', 'You are browsing as a guest. <a href="pages/login.html">Login</a> for personalized guidance.')}</p>`;
        }
        // Hide admin links
        this.updateAdminUI();
    }
}
	
    // Show message functions (keep as is)
    showSuccessMessage(message) {
        this.showMessage(message, 'success');
	}
	
    showErrorMessage(message) {
        this.showMessage(message, 'error');
	}
	
    showInfoMessage(message) {
        this.showMessage(message, 'info');
	}
	
    showMessage(message, type = 'info') {
		// Check if message is a translation key
		let displayMessage;
		
		if (window.t && typeof window.t === 'function') {
			// Try to translate the message
			displayMessage = window.t(message, message);
			} else if (window.i18n && window.i18n.translate) {
			// Fallback to i18n instance
			displayMessage = window.i18n.translate(message, message);
			} else {
			// Use message as-is
			displayMessage = message;
		}
		
		const existing = document.querySelector('.auth-message');
		if (existing) existing.remove();
		
		const messageDiv = document.createElement('div');
		messageDiv.className = `auth-message ${type}-message fade-in`;
		
		// Check if it contains HTML
		if (displayMessage.includes('<') && displayMessage.includes('>')) {
			messageDiv.innerHTML = displayMessage;
			} else {
			messageDiv.textContent = displayMessage;
		}
		
		const authContainer = document.querySelector('.auth-container') || 
		document.querySelector('.container') || 
		document.body;
		authContainer.prepend(messageDiv);
		
		setTimeout(() => {
			if (messageDiv.parentNode) {
				messageDiv.remove();
			}
		}, 5000);
	}
	
	// Request password reset
	async requestPasswordReset(email) {
		try {
			const { error } = await this.supabase.auth.resetPasswordForEmail(email, {
				redirectTo: `${window.location.origin}/pages/reset-password.html`,
			});
			
			if (error) {
				console.error('Password reset request error:', error);
				throw error;
			}
			
			return { success: true };
			} catch (error) {
			console.error('Password reset request failed:', error);
			return { 
				success: false, 
				error: error.message || 'Failed to send reset email' 
			};
		}
	}
async setSessionFromToken(accessToken, refreshToken) {
    try {
        const { data, error } = await this.supabase.auth.setSession({
            access_token: accessToken,
            refresh_token: refreshToken
        });
        
        if (error) throw error;
        
        this.currentUser = data.session?.user || null;
        return { success: true };
    } catch (error) {
        console.error('Set session error:', error);
        return { success: false, error: error.message };
    }
}
	
	// Update password (after clicking reset link)
	async updatePassword(newPassword) {
		try {
			const { error } = await this.supabase.auth.updateUser({
				password: newPassword
			});
			
			if (error) {
				console.error('Update password error:', error);
				throw error;
			}
			
			return { success: true };
			} catch (error) {
			console.error('Update password failed:', error);
			return { 
				success: false, 
				error: error.message || 'Failed to update password' 
			};
		}
	}
}

// Initialize auth manager
const auth = new AuthManager();
window.auth = auth;

// Helper functions
async function checkAuthState() {
    const { data } = await window.supabaseClient.auth.getSession();
    auth.currentUser = data.session?.user || null;
    auth.updateAuthUI();
    return auth.currentUser;
}

async function loadUserData() {
    // Wait for auth to initialize if needed
    if (!auth.initialized) {
        await new Promise(resolve => {
            const checkInit = setInterval(() => {
                if (auth.initialized) {
                    clearInterval(checkInit);
                    resolve();
                }
            }, 100);
        });
    }
    
    // Give it a moment for currentUser to be set
    if (!auth.currentUser) {
        // Double-check with a small delay
        await new Promise(resolve => setTimeout(resolve, 500));
        const { data } = await auth.supabase.auth.getSession();
        auth.currentUser = data.session?.user || null;
    }
    
    if (!auth.currentUser) {
        console.log('No user found, redirecting to index');
        window.location.href = '../index.html';
        return;
    }
    
    const userData = await auth.getUserData();
    if (userData) {
        const userNameElements = document.querySelectorAll('#user-name, #welcome-name');
        userNameElements.forEach(el => {
            el.textContent = userData.name || userData.email.split('@')[0];
		});
        
        document.getElementById('user-email').textContent = userData.email;
        
        const avatar = document.getElementById('user-avatar');
        if (avatar && userData.name) {
            const initials = userData.name.split(' ').map(n => n[0]).join('').toUpperCase();
            avatar.textContent = initials;
		}
        
        document.getElementById('meditation-streak').textContent = userData.meditation_streak || 0;
        document.getElementById('total-meditations').textContent = userData.total_meditations || 0;
        document.getElementById('journal-entries').textContent = userData.journal_entries || 0;
	}
}

async function checkAdminAccess() {
    const isAdmin = await auth.isAdmin();
    if (!isAdmin) {
        window.location.href = '../index.html';
	}
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        // Prevent multiple clicks
        let isLoggingOut = false;
        logoutBtn.addEventListener('click', async () => {
            if (isLoggingOut) return;
            isLoggingOut = true;
            
            // Disable button and show loading
            logoutBtn.disabled = true;
            logoutBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + 
                                  (window.t ? window.t('logging_out', 'Logging out...') : 'Logging out...');
            
            await auth.signOut();
            
            // Re-enable button (though redirect should happen)
            isLoggingOut = false;
        });
    }
    
    const dashboardLogout = document.getElementById('dashboard-logout');
    if (dashboardLogout) {
        dashboardLogout.addEventListener('click', () => auth.signOut());
	}
    
    const adminLogout = document.getElementById('admin-logout');
    if (adminLogout) {
        adminLogout.addEventListener('click', () => auth.signOut());
	}
    
    // Initial check for dashboard/admin pages
    if (window.location.pathname.includes('dashboard.html') || 
        window.location.pathname.includes('admin.html')) {
        checkAuthState().then(user => {
            if (!user) {
                window.location.href = '../index.html';
			}
		});
	}
});