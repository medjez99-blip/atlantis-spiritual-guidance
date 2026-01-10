// Form handling
class FormManager {
    constructor() {
        this.initForms();
	}
	
    initForms() {
        // Login form
        const loginForm = document.getElementById('login-form-element');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
		}
		
        // Signup form
        const signupForm = document.getElementById('signup-form-element');
        if (signupForm) {
            signupForm.addEventListener('submit', (e) => this.handleSignup(e));
		}
		
        // Reset password form
        const resetForm = document.getElementById('reset-form-element');
        if (resetForm) {
            resetForm.addEventListener('submit', (e) => this.handleResetPassword(e));
		}
		
        // Auth tabs
        const loginTab = document.getElementById('login-tab');
        const signupTab = document.getElementById('signup-tab');
        const resetLink = document.getElementById('reset-password-link');
        const backToLogin = document.getElementById('back-to-login');
		
        if (loginTab) loginTab.addEventListener('click', () => this.showForm('login'));
        if (signupTab) signupTab.addEventListener('click', () => this.showForm('signup'));
        if (resetLink) resetLink.addEventListener('click', (e) => {
            e.preventDefault();
            this.showForm('reset');
		});
        if (backToLogin) backToLogin.addEventListener('click', (e) => {
            e.preventDefault();
            this.showForm('login');
		});
		
        // Password visibility toggles
        this.initPasswordToggles();
	}
	
	translate(key, defaultText = '') {
		if (window.i18n && window.i18n.translate) {
			return window.i18n.translate(key, defaultText);
		}
		return defaultText || key;
	}
    // Show specific form
    showForm(formName) {
        // Hide all forms
        document.querySelectorAll('.auth-form').forEach(form => {
            form.classList.remove('active');
		});
		
        // Remove active class from all tabs
        document.querySelectorAll('.auth-tab').forEach(tab => {
            tab.classList.remove('active');
		});
		
        // Show selected form
        const form = document.getElementById(`${formName}-form`);
        if (form) {
            form.classList.add('active');
		}
		
        // Activate corresponding tab
        const tab = document.getElementById(`${formName}-tab`);
        if (tab) {
            tab.classList.add('active');
		}
	}
	
    // Handle login
    async handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    // Validate
    if (!this.validateEmail(email)) {
        auth.showErrorMessage('invalid_email');
        return;
    }
    
    if (password.length < 6) {
        auth.showErrorMessage('password_length_error');
        return;
    }
    
    // Show loading
    const submitBtn = e.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + this.translate('logging_in');
    submitBtn.disabled = true;
    
    // Sign in
    const result = await auth.signIn(email, password);
    
    // Reset button
    submitBtn.textContent = originalText;
    submitBtn.disabled = false;
    
    if (!result.success) {
        auth.showErrorMessage(result.error || 'Login failed. Please check your credentials.');
    } else {
        // Fallback redirect in case other redirects don't fire
        setTimeout(() => {
            const currentPath = window.location.pathname;
            const isLoginPage = currentPath.includes('login') && 
                               (currentPath.endsWith('login') || 
                                currentPath.includes('login.html'));
            if (isLoginPage) {
                console.log('Fallback redirect to dashboard...');
                window.location.href = '../pages/dashboard.html';
            }
        }, 2000); // Longer timeout as final fallback
    }
}
	
    // Handle signup
    async handleSignup(e) {
		e.preventDefault();
		const name = document.getElementById('signup-name').value;
		const email = document.getElementById('signup-email').value;
		const password = document.getElementById('signup-password').value;
		const confirm = document.getElementById('signup-confirm').value;
		const terms = document.getElementById('terms').checked;
		
		// Validate
		if (!name.trim()) {
			auth.showErrorMessage('name_required');
			return;
		}
		
		if (!this.validateEmail(email)) {
			auth.showErrorMessage('invalid_email');
			return;
		}
		
		if (password.length < 6) {
			auth.showErrorMessage('password_length_error');
			return;
		}
		
		if (password !== confirm) {
			auth.showErrorMessage('password_mismatch');
			return;
		}
		
		if (!terms) {
			auth.showErrorMessage('accept_terms_error');
			return;
		}
		
        // Show loading
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + this.translate('creating_account');
        submitBtn.disabled = true;
		
        // Sign up
        const result = await auth.signUp(email, password, name);
		
        // Reset button
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
		
        if (result.success) {
            auth.showSuccessMessage('signup_success');
            this.showForm('login');
			} else {
            auth.showErrorMessage(result.error || 'signup_failed');
		}
	}
	
    // Handle reset password
    async handleResetPassword(e) {
		e.preventDefault();
		const email = document.getElementById('reset-email').value;
		
		if (!this.validateEmail(email)) {
			auth.showErrorMessage('invalid_email');
			return;
		}
		
        // Show loading
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + this.translate('sending_reset_link');
        submitBtn.disabled = true;
		
        // Send reset email
        const result = await auth.resetPassword(email);
		
        // Reset button
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
		
        if (result.success) {
            auth.showSuccessMessage('Password reset email sent! Please check your inbox.');
            this.showForm('login');
			} else {
            auth.showErrorMessage(result.error || 'Failed to send reset email. Please try again.');
		}
	}
	
    // Validate email
    validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
	}
	
    // Initialize password visibility toggles
    initPasswordToggles() {
        const toggleLogin = document.getElementById('toggle-login-password');
        const toggleSignup = document.getElementById('toggle-signup-password');
		
        if (toggleLogin) {
            toggleLogin.addEventListener('click', () => {
                this.togglePasswordVisibility('login-password', toggleLogin);
			});
		}
		
        if (toggleSignup) {
            toggleSignup.addEventListener('click', () => {
                this.togglePasswordVisibility('signup-password', toggleSignup);
			});
		}
    const toggleNewPassword = document.getElementById('toggle-new-password');
    if (toggleNewPassword) {
        toggleNewPassword.addEventListener('click', () => {
            this.togglePasswordVisibility('new-password', toggleNewPassword);
        });
    }
	}
	
    // Toggle password visibility
    togglePasswordVisibility(inputId, toggleBtn) {
        const input = document.getElementById(inputId);
        const icon = toggleBtn.querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
			} else {
            input.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
		}
	}
	
    // Save journal entry
    async saveJournalEntry(text, mood) {
        if (!auth.currentUser) return;
		
        try {
            const { error } = await supabase
			.from('journal_entries')
			.insert([
				{
					user_id: auth.currentUser.id,
					content: text,
					mood: mood,
					created_at: new Date().toISOString()
				}
			]);
			
            if (error) throw error;
			
            // Update user stats
            await this.updateUserStats('journal_entries');
			
            return { success: true };
			} catch (error) {
            console.error('Save journal error:', error);
            return { success: false, error: error.message };
		}
	}
	
    // Update user stats
    async updateUserStats(field) {
        if (!auth.currentUser) return;
		
        try {
            const { data: userData } = await supabase
			.from('users')
			.select(field)
			.eq('id', auth.currentUser.id)
			.single();
			
            if (userData) {
                const newValue = (userData[field] || 0) + 1;
                
                const { error } = await supabase
				.from('users')
				.update({ [field]: newValue })
				.eq('id', auth.currentUser.id);
				
                if (error) throw error;
			}
			} catch (error) {
            console.error('Update stats error:', error);
		}
	}
	
	// Handle password reset request
	async handlePasswordResetRequest(e) {
		e.preventDefault();
		const email = document.getElementById('reset-request-email').value;
		
		if (!this.validateEmail(email)) {
			auth.showErrorMessage('invalid_email');
			return;
		}
		
		// Show loading
		const submitBtn = e.target.querySelector('button[type="submit"]');
		const originalText = submitBtn.textContent;
		submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + this.translate('sending');
		submitBtn.disabled = true;
		
		// Send reset request
		const result = await auth.requestPasswordReset(email);
		
		// Reset button
		submitBtn.textContent = originalText;
		submitBtn.disabled = false;
		
		if (result.success) {
			auth.showSuccessMessage('reset_email_sent');
			// Optionally redirect or show success message
			setTimeout(() => {
				window.location.href = 'login.html';
			}, 3000);
			} else {
			auth.showErrorMessage(result.error || 'reset_request_failed');
		}
	}
	
	// Handle password update
	async handlePasswordUpdate(e) {
		e.preventDefault();
		const newPassword = document.getElementById('new-password').value;
		const confirmPassword = document.getElementById('confirm-new-password').value;
		
		if (newPassword.length < 6) {
			auth.showErrorMessage('password_length_error');
			return;
		}
		
		if (newPassword !== confirmPassword) {
			auth.showErrorMessage('password_mismatch');
			return;
		}
		
		// Show loading
		const submitBtn = e.target.querySelector('button[type="submit"]');
		const originalText = submitBtn.textContent;
		submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + this.translate('updating');
		submitBtn.disabled = true;
		
		// Update password
		const result = await auth.updatePassword(newPassword);
		
		// Reset button
		submitBtn.textContent = originalText;
		submitBtn.disabled = false;
		
		if (result.success) {
			// Show success message
			document.getElementById('reset-password-form').classList.remove('active');
			document.getElementById('reset-success').classList.add('active');
			} else {
			auth.showErrorMessage(result.error || 'password_update_failed');
		}
	}
}

// Initialize form manager
const forms = new FormManager();

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    // Journal save button
    const saveJournalBtn = document.getElementById('save-journal');
    if (saveJournalBtn) {
        saveJournalBtn.addEventListener('click', async () => {
            const text = document.getElementById('journal-text').value;
            const moodBtn = document.querySelector('.mood-btn.active');
            const mood = moodBtn ? moodBtn.dataset.mood : null;
            
            if (!text.trim()) {
                auth.showErrorMessage('journal_empty');
                return;
			}
            
            const result = await forms.saveJournalEntry(text, mood);
            if (result.success) {
                auth.showSuccessMessage('journal_saved');
                document.getElementById('journal-text').value = '';
                // Update entry count
                const entriesElement = document.getElementById('journal-entries');
                const currentCount = parseInt(entriesElement.textContent) || 0;
                entriesElement.textContent = currentCount + 1;
				} else {
                auth.showErrorMessage('journal_save_failed');
			}
		});
	}
	
    // Mood selector
    const moodBtns = document.querySelectorAll('.mood-btn');
    moodBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            moodBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
		});
	});
});