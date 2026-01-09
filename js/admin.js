// Admin functions
async function loadAdminData() {
    try {
        console.log('Loading admin data...');
        // This would fetch real data from Supabase
        // For now, simulate data
        document.getElementById('total-users').textContent = '42';
        document.getElementById('active-sessions').textContent = '15';
        document.getElementById('total-content').textContent = '28';
        
        // Simulate loading users table
        const usersTableBody = document.querySelector('#users-table tbody');
        if (usersTableBody) {
            usersTableBody.innerHTML = `
                <tr>
                    <td>1</td>
                    <td>John Doe</td>
                    <td>john@example.com</td>
                    <td>2024-01-01</td>
                    <td><span class="status-active">Active</span></td>
                    <td><button class="btn-sm">Edit</button></td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('Error loading admin data:', error);
    }
}

async function checkAdminAccess() {
    try {
        if (!window.auth || !window.auth.currentUser) {
            window.location.href = '../index.html';
            return;
        }
        
        const isAdmin = await window.auth.isAdmin();
        if (!isAdmin) {
            window.location.href = '../index.html';
        }
    } catch (error) {
        console.error('Error checking admin access:', error);
        window.location.href = '../index.html';
    }
}

async function addNewLanguage() {
    const name = document.getElementById('new-language-name').value;
    const code = document.getElementById('new-language-code').value;
    
    if (!name || !code) {
        alert('Please enter both language name and code');
        return;
    }
    
    if (window.i18n) {
        // This would normally save to Supabase
        alert(`Language ${name} (${code}) added successfully!`);
        document.getElementById('new-language-name').value = '';
        document.getElementById('new-language-code').value = '';
    } else {
        alert('i18n not initialized');
    }
}

// Make functions available globally
window.loadAdminData = loadAdminData;
window.checkAdminAccess = checkAdminAccess;
window.addNewLanguage = addNewLanguage;
window.logout = window.auth ? window.auth.signOut : () => {};