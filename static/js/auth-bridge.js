// Authentication Bridge for Roxli Account System

class AuthBridge {
    constructor() {
        this.mainAuthUrl = 'https://auth.roxli.in';
        this.checkAuth();
    }

    async checkAuth() {
        try {
            // First check if we have a token in cookies
            const token = this.getCookie('roxli_token');
            
            if (token) {
                // Verify token with main auth system
                const response = await fetch(`${this.mainAuthUrl}/api/verify`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    if (data.valid) {
                        // Token is valid, user is authenticated
                        return true;
                    }
                }
            }
            
            // No valid token
            return false;
            
        } catch (error) {
            console.error('Auth check failed:', error);
            return false;
        }
    }

    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    redirectToLogin() {
        // Don't redirect automatically - let the server handle it
        console.log('Authentication required');
    }

    async loginWithPopup() {
        return new Promise((resolve, reject) => {
            const popup = window.open(
                `${this.mainAuthUrl}/popup`,
                'roxli-auth',
                'width=400,height=600,scrollbars=yes,resizable=yes'
            );

            const messageHandler = (event) => {
                if (event.origin !== this.mainAuthUrl) return;

                if (event.data.type === 'ROXLI_AUTH_SUCCESS') {
                    popup.close();
                    window.removeEventListener('message', messageHandler);
                    // Reload page to get new auth state
                    window.location.reload();
                    resolve(true);
                } else if (event.data.type === 'ROXLI_AUTH_ERROR') {
                    popup.close();
                    window.removeEventListener('message', messageHandler);
                    reject(new Error(event.data.error || 'Authentication failed'));
                }
            };

            window.addEventListener('message', messageHandler);

            // Check if popup was closed manually
            const checkClosed = setInterval(() => {
                if (popup.closed) {
                    clearInterval(checkClosed);
                    window.removeEventListener('message', messageHandler);
                    reject(new Error('Authentication cancelled'));
                }
            }, 1000);
        });
    }
}

// Profile Dropdown Management
class ProfileDropdown {
    constructor() {
        this.dropdown = document.querySelector('.profile-dropdown');
        this.dropdownBtn = document.getElementById('profileDropdownBtn');
        this.dropdownMenu = document.getElementById('profileDropdownMenu');
        this.accountsList = document.getElementById('accountsList');
        
        if (this.dropdownBtn && this.dropdownMenu) {
            this.init();
        }
    }
    
    getLoggedInAccounts() {
        const accounts = localStorage.getItem('roxli_logged_accounts');
        return accounts ? JSON.parse(accounts) : [];
    }
    
    addLoggedInAccount(email) {
        const accounts = this.getLoggedInAccounts();
        if (!accounts.includes(email)) {
            accounts.push(email);
            localStorage.setItem('roxli_logged_accounts', JSON.stringify(accounts));
        }
    }
    
    removeLoggedInAccount(email) {
        const accounts = this.getLoggedInAccounts();
        const filtered = accounts.filter(acc => acc !== email);
        localStorage.setItem('roxli_logged_accounts', JSON.stringify(filtered));
    }
    
    init() {
        // Toggle dropdown on button click
        this.dropdownBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggle();
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!this.dropdown.contains(e.target)) {
                this.close();
            }
        });
        
        // Load accounts when dropdown opens
        this.dropdownBtn.addEventListener('click', () => {
            this.loadAccounts();
        });
    }
    
    toggle() {
        this.dropdown.classList.toggle('open');
    }
    
    close() {
        this.dropdown.classList.remove('open');
    }
    
    async loadAccounts() {
        try {
            const loggedInEmails = this.getLoggedInAccounts();
            const emailParams = loggedInEmails.map(email => `emails=${encodeURIComponent(email)}`).join('&');
            const response = await fetch(`/api/available-accounts?${emailParams}`);
            if (response.ok) {
                const data = await response.json();
                this.renderAccounts(data.accounts, data.currentUser);
            }
        } catch (error) {
            console.error('Failed to load accounts:', error);
        }
    }
    
    renderAccounts(accounts, currentUser) {
        if (!this.accountsList) return;
        
        this.accountsList.innerHTML = '';
        
        if (!accounts || accounts.length === 0) {
            this.accountsList.innerHTML = '<div style="padding: 1rem; text-align: center; color: var(--text-muted);">No accounts available</div>';
            return;
        }
        
        accounts.forEach(account => {
            const isCurrent = account.email === currentUser.email;
            const accountItem = document.createElement('button');
            accountItem.className = `account-item ${isCurrent ? 'current' : ''}`;
            accountItem.onclick = () => this.switchAccount(account.email);
            
            // Determine if we should show image or initials
            const hasValidAvatar = account.avatar && 
                                 account.avatar !== '' && 
                                 !account.avatar.includes('data:image/svg+xml') &&
                                 account.avatar !== 'https://www.w3schools.com/howto/img_avatar.png';
            
            const initials = `${account.firstName[0] || 'U'}${account.lastName[0] || 'U'}`;
            
            accountItem.innerHTML = `
                <div class="account-avatar-wrapper" style="position: relative; width: 32px; height: 32px;">
                    ${hasValidAvatar ? 
                        `<img src="${account.avatar}" alt="${account.firstName}" class="account-avatar" style="width: 32px; height: 32px; border-radius: 50%; object-fit: cover;" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">` : 
                        ''
                    }
                    <div class="profile-initials" style="background: linear-gradient(135deg, #667eea, #764ba2); display: ${hasValidAvatar ? 'none' : 'flex'}; align-items: center; justify-content: center; font-size: 14px; font-weight: bold; color: white; width: 32px; height: 32px; border-radius: 50%; position: ${hasValidAvatar ? 'absolute' : 'static'}; top: 0; left: 0;">
                        ${initials}
                    </div>
                </div>
                <div class="account-info">
                    <div class="account-name">${account.firstName} ${account.lastName}</div>
                    <div class="account-email">${account.email}</div>
                </div>
                ${isCurrent ? '<i class="fas fa-check" style="color: var(--primary); margin-left: auto;"></i>' : ''}
            `;
            
            this.accountsList.appendChild(accountItem);
        });
    }
    
    async switchAccount(email) {
        try {
            // If switching to current user, just close dropdown
            const currentUserResponse = await fetch('/api/user');
            if (currentUserResponse.ok) {
                const currentUserData = await currentUserResponse.json();
                if (currentUserData.user && currentUserData.user.email === email) {
                    this.close();
                    return;
                }
            }
            
            // Use local switch account API
            const response = await fetch('/api/switch-account', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.success) {
                    // Reload page to update UI
                    window.location.reload();
                } else {
                    alert(data.error || 'Failed to switch account');
                }
            } else {
                const errorData = await response.json();
                alert(errorData.error || 'Failed to switch account');
            }
        } catch (error) {
            console.error('Account switch failed:', error);
            alert('Failed to switch account. Please try again.');
        }
        
        this.close();
    }
}

// Global functions for dropdown actions
window.addAccount = function() {
    const popup = window.open('https://auth.roxli.in/popup', 'roxli-auth', 'width=400,height=600,scrollbars=yes,resizable=yes');
    
    const messageHandler = (event) => {
        if (event.origin !== 'https://auth.roxli.in') return;
        
        if (event.data.type === 'ROXLI_AUTH_SUCCESS') {
            popup.close();
            window.removeEventListener('message', messageHandler);
            
            // Set the token in cookies and call set-token API
            if (event.data.token) {
                document.cookie = `roxli_token=${event.data.token}; path=/; SameSite=Lax`;
                
                // Also set token via API to ensure session is created
                fetch('/api/set-token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: event.data.token })
                }).catch(console.error);
            }
            
            // Add new account to logged-in accounts
            if (event.data.user && event.data.user.email) {
                window.profileDropdown.addLoggedInAccount(event.data.user.email);
            }
            
            // Reload page to update UI
            window.location.reload();
        }
    };
    
    window.addEventListener('message', messageHandler);
};

window.signOutCurrent = function() {
    if (confirm('Are you sure you want to sign out?')) {
        // Get current user email to remove from logged-in accounts
        fetch('/api/user')
            .then(response => response.json())
            .then(data => {
                if (data.user && data.user.email) {
                    window.profileDropdown.removeLoggedInAccount(data.user.email);
                }
            })
            .catch(() => {});
        
        fetch('https://auth.roxli.in/api/logout', { method: 'POST' })
            .then(() => {
                document.cookie = 'roxli_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                window.location.href = 'https://auth.roxli.in';
            })
            .catch(error => {
                console.error('Logout failed:', error);
                // Force logout anyway
                document.cookie = 'roxli_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                window.location.href = 'https://auth.roxli.in';
            });
    }
};

// Initialize auth bridge when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.authBridge = new AuthBridge();
    window.profileDropdown = new ProfileDropdown();
    
    // Track current user in logged-in accounts
    fetch('/api/user')
        .then(response => response.json())
        .then(data => {
            if (data.user && data.user.email && window.profileDropdown) {
                window.profileDropdown.addLoggedInAccount(data.user.email);
            }
        })
        .catch(() => {});
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthBridge;
}