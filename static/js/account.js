// Account Management JavaScript

// Enhanced Theme Management
function initTheme() {
    const savedTheme = localStorage.getItem('roxli-theme');
    const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    const theme = savedTheme || systemTheme;
    
    document.documentElement.setAttribute('data-theme', theme);
    
    // Add smooth transition for theme changes
    document.documentElement.style.setProperty('--transition-theme', 'background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease');
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('roxli-theme', newTheme);
}

// Auto-detect system theme changes
function watchSystemTheme() {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    mediaQuery.addEventListener('change', (e) => {
        if (!localStorage.getItem('roxli-theme')) {
            const theme = e.matches ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', theme);
        }
    });
}

// Mobile sidebar toggle
document.addEventListener('DOMContentLoaded', function() {
    // Initialize enhanced theme system
    initTheme();
    watchSystemTheme();
    
    // Theme functionality remains automatic
    
    // System theme changes are now handled by watchSystemTheme()
    
    // Mobile sidebar
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    
    function openSidebar() {
        sidebar.classList.add('open');
        sidebarOverlay.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
    
    function closeSidebar() {
        sidebar.classList.remove('open');
        sidebarOverlay.classList.remove('active');
        document.body.style.overflow = '';
    }
    
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', openSidebar);
    }
    
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', closeSidebar);
    }
    
    // Close sidebar on escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && sidebar.classList.contains('open')) {
            closeSidebar();
        }
    });
    
    // Set active nav link for all navigation types
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link, .mobile-nav-item, .tablet-nav-link, .desktop-nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
    
    // Mobile navigation active state
    const mobileNavItems = document.querySelectorAll('.mobile-nav-item');
    mobileNavItems.forEach(item => {
        if (item.getAttribute('href') === currentPath) {
            item.classList.add('active');
        }
    });
});

// Handle popup authentication messages
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://auth.roxli.in') return;
    
    if (event.data.type === 'ROXLI_AUTH_SUCCESS') {
        // Set the token in cookies and call set-token API
        if (event.data.token) {
            document.cookie = `roxli_token=${event.data.token}; path=/; SameSite=Lax`;
            
            // Set token via API to ensure session is created
            fetch('/api/set-token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: event.data.token })
            }).then(() => {
                // Add new account to logged-in accounts
                if (event.data.user && event.data.user.email && window.profileDropdown) {
                    window.profileDropdown.addLoggedInAccount(event.data.user.email);
                }
                // Reload page to update authentication state
                window.location.reload();
            }).catch(console.error);
        } else {
            // Fallback: just reload
            window.location.reload();
        }
    }
});

// Utility functions
function showLoading(element) {
    if (element) {
        element.innerHTML = '<span class="loading"><span class="spinner"></span> Loading...</span>';
        element.disabled = true;
    }
}

function hideLoading(element, originalText) {
    if (element) {
        element.innerHTML = originalText;
        element.disabled = false;
    }
}

function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    
    const container = document.querySelector('.content-wrapper') || document.body;
    container.insertBefore(alertDiv, container.firstChild);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Export functions for global use
window.showLoading = showLoading;
window.hideLoading = hideLoading;
window.showAlert = showAlert;