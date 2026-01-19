// Authentication functions for Fail2ban UI
"use strict";

let authEnabled = false;
let isAuthenticated = false;
let currentUser = null;

// Check authentication status on page load
async function checkAuthStatus() {
  // Immediately hide main content to prevent flash
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  if (mainContent) {
    mainContent.style.display = 'none';
  }
  if (nav) {
    nav.style.display = 'none';
  }
  
  try {
    const response = await fetch('/auth/status', {
      headers: serverHeaders()
    });
    
    if (!response.ok) {
      throw new Error('Failed to check auth status');
    }
    
    const data = await response.json();
    authEnabled = data.enabled || false;
    isAuthenticated = data.authenticated || false;
    
    if (authEnabled) {
      if (isAuthenticated && data.user) {
        currentUser = data.user;
        showAuthenticatedUI();
      } else {
        showLoginPage();
      }
    } else {
      // OIDC not enabled, show main content
      showMainContent();
    }
    
    return { enabled: authEnabled, authenticated: isAuthenticated, user: currentUser };
  } catch (error) {
    console.error('Error checking auth status:', error);
    // If auth check fails and we're on a protected route, show login
    if (authEnabled) {
      showLoginPage();
    } else {
      showMainContent();
    }
    return { enabled: false, authenticated: false, user: null };
  }
}

// Get current user info
async function getUserInfo() {
  try {
    const response = await fetch('/auth/user', {
      headers: serverHeaders()
    });
    
    if (!response.ok) {
      if (response.status === 401) {
        isAuthenticated = false;
        currentUser = null;
        showLoginPage();
        return null;
      }
      throw new Error('Failed to get user info');
    }
    
    const data = await response.json();
    if (data.authenticated && data.user) {
      currentUser = data.user;
      isAuthenticated = true;
      return data.user;
    }
    
    return null;
  } catch (error) {
    console.error('Error getting user info:', error);
    return null;
  }
}

// Handle login - redirect to login endpoint with action parameter
function handleLogin() {
  const loginLoading = document.getElementById('loginLoading');
  const loginError = document.getElementById('loginError');
  const loginErrorText = document.getElementById('loginErrorText');
  const loginButton = event?.target?.closest('button');
  
  // Show loading state
  if (loginLoading) loginLoading.classList.remove('hidden');
  if (loginButton) {
    loginButton.disabled = true;
    loginButton.classList.add('opacity-75', 'cursor-not-allowed');
  }
  
  // Hide error if shown
  if (loginError) {
    loginError.classList.add('hidden');
    if (loginErrorText) loginErrorText.textContent = '';
  }
  
  // Redirect to login endpoint with action=redirect to trigger OIDC redirect
  window.location.href = '/auth/login?action=redirect';
}

// Handle logout - use direct redirect instead of fetch to avoid CORS issues
function handleLogout() {
  // Clear local state
  isAuthenticated = false;
  currentUser = null;
  
  // Direct redirect to logout endpoint (server will handle redirect to provider)
  // Using window.location.href instead of fetch to avoid CORS issues with redirects
  window.location.href = '/auth/logout';
}

// Show login page
function showLoginPage() {
  const loginPage = document.getElementById('loginPage');
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  
  // Hide main content and nav immediately
  if (mainContent) {
    mainContent.style.display = 'none';
    mainContent.classList.add('hidden');
  }
  if (nav) {
    nav.style.display = 'none';
    nav.classList.add('hidden');
  }
  
  // Show login page
  if (loginPage) {
    loginPage.style.display = 'flex';
    loginPage.classList.remove('hidden');
  }
}

// Show main content (when authenticated or OIDC disabled)
function showMainContent() {
  const loginPage = document.getElementById('loginPage');
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  
  // Hide login page immediately
  if (loginPage) {
    loginPage.style.display = 'none';
    loginPage.classList.add('hidden');
  }
  
  // Show main content and nav
  if (mainContent) {
    mainContent.style.display = '';
    mainContent.classList.remove('hidden');
  }
  if (nav) {
    nav.style.display = '';
    nav.classList.remove('hidden');
  }
}

// Toggle user menu dropdown
function toggleUserMenu() {
  const dropdown = document.getElementById('userMenuDropdown');
  if (dropdown) {
    dropdown.classList.toggle('hidden');
  }
}

// Close user menu when clicking outside
document.addEventListener('click', function(event) {
  const userMenuButton = document.getElementById('userMenuButton');
  const userMenuDropdown = document.getElementById('userMenuDropdown');
  
  if (userMenuButton && userMenuDropdown && 
      !userMenuButton.contains(event.target) && 
      !userMenuDropdown.contains(event.target)) {
    userMenuDropdown.classList.add('hidden');
  }
});

// Show authenticated UI (update header with user info)
function showAuthenticatedUI() {
  showMainContent();
  
  const userInfoContainer = document.getElementById('userInfoContainer');
  const userDisplayName = document.getElementById('userDisplayName');
  const userMenuDisplayName = document.getElementById('userMenuDisplayName');
  const userMenuEmail = document.getElementById('userMenuEmail');
  const mobileUserInfoContainer = document.getElementById('mobileUserInfoContainer');
  const mobileUserDisplayName = document.getElementById('mobileUserDisplayName');
  const mobileUserEmail = document.getElementById('mobileUserEmail');
  
  if (userInfoContainer && currentUser) {
    userInfoContainer.classList.remove('hidden');
    
    const displayName = currentUser.name || currentUser.username || currentUser.email;
    
    if (userDisplayName) {
      userDisplayName.textContent = displayName;
    }
    
    if (userMenuDisplayName) {
      userMenuDisplayName.textContent = displayName;
    }
    
    if (userMenuEmail && currentUser.email) {
      userMenuEmail.textContent = currentUser.email;
    }
  }
  
  // Update mobile menu
  if (mobileUserInfoContainer && currentUser) {
    mobileUserInfoContainer.classList.remove('hidden');
    
    const displayName = currentUser.name || currentUser.username || currentUser.email;
    
    if (mobileUserDisplayName) {
      mobileUserDisplayName.textContent = displayName;
    }
    
    if (mobileUserEmail && currentUser.email) {
      mobileUserEmail.textContent = currentUser.email;
    }
  }
}

// Handle 401/403 responses from API
function handleAuthError(response) {
  if (response.status === 401 || response.status === 403) {
    if (authEnabled) {
      isAuthenticated = false;
      currentUser = null;
      showLoginPage();
      return true;
    }
  }
  return false;
}
