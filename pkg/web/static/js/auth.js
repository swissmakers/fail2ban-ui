// Auth flow for Fail2ban UI.
"use strict";

// =========================================================================
//  Global Variables
// =========================================================================

let authEnabled = false;
let isAuthenticated = false;
let currentUser = null;

// =========================================================================
//  Check Authentication Status
// =========================================================================

async function checkAuthStatus() {
  // Both login page and main content are hidden by default
  // We'll show the appropriate one based on authentication status
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  const loginPage = document.getElementById('loginPage');
  const footer = document.getElementById('footer');
  if (loginPage) {
    loginPage.classList.add('hidden');
    loginPage.style.display = 'none';
  }
  if (mainContent) {
    mainContent.classList.add('hidden');
    mainContent.style.display = 'none';
  }
  if (nav) {
    nav.classList.add('hidden');
    nav.style.display = 'none';
  }
  if (footer) {
    footer.classList.add('hidden');
    footer.style.display = 'none';
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
    const skipLoginPageFlag = data.skipLoginPage || false;

    if (authEnabled) {
      if (isAuthenticated && data.user) {
        // Authenticated: show main content, hide login page
        currentUser = data.user;
        showAuthenticatedUI();
      } else {
        // Not authenticated
        if (skipLoginPageFlag) {
          window.location.href = '/auth/login';
          return { enabled: authEnabled, authenticated: false, user: null };
        } else {
          // Show login page, hide main content
          showLoginPage();
        }
      }
    } else {
      // OIDC not enabled: show main content, hide login page
      showMainContent();
    }

    return { enabled: authEnabled, authenticated: isAuthenticated, user: currentUser };
  } catch (error) {
    console.error('Error checking auth status:', error);
    const oidcEnabled = document.body.getAttribute('data-oidc-enabled') === 'true';
    const skipLoginPage = document.body.getAttribute('data-skip-login-page') === 'true';

    if (oidcEnabled) {
      if (skipLoginPage) {
        window.location.href = '/auth/login';
      } else {
        showLoginPage();
      }
    } else {
      showMainContent();
    }
    return { enabled: false, authenticated: false, user: null };
  }
}

// =========================================================================
//  Handle Login and Logout
// =========================================================================

function handleLogin() {
  const loginLoading = document.getElementById('loginLoading');
  const loginError = document.getElementById('loginError');
  const loginErrorText = document.getElementById('loginErrorText');
  const loginButton = event?.target?.closest('button');

  if (loginLoading) loginLoading.classList.remove('hidden');
  if (loginButton) {
    loginButton.disabled = true;
    loginButton.classList.add('opacity-75', 'cursor-not-allowed');
  }

  if (loginError) {
    loginError.classList.add('hidden');
    if (loginErrorText) loginErrorText.textContent = '';
  }
  window.location.href = '/auth/login?action=redirect';
}

function handleLogout() {
  // Clear authentication status and redirect to logout endpoint
  isAuthenticated = false;
  currentUser = null;
  window.location.href = '/auth/logout';
}

// =========================================================================
//  Show Different Application States (Login, Main Content, etc.)
// =========================================================================

function showLoginPage() {
  const loginPage = document.getElementById('loginPage');
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  const footer = document.getElementById('footer');
  
  // Hide main content
  if (mainContent) {
    mainContent.style.display = 'none';
    mainContent.classList.add('hidden');
  }
  if (nav) {
    nav.style.display = 'none';
    nav.classList.add('hidden');
  }
  if (footer) {
    footer.style.display = 'none';
    footer.classList.add('hidden');
  }
  
  // Show login page
  if (loginPage) {
    loginPage.style.display = 'flex';
    loginPage.classList.remove('hidden');
  }
}

function showMainContent() {
  const loginPage = document.getElementById('loginPage');
  const mainContent = document.getElementById('mainContent');
  const nav = document.querySelector('nav');
  const footer = document.getElementById('footer');
  
  // Hide login page
  if (loginPage) {
    loginPage.style.display = 'none';
    loginPage.classList.add('hidden');
  }
  
  // Show main content
  if (mainContent) {
    mainContent.style.display = 'block';
    mainContent.classList.remove('hidden');
  }
  if (nav) {
    nav.style.display = 'block';
    nav.classList.remove('hidden');
  }
  if (footer) {
    footer.style.display = 'block';
    footer.classList.remove('hidden');
  }
}

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

// =========================================================================
//  Helper Functions
// =========================================================================

function toggleUserMenu() {
  const dropdown = document.getElementById('userMenuDropdown');
  if (dropdown) {
    dropdown.classList.toggle('hidden');
  }
}

document.addEventListener('click', function(event) {
  const userMenuButton = document.getElementById('userMenuButton');
  const userMenuDropdown = document.getElementById('userMenuDropdown');

  if (userMenuButton && userMenuDropdown &&
      !userMenuButton.contains(event.target) &&
      !userMenuDropdown.contains(event.target)) {
    userMenuDropdown.classList.add('hidden');
  }
});
