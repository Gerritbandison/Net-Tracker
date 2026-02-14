/**
 * NetMonDash Dashboard JavaScript (Enhanced)
 *
 * Client-side functionality for WebSocket connections, data updates, UI interactions,
 * dark mode, toast notifications, keyboard shortcuts, desktop notifications,
 * auto-refresh, data caching, skeleton loading states, and smooth transitions.
 */

// =============================================================================
// Global State
// =============================================================================

let ws = null;
let reconnectTimeout = null;
let isConnected = false;
let reconnectDelay = 1000; // Start at 1 second for exponential backoff
const RECONNECT_MAX_DELAY = 30000; // Max 30 seconds
let autoRefreshInterval = null;
const dataCache = new Map();
const DATA_CACHE_TTL = 60000; // 1 minute cache TTL

// =============================================================================
// localStorage Helpers
// =============================================================================

/**
 * Get a value from localStorage with a fallback default
 */
function getLocalSetting(key, defaultValue) {
    try {
        const stored = localStorage.getItem('netmondash_' + key);
        if (stored === null) {
            return defaultValue;
        }
        return JSON.parse(stored);
    } catch (e) {
        console.warn('Error reading localStorage key:', key, e);
        return defaultValue;
    }
}

/**
 * Save a value to localStorage
 */
function setLocalSetting(key, value) {
    try {
        localStorage.setItem('netmondash_' + key, JSON.stringify(value));
    } catch (e) {
        console.warn('Error writing localStorage key:', key, e);
    }
}

// =============================================================================
// Dark Mode
// =============================================================================

/**
 * Initialize dark mode from saved preference
 */
function initDarkMode() {
    const darkEnabled = getLocalSetting('darkMode', false);
    if (darkEnabled) {
        document.documentElement.setAttribute('data-theme', 'dark');
    } else {
        document.documentElement.removeAttribute('data-theme');
    }
    updateDarkModeToggleIcon(darkEnabled);
    injectDarkModeToggle();
}

/**
 * Toggle dark mode on/off and persist to localStorage
 */
function toggleDarkMode() {
    const currentlyDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const newState = !currentlyDark;

    if (newState) {
        document.documentElement.setAttribute('data-theme', 'dark');
    } else {
        document.documentElement.removeAttribute('data-theme');
    }

    setLocalSetting('darkMode', newState);
    updateDarkModeToggleIcon(newState);
}

/**
 * Update the dark mode toggle button icon (moon/sun)
 */
function updateDarkModeToggleIcon(isDark) {
    const btn = document.getElementById('dark-mode-toggle');
    if (!btn) return;

    if (isDark) {
        // Sun icon for "switch to light"
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
        btn.setAttribute('title', 'Switch to light mode');
    } else {
        // Moon icon for "switch to dark"
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
        btn.setAttribute('title', 'Switch to dark mode');
    }
}

/**
 * Inject the dark mode toggle button into the nav area if not already present
 */
function injectDarkModeToggle() {
    if (document.getElementById('dark-mode-toggle')) return;

    const btn = document.createElement('button');
    btn.id = 'dark-mode-toggle';
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Toggle dark mode');
    btn.style.cssText = 'background:none;border:none;cursor:pointer;padding:6px;border-radius:6px;display:inline-flex;align-items:center;justify-content:center;color:inherit;transition:background 0.2s;';
    btn.addEventListener('mouseenter', function () {
        this.style.background = 'rgba(128,128,128,0.15)';
    });
    btn.addEventListener('mouseleave', function () {
        this.style.background = 'none';
    });
    btn.addEventListener('click', toggleDarkMode);

    // Try to find a suitable nav container to insert into
    const nav = document.querySelector('nav') ||
                document.querySelector('[role="navigation"]') ||
                document.querySelector('.navbar') ||
                document.querySelector('header');

    if (nav) {
        // Insert near the end of the nav
        const navRight = nav.querySelector('.nav-right') ||
                         nav.querySelector('.navbar-end') ||
                         nav.querySelector('.ml-auto') ||
                         nav;
        navRight.appendChild(btn);
    } else {
        // Fallback: fixed position top-right
        btn.style.cssText += 'position:fixed;top:12px;right:60px;z-index:9999;';
        document.body.appendChild(btn);
    }

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    updateDarkModeToggleIcon(isDark);
}

// =============================================================================
// Toast Notification System
// =============================================================================

/**
 * Ensure the toast container exists in the DOM
 */
function ensureToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;top:16px;right:16px;z-index:10000;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:400px;';
        document.body.appendChild(container);
    }
    return container;
}

/**
 * Create and display a toast notification
 *
 * @param {string} message - The notification text
 * @param {string} type - One of: 'info', 'success', 'warning', 'error'
 * @param {number} duration - Auto-dismiss time in ms (default 5000)
 * @returns {HTMLElement} The toast element
 */
function createToast(message, type, duration) {
    if (typeof type === 'undefined') type = 'info';
    if (typeof duration === 'undefined') duration = 5000;

    const container = ensureToastContainer();

    // Enforce max 5 visible toasts
    const existing = container.querySelectorAll('.toast-item');
    if (existing.length >= 5) {
        removeToast(existing[0]);
    }

    // Color schemes per type
    const colors = {
        info:    { bg: '#3b82f6', text: '#ffffff', icon: 'i' },
        success: { bg: '#22c55e', text: '#ffffff', icon: '\u2713' },
        warning: { bg: '#f59e0b', text: '#ffffff', icon: '!' },
        error:   { bg: '#ef4444', text: '#ffffff', icon: '\u2717' }
    };
    const scheme = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.className = 'toast-item';
    toast.style.cssText = [
        'pointer-events:auto',
        'display:flex',
        'align-items:center',
        'gap:10px',
        'padding:12px 16px',
        'border-radius:8px',
        'box-shadow:0 4px 12px rgba(0,0,0,0.15)',
        'font-size:14px',
        'line-height:1.4',
        'min-width:280px',
        'max-width:400px',
        'opacity:0',
        'transform:translateX(40px)',
        'transition:opacity 0.3s ease, transform 0.3s ease',
        'background:' + scheme.bg,
        'color:' + scheme.text
    ].join(';') + ';';

    // Icon badge
    const iconSpan = document.createElement('span');
    iconSpan.style.cssText = 'flex-shrink:0;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold;font-size:14px;background:rgba(255,255,255,0.25);';
    iconSpan.textContent = scheme.icon;

    // Message text
    const textSpan = document.createElement('span');
    textSpan.style.cssText = 'flex:1;word-break:break-word;';
    textSpan.textContent = message;

    // Close button
    const closeBtn = document.createElement('button');
    closeBtn.style.cssText = 'flex-shrink:0;background:none;border:none;color:inherit;cursor:pointer;font-size:18px;line-height:1;padding:0 0 0 4px;opacity:0.8;';
    closeBtn.innerHTML = '&times;';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.addEventListener('click', function () {
        removeToast(toast);
    });

    toast.appendChild(iconSpan);
    toast.appendChild(textSpan);
    toast.appendChild(closeBtn);
    container.appendChild(toast);

    // Trigger slide-in animation
    requestAnimationFrame(function () {
        requestAnimationFrame(function () {
            toast.style.opacity = '1';
            toast.style.transform = 'translateX(0)';
        });
    });

    // Auto-dismiss
    if (duration > 0) {
        toast._dismissTimer = setTimeout(function () {
            removeToast(toast);
        }, duration);
    }

    return toast;
}

/**
 * Remove a toast element with a fade-out animation
 */
function removeToast(toastElement) {
    if (!toastElement || !toastElement.parentElement) return;

    if (toastElement._dismissTimer) {
        clearTimeout(toastElement._dismissTimer);
    }

    toastElement.style.opacity = '0';
    toastElement.style.transform = 'translateX(40px)';

    setTimeout(function () {
        if (toastElement.parentElement) {
            toastElement.remove();
        }
    }, 300);
}

// =============================================================================
// Skeleton Loading States
// =============================================================================

/**
 * Show a loading skeleton placeholder inside an element
 */
function showSkeleton(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;

    // Save original content so we can restore it later
    if (!el.hasAttribute('data-original-content')) {
        el.setAttribute('data-original-content', el.innerHTML);
    }

    const skeletonHTML = [
        '<div class="skeleton-container" style="display:flex;flex-direction:column;gap:12px;padding:8px;">',
        '  <div class="skeleton-line" style="height:16px;width:85%;border-radius:4px;background:linear-gradient(90deg,#e0e0e0 25%,#f0f0f0 50%,#e0e0e0 75%);background-size:200% 100%;animation:skeleton-shimmer 1.5s infinite;"></div>',
        '  <div class="skeleton-line" style="height:16px;width:65%;border-radius:4px;background:linear-gradient(90deg,#e0e0e0 25%,#f0f0f0 50%,#e0e0e0 75%);background-size:200% 100%;animation:skeleton-shimmer 1.5s infinite;animation-delay:0.1s;"></div>',
        '  <div class="skeleton-line" style="height:16px;width:75%;border-radius:4px;background:linear-gradient(90deg,#e0e0e0 25%,#f0f0f0 50%,#e0e0e0 75%);background-size:200% 100%;animation:skeleton-shimmer 1.5s infinite;animation-delay:0.2s;"></div>',
        '  <div class="skeleton-line" style="height:16px;width:55%;border-radius:4px;background:linear-gradient(90deg,#e0e0e0 25%,#f0f0f0 50%,#e0e0e0 75%);background-size:200% 100%;animation:skeleton-shimmer 1.5s infinite;animation-delay:0.3s;"></div>',
        '</div>'
    ].join('');

    el.innerHTML = skeletonHTML;
    el.classList.add('is-loading');

    // Inject keyframe animation if not already present
    injectSkeletonStyles();
}

/**
 * Hide the skeleton and restore or replace content in an element
 */
function hideSkeleton(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;

    el.classList.remove('is-loading');

    // If there is stored original content and the caller did not set new content,
    // we restore the original. The caller can also just replace innerHTML directly.
    const originalContent = el.getAttribute('data-original-content');
    if (originalContent !== null && el.querySelector('.skeleton-container')) {
        el.innerHTML = originalContent;
        el.removeAttribute('data-original-content');
    }
}

/**
 * Inject the CSS keyframes for skeleton shimmer if not already in the document
 */
function injectSkeletonStyles() {
    if (document.getElementById('skeleton-styles')) return;

    const style = document.createElement('style');
    style.id = 'skeleton-styles';
    style.textContent = [
        '@keyframes skeleton-shimmer {',
        '  0% { background-position: 200% 0; }',
        '  100% { background-position: -200% 0; }',
        '}',
        '.page-transition { transition: opacity 0.3s ease, transform 0.3s ease; }',
        '.page-transition-enter { opacity: 0; transform: translateY(8px); }',
        '.page-transition-active { opacity: 1; transform: translateY(0); }'
    ].join('\n');
    document.head.appendChild(style);
}

// =============================================================================
// API Call Wrapper with Retry Logic and Caching
// =============================================================================

/**
 * Make an API call with error handling, retry logic, and optional caching
 *
 * @param {string} url - The URL to fetch
 * @param {Object} options - Fetch options plus custom fields:
 *   options.retries {number} - Number of retries on failure (default 2)
 *   options.retryDelay {number} - Base delay between retries in ms (default 1000)
 *   options.useCache {boolean} - Whether to use cached response (default false)
 *   options.cacheTTL {number} - Cache TTL in ms (default DATA_CACHE_TTL)
 * @returns {Promise<Response>} The fetch response
 */
async function apiCall(url, options) {
    if (typeof options === 'undefined') options = {};

    const retries = typeof options.retries === 'number' ? options.retries : 2;
    const retryDelay = options.retryDelay || 1000;
    const useCache = options.useCache || false;
    const cacheTTL = options.cacheTTL || DATA_CACHE_TTL;

    // Strip custom keys before passing to fetch
    const fetchOptions = Object.assign({}, options);
    delete fetchOptions.retries;
    delete fetchOptions.retryDelay;
    delete fetchOptions.useCache;
    delete fetchOptions.cacheTTL;

    // Check cache first (only for GET requests or when no method specified)
    const method = (fetchOptions.method || 'GET').toUpperCase();
    if (useCache && method === 'GET') {
        const cached = dataCache.get(url);
        if (cached && (Date.now() - cached.timestamp) < cacheTTL) {
            return cached.response.clone();
        }
    }

    let lastError;
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const response = await fetch(url, fetchOptions);

            if (!response.ok) {
                throw new Error('HTTP ' + response.status + ': ' + response.statusText);
            }

            // Cache successful GET responses
            if (useCache && method === 'GET') {
                // Clone the response before caching so it can be read again
                dataCache.set(url, {
                    timestamp: Date.now(),
                    response: response.clone()
                });
            }

            return response;

        } catch (error) {
            lastError = error;
            console.warn('API call attempt ' + (attempt + 1) + ' failed for ' + url + ':', error.message);

            if (attempt < retries) {
                // Wait before retrying with linear backoff
                await new Promise(function (resolve) {
                    setTimeout(resolve, retryDelay * (attempt + 1));
                });
            }
        }
    }

    // All retries exhausted
    console.error('API call failed after ' + (retries + 1) + ' attempts:', url, lastError);
    throw lastError;
}

// =============================================================================
// Keyboard Shortcuts
// =============================================================================

/**
 * Handle keyboard shortcuts (only when not focused on input/textarea)
 */
function handleKeyboardShortcuts(event) {
    // Do not intercept when the user is typing in an input, textarea, or contenteditable
    const tag = event.target.tagName.toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || event.target.isContentEditable) {
        // Exception: Escape should still work inside inputs to close modals
        if (event.key === 'Escape') {
            closeOpenModals();
        }
        return;
    }

    // Ignore if modifier keys are held (Ctrl, Alt, Meta) except for specific combos
    if (event.ctrlKey || event.altKey || event.metaKey) {
        return;
    }

    switch (event.key) {
        case 'r':
            event.preventDefault();
            refreshData();
            break;

        case 'd':
            event.preventDefault();
            toggleDarkMode();
            break;

        case '/':
            event.preventDefault();
            focusSearchInput();
            break;

        case 'Escape':
            closeOpenModals();
            break;
    }
}

/**
 * Focus the search input if one exists on the page
 */
function focusSearchInput() {
    const searchInput = document.querySelector('input[type="search"]') ||
                        document.querySelector('input[name="search"]') ||
                        document.querySelector('input[placeholder*="earch"]') ||
                        document.querySelector('#search-input') ||
                        document.querySelector('.search-input');
    if (searchInput) {
        searchInput.focus();
        searchInput.select();
    }
}

/**
 * Close any open modal dialogs
 */
function closeOpenModals() {
    const modals = document.querySelectorAll('.modal.active, .modal.show, .modal[open], [data-modal].active, dialog[open]');
    modals.forEach(function (modal) {
        if (modal.tagName.toLowerCase() === 'dialog') {
            modal.close();
        } else {
            modal.classList.remove('active', 'show');
            modal.removeAttribute('open');
            modal.style.display = 'none';
        }
    });
}

// =============================================================================
// Desktop Notifications
// =============================================================================

/**
 * Request notification permission from the browser
 */
function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
}

/**
 * Send a desktop notification if permission is granted
 */
function sendDesktopNotification(title, body) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, {
            body: body,
            icon: '/static/img/icon.png',
            badge: '/static/img/badge.png'
        });
    }
}

// =============================================================================
// Auto-Refresh
// =============================================================================

/**
 * Start auto-refresh with a configurable interval from localStorage
 */
function startAutoRefresh() {
    stopAutoRefresh();

    const intervalMs = getLocalSetting('refreshInterval', 30000); // Default 30 seconds

    if (intervalMs > 0) {
        autoRefreshInterval = setInterval(function () {
            if (typeof refreshData === 'function') {
                refreshData();
            }
        }, intervalMs);
    }
}

/**
 * Stop the auto-refresh interval
 */
function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

// =============================================================================
// Smooth Page Transitions
// =============================================================================

/**
 * Apply a smooth transition effect when updating a container's content
 *
 * @param {string|HTMLElement} target - Element ID or element reference
 * @param {Function} updateFn - Callback that performs the actual content update
 */
function smoothTransition(target, updateFn) {
    const el = typeof target === 'string' ? document.getElementById(target) : target;
    if (!el) {
        if (typeof updateFn === 'function') updateFn();
        return;
    }

    el.classList.add('page-transition');
    el.style.opacity = '0';
    el.style.transform = 'translateY(8px)';

    setTimeout(function () {
        if (typeof updateFn === 'function') updateFn();

        requestAnimationFrame(function () {
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
        });
    }, 150);
}

// =============================================================================
// Confirm Dialog (Promise-based)
// =============================================================================

/**
 * Show a promise-based confirm dialog
 *
 * @param {string} message - The confirmation message to display
 * @returns {Promise<boolean>} Resolves true if confirmed, false if cancelled
 */
function showConfirmDialog(message) {
    return new Promise(function (resolve) {
        // Create overlay
        const overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:20000;opacity:0;transition:opacity 0.2s ease;';

        // Create dialog box
        const dialog = document.createElement('div');
        dialog.style.cssText = 'background:#fff;border-radius:12px;padding:24px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.2);transform:scale(0.95);transition:transform 0.2s ease;';

        // Check dark mode
        if (document.documentElement.getAttribute('data-theme') === 'dark') {
            dialog.style.background = '#1e293b';
            dialog.style.color = '#e2e8f0';
        }

        // Message
        const msgEl = document.createElement('p');
        msgEl.style.cssText = 'margin:0 0 20px 0;font-size:15px;line-height:1.5;';
        msgEl.textContent = message;

        // Button row
        const btnRow = document.createElement('div');
        btnRow.style.cssText = 'display:flex;gap:10px;justify-content:flex-end;';

        var cancelBtn = document.createElement('button');
        cancelBtn.textContent = 'Cancel';
        cancelBtn.style.cssText = 'padding:8px 18px;border-radius:6px;border:1px solid #d1d5db;background:transparent;cursor:pointer;font-size:14px;color:inherit;';

        var confirmBtn = document.createElement('button');
        confirmBtn.textContent = 'Confirm';
        confirmBtn.style.cssText = 'padding:8px 18px;border-radius:6px;border:none;background:#3b82f6;color:#fff;cursor:pointer;font-size:14px;font-weight:500;';

        btnRow.appendChild(cancelBtn);
        btnRow.appendChild(confirmBtn);
        dialog.appendChild(msgEl);
        dialog.appendChild(btnRow);
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);

        // Animate in
        requestAnimationFrame(function () {
            overlay.style.opacity = '1';
            dialog.style.transform = 'scale(1)';
        });

        function cleanup(result) {
            overlay.style.opacity = '0';
            dialog.style.transform = 'scale(0.95)';
            setTimeout(function () {
                overlay.remove();
            }, 200);
            resolve(result);
        }

        cancelBtn.addEventListener('click', function () { cleanup(false); });
        confirmBtn.addEventListener('click', function () { cleanup(true); });

        // Escape key cancels
        overlay.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') cleanup(false);
        });

        // Click outside cancels
        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) cleanup(false);
        });

        // Focus the confirm button for keyboard accessibility
        confirmBtn.focus();
    });
}

// =============================================================================
// Formatting Utilities
// =============================================================================

/**
 * Format date/time
 */
function formatDateTime(date) {
    const options = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    return date.toLocaleDateString('en-US', options);
}

/**
 * Format time ago (e.g., "5m ago", "2h ago")
 */
function formatTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);

    if (seconds < 60) {
        return 'just now';
    }

    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) {
        return minutes + 'm ago';
    }

    const hours = Math.floor(minutes / 60);
    if (hours < 24) {
        return hours + 'h ago';
    }

    const days = Math.floor(hours / 24);
    if (days < 7) {
        return days + 'd ago';
    }

    const weeks = Math.floor(days / 7);
    if (weeks < 4) {
        return weeks + 'w ago';
    }

    const months = Math.floor(days / 30);
    return months + 'mo ago';
}

/**
 * Format bytes to human-readable string (e.g., "1.5 MB")
 */
function formatBytes(bytes, decimals) {
    if (typeof decimals === 'undefined') decimals = 2;
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

/**
 * Format a number with comma separators (e.g., 1234 -> "1,234")
 */
function formatNumber(num) {
    if (num === null || typeof num === 'undefined') return '0';
    return Number(num).toLocaleString('en-US');
}

/**
 * Format a duration in seconds to a human-readable string (e.g., "2m 30s")
 */
function formatDuration(seconds) {
    if (typeof seconds !== 'number' || isNaN(seconds) || seconds < 0) return '0s';

    seconds = Math.floor(seconds);

    if (seconds === 0) return '0s';

    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    const parts = [];
    if (days > 0) parts.push(days + 'd');
    if (hours > 0) parts.push(hours + 'h');
    if (minutes > 0) parts.push(minutes + 'm');
    if (secs > 0 || parts.length === 0) parts.push(secs + 's');

    return parts.join(' ');
}

/**
 * Return a CSS color string for a security score (0-100)
 *
 * 0-39: red, 40-69: orange/amber, 70-89: yellow-green, 90-100: green
 */
function getSecurityScoreColor(score) {
    if (typeof score !== 'number' || isNaN(score)) return '#9ca3af'; // gray fallback

    if (score < 40) return '#ef4444';   // red
    if (score < 70) return '#f59e0b';   // amber
    if (score < 90) return '#84cc16';   // lime/yellow-green
    return '#22c55e';                    // green
}

/**
 * Get formatted timestamp for filenames
 */
function getTimestamp() {
    var now = new Date();
    return now.toISOString().replace(/[:.]/g, '-').substring(0, 19);
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Debounce function - delays execution until after wait ms have passed
 */
function debounce(func, wait) {
    var timeout;
    return function executedFunction() {
        var context = this;
        var args = arguments;
        var later = function () {
            clearTimeout(timeout);
            func.apply(context, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Copy text to clipboard using modern API with fallback
 */
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () {
            showNotification('Copied to clipboard', 'success');
        }).catch(function (err) {
            console.error('Failed to copy:', err);
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

/**
 * Fallback copy to clipboard using textarea + execCommand
 */
function fallbackCopyToClipboard(text) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();

    try {
        document.execCommand('copy');
        showNotification('Copied to clipboard', 'success');
    } catch (err) {
        console.error('Fallback copy failed:', err);
        showNotification('Failed to copy', 'error');
    }

    document.body.removeChild(textarea);
}

// =============================================================================
// WebSocket Connection Management
// =============================================================================

/**
 * Connect to WebSocket server
 */
function connectWebSocket() {
    var protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    var wsUrl = protocol + '//' + window.location.host + '/ws';

    console.log('Connecting to WebSocket: ' + wsUrl);

    try {
        ws = new WebSocket(wsUrl);

        ws.onopen = handleWebSocketOpen;
        ws.onmessage = handleWebSocketMessage;
        ws.onerror = handleWebSocketError;
        ws.onclose = handleWebSocketClose;

    } catch (error) {
        console.error('WebSocket connection error:', error);
        updateConnectionStatus('disconnected');
        scheduleReconnect();
    }
}

/**
 * Handle WebSocket connection open
 */
function handleWebSocketOpen() {
    console.log('WebSocket connected');
    isConnected = true;
    reconnectDelay = 1000; // Reset backoff on successful connection
    updateConnectionStatus('connected');

    // Clear reconnect timeout
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }

    // Subscribe to all updates
    sendWebSocketMessage({
        type: 'subscribe',
        channel: 'all'
    });
}

/**
 * Handle incoming WebSocket messages
 */
function handleWebSocketMessage(event) {
    try {
        var message = JSON.parse(event.data);
        console.log('WebSocket message received:', message.type);

        switch (message.type) {
            case 'connected':
                console.log('WebSocket connection confirmed');
                break;

            case 'pong':
                // Heartbeat response
                break;

            case 'scan_update':
                handleScanUpdate(message.data);
                break;

            case 'device_update':
                handleDeviceUpdate(message.data, message.event);
                break;

            case 'alert':
                handleNewAlert(message.data);
                break;

            case 'stats':
                handleStatsUpdate(message.data);
                break;

            case 'heartbeat':
                // Send ping response
                sendWebSocketMessage({ type: 'ping' });
                break;

            default:
                console.log('Unknown message type:', message.type);
        }

    } catch (error) {
        console.error('Error parsing WebSocket message:', error);
    }
}

/**
 * Handle WebSocket errors
 */
function handleWebSocketError(error) {
    console.error('WebSocket error:', error);
    updateConnectionStatus('disconnected');
}

/**
 * Handle WebSocket connection close
 */
function handleWebSocketClose() {
    console.log('WebSocket disconnected');
    isConnected = false;
    updateConnectionStatus('disconnected');
    scheduleReconnect();
}

/**
 * Send message via WebSocket
 */
function sendWebSocketMessage(message) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
    } else {
        console.warn('WebSocket not connected, cannot send message');
    }
}

/**
 * Schedule WebSocket reconnection with exponential backoff
 *
 * Backoff sequence: 1s, 2s, 4s, 8s, 16s, 30s (max)
 * Resets to 1s on successful connection (in handleWebSocketOpen).
 */
function scheduleReconnect() {
    if (reconnectTimeout) {
        return; // Already scheduled
    }

    var delay = reconnectDelay;
    console.log('Scheduling WebSocket reconnection in ' + (delay / 1000) + 's...');
    updateConnectionStatus('connecting');

    reconnectTimeout = setTimeout(function () {
        reconnectTimeout = null;
        connectWebSocket();
    }, delay);

    // Increase delay for next attempt (exponential backoff, capped at max)
    reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_DELAY);
}

/**
 * Update connection status indicator in the UI
 */
function updateConnectionStatus(status) {
    var indicator = document.getElementById('status-indicator');
    var text = document.getElementById('status-text');

    if (!indicator || !text) return;

    indicator.className = 'h-3 w-3 rounded-full';

    switch (status) {
        case 'connected':
            indicator.classList.add('bg-green-500');
            text.textContent = 'Connected';
            break;
        case 'connecting':
            indicator.classList.add('bg-yellow-500');
            text.textContent = 'Connecting...';
            break;
        case 'disconnected':
            indicator.classList.add('bg-red-500');
            text.textContent = 'Disconnected';
            break;
    }
}

// =============================================================================
// WebSocket Event Handlers
// =============================================================================

/**
 * Handle scan update from WebSocket
 */
function handleScanUpdate(data) {
    console.log('Scan update received:', data);
    showNotification('Scan complete: ' + data.device_count + ' devices found', 'info');

    // Refresh current page data
    if (typeof refreshData === 'function') {
        refreshData();
    }
}

/**
 * Handle device update from WebSocket
 */
function handleDeviceUpdate(device, event) {
    console.log('Device update:', event, device);

    if (event === 'new') {
        showNotification('New device detected: ' + device.ip, 'info');
        sendDesktopNotification('New Device Detected', 'IP: ' + device.ip);
    }

    // Refresh device list if on devices page
    if (typeof loadDevices === 'function') {
        loadDevices();
    }
}

/**
 * Handle new alert from WebSocket
 */
function handleNewAlert(alert) {
    console.log('New alert:', alert);

    var severity = alert.severity || 'info';
    showNotification(alert.title + ': ' + alert.message, severity);

    // Send desktop notification for critical/error severity alerts
    if (severity === 'error' || severity === 'critical' || severity === 'warning') {
        sendDesktopNotification(
            'NetMonDash Alert: ' + alert.title,
            alert.message
        );
    }

    // Refresh alerts if on insights page
    if (typeof loadAlerts === 'function') {
        loadAlerts();
    }
}

/**
 * Handle stats update from WebSocket
 */
function handleStatsUpdate(stats) {
    console.log('Stats update:', stats);

    // Update stats display if elements exist, using smooth transitions
    var totalDevicesEl = document.getElementById('total-devices');
    var onlineDevicesEl = document.getElementById('online-devices');
    var alertCountEl = document.getElementById('alert-count');

    if (totalDevicesEl) {
        smoothTransition(totalDevicesEl, function () {
            totalDevicesEl.textContent = formatNumber(stats.total_devices || 0);
        });
    }
    if (onlineDevicesEl) {
        smoothTransition(onlineDevicesEl, function () {
            onlineDevicesEl.textContent = formatNumber(stats.online_devices || 0);
        });
    }
    if (alertCountEl) {
        smoothTransition(alertCountEl, function () {
            alertCountEl.textContent = formatNumber(stats.unacknowledged_alerts || 0);
        });
    }
}

// =============================================================================
// Data Refresh and Export
// =============================================================================

/**
 * Refresh current page data
 */
function refreshData() {
    console.log('Refreshing data...');

    // Trigger page-specific refresh function
    if (typeof loadOverviewData === 'function') {
        loadOverviewData();
    } else if (typeof loadDevices === 'function') {
        loadDevices();
    } else if (typeof loadWiFiMetrics === 'function') {
        loadWiFiMetrics();
    }

    showNotification('Data refreshed', 'success');
}

/**
 * Export data to file
 */
async function exportData(dataType, format) {
    try {
        var response = await apiCall('/api/export?data_type=' + encodeURIComponent(dataType) + '&format=' + encodeURIComponent(format), {
            retries: 2,
            retryDelay: 1000
        });

        if (format === 'json') {
            var data = await response.json();
            var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            downloadBlob(blob, 'netmondash_' + dataType + '_' + getTimestamp() + '.json');
        } else if (format === 'csv') {
            var csvBlob = await response.blob();
            downloadBlob(csvBlob, 'netmondash_' + dataType + '_' + getTimestamp() + '.csv');
        }

        showNotification('Data exported successfully', 'success');

    } catch (error) {
        console.error('Export error:', error);
        showNotification('Export failed: ' + error.message, 'error');
    }
}

/**
 * Download blob as file
 */
function downloadBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// =============================================================================
// Show Notification (backwards-compatible wrapper)
// =============================================================================

/**
 * Show notification - uses the new toast system
 */
function showNotification(message, type) {
    if (typeof type === 'undefined') type = 'info';
    createToast(message, type, 5000);
}

// =============================================================================
// Dashboard Initialization
// =============================================================================

/**
 * Initialize dashboard on page load
 */
function initializeDashboard() {
    console.log('Initializing NetMonDash dashboard...');

    // Inject skeleton animation styles early
    injectSkeletonStyles();

    // Initialize dark mode from saved preference
    initDarkMode();

    // Set up toast notification container
    ensureToastContainer();

    // Request notification permission
    requestNotificationPermission();

    // Connect to WebSocket
    connectWebSocket();

    // Set up auto-refresh with configurable interval
    startAutoRefresh();

    // Register keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);

    console.log('Dashboard initialized');
}

// =============================================================================
// Bootstrap
// =============================================================================

// Initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDashboard);
} else {
    initializeDashboard();
}

// Clean up on page unload
window.addEventListener('beforeunload', function () {
    if (ws) {
        ws.close();
    }
    stopAutoRefresh();
});
