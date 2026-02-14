/**
 * NetMonDash Dashboard JavaScript (v2.0 Enhanced)
 *
 * Client-side functionality: WebSocket, charts, real-time data, offline caching,
 * dark mode, toast notifications, keyboard shortcuts, desktop notifications,
 * auto-refresh, pagination, trend rendering, risk display, and smooth transitions.
 */

// =============================================================================
// Global State
// =============================================================================

let ws = null;
let reconnectTimeout = null;
let isConnected = false;
let reconnectDelay = 1000;
const RECONNECT_MAX_DELAY = 30000;
let autoRefreshInterval = null;
const dataCache = new Map();
const DATA_CACHE_TTL = 60000;
const DB_NAME = 'NetMonDashCache';
const DB_VERSION = 1;
let offlineDB = null;

// =============================================================================
// IndexedDB Offline Cache
// =============================================================================

function openOfflineDB() {
    return new Promise(function (resolve, reject) {
        if (offlineDB) { resolve(offlineDB); return; }
        if (!window.indexedDB) { resolve(null); return; }

        var request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = function (e) {
            var db = e.target.result;
            if (!db.objectStoreNames.contains('apiCache')) {
                db.createObjectStore('apiCache', { keyPath: 'url' });
            }
            if (!db.objectStoreNames.contains('trendData')) {
                db.createObjectStore('trendData', { keyPath: 'key' });
            }
        };
        request.onsuccess = function (e) {
            offlineDB = e.target.result;
            resolve(offlineDB);
        };
        request.onerror = function () { resolve(null); };
    });
}

async function cacheToIDB(storeName, key, data) {
    try {
        var db = await openOfflineDB();
        if (!db) return;
        var tx = db.transaction(storeName, 'readwrite');
        var store = tx.objectStore(storeName);
        store.put({ url: key, key: key, data: data, timestamp: Date.now() });
    } catch (e) { /* silently fail */ }
}

async function getFromIDB(storeName, key, maxAge) {
    try {
        var db = await openOfflineDB();
        if (!db) return null;
        return new Promise(function (resolve) {
            var tx = db.transaction(storeName, 'readonly');
            var store = tx.objectStore(storeName);
            var request = store.get(key);
            request.onsuccess = function () {
                var result = request.result;
                if (!result) { resolve(null); return; }
                if (maxAge && (Date.now() - result.timestamp) > maxAge) { resolve(null); return; }
                resolve(result.data);
            };
            request.onerror = function () { resolve(null); };
        });
    } catch (e) { return null; }
}

// =============================================================================
// localStorage Helpers
// =============================================================================

function getLocalSetting(key, defaultValue) {
    try {
        var stored = localStorage.getItem('netmondash_' + key);
        if (stored === null) return defaultValue;
        return JSON.parse(stored);
    } catch (e) {
        return defaultValue;
    }
}

function setLocalSetting(key, value) {
    try {
        localStorage.setItem('netmondash_' + key, JSON.stringify(value));
    } catch (e) { /* silently fail */ }
}

// =============================================================================
// Dark Mode
// =============================================================================

function initDarkMode() {
    var darkEnabled = getLocalSetting('darkMode', false);
    if (darkEnabled) {
        document.documentElement.setAttribute('data-theme', 'dark');
    } else {
        document.documentElement.removeAttribute('data-theme');
    }
    updateDarkModeToggleIcon(darkEnabled);
    injectDarkModeToggle();
}

function toggleDarkMode() {
    var currentlyDark = document.documentElement.getAttribute('data-theme') === 'dark';
    var newState = !currentlyDark;
    if (newState) {
        document.documentElement.setAttribute('data-theme', 'dark');
    } else {
        document.documentElement.removeAttribute('data-theme');
    }
    setLocalSetting('darkMode', newState);
    updateDarkModeToggleIcon(newState);
}

function updateDarkModeToggleIcon(isDark) {
    var btn = document.getElementById('dark-mode-toggle');
    if (!btn) return;
    if (isDark) {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
        btn.setAttribute('title', 'Switch to light mode');
    } else {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
        btn.setAttribute('title', 'Switch to dark mode');
    }
}

function injectDarkModeToggle() {
    if (document.getElementById('dark-mode-toggle')) return;
    var btn = document.createElement('button');
    btn.id = 'dark-mode-toggle';
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Toggle dark mode');
    btn.style.cssText = 'background:none;border:none;cursor:pointer;padding:6px;border-radius:6px;display:inline-flex;align-items:center;justify-content:center;color:inherit;transition:background 0.2s;';
    btn.addEventListener('mouseenter', function () { this.style.background = 'rgba(128,128,128,0.15)'; });
    btn.addEventListener('mouseleave', function () { this.style.background = 'none'; });
    btn.addEventListener('click', toggleDarkMode);

    var nav = document.querySelector('nav') || document.querySelector('[role="navigation"]') || document.querySelector('.navbar') || document.querySelector('header');
    if (nav) {
        var navRight = nav.querySelector('.nav-right') || nav.querySelector('.navbar-end') || nav.querySelector('.ml-auto') || nav;
        navRight.appendChild(btn);
    } else {
        btn.style.cssText += 'position:fixed;top:12px;right:60px;z-index:9999;';
        document.body.appendChild(btn);
    }
    var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    updateDarkModeToggleIcon(isDark);
}

// =============================================================================
// Toast Notification System
// =============================================================================

function ensureToastContainer() {
    var container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = 'position:fixed;top:16px;right:16px;z-index:10000;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:400px;';
        document.body.appendChild(container);
    }
    return container;
}

function createToast(message, type, duration) {
    if (typeof type === 'undefined') type = 'info';
    if (typeof duration === 'undefined') duration = 5000;

    var container = ensureToastContainer();
    var existing = container.querySelectorAll('.toast-item');
    if (existing.length >= 5) removeToast(existing[0]);

    var colors = {
        info:    { bg: '#3b82f6', text: '#ffffff', icon: 'i' },
        success: { bg: '#22c55e', text: '#ffffff', icon: '\u2713' },
        warning: { bg: '#f59e0b', text: '#ffffff', icon: '!' },
        error:   { bg: '#ef4444', text: '#ffffff', icon: '\u2717' }
    };
    var scheme = colors[type] || colors.info;

    var toast = document.createElement('div');
    toast.className = 'toast-item';
    toast.style.cssText = 'pointer-events:auto;display:flex;align-items:center;gap:10px;padding:12px 16px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.15);font-size:14px;line-height:1.4;min-width:280px;max-width:400px;opacity:0;transform:translateX(40px);transition:opacity 0.3s ease, transform 0.3s ease;background:' + scheme.bg + ';color:' + scheme.text + ';';

    var iconSpan = document.createElement('span');
    iconSpan.style.cssText = 'flex-shrink:0;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold;font-size:14px;background:rgba(255,255,255,0.25);';
    iconSpan.textContent = scheme.icon;

    var textSpan = document.createElement('span');
    textSpan.style.cssText = 'flex:1;word-break:break-word;';
    textSpan.textContent = message;

    var closeBtn = document.createElement('button');
    closeBtn.style.cssText = 'flex-shrink:0;background:none;border:none;color:inherit;cursor:pointer;font-size:18px;line-height:1;padding:0 0 0 4px;opacity:0.8;';
    closeBtn.innerHTML = '&times;';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.addEventListener('click', function () { removeToast(toast); });

    toast.appendChild(iconSpan);
    toast.appendChild(textSpan);
    toast.appendChild(closeBtn);
    container.appendChild(toast);

    requestAnimationFrame(function () {
        requestAnimationFrame(function () {
            toast.style.opacity = '1';
            toast.style.transform = 'translateX(0)';
        });
    });

    if (duration > 0) {
        toast._dismissTimer = setTimeout(function () { removeToast(toast); }, duration);
    }
    return toast;
}

function removeToast(toastElement) {
    if (!toastElement || !toastElement.parentElement) return;
    if (toastElement._dismissTimer) clearTimeout(toastElement._dismissTimer);
    toastElement.style.opacity = '0';
    toastElement.style.transform = 'translateX(40px)';
    setTimeout(function () { if (toastElement.parentElement) toastElement.remove(); }, 300);
}

// =============================================================================
// Skeleton Loading States
// =============================================================================

function showSkeleton(elementId) {
    var el = document.getElementById(elementId);
    if (!el) return;
    if (!el.hasAttribute('data-original-content')) {
        el.setAttribute('data-original-content', el.innerHTML);
    }
    el.innerHTML = '<div class="skeleton-container" style="display:flex;flex-direction:column;gap:12px;padding:8px;">' +
        '<div class="skeleton-line" style="height:16px;width:85%;border-radius:4px;background:linear-gradient(90deg,#e0e0e0 25%,#f0f0f0 50%,#e0e0e0 75%);background-size:200% 100%;animation:skeleton-shimmer 1.5s infinite;"></div>' +
        '<div class="skeleton-line" style="height:16px;width:65%;border-radius:4px;background:linear-gradient(90deg,#e0e0e0 25%,#f0f0f0 50%,#e0e0e0 75%);background-size:200% 100%;animation:skeleton-shimmer 1.5s infinite;animation-delay:0.1s;"></div>' +
        '<div class="skeleton-line" style="height:16px;width:75%;border-radius:4px;background:linear-gradient(90deg,#e0e0e0 25%,#f0f0f0 50%,#e0e0e0 75%);background-size:200% 100%;animation:skeleton-shimmer 1.5s infinite;animation-delay:0.2s;"></div>' +
        '</div>';
    el.classList.add('is-loading');
    injectSkeletonStyles();
}

function hideSkeleton(elementId) {
    var el = document.getElementById(elementId);
    if (!el) return;
    el.classList.remove('is-loading');
    var originalContent = el.getAttribute('data-original-content');
    if (originalContent !== null && el.querySelector('.skeleton-container')) {
        el.innerHTML = originalContent;
        el.removeAttribute('data-original-content');
    }
}

function injectSkeletonStyles() {
    if (document.getElementById('skeleton-styles')) return;
    var style = document.createElement('style');
    style.id = 'skeleton-styles';
    style.textContent = '@keyframes skeleton-shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }\n' +
        '.page-transition { transition: opacity 0.3s ease, transform 0.3s ease; }\n' +
        '.page-transition-enter { opacity: 0; transform: translateY(8px); }\n' +
        '.page-transition-active { opacity: 1; transform: translateY(0); }';
    document.head.appendChild(style);
}

// =============================================================================
// API Call Wrapper with Retry, Cache, and Offline Fallback
// =============================================================================

async function apiCall(url, options) {
    if (typeof options === 'undefined') options = {};

    var retries = typeof options.retries === 'number' ? options.retries : 2;
    var retryDelay = options.retryDelay || 1000;
    var useCache = options.useCache || false;
    var cacheTTL = options.cacheTTL || DATA_CACHE_TTL;
    var offlineFallback = options.offlineFallback !== false;

    var fetchOptions = Object.assign({}, options);
    delete fetchOptions.retries;
    delete fetchOptions.retryDelay;
    delete fetchOptions.useCache;
    delete fetchOptions.cacheTTL;
    delete fetchOptions.offlineFallback;

    var method = (fetchOptions.method || 'GET').toUpperCase();

    // Memory cache check
    if (useCache && method === 'GET') {
        var cached = dataCache.get(url);
        if (cached && (Date.now() - cached.timestamp) < cacheTTL) {
            return cached.response.clone();
        }
    }

    var lastError;
    for (var attempt = 0; attempt <= retries; attempt++) {
        try {
            var response = await fetch(url, fetchOptions);
            if (!response.ok) {
                throw new Error('HTTP ' + response.status + ': ' + response.statusText);
            }

            // Cache successful GET responses
            if (useCache && method === 'GET') {
                dataCache.set(url, { timestamp: Date.now(), response: response.clone() });
                // Also persist to IndexedDB for offline use
                if (offlineFallback) {
                    response.clone().json().then(function (data) {
                        cacheToIDB('apiCache', url, data);
                    }).catch(function () {});
                }
            }
            return response;

        } catch (error) {
            lastError = error;
            if (attempt < retries) {
                await new Promise(function (resolve) { setTimeout(resolve, retryDelay * (attempt + 1)); });
            }
        }
    }

    // Offline fallback from IndexedDB
    if (offlineFallback && method === 'GET') {
        var offlineData = await getFromIDB('apiCache', url, 3600000); // 1 hour max age
        if (offlineData) {
            console.warn('Using offline cached data for:', url);
            return new Response(JSON.stringify(offlineData), {
                status: 200,
                headers: { 'Content-Type': 'application/json', 'X-Offline': 'true' }
            });
        }
    }

    throw lastError;
}

/**
 * Fetch JSON from an API endpoint with caching
 */
async function fetchJSON(url, options) {
    var opts = Object.assign({ useCache: true }, options || {});
    var response = await apiCall(url, opts);
    return response.json();
}

/**
 * Fetch multiple API endpoints in parallel
 */
async function fetchParallel(urls) {
    var promises = urls.map(function (url) {
        return fetchJSON(url).catch(function (err) {
            console.warn('Parallel fetch failed for ' + url + ':', err.message);
            return null;
        });
    });
    return Promise.all(promises);
}

// =============================================================================
// Keyboard Shortcuts
// =============================================================================

function handleKeyboardShortcuts(event) {
    var tag = event.target.tagName.toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || event.target.isContentEditable) {
        if (event.key === 'Escape') closeOpenModals();
        return;
    }
    if (event.ctrlKey || event.altKey || event.metaKey) return;

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
        case '1':
            event.preventDefault();
            window.location.href = '/';
            break;
        case '2':
            event.preventDefault();
            window.location.href = '/devices';
            break;
        case '3':
            event.preventDefault();
            window.location.href = '/wifi';
            break;
        case '4':
            event.preventDefault();
            window.location.href = '/insights';
            break;
        case '5':
            event.preventDefault();
            window.location.href = '/settings';
            break;
        case 'Escape':
            closeOpenModals();
            break;
    }
}

function focusSearchInput() {
    var searchInput = document.querySelector('input[type="search"]') ||
                      document.querySelector('input[name="search"]') ||
                      document.querySelector('input[placeholder*="earch"]') ||
                      document.querySelector('#search-input') ||
                      document.querySelector('#search-devices') ||
                      document.querySelector('.search-input');
    if (searchInput) {
        searchInput.focus();
        searchInput.select();
    }
}

function closeOpenModals() {
    var modals = document.querySelectorAll('.modal.active, .modal.show, .modal[open], [data-modal].active, dialog[open]');
    modals.forEach(function (modal) {
        if (modal.tagName.toLowerCase() === 'dialog') {
            modal.close();
        } else {
            modal.classList.remove('active', 'show');
            modal.removeAttribute('open');
            modal.style.display = 'none';
        }
    });
    // Also handle hidden class modals
    var hiddenModals = document.querySelectorAll('.modal:not(.hidden)');
    hiddenModals.forEach(function (m) {
        if (!m.classList.contains('hidden')) m.classList.add('hidden');
    });
}

// =============================================================================
// Desktop Notifications
// =============================================================================

function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
}

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

function startAutoRefresh() {
    stopAutoRefresh();
    var intervalMs = getLocalSetting('refreshInterval', 30000);
    if (intervalMs > 0) {
        autoRefreshInterval = setInterval(function () {
            if (typeof refreshData === 'function') refreshData();
        }, intervalMs);
    }
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

// =============================================================================
// Smooth Page Transitions
// =============================================================================

function smoothTransition(target, updateFn) {
    var el = typeof target === 'string' ? document.getElementById(target) : target;
    if (!el) { if (typeof updateFn === 'function') updateFn(); return; }
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

function showConfirmDialog(message) {
    return new Promise(function (resolve) {
        var overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:20000;opacity:0;transition:opacity 0.2s ease;';

        var dialog = document.createElement('div');
        dialog.style.cssText = 'background:#fff;border-radius:12px;padding:24px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.2);transform:scale(0.95);transition:transform 0.2s ease;';
        if (document.documentElement.getAttribute('data-theme') === 'dark') {
            dialog.style.background = '#1e293b';
            dialog.style.color = '#e2e8f0';
        }

        var msgEl = document.createElement('p');
        msgEl.style.cssText = 'margin:0 0 20px 0;font-size:15px;line-height:1.5;';
        msgEl.textContent = message;

        var btnRow = document.createElement('div');
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

        requestAnimationFrame(function () {
            overlay.style.opacity = '1';
            dialog.style.transform = 'scale(1)';
        });

        function cleanup(result) {
            overlay.style.opacity = '0';
            dialog.style.transform = 'scale(0.95)';
            setTimeout(function () { overlay.remove(); }, 200);
            resolve(result);
        }

        cancelBtn.addEventListener('click', function () { cleanup(false); });
        confirmBtn.addEventListener('click', function () { cleanup(true); });
        overlay.addEventListener('keydown', function (e) { if (e.key === 'Escape') cleanup(false); });
        overlay.addEventListener('click', function (e) { if (e.target === overlay) cleanup(false); });
        confirmBtn.focus();
    });
}

// =============================================================================
// Formatting Utilities
// =============================================================================

function formatDateTime(date) {
    if (!(date instanceof Date) || isNaN(date)) return '--';
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function formatTimeAgo(date) {
    if (!(date instanceof Date) || isNaN(date)) return '--';
    var seconds = Math.floor((new Date() - date) / 1000);
    if (seconds < 60) return 'just now';
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + 'm ago';
    var hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + 'h ago';
    var days = Math.floor(hours / 24);
    if (days < 7) return days + 'd ago';
    var weeks = Math.floor(days / 7);
    if (weeks < 4) return weeks + 'w ago';
    var months = Math.floor(days / 30);
    return months + 'mo ago';
}

function formatBytes(bytes, decimals) {
    if (typeof decimals === 'undefined') decimals = 2;
    if (bytes === 0) return '0 Bytes';
    var k = 1024;
    var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

function formatNumber(num) {
    if (num === null || typeof num === 'undefined') return '0';
    return Number(num).toLocaleString('en-US');
}

function formatDuration(seconds) {
    if (typeof seconds !== 'number' || isNaN(seconds) || seconds < 0) return '0s';
    seconds = Math.floor(seconds);
    if (seconds === 0) return '0s';
    var days = Math.floor(seconds / 86400);
    var hours = Math.floor((seconds % 86400) / 3600);
    var minutes = Math.floor((seconds % 3600) / 60);
    var secs = seconds % 60;
    var parts = [];
    if (days > 0) parts.push(days + 'd');
    if (hours > 0) parts.push(hours + 'h');
    if (minutes > 0) parts.push(minutes + 'm');
    if (secs > 0 || parts.length === 0) parts.push(secs + 's');
    return parts.join(' ');
}

function formatLatency(ms) {
    if (ms === null || ms === undefined) return '--';
    if (ms < 1) return '<1 ms';
    return ms.toFixed(1) + ' ms';
}

function formatPercentage(value, decimals) {
    if (value === null || value === undefined) return '--';
    if (typeof decimals === 'undefined') decimals = 1;
    return Number(value).toFixed(decimals) + '%';
}

function getSecurityScoreColor(score) {
    if (typeof score !== 'number' || isNaN(score)) return '#9ca3af';
    if (score < 40) return '#ef4444';
    if (score < 70) return '#f59e0b';
    if (score < 90) return '#84cc16';
    return '#22c55e';
}

function getRiskColor(score) {
    if (typeof score !== 'number' || isNaN(score)) return '#9ca3af';
    if (score >= 70) return '#ef4444';
    if (score >= 40) return '#f59e0b';
    if (score >= 20) return '#84cc16';
    return '#22c55e';
}

function getRiskGrade(score) {
    if (score >= 80) return 'F';
    if (score >= 60) return 'D';
    if (score >= 40) return 'C';
    if (score >= 20) return 'B';
    return 'A';
}

function getLatencyColor(ms) {
    if (ms === null || ms === undefined) return 'text-gray-400';
    if (ms < 10) return 'text-green-600';
    if (ms < 50) return 'text-yellow-600';
    return 'text-red-600';
}

function getTimestamp() {
    return new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
}

// =============================================================================
// Utility Functions
// =============================================================================

function debounce(func, wait) {
    var timeout;
    return function () {
        var context = this, args = arguments;
        clearTimeout(timeout);
        timeout = setTimeout(function () { func.apply(context, args); }, wait);
    };
}

function throttle(func, limit) {
    var lastFunc, lastRan;
    return function () {
        var context = this, args = arguments;
        if (!lastRan) {
            func.apply(context, args);
            lastRan = Date.now();
        } else {
            clearTimeout(lastFunc);
            lastFunc = setTimeout(function () {
                if (Date.now() - lastRan >= limit) {
                    func.apply(context, args);
                    lastRan = Date.now();
                }
            }, limit - (Date.now() - lastRan));
        }
    };
}

function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () {
            showNotification('Copied to clipboard', 'success');
        }).catch(function () {
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

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
        showNotification('Failed to copy', 'error');
    }
    document.body.removeChild(textarea);
}

// =============================================================================
// Chart Helpers (Plotly wrappers)
// =============================================================================

function isDarkMode() {
    return document.documentElement.classList.contains('dark') ||
           document.documentElement.getAttribute('data-theme') === 'dark';
}

function getChartColors() {
    var dark = isDarkMode();
    return {
        text: dark ? '#D1D5DB' : '#374151',
        grid: dark ? '#374151' : '#E5E7EB',
        paper: 'rgba(0,0,0,0)',
        plot: 'rgba(0,0,0,0)',
        primary: '#3B82F6',
        success: '#10B981',
        warning: '#F59E0B',
        danger: '#EF4444',
        purple: '#8B5CF6',
        pink: '#EC4899',
        cyan: '#06B6D4',
        lime: '#84CC16',
        palette: ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899', '#06B6D4', '#84CC16']
    };
}

function getChartLayout(overrides) {
    var c = getChartColors();
    var base = {
        paper_bgcolor: c.paper,
        plot_bgcolor: c.plot,
        font: { color: c.text, size: 12 },
        margin: { t: 20, r: 20, b: 40, l: 50 },
        hovermode: 'closest'
    };
    return Object.assign(base, overrides || {});
}

function getAxisConfig(title) {
    var c = getChartColors();
    return {
        title: title || '',
        color: c.text,
        gridcolor: c.grid,
        zerolinecolor: c.grid
    };
}

/**
 * Render a mini sparkline chart in a container
 */
function renderSparkline(containerId, values, color) {
    var el = document.getElementById(containerId);
    if (!el || !values || values.length === 0) return;
    if (!color) color = '#3B82F6';

    var trace = {
        y: values,
        type: 'scatter',
        mode: 'lines',
        line: { color: color, width: 2 },
        fill: 'tozeroy',
        fillcolor: color.replace(')', ',0.1)').replace('rgb', 'rgba'),
        hoverinfo: 'y'
    };

    var layout = {
        margin: { t: 2, r: 2, b: 2, l: 2 },
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        xaxis: { visible: false },
        yaxis: { visible: false },
        showlegend: false,
        height: 40
    };

    Plotly.newPlot(containerId, [trace], layout, { responsive: true, displayModeBar: false, staticPlot: true });
}

/**
 * Render a trend line chart with timestamps
 */
function renderTrendChart(containerId, data, options) {
    var el = document.getElementById(containerId);
    if (!el) return;

    var opts = options || {};
    var c = getChartColors();
    var traces = [];

    if (Array.isArray(data)) {
        // Single series: [{timestamp, value}]
        traces.push({
            x: data.map(function (d) { return new Date(d.timestamp || d.date || d.time); }),
            y: data.map(function (d) { return d.value || d.count || d.avg || 0; }),
            type: 'scatter',
            mode: 'lines+markers',
            name: opts.name || 'Value',
            line: { color: opts.color || c.primary, width: 2 },
            marker: { size: 4 },
            fill: opts.fill ? 'tozeroy' : undefined,
            fillcolor: opts.fill ? (opts.color || c.primary).replace(')', ',0.1)').replace('rgb', 'rgba') : undefined
        });
    } else if (data && typeof data === 'object') {
        // Multi-series: {series_name: [{timestamp, value}]}
        var idx = 0;
        Object.keys(data).forEach(function (key) {
            var series = data[key];
            if (!Array.isArray(series)) return;
            traces.push({
                x: series.map(function (d) { return new Date(d.timestamp || d.date || d.time); }),
                y: series.map(function (d) { return d.value || d.count || d.avg || 0; }),
                type: 'scatter',
                mode: 'lines+markers',
                name: key,
                line: { color: c.palette[idx % c.palette.length], width: 2 },
                marker: { size: 4 }
            });
            idx++;
        });
    }

    if (traces.length === 0) {
        el.innerHTML = '<div class="flex items-center justify-center h-full text-gray-400">No data available</div>';
        return;
    }

    var layout = getChartLayout({
        xaxis: Object.assign(getAxisConfig(opts.xTitle || ''), { type: 'date' }),
        yaxis: Object.assign(getAxisConfig(opts.yTitle || ''), { rangemode: 'tozero' }),
        legend: traces.length > 1 ? { orientation: 'h', y: 1.1, font: { color: c.text } } : { visible: false }
    });

    Plotly.newPlot(containerId, traces, layout, { responsive: true });
}

/**
 * Render a gauge/score meter chart
 */
function renderGauge(containerId, value, options) {
    var el = document.getElementById(containerId);
    if (!el) return;

    var opts = options || {};
    var min = opts.min || 0;
    var max = opts.max || 100;
    var suffix = opts.suffix || '';
    var c = getChartColors();

    var color = opts.color || getSecurityScoreColor(value);
    var steps = opts.steps || [
        { range: [0, 40], color: isDarkMode() ? '#4C1D1D' : '#FEE2E2' },
        { range: [40, 70], color: isDarkMode() ? '#4C3B1D' : '#FEF3C7' },
        { range: [70, 90], color: isDarkMode() ? '#2B4C1D' : '#ECFCCB' },
        { range: [90, 100], color: isDarkMode() ? '#1D4C2B' : '#D1FAE5' }
    ];

    var trace = {
        type: 'indicator',
        mode: 'gauge+number',
        value: value,
        number: { suffix: suffix, font: { color: c.text } },
        gauge: {
            axis: { range: [min, max], tickcolor: c.text, dtick: opts.dtick || 20 },
            bar: { color: color },
            bgcolor: isDarkMode() ? '#374151' : '#E5E7EB',
            borderwidth: 0,
            steps: steps,
            threshold: {
                line: { color: color, width: 4 },
                thickness: 0.75,
                value: value
            }
        }
    };

    var layout = getChartLayout({ margin: { t: 30, r: 30, b: 10, l: 30 } });
    Plotly.newPlot(containerId, [trace], layout, { responsive: true, displayModeBar: false });
}

/**
 * Render a donut/pie chart
 */
function renderPieChart(containerId, labels, values, options) {
    var el = document.getElementById(containerId);
    if (!el || !labels || labels.length === 0) {
        if (el) el.innerHTML = '<div class="flex items-center justify-center h-full text-gray-400">No data available</div>';
        return;
    }

    var opts = options || {};
    var c = getChartColors();

    var trace = {
        labels: labels,
        values: values,
        type: 'pie',
        hole: opts.hole !== undefined ? opts.hole : 0.4,
        marker: { colors: c.palette.slice(0, labels.length) },
        textinfo: opts.textinfo || 'label+percent',
        textposition: 'outside',
        automargin: true
    };

    var layout = getChartLayout({
        margin: { t: 10, r: 10, b: 10, l: 10 },
        showlegend: true,
        legend: { orientation: 'h', y: -0.1, font: { color: c.text } }
    });

    Plotly.newPlot(containerId, [trace], layout, { responsive: true });
}

/**
 * Render a horizontal bar chart
 */
function renderBarChart(containerId, labels, values, options) {
    var el = document.getElementById(containerId);
    if (!el || !labels || labels.length === 0) {
        if (el) el.innerHTML = '<div class="flex items-center justify-center h-full text-gray-400">No data available</div>';
        return;
    }

    var opts = options || {};
    var c = getChartColors();

    var trace = {
        x: opts.horizontal ? values : labels,
        y: opts.horizontal ? labels : values,
        type: 'bar',
        orientation: opts.horizontal ? 'h' : 'v',
        marker: { color: opts.colors || c.primary },
        text: values.map(function (v) { return v.toString(); }),
        textposition: 'outside'
    };

    var layout = getChartLayout({
        xaxis: getAxisConfig(opts.horizontal ? opts.xTitle || '' : ''),
        yaxis: Object.assign(getAxisConfig(opts.yTitle || ''), opts.horizontal ? { autorange: 'reversed' } : { rangemode: 'tozero' }),
        margin: opts.horizontal ? { t: 10, r: 20, b: 40, l: 120 } : { t: 20, r: 20, b: 60, l: 50 }
    });

    Plotly.newPlot(containerId, [trace], layout, { responsive: true });
}

// =============================================================================
// Pagination Component
// =============================================================================

function renderPagination(containerId, currentPage, totalPages, onPageChange) {
    var el = document.getElementById(containerId);
    if (!el || totalPages <= 1) {
        if (el) el.innerHTML = '';
        return;
    }

    var html = '<nav class="flex items-center justify-center gap-1" aria-label="Pagination">';

    // Previous button
    html += '<button ' + (currentPage <= 1 ? 'disabled' : '') + ' onclick="' + onPageChange + '(' + (currentPage - 1) + ')" ' +
        'class="px-3 py-1.5 rounded text-sm ' + (currentPage <= 1 ? 'text-gray-400 cursor-not-allowed' : 'text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20') + '">&laquo; Prev</button>';

    // Page numbers
    var startPage = Math.max(1, currentPage - 2);
    var endPage = Math.min(totalPages, currentPage + 2);

    if (startPage > 1) {
        html += '<button onclick="' + onPageChange + '(1)" class="px-3 py-1.5 rounded text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">1</button>';
        if (startPage > 2) html += '<span class="px-2 text-gray-400">...</span>';
    }

    for (var p = startPage; p <= endPage; p++) {
        if (p === currentPage) {
            html += '<button class="px-3 py-1.5 rounded text-sm bg-blue-600 text-white font-semibold">' + p + '</button>';
        } else {
            html += '<button onclick="' + onPageChange + '(' + p + ')" class="px-3 py-1.5 rounded text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">' + p + '</button>';
        }
    }

    if (endPage < totalPages) {
        if (endPage < totalPages - 1) html += '<span class="px-2 text-gray-400">...</span>';
        html += '<button onclick="' + onPageChange + '(' + totalPages + ')" class="px-3 py-1.5 rounded text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">' + totalPages + '</button>';
    }

    // Next button
    html += '<button ' + (currentPage >= totalPages ? 'disabled' : '') + ' onclick="' + onPageChange + '(' + (currentPage + 1) + ')" ' +
        'class="px-3 py-1.5 rounded text-sm ' + (currentPage >= totalPages ? 'text-gray-400 cursor-not-allowed' : 'text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20') + '">Next &raquo;</button>';

    html += '</nav>';
    html += '<div class="text-center text-xs text-gray-500 dark:text-gray-400 mt-2">Page ' + currentPage + ' of ' + totalPages + '</div>';

    el.innerHTML = html;
}

// =============================================================================
// Risk Badge Component
// =============================================================================

function renderRiskBadge(score, grade) {
    if (score === null || score === undefined) return '<span class="text-gray-400 text-xs">N/A</span>';
    var color = getRiskColor(score);
    var g = grade || getRiskGrade(score);
    return '<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold" style="background:' + color + '20;color:' + color + ';">' +
        '<span class="w-2 h-2 rounded-full" style="background:' + color + ';"></span>' +
        g + ' (' + score + ')' +
        '</span>';
}

// =============================================================================
// Health Score Component
// =============================================================================

function renderHealthScore(containerId, score, label) {
    var el = document.getElementById(containerId);
    if (!el) return;

    var color = getSecurityScoreColor(score);
    var circumference = 2 * Math.PI * 45;
    var offset = circumference - (score / 100) * circumference;

    el.innerHTML = '<div class="score-meter">' +
        '<svg viewBox="0 0 100 100">' +
        '<circle class="meter-track" cx="50" cy="50" r="45"/>' +
        '<circle class="meter-fill" cx="50" cy="50" r="45" style="stroke:' + color + ';stroke-dasharray:' + circumference + ';stroke-dashoffset:' + offset + ';"/>' +
        '</svg>' +
        '<div class="score-label">' +
        '<div class="score-number" style="color:' + color + ';">' + score + '</div>' +
        '<div class="score-text">' + (label || 'Score') + '</div>' +
        '</div></div>';
}

// =============================================================================
// WebSocket Connection Management
// =============================================================================

function connectWebSocket() {
    var protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    var wsUrl = protocol + '//' + window.location.host + '/ws';

    try {
        ws = new WebSocket(wsUrl);
        ws.onopen = handleWebSocketOpen;
        ws.onmessage = handleWebSocketMessage;
        ws.onerror = handleWebSocketError;
        ws.onclose = handleWebSocketClose;
    } catch (error) {
        updateConnectionStatus('disconnected');
        scheduleReconnect();
    }
}

function handleWebSocketOpen() {
    isConnected = true;
    reconnectDelay = 1000;
    updateConnectionStatus('connected');

    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }

    sendWebSocketMessage({ type: 'subscribe', channel: 'all' });
}

function handleWebSocketMessage(event) {
    try {
        var message = JSON.parse(event.data);

        switch (message.type) {
            case 'connected':
            case 'pong':
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
            case 'scan_progress':
                handleScanProgress(message.data);
                break;
            case 'risk_update':
                handleRiskUpdate(message.data);
                break;
            case 'heartbeat':
                sendWebSocketMessage({ type: 'ping' });
                break;
        }
    } catch (error) {
        console.error('Error parsing WebSocket message:', error);
    }
}

function handleWebSocketError() {
    updateConnectionStatus('disconnected');
}

function handleWebSocketClose() {
    isConnected = false;
    updateConnectionStatus('disconnected');
    scheduleReconnect();
}

function sendWebSocketMessage(message) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(message));
    }
}

function scheduleReconnect() {
    if (reconnectTimeout) return;
    var delay = reconnectDelay;
    updateConnectionStatus('connecting');
    reconnectTimeout = setTimeout(function () {
        reconnectTimeout = null;
        connectWebSocket();
    }, delay);
    reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_DELAY);
}

function updateConnectionStatus(status) {
    var indicator = document.getElementById('status-indicator');
    var text = document.getElementById('status-text');
    if (indicator) {
        indicator.className = 'h-3 w-3 rounded-full';
        switch (status) {
            case 'connected': indicator.classList.add('bg-green-500'); break;
            case 'connecting': indicator.classList.add('bg-yellow-500'); break;
            case 'disconnected': indicator.classList.add('bg-red-500'); break;
        }
    }
    if (text) {
        switch (status) {
            case 'connected': text.textContent = 'Connected'; break;
            case 'connecting': text.textContent = 'Connecting...'; break;
            case 'disconnected': text.textContent = 'Disconnected'; break;
        }
    }
    // Also update mobile indicators
    var mobileIndicator = document.getElementById('status-indicator-mobile');
    var mobileText = document.getElementById('status-text-mobile');
    if (mobileIndicator) {
        mobileIndicator.className = 'h-3 w-3 rounded-full';
        switch (status) {
            case 'connected': mobileIndicator.classList.add('bg-green-500'); break;
            case 'connecting': mobileIndicator.classList.add('bg-yellow-500'); break;
            case 'disconnected': mobileIndicator.classList.add('bg-red-500'); break;
        }
    }
    if (mobileText) {
        switch (status) {
            case 'connected': mobileText.textContent = 'Connected'; break;
            case 'connecting': mobileText.textContent = 'Connecting...'; break;
            case 'disconnected': mobileText.textContent = 'Disconnected'; break;
        }
    }
}

// =============================================================================
// WebSocket Event Handlers
// =============================================================================

function handleScanUpdate(data) {
    showNotification('Scan complete: ' + (data.device_count || 0) + ' devices found', 'info');
    if (typeof refreshData === 'function') refreshData();
}

function handleDeviceUpdate(device, event) {
    if (event === 'new') {
        showNotification('New device detected: ' + (device.ip || 'unknown'), 'info');
        sendDesktopNotification('New Device Detected', 'IP: ' + (device.ip || 'unknown'));
    } else if (event === 'offline') {
        showNotification('Device went offline: ' + (device.ip || device.hostname || 'unknown'), 'warning');
    }
    if (typeof loadDevices === 'function') loadDevices();
}

function handleNewAlert(alert) {
    var severity = alert.severity || 'info';
    showNotification((alert.title || 'Alert') + ': ' + (alert.message || ''), severity);
    if (severity === 'error' || severity === 'critical' || severity === 'warning') {
        sendDesktopNotification('NetMonDash Alert: ' + (alert.title || 'Alert'), alert.message || '');
    }
    if (typeof loadAlerts === 'function') loadAlerts();
}

function handleStatsUpdate(stats) {
    var el;
    el = document.getElementById('total-devices');
    if (el) smoothTransition(el, function () { el.textContent = formatNumber(stats.total_devices || 0); });

    el = document.getElementById('online-devices');
    if (el) smoothTransition(el, function () { el.textContent = formatNumber(stats.online_devices || 0); });

    el = document.getElementById('alert-count');
    if (el) smoothTransition(el, function () { el.textContent = formatNumber(stats.unacknowledged_alerts || 0); });
}

function handleScanProgress(data) {
    var progressBar = document.getElementById('scan-progress-bar');
    var progressText = document.getElementById('scan-progress-text');
    if (progressBar) {
        progressBar.style.width = (data.percent || 0) + '%';
    }
    if (progressText) {
        progressText.textContent = data.message || ('Scanning... ' + (data.percent || 0) + '%');
    }
}

function handleRiskUpdate(data) {
    // Update risk displays if they exist
    var riskEl = document.getElementById('network-risk-score');
    if (riskEl && data.overall_score !== undefined) {
        riskEl.textContent = data.overall_score;
    }
}

// =============================================================================
// Data Refresh and Export
// =============================================================================

function refreshData() {
    // Clear memory cache on explicit refresh
    dataCache.clear();

    if (typeof loadOverviewData === 'function') {
        loadOverviewData();
    } else if (typeof loadDevices === 'function') {
        loadDevices();
    } else if (typeof loadWiFiMetrics === 'function') {
        loadWiFiMetrics();
    } else if (typeof loadQuickInsights === 'function') {
        loadQuickInsights();
    }

    showNotification('Data refreshed', 'success');
}

async function exportData(dataType, format) {
    try {
        var response = await apiCall('/api/export?data_type=' + encodeURIComponent(dataType) + '&format=' + encodeURIComponent(format), {
            retries: 2, retryDelay: 1000
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
        showNotification('Export failed: ' + error.message, 'error');
    }
}

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

function showNotification(message, type) {
    if (typeof type === 'undefined') type = 'info';
    createToast(message, type, 5000);
}

// =============================================================================
// Trend Data Loaders
// =============================================================================

async function loadTrendData(endpoint, cacheKey) {
    try {
        var data = await fetchJSON(endpoint);
        if (data && cacheKey) {
            cacheToIDB('trendData', cacheKey, data);
        }
        return data;
    } catch (e) {
        // Try offline cache
        if (cacheKey) {
            var cached = await getFromIDB('trendData', cacheKey, 3600000);
            if (cached) return cached;
        }
        return null;
    }
}

async function loadDeviceCountTrend(containerId, days) {
    var data = await loadTrendData('/api/trends/devices?days=' + (days || 7), 'device_count_trend');
    if (data && data.trend) {
        renderTrendChart(containerId, data.trend, {
            name: 'Devices',
            color: '#3B82F6',
            fill: true,
            yTitle: 'Count'
        });
    }
}

async function loadLatencyTrend(containerId, days) {
    var data = await loadTrendData('/api/trends/latency?days=' + (days || 7), 'latency_trend');
    if (data && data.trend) {
        renderTrendChart(containerId, data.trend, {
            name: 'Avg Latency',
            color: '#F59E0B',
            yTitle: 'ms'
        });
    }
}

async function loadAlertTrend(containerId, days) {
    var data = await loadTrendData('/api/trends/alerts?days=' + (days || 7), 'alert_trend');
    if (data && data.trend) {
        renderTrendChart(containerId, data.trend, {
            name: 'Alerts',
            color: '#EF4444',
            fill: true,
            yTitle: 'Count'
        });
    }
}

// =============================================================================
// Network Health Summary Loader
// =============================================================================

async function loadNetworkHealth(callback) {
    try {
        var data = await fetchJSON('/api/network/health');
        if (callback) callback(data);
        return data;
    } catch (e) {
        return null;
    }
}

// =============================================================================
// Comprehensive Analysis Loader
// =============================================================================

async function loadComprehensiveAnalysis(callback) {
    try {
        var response = await apiCall('/api/analyze/comprehensive', { method: 'POST', retries: 1 });
        var data = await response.json();
        if (callback) callback(data);
        return data;
    } catch (e) {
        return null;
    }
}

// =============================================================================
// Device Risk Loader
// =============================================================================

async function loadDeviceRisks(callback) {
    try {
        var response = await apiCall('/api/analyze/device-risks', { method: 'POST', retries: 1 });
        var data = await response.json();
        if (callback) callback(data);
        return data;
    } catch (e) {
        return null;
    }
}

// =============================================================================
// Vendor Analytics Loader
// =============================================================================

async function loadVendorAnalytics(containerId) {
    try {
        var data = await fetchJSON('/api/vendors');
        if (data && data.vendors) {
            var labels = data.vendors.map(function (v) { return v.vendor || 'Unknown'; });
            var values = data.vendors.map(function (v) { return v.count || 0; });
            renderBarChart(containerId, labels, values, { horizontal: true, xTitle: 'Device Count' });
        }
    } catch (e) {
        var el = document.getElementById(containerId);
        if (el) el.innerHTML = '<div class="flex items-center justify-center h-full text-gray-400">Failed to load vendor data</div>';
    }
}

// =============================================================================
// Dashboard Initialization
// =============================================================================

function initializeDashboard() {
    // Inject skeleton animation styles early
    injectSkeletonStyles();

    // Initialize dark mode from saved preference
    initDarkMode();

    // Set up toast notification container
    ensureToastContainer();

    // Open IndexedDB for offline caching
    openOfflineDB();

    // Request notification permission
    requestNotificationPermission();

    // Connect to WebSocket
    connectWebSocket();

    // Set up auto-refresh with configurable interval
    startAutoRefresh();

    // Register keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

// =============================================================================
// Bootstrap
// =============================================================================

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDashboard);
} else {
    initializeDashboard();
}

window.addEventListener('beforeunload', function () {
    if (ws) ws.close();
    stopAutoRefresh();
});
