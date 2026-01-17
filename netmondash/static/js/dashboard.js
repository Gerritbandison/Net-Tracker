/**
 * NetMonDash Dashboard JavaScript
 *
 * Client-side functionality for WebSocket connections, data updates, and UI interactions.
 */

// Global variables
let ws = null;
let reconnectTimeout = null;
let isConnected = false;

/**
 * Initialize dashboard on page load
 */
function initializeDashboard() {
    console.log('Initializing NetMonDash dashboard...');

    // Connect to WebSocket
    connectWebSocket();

    // Set up periodic refresh
    const refreshInterval = 30000; // 30 seconds
    setInterval(() => {
        if (typeof refreshData === 'function') {
            refreshData();
        }
    }, refreshInterval);

    console.log('Dashboard initialized');
}

/**
 * Connect to WebSocket server
 */
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    console.log(`Connecting to WebSocket: ${wsUrl}`);

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
        const message = JSON.parse(event.data);
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
 * Schedule WebSocket reconnection
 */
function scheduleReconnect() {
    if (reconnectTimeout) {
        return; // Already scheduled
    }

    console.log('Scheduling WebSocket reconnection in 5 seconds...');
    updateConnectionStatus('connecting');

    reconnectTimeout = setTimeout(() => {
        reconnectTimeout = null;
        connectWebSocket();
    }, 5000);
}

/**
 * Update connection status indicator
 */
function updateConnectionStatus(status) {
    const indicator = document.getElementById('status-indicator');
    const text = document.getElementById('status-text');

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

/**
 * Handle scan update from WebSocket
 */
function handleScanUpdate(data) {
    console.log('Scan update received:', data);
    showNotification(`Scan complete: ${data.device_count} devices found`, 'info');

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
        showNotification(`New device detected: ${device.ip}`, 'info');
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

    const severity = alert.severity || 'info';
    showNotification(`${alert.title}: ${alert.message}`, severity);

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

    // Update stats display if elements exist
    if (document.getElementById('total-devices')) {
        document.getElementById('total-devices').textContent = stats.total_devices || 0;
    }
    if (document.getElementById('online-devices')) {
        document.getElementById('online-devices').textContent = stats.online_devices || 0;
    }
    if (document.getElementById('alert-count')) {
        document.getElementById('alert-count').textContent = stats.unacknowledged_alerts || 0;
    }
}

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
        const response = await fetch(`/api/export?data_type=${dataType}&format=${format}`);

        if (format === 'json') {
            const data = await response.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            downloadBlob(blob, `netmondash_${dataType}_${getTimestamp()}.json`);
        } else if (format === 'csv') {
            const blob = await response.blob();
            downloadBlob(blob, `netmondash_${dataType}_${getTimestamp()}.csv`);
        }

        showNotification('Data exported successfully', 'success');

    } catch (error) {
        console.error('Export error:', error);
        showNotification('Export failed', 'error');
    }
}

/**
 * Download blob as file
 */
function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

/**
 * Get formatted timestamp
 */
function getTimestamp() {
    const now = new Date();
    return now.toISOString().replace(/[:.]/g, '-').substring(0, 19);
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} fixed top-4 right-4 z-50 shadow-lg max-w-md fade-in`;
    notification.innerHTML = `
        <div class="flex items-center justify-between">
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-lg">&times;</button>
        </div>
    `;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.classList.add('opacity-0');
            setTimeout(() => notification.remove(), 300);
        }
    }, 5000);
}

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
 * Format time ago
 */
function formatTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);

    if (seconds < 60) {
        return 'just now';
    }

    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) {
        return `${minutes}m ago`;
    }

    const hours = Math.floor(minutes / 60);
    if (hours < 24) {
        return `${hours}h ago`;
    }

    const days = Math.floor(hours / 24);
    if (days < 7) {
        return `${days}d ago`;
    }

    const weeks = Math.floor(days / 7);
    if (weeks < 4) {
        return `${weeks}w ago`;
    }

    const months = Math.floor(days / 30);
    return `${months}mo ago`;
}

/**
 * Format bytes
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

/**
 * Debounce function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Copied to clipboard', 'success');
        }).catch(err => {
            console.error('Failed to copy:', err);
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

/**
 * Fallback copy to clipboard
 */
function fallbackCopyToClipboard(text) {
    const textarea = document.createElement('textarea');
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

/**
 * Request notification permission
 */
function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
}

/**
 * Send desktop notification
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

// Initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDashboard);
} else {
    initializeDashboard();
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (ws) {
        ws.close();
    }
});
