// Shared API and WebSocket configuration

const getRawApiUrl = () => {
  const envUrl = import.meta.env.VITE_API_URL;
  if (envUrl && envUrl.trim() !== '') {
    return envUrl.trim();
  }
  return 'http://127.0.0.1:8000';
};

// Base API URL with any trailing slashes removed
export const API_BASE = getRawApiUrl().replace(/\/+$/, '');

/**
 * Derives the WebSocket URL from the base API URL or path.
 * Converts http:// -> ws:// and https:// -> wss://
 */
export const getWsUrl = (path = '/ws/alerts') => {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;

  if (API_BASE.startsWith('https://')) {
    return `${API_BASE.replace(/^https:\/\//i, 'wss://')}${cleanPath}`;
  }
  if (API_BASE.startsWith('http://')) {
    return `${API_BASE.replace(/^http:\/\//i, 'ws://')}${cleanPath}`;
  }
  if (API_BASE.startsWith('wss://') || API_BASE.startsWith('ws://')) {
    return `${API_BASE}${cleanPath}`;
  }

  const isSecure = typeof window !== 'undefined' && window.location.protocol === 'https:';
  const proto = isSecure ? 'wss://' : 'ws://';
  return `${proto}${API_BASE.replace(/^\/\//, '')}${cleanPath}`;
};

export const WS_URL = getWsUrl('/ws/alerts');
