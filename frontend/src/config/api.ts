// Centralized API configuration
// In production (Vercel), API_BASE_URL defaults to '' so relative '/api/v1' routes are proxied to backend.
// In local development, it can fall back to 'http://127.0.0.1:8000' or VITE_API_BASE_URL if set.
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL !== undefined 
  ? import.meta.env.VITE_API_BASE_URL 
  : (import.meta.env.MODE === 'development' ? 'http://127.0.0.1:8000' : '');
