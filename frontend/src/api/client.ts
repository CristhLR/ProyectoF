const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8080';
const API_VERSION_PATH = '/api/v1';

function buildUrl(path: string) {
  if (path.startsWith('http://') || path.startsWith('https://')) {
    return path;
  }

  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  if (normalizedPath.startsWith(API_VERSION_PATH)) {
    return `${API_BASE_URL}${normalizedPath}`;
  }

  return `${API_BASE_URL}${API_VERSION_PATH}${normalizedPath}`;
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('token');
  const headers = new Headers(init.headers || {});

  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(buildUrl(path), {
    ...init,
    headers,
  });

  if (response.status === 401) {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    localStorage.removeItem('user');
    window.location.href = '/login';
    throw new Error('No autorizado');
  }

  if (!response.ok) {
    let errorMessage = 'Error en la petición';
    try {
      const data = await response.json();
      errorMessage = (data as { error?: string })?.error || errorMessage;
    } catch (err) {
      const text = await response.text();
      if (text) {
        errorMessage = text;
      }
    }
    throw new Error(errorMessage);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export type ApiError = Error;
