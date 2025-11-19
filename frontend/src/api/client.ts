const API_BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8080";
const API_VERSION_PATH = "/api/v1";

function buildUrl(path: string) {
  if (path.startsWith("http://") || path.startsWith("https://")) {
    return path;
  }

  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  if (normalizedPath.startsWith(API_VERSION_PATH)) {
    return `${API_BASE_URL}${normalizedPath}`;
  }

  return `${API_BASE_URL}${API_VERSION_PATH}${normalizedPath}`;
}

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const token =
    typeof window !== "undefined" ? localStorage.getItem("token") : null;

  const headers = new Headers(init.headers || {});

  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }

  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(buildUrl(path), {
    ...init,
    headers,
  });

  // si el backend dijo 401, limpiamos y mandamos al login
  if (response.status === 401) {
    if (typeof window !== "undefined") {
      localStorage.removeItem("token");
      localStorage.removeItem("role");
      localStorage.removeItem("user");
      window.location.href = "/login";
    }
    throw new Error("No autorizado");
  }

  const contentType = response.headers.get("content-type") || "";

  if (!response.ok) {
    if (contentType.includes("application/json")) {
      const data = await response.json().catch(() => null);
      const msg =
        (data && (data.error || data.message)) ||
        `Error en la petición (${response.status})`;
      throw new Error(msg);
    } else {
      const text = await response.text().catch(() => "");
      throw new Error(text || `Error en la petición (${response.status})`);
    }
  }

  if (response.status === 204) {
    return undefined as T;
  }

  if (contentType.includes("application/json")) {
    const data = await response.json();
    return data as T;
  }

  return {} as T;
}

export type ApiError = Error;
