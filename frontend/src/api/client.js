// Thin wrapper around the Java REST API (proxied by Vite in dev).
const BASE = '/api'

// Admin token, needed for every call except /health when the backend sets DNSFILTER_API_TOKEN.
// Stored per browser. Any 401 fires AUTH_EVENT so the app can ask for it once, in one place.
const TOKEN_KEY = 'dnsfilter.token'
export const AUTH_EVENT = 'dnsfilter:auth-required'
export function getToken() {
  try { return localStorage.getItem(TOKEN_KEY) || '' } catch { return '' }
}
export function setToken(t) {
  try { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY) } catch { /* ignore */ }
}

async function req(path, options = {}) {
  const token = getToken()
  const res = await fetch(BASE + path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  })
  const body = res.status === 204 ? null : await res.json().catch(() => null)
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event(AUTH_EVENT))
    const err = new Error(body?.error || `${res.status} ${res.statusText}`)
    err.status = res.status
    throw err
  }
  return body
}

const q = encodeURIComponent

export const api = {
  health: () => req('/health'),
  stats: () => req('/stats'),
  queries: (limit = 100, { status, search } = {}) =>
    req(`/queries?limit=${limit}${status ? `&status=${q(status)}` : ''}${search ? `&search=${q(search)}` : ''}`),
  top: (n = 10) => req(`/top?n=${n}`),
  timeseries: () => req('/timeseries'),
  resolve: (name, type = 'A') => req(`/resolve?name=${q(name)}&type=${q(type)}`),
  check: (domain) => req(`/blocklist?domain=${q(domain)}`),
  blocklistInfo: () => req('/blocklist'),
  addBlocked: (domain, category = 'custom') =>
    req('/blocklist', { method: 'POST', body: JSON.stringify({ domain, category }) }),
  removeBlocked: (domain) => req(`/blocklist?domain=${q(domain)}`, { method: 'DELETE' }),
  reloadBlocklists: () => req('/blocklist/reload', { method: 'POST' }),
  allowlist: () => req('/allowlist'),
  allow: (domain) => req('/allowlist', { method: 'POST', body: JSON.stringify({ domain }) }),
  unallow: (domain) => req(`/allowlist?domain=${q(domain)}`, { method: 'DELETE' }),
  cache: () => req('/cache'),
  flushCache: () => req('/cache', { method: 'DELETE' }),
}
