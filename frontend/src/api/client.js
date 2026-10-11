// Thin wrapper around the Java REST API (proxied by Vite in dev).
const BASE = '/api'

async function req(path, options = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.status === 204 ? null : res.json()
}

export const api = {
  health: () => req('/health'),
  stats: () => req('/stats'),
  queries: (limit = 100) => req(`/queries?limit=${limit}`),
  top: () => req('/top'),                                   // TODO Day 3 (backend)
  addBlocked: (domain, category = 'custom') =>
    req('/blocklist', { method: 'POST', body: JSON.stringify({ domain, category }) }),
  removeBlocked: (domain) =>
    req(`/blocklist?domain=${encodeURIComponent(domain)}`, { method: 'DELETE' }),
  allow: (domain) => req('/allowlist', { method: 'POST', body: JSON.stringify({ domain }) }),
}
