// Formatting helpers shared by the dashboard.

/** 1,284 / 12.9K / 1.2M */
export function compact(n) {
  if (n == null || Number.isNaN(n)) return '–'
  const abs = Math.abs(n)
  if (abs < 1000) return String(Math.round(n))
  if (abs < 1e6) return (n / 1e3).toFixed(abs < 1e4 ? 1 : 0).replace(/\.0$/, '') + 'K'
  return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M'
}

export function full(n) {
  return n == null ? '–' : Number(n).toLocaleString()
}

/** Milliseconds with sensible precision: 0.052 ms, 1.24 ms, 18 ms */
export function ms(v) {
  if (v == null) return '–'
  if (v < 1) return v.toFixed(3) + ' ms'
  if (v < 10) return v.toFixed(2) + ' ms'
  return v.toFixed(0) + ' ms'
}

export function pct(part, whole) {
  if (!whole) return '0%'
  const p = (part / whole) * 100
  return (p < 10 ? p.toFixed(1) : p.toFixed(0)) + '%'
}

export function uptime(sec) {
  if (sec == null) return ''
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60)
  if (d) return `${d}d ${h}h`
  if (h) return `${h}h ${m}m`
  if (m) return `${m}m`
  return `${sec}s`
}

export function clock(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function hhmm(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
}

/** Fixed entity -> color mapping. Color follows the status, never its rank. */
export const STATUS = {
  FORWARDED: { label: 'Forwarded', color: 'var(--series-forwarded)' },
  BLOCKED: { label: 'Blocked', color: 'var(--series-blocked)' },
  CACHED: { label: 'Cached', color: 'var(--series-cached)' },
  ERROR: { label: 'Error', color: 'var(--critical)' },
}
