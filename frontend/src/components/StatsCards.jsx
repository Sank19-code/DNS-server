import { compact, full, ms, pct } from '../lib/format.js'

// Headline numbers. Values are plain ink; identity colors live in the charts.
export default function StatsCards({ stats }) {
  if (!stats) {
    return <div className="tiles">{[0, 1, 2, 3, 4].map((i) => <div className="tile" key={i}><div className="label">&nbsp;</div><div className="value">–</div></div>)}</div>
  }
  const lat = stats.latencyMs || {}
  const cachedP50 = lat.CACHED?.p50
  const upstreamP50 = lat.FORWARDED?.p50
  const speedup = cachedP50 && upstreamP50 ? upstreamP50 / cachedP50 : null

  const tiles = [
    {
      label: 'Total queries',
      value: compact(stats.totalQueries),
      detail: `${full(stats.forwarded)} forwarded · ${full(stats.errors)} ${stats.errors === 1 ? 'error' : 'errors'}`,
    },
    {
      label: 'Blocked',
      value: pct(stats.blocked, stats.totalQueries),
      detail: `${full(stats.blocked)} queries blocked`,
    },
    {
      label: 'Cache hit rate',
      value: pct(stats.cacheHits, stats.cacheHits + stats.cacheMisses),
      detail: `${full(stats.cacheSize)} / ${full(stats.cacheCapacity)} entries cached`,
    },
    {
      label: 'Cache speed-up (p50)',
      value: speedup ? `${speedup >= 10 ? speedup.toFixed(0) : speedup.toFixed(1)}×` : '–',
      detail: speedup ? `${ms(cachedP50)} cached vs ${ms(upstreamP50)} upstream` : 'needs cached + upstream lookups',
    },
    {
      label: 'Domains on blocklist',
      value: compact(stats.blocklistSize),
      detail: `${full(stats.allowlistSize)} allowlisted${stats.rateLimited ? ` · ${full(stats.rateLimited)} rate-limited` : ''}`,
    },
  ]
  return (
    <div className="tiles">
      {tiles.map((t) => (
        <div className="tile" key={t.label}>
          <div className="label">{t.label}</div>
          <div className="value">{t.value}</div>
          <div className="detail">{t.detail}</div>
        </div>
      ))}
    </div>
  )
}
