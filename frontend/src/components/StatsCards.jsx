// Total queries, % blocked, cache hit rate, blocklist size.
export default function StatsCards({ stats }) {
  if (!stats) return <div className="cards">Loading...</div>
  const pct = (a, b) => (b ? ((a / b) * 100).toFixed(1) + '%' : '0%')
  const cards = [
    ['Total queries', stats.totalQueries],
    ['Blocked', `${stats.blocked} (${pct(stats.blocked, stats.totalQueries)})`],
    ['Cache hit rate', pct(stats.cacheHits, stats.cacheHits + stats.cacheMisses)],
    ['Domains on blocklist', stats.blocklistSize],
  ]
  return (
    <div className="cards">
      {cards.map(([label, value]) => (
        <div className="card" key={label}>
          <div className="muted">{label}</div>
          <div className="big">{value}</div>
        </div>
      ))}
    </div>
  )
}
