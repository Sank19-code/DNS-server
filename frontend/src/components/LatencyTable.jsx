import { full, ms, STATUS } from '../lib/format.js'

// Response time by outcome over the last 500 queries. A table, not a chart: the values span
// ~3 orders of magnitude (0.05 ms blocked vs 15 ms upstream), which bars can't show honestly.
export default function LatencyTable({ latency }) {
  const rows = ['BLOCKED', 'CACHED', 'FORWARDED', 'ERROR'].filter((s) => latency?.[s])
  return (
    <section className="panel">
      <h2>Response time</h2>
      <p className="sub">By outcome, last 500 queries</p>
      {rows.length === 0 ? (
        <div className="empty">No queries yet</div>
      ) : (
        <table>
          <thead>
            <tr><th>Outcome</th><th className="r">Count</th><th className="r">p50</th><th className="r">p95</th><th className="r">p99</th></tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s}>
                <td><span className="status"><i className="dot-key" style={{ background: STATUS[s].color }} />{STATUS[s].label}</span></td>
                <td className="r num">{full(latency[s].count)}</td>
                <td className="r num">{ms(latency[s].p50)}</td>
                <td className="r num">{ms(latency[s].p95)}</td>
                <td className="r num">{ms(latency[s].p99)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
