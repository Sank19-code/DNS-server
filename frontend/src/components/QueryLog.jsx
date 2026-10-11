// Live table of recent queries, color-coded by status.
export default function QueryLog({ queries }) {
  return (
    <section className="panel">
      <h2>Recent queries</h2>
      <table>
        <thead>
          <tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Status</th><th>Latency</th></tr>
        </thead>
        <tbody>
          {queries.length === 0 && (
            <tr><td colSpan="6" className="muted">No queries yet</td></tr>
          )}
          {queries.map((q, i) => (
            <tr key={i}>
              <td>{new Date(q.timestamp).toLocaleTimeString()}</td>
              <td>{q.clientIp}</td>
              <td>{q.domain}</td>
              <td>{q.type}</td>
              <td><span className={`tag ${q.status?.toLowerCase()}`}>{q.status}{q.category ? ` · ${q.category}` : ''}</span></td>
              <td>{(q.latencyMicros / 1000).toFixed(1)} ms</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
