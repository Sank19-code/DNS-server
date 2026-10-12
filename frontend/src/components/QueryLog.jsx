import { useState } from 'react'
import { usePoll } from '../hooks/usePoll.js'
import { api } from '../api/client.js'
import { clock, ms } from '../lib/format.js'
import StatusTag from './StatusTag.jsx'

const FILTERS = [
  ['', 'All'], ['BLOCKED', 'Blocked'], ['CACHED', 'Cached'], ['FORWARDED', 'Forwarded'], ['ERROR', 'Errors'],
]

// Live log of recent queries with a status filter, search and pause.
export default function QueryLog() {
  const [status, setStatus] = useState('')
  const [search, setSearch] = useState('')
  const [paused, setPaused] = useState(false)
  const { data } = usePoll(
    () => (paused ? Promise.reject(new Error('paused')) : api.queries(100, { status, search: search.trim() })),
    2000, [status, search, paused])
  const rows = data || []

  return (
    <section className="panel">
      <h2>Recent queries</h2>
      <p className="sub">Newest first · refreshes every 2 s{paused ? ' · paused' : ''}</p>
      <div className="toolbar">
        <div className="chips" role="group" aria-label="Filter by outcome">
          {FILTERS.map(([v, label]) => (
            <button key={label} className="chip" aria-pressed={status === v} onClick={() => setStatus(v)}>{label}</button>
          ))}
        </div>
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search domain or client"
               aria-label="Search queries" spellCheck="false" />
        <button onClick={() => setPaused((p) => !p)} aria-pressed={paused}>{paused ? 'Resume' : 'Pause'}</button>
      </div>
      <div className="scroll">
        <table>
          <thead>
            <tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Outcome</th><th className="r">Latency</th></tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan="6" className="empty">No matching queries</td></tr>
            )}
            {rows.map((q, i) => (
              <tr key={`${q.timestamp}-${i}`}>
                <td className="num muted">{clock(q.timestamp)}</td>
                <td className="text-2">{q.clientIp}</td>
                <td className="domain" title={q.domain}>{q.domain}</td>
                <td className="text-2">{q.type}</td>
                <td><StatusTag status={q.status} category={q.category} /></td>
                <td className="r num">{ms(q.latencyMicros / 1000)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
