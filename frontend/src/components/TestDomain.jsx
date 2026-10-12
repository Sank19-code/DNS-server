import { useState } from 'react'
import { api } from '../api/client.js'
import { ms } from '../lib/format.js'
import StatusTag from './StatusTag.jsx'

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'HTTPS']

// Runs a lookup through the real pipeline over HTTP - the demo for people without nslookup.
export default function TestDomain({ onDone, upstream }) {
  const [name, setName] = useState('')
  const [type, setType] = useState('A')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setBusy(true)
    setError(null)
    try {
      setResult(await api.resolve(name.trim(), type))
      onDone?.()
    } catch (err) {
      setResult(null)
      setError(err.status === 429 ? 'Too many lookups — wait a few seconds.' : err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel">
      <h2>Test a domain</h2>
      <p className="sub">Resolve through the filter: blocklist → cache → upstream</p>
      <form onSubmit={submit}>
        <div className="field-row">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="ads.doubleclick.net"
                 aria-label="Domain to resolve" spellCheck="false" autoCapitalize="off" />
          <select value={type} onChange={(e) => setType(e.target.value)} aria-label="Record type">
            {TYPES.map((t) => <option key={t}>{t}</option>)}
          </select>
        </div>
        <div className="btn-row">
          <button className="primary" type="submit" disabled={busy || !name.trim()}>{busy ? 'Resolving…' : 'Resolve'}</button>
          {['google.com', 'ad.doubleclick.net'].map((d) => (
            <button type="button" key={d} onClick={() => setName(d)}>{d}</button>
          ))}
        </div>
      </form>
      {error && <p className="error-text">{error}</p>}
      {!result && !error && (
        <p className="msg">Try a blocked name first, then resolve a normal one twice: the second answer comes
          from the cache in a fraction of the time.</p>
      )}
      {result && (
        <div className="result" aria-live="polite">
          <div className="headline"><StatusTag status={result.status} category={result.category} /></div>
          <div className="facts">
            <span>{result.domain} {result.type}</span>
            <span>{result.rcode}</span>
            <span className="num">{ms(result.latencyMs)}</span>
          </div>
          {result.answers?.length > 0 ? (
            <ul>
              {result.answers.map((a, i) => (
                <li key={i} className="num">{a.type} {a.data} <span className="muted">TTL {a.ttl}s</span></li>
              ))}
            </ul>
          ) : (
            <div className="muted">
              {result.status === 'BLOCKED'
                ? 'Blocked — the client is told this name does not exist.'
                : result.status === 'ERROR'
                  ? `The upstream DNS server (${upstream || 'upstream'}) didn't answer in time, so the client got ${result.rcode}. Check that it's reachable from this network.`
                  : 'No records returned.'}
            </div>
          )}
        </div>
      )}
    </section>
  )
}
