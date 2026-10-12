import { useState } from 'react'
import { api, getToken, setToken } from '../api/client.js'

const CATEGORIES = ['custom', 'ads', 'trackers', 'malware']

// Add / remove / allow / check a domain at runtime. Changes apply instantly - the blocklist is
// checked before the cache, so no restart and no stale cached answers.
export default function BlocklistManager({ stats, onChange }) {
  const [domain, setDomain] = useState('')
  const [category, setCategory] = useState('custom')
  const [msg, setMsg] = useState(null)
  const [needToken, setNeedToken] = useState(false)
  const [token, setTokenInput] = useState(getToken())

  const run = async (label, fn) => {
    const d = domain.trim()
    if (!d) return
    try {
      const res = await fn(d)
      setMsg({ ok: true, text: label(res, d) })
      onChange?.()
    } catch (e) {
      if (e.status === 401) {
        setNeedToken(true)
        setMsg({ ok: false, text: 'This server requires an admin token for changes.' })
      } else {
        setMsg({ ok: false, text: e.message })
      }
    }
  }

  const cats = stats?.blocklistCategories || {}

  return (
    <section className="panel">
      <h2>Manage blocklist</h2>
      <p className="sub">
        {Object.keys(cats).length
          ? Object.entries(cats).map(([k, v]) => `${k} ${v.toLocaleString()}`).join(' · ')
          : 'Blocking a domain also blocks all its subdomains'}
      </p>
      <div className="field-row">
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="tracker.example.com"
               aria-label="Domain" spellCheck="false" autoCapitalize="off" />
        <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category">
          {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
        </select>
      </div>
      <div className="btn-row">
        <button className="primary" onClick={() => run((r) => `Blocked ${r.domain} [${r.category}]`, (d) => api.addBlocked(d, category))}>Block</button>
        <button onClick={() => run((r) => `Unblocked ${r.domain}`, api.removeBlocked)}>Unblock</button>
        <button onClick={() => run((r) => `Allowlisted ${r.domain} — it will always resolve`, api.allow)}>Allow</button>
        <button onClick={() => run((r) => r.blocked
          ? `${r.domain} is blocked [${r.category}]${r.listedExactly ? '' : ' via a parent domain'}`
          : `${r.domain} is not blocked`, api.check)}>Check</button>
      </div>
      {msg && <p className={msg.ok ? 'msg' : 'error-text'} role="status">{msg.text}</p>}

      {needToken && (
        <form className="field-row" style={{ marginTop: 8 }}
              onSubmit={(e) => { e.preventDefault(); setToken(token.trim()); setNeedToken(false); setMsg({ ok: true, text: 'Token saved in this browser. Try again.' }) }}>
          <input type="password" value={token} onChange={(e) => setTokenInput(e.target.value)} placeholder="Admin token" aria-label="Admin token" />
          <button type="submit">Save</button>
        </form>
      )}

      <div className="btn-row" style={{ marginTop: 16 }}>
        <button onClick={async () => {
          try { const r = await api.flushCache(); setMsg({ ok: true, text: `Cache flushed (${r.flushed} entries)` }); onChange?.() }
          catch (e) { if (e.status === 401) setNeedToken(true); setMsg({ ok: false, text: e.message }) }
        }}>Flush DNS cache</button>
      </div>
    </section>
  )
}
