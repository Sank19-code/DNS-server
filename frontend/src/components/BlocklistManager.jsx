import { useState } from 'react'
import { api } from '../api/client.js'

// Add / remove / allow a domain at runtime (no server restart).
export default function BlocklistManager() {
  const [domain, setDomain] = useState('')
  const [msg, setMsg] = useState('')

  const run = async (fn, label) => {
    if (!domain.trim()) return
    try {
      await fn(domain.trim())
      setMsg(`${label}: ${domain}`)
      setDomain('')
    } catch (e) {
      setMsg(`Failed: ${e.message}`)
    }
  }

  return (
    <section className="panel">
      <h2>Blocklist</h2>
      <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="ads.example.com" />
      <div className="row">
        <button onClick={() => run(api.addBlocked, 'Blocked')}>Block</button>
        <button onClick={() => run(api.removeBlocked, 'Unblocked')}>Unblock</button>
        <button onClick={() => run(api.allow, 'Allowlisted')}>Allow</button>
      </div>
      {msg && <p className="muted">{msg}</p>}
    </section>
  )
}
