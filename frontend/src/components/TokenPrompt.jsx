import { useState } from 'react'
import { getToken, setToken } from '../api/client.js'

// Shown when the server answers 401: it has an admin token set and this browser doesn't have it.
export default function TokenPrompt({ onSaved }) {
  const [token, setTokenInput] = useState(getToken())
  const rejected = Boolean(getToken())

  const save = (e) => {
    e.preventDefault()
    setToken(token.trim())
    onSaved?.()
  }

  return (
    <section className="panel token-prompt" role="alert">
      <h2>Admin token required</h2>
      <p className="sub">
        {rejected
          ? 'The saved token was rejected. Paste the current value of DNSFILTER_API_TOKEN.'
          : 'This server is protected. Paste the value of DNSFILTER_API_TOKEN to see its data.'}
      </p>
      <form className="field-row" onSubmit={save}>
        <input type="password" value={token} onChange={(e) => setTokenInput(e.target.value)}
               placeholder="Admin token" aria-label="Admin token" autoComplete="current-password" />
        <button type="submit" className="primary" disabled={!token.trim()}>Save</button>
      </form>
    </section>
  )
}
