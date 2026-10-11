import { useEffect, useState } from 'react'
import { api } from './api/client.js'
import StatsCards from './components/StatsCards.jsx'
import QueryLog from './components/QueryLog.jsx'
import TopDomains from './components/TopDomains.jsx'
import BlocklistManager from './components/BlocklistManager.jsx'

const POLL_MS = 2000

export default function App() {
  const [stats, setStats] = useState(null)
  const [queries, setQueries] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    const load = async () => {
      try {
        const [s, q] = await Promise.all([api.stats(), api.queries(100)])
        setStats(s)
        setQueries(q)
        setError(null)
      } catch (e) {
        setError('Backend not reachable - is the Java server running on :8080?')
      }
    }
    load()
    const id = setInterval(load, POLL_MS)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="app">
      <header>
        <h1>DNS Filter</h1>
        <span className={error ? 'dot red' : 'dot green'} />
        <span className="muted">{error ?? 'Live'}</span>
      </header>
      <StatsCards stats={stats} />
      <div className="grid">
        <TopDomains />
        <BlocklistManager />
      </div>
      <QueryLog queries={queries} />
    </div>
  )
}
