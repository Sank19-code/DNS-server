import { useEffect, useState } from 'react'
import { api, AUTH_EVENT } from './api/client.js'
import { usePoll } from './hooks/usePoll.js'
import { uptime } from './lib/format.js'
import StatsCards from './components/StatsCards.jsx'
import TrafficChart from './components/TrafficChart.jsx'
import TestDomain from './components/TestDomain.jsx'
import TopDomains from './components/TopDomains.jsx'
import LatencyTable from './components/LatencyTable.jsx'
import BlocklistManager from './components/BlocklistManager.jsx'
import QueryLog from './components/QueryLog.jsx'
import TokenPrompt from './components/TokenPrompt.jsx'

export default function App() {
  const stats = usePoll(api.stats, 2000)
  const top = usePoll(() => api.top(8), 5000)
  const series = usePoll(api.timeseries, 5000)
  const s = stats.data
  const [needToken, setNeedToken] = useState(false)
  const down = Boolean(stats.error) && stats.error.status !== 401

  useEffect(() => {
    const onAuth = () => setNeedToken(true)
    window.addEventListener(AUTH_EVENT, onAuth)
    return () => window.removeEventListener(AUTH_EVENT, onAuth)
  }, [])

  const refreshAll = () => { stats.refresh(); top.refresh(); series.refresh() }

  return (
    <div className="app">
      <header className="top">
        <h1>DNS Filter</h1>
        <span className={`live ${down ? 'down' : ''}`} role="status">
          <i className="dot" aria-hidden="true" />
          {down ? 'Backend unreachable — is the Java server running on :8081?' : 'Live'}
        </span>
        {s && (
          <div className="meta muted">
            <span>Up {uptime(s.uptimeSeconds)}</span>
            {s.countingSince < s.startedAt - 60_000 && (
              <span title="Totals were restored from the saved stats file">
                Counting since {new Date(s.countingSince).toLocaleDateString()}
              </span>
            )}
            <span>Upstream {s.upstreams?.join(', ')}</span>
          </div>
        )}
      </header>

      {needToken && <TokenPrompt onSaved={() => { setNeedToken(false); refreshAll() }} />}

      <StatsCards stats={s} />

      <div className="row-2">
        <TrafficChart series={series.data} />
        <TestDomain onDone={refreshAll} upstream={s?.upstreams?.[0]} />
      </div>

      <TopDomains top={top.data} />

      <div className="row-even">
        <LatencyTable latency={s?.latencyMs} />
        <BlocklistManager stats={s} onChange={refreshAll} />
      </div>

      <QueryLog />
    </div>
  )
}
