import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useCssVars } from '../hooks/useCssVars.js'
import { compact, full, hhmm, STATUS } from '../lib/format.js'

const SERIES = ['forwarded', 'cached', 'blocked'] // stacking order, bottom -> top
const KEY = { forwarded: 'FORWARDED', cached: 'CACHED', blocked: 'BLOCKED' }

function TrafficTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const row = payload[0].payload
  return (
    <div className="tip">
      <div className="tip-title">{hhmm(row.time)}</div>
      {[...SERIES].reverse().map((s) => (
        <div className="tip-row" key={s}>
          <span><i className="swatch" style={{ background: STATUS[KEY[s]].color }} />{STATUS[KEY[s]].label}</span>
          <span className="num">{full(row[s])}</span>
        </div>
      ))}
      {row.errors > 0 && (
        <div className="tip-row"><span>Errors</span><span className="num">{full(row.errors)}</span></div>
      )}
      <div className="tip-row tip-total"><span>Total</span><span className="num">{full(row.total)}</span></div>
    </div>
  )
}

// Queries per minute over the last hour, stacked by outcome.
export default function TrafficChart({ series }) {
  const c = useCssVars(['--series-forwarded', '--series-cached', '--series-blocked', '--grid', '--axis', '--muted', '--surface', '--surface-2'])
  const data = series || []
  const totals = SERIES.reduce((acc, s) => ({ ...acc, [s]: data.reduce((n, d) => n + d[s], 0) }), {})
  const empty = data.every((d) => d.total === 0)
  const color = { forwarded: c['--series-forwarded'], cached: c['--series-cached'], blocked: c['--series-blocked'] }

  return (
    <section className="panel">
      <h2>Traffic</h2>
      <p className="sub">Queries per minute, last 60 minutes</p>
      <div className="legend">
        {SERIES.map((s) => (
          <span className="key" key={s}>
            <i className="swatch" style={{ background: color[s] }} />
            {STATUS[KEY[s]].label} <span className="num">{full(totals[s])}</span>
          </span>
        ))}
      </div>
      <div style={{ height: 240, position: 'relative' }}>
        {empty && <div className="empty" style={{ position: 'absolute', inset: '35% 0 auto' }}>No queries in the last hour yet — try <code>nslookup -port=5300 google.com 127.0.0.1</code></div>}
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -12 }} barCategoryGap={1}>
            <CartesianGrid vertical={false} stroke={c['--grid']} strokeWidth={1} />
            <XAxis dataKey="time" tickFormatter={hhmm} interval="preserveStartEnd" tick={{ fontSize: 11, fill: c['--muted'] }}
                   axisLine={{ stroke: c['--axis'] }} tickLine={false} minTickGap={48} />
            <YAxis allowDecimals={false} tickFormatter={compact} tick={{ fontSize: 11, fill: c['--muted'] }}
                   axisLine={false} tickLine={false} width={44} />
            <Tooltip content={<TrafficTooltip />} cursor={{ fill: c['--surface-2'] }} isAnimationActive={false} />
            {SERIES.map((s, i) => (
              <Bar key={s} dataKey={s} stackId="q" fill={color[s]} maxBarSize={24}
                   stroke={c['--surface']} strokeWidth={1}
                   radius={i === SERIES.length - 1 ? [4, 4, 0, 0] : 0} isAnimationActive={false} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}
