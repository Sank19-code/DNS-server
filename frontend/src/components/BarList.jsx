import { full } from '../lib/format.js'

// Ranked horizontal bars: name above, thin bar below, value at the right.
// HTML instead of SVG so long domain names truncate cleanly and never collide.
export default function BarList({ items, color, emptyText = 'Nothing yet' }) {
  if (!items || items.length === 0) return <div className="empty">{emptyText}</div>
  const max = Math.max(...items.map((i) => i.count), 1)
  return (
    <div className="barlist" role="list">
      {items.map((it) => (
        <div className="item" role="listitem" key={it.name} title={`${it.name}: ${full(it.count)} queries`}>
          <div style={{ minWidth: 0 }}>
            <div className="name">{it.name}</div>
            <div className="bar" style={{ width: `${(it.count / max) * 100}%`, background: color }} />
          </div>
          <div className="val">{full(it.count)}</div>
        </div>
      ))}
    </div>
  )
}
