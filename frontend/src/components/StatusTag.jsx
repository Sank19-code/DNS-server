import { STATUS } from '../lib/format.js'

// Colored mark beside plain-ink text, so the status never relies on color alone.
export default function StatusTag({ status, category }) {
  const s = STATUS[status]
  if (!s) return <span className="status">{status ?? '–'}</span>
  return (
    <span className="status">
      {status === 'ERROR'
        ? <i className="icon" aria-hidden="true">!</i>
        : <i className="dot-key" style={{ background: s.color }} aria-hidden="true" />}
      {s.label}
      {category && <span className="cat">· {category}</span>}
    </span>
  )
}
