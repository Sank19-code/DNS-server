import BarList from './BarList.jsx'

// Top queried, top blocked, and what kind of thing got blocked.
export default function TopDomains({ top }) {
  return (
    <div className="row-3">
      <section className="panel">
        <h2>Top domains</h2>
        <p className="sub">Most queried (allowed)</p>
        <BarList items={top?.topDomains} color="var(--series-forwarded)" emptyText="No allowed queries yet" />
      </section>
      <section className="panel">
        <h2>Top blocked</h2>
        <p className="sub">Most blocked domains</p>
        <BarList items={top?.topBlocked} color="var(--series-blocked)" emptyText="Nothing blocked yet" />
      </section>
      <section className="panel">
        <h2>Blocked by category</h2>
        <p className="sub">Which list caught them</p>
        <BarList items={top?.blockedByCategory} color="var(--series-blocked)" emptyText="Nothing blocked yet" />
        {top?.topClients?.length > 0 && (
          <>
            <h2 style={{ marginTop: 18 }}>Top clients</h2>
            <p className="sub">Who is asking</p>
            <BarList items={top.topClients.slice(0, 5)} color="var(--muted)" />
          </>
        )}
      </section>
    </div>
  )
}
