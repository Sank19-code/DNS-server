# Architecture

```
            UDP :5300 (53 in prod)
 client ──────────────────────────► DnsServer
                                      │  Admission: per-IP bucket, then global  over limit -> drop
                                      │  bounded queue -> 16 worker threads    queue full -> drop
            TCP :5300                 │
 client ──────────────────────────► TcpDnsServer  (same Admission; ≤64 conns, ≤8 per IP,
                                      │            10 s idle, 2 s per message, 5 s per write)
                                      ▼
                                 QueryHandler.resolve(query, client, UDP | TCP)
                                      │ 1. DnsParser.parseQuery          malformed -> FORMERR
                                      │ 2. Blocklist.check(name)         blocked   -> NXDOMAIN / 0.0.0.0
                                      │ 3. DnsCache.get(name:type[:e|:do]) hit     -> new ID, aged TTLs
                                      │ 4. UpstreamResolver.forward/forwardTcp      timeout -> SERVFAIL
                                      │    validate -> DnsCache.put(ttl)
                                      │ 5. fit: UDP reply > client limit -> empty TC=1 reply
                                      │ 6. StatsCollector.record
                                      ▼
                                 reply to client

 browser ──HTTP──► ApiServer (JDK HttpServer :8081)
                     /api/*  -> StatsCollector, Blocklist, DnsCache, QueryHandler (/api/resolve)
                     /       -> StaticFiles (built React dashboard)
```

## Packages (`backend/src/main/java/com/sankar/dnsfilter/`)

| Package | Classes | Responsibility |
|---|---|---|
| `protocol` | `DnsParser`, `DnsWriter`, `DnsHeader`, `DnsMessage`, `DnsQuestion`, `DnsRecord` | Byte-level parsing and building (RFC 1035) |
| `server` | `DnsServer`, `TcpDnsServer`, `QueryHandler`, `Admission`, `RateLimiter` | UDP + TCP listeners, rate limiting, back-pressure, the per-query pipeline |
| `filter` | `Blocklist`, `BlocklistLoader`, `RemoteBlocklist` | Domain matching, list formats, list download, reload, saved overrides |
| `cache` | `LruCache`, `DnsCache`, `CacheEntry` | O(1) LRU with TTL expiry |
| `resolver` | `UpstreamResolver` | Forwarding over UDP / TCP with anti-spoofing checks and fallback |
| `stats` | `StatsCollector`, `StatsStore`, `TimeSeries`, `QueryLogEntry`, `DomainCount` | Counters, ring-buffer log, top-N, percentiles, save / restore |
| `api` | `ApiServer`, `StaticFiles` | REST API + dashboard hosting, access control |
| `config` | `Config` | Properties file + `config.local.properties`, env-var / `-D` overrides |
| `bench` | `Benchmark` | UDP load generator |

## Threading model

- **One receiver thread** loops on `DatagramSocket.receive()`, applies the rate limiter, and hands
  each packet to a fixed pool of 16 workers. One slow upstream lookup never blocks other clients.
- The pool's queue is **bounded** (1,000). When it is full, packets are dropped and counted, not
  queued forever. An unbounded queue turns a flood into an out-of-memory crash, and DNS clients
  retry anyway.
- Workers send their reply on the shared socket. `DatagramSocket.send` is thread-safe.
- **TCP** gets one thread per connection from a pool of at most 64 (`SynchronousQueue`: no waiting
  room, so connection 65 is closed at once), and one IP may hold at most 8. A socket timeout only
  bounds each `read()`, so a query that has started arriving gets one fixed 2 s deadline for all of
  it. Java has no write timeout, so a watchdog thread closes the socket of a client whose reply has
  been stuck for 5 s, which makes the blocked `write()` throw and frees the thread.
- **Upstream lookups** hold a permit from a semaphore of 12 (below the 16 workers). With none free,
  the query gets SERVFAIL at once, so a flood of never-seen names can't park every worker on a
  1.5 s upstream timeout while cached and blocked names wait in the queue.
- **One background thread** re-downloads the remote lists every 24 h and saves the stats every 5 min.
- Shared state is built for this: `LruCache` uses `synchronized` methods (microseconds of work
  against milliseconds of network); counters are `LongAdder` (no contention between 16 threads
  incrementing one counter); maps are `ConcurrentHashMap`; the ring buffer takes a short lock.

## Data structures (the interview talking points)

| Where | Structure | Why |
|---|---|---|
| `LruCache` | HashMap + doubly linked list with sentinel head/tail | O(1) get / put / evict. Written by hand instead of `LinkedHashMap` to show the mechanism. |
| `Blocklist` | HashMap of domains, walked label by label | O(#labels) per lookup (≈3–4 hash lookups) whether the list has 10 or 100k entries. No regex. |
| `StatsCollector.topN` | Min-heap of size n | O(M log n) instead of sorting all M domains. The root is the smallest of the current top n, so each new key is compared against it and only replaces it if larger. |
| Query log | Ring buffer, 500 entries | Fixed memory; newest-first reads without shifting. |
| `TimeSeries` | 60 buckets indexed by `minute % 60` | Fixed memory; stale buckets are reset lazily when their slot comes round again. |
| `RateLimiter` | Token bucket per IP, in an access-ordered `LinkedHashMap` capped at 10,000 | Allows short bursts but caps the sustained rate. The LRU cap keeps memory fixed and each packet O(1) even when every packet has a new spoofed source; an active flooder is always "recent", so it stays limited. |

## Design decisions

- **Block before cache.** Adding a domain through the API takes effect immediately, even if an
  answer for it is still cached.
- **Cache key = `name:type` + EDNS variant.** A and AAAA answers differ. Names are lower-cased, so
  `Google.COM` hits the `google.com` entry. Plain, EDNS (`:e`) and EDNS+DNSSEC-OK (`:do`) queries
  get separate entries, so a client never gets an OPT record it didn't ask for or misses DNSSEC
  records it did ask for.
- **Fit the reply to the transport.** A UDP client accepts 512 bytes, or the size in its EDNS OPT
  record. A bigger reply (cached or fresh) is replaced by an empty TC=1 reply. The client then
  retries over TCP (`TcpDnsServer`), and we forward that query over TCP too, so it arrives whole.
- **TTL = minimum answer TTL, capped at `cache.maxTtl`.** Never serve a record longer than its owner
  allows. On a hit every TTL in the reply is reduced by the entry's age (`DnsWriter.adjustTtl`), so
  downstream caches don't extend the lifetime either.
- **Negative caching (RFC 2308).** NXDOMAIN / NODATA replies are cached for the SOA record's TTL
  (capped at 300 s), which stops a misbehaving app from hammering upstream for a name that doesn't exist.
- **Cached replies echo the client's casing.** Some resolvers randomise letter case as an
  anti-spoofing measure (DNS 0x20) and reject replies that don't match.
- **Anti-spoofing on the upstream side.** Each forward uses a fresh socket, so the OS picks a random
  source port, and a fresh `SecureRandom` transaction ID. Never the client's ID: an attacker who is
  also a client would know that one. A reply is accepted only if it comes from the upstream's
  address, carries our ID, has QR=1 and echoes our question. The client's ID is put back before
  replying. Random port × random ID is the standard defence against Kaminsky-style cache poisoning.
- **Most-specific rule wins; allow beats block at the same level.** Allowlisting `safe.example.com`
  un-blocks that subtree even if `example.com` is blocked. Blocking `bad.safe.example.com` still
  works. The walk stops before the bare TLD, so a stray `com` entry can't take down the internet.
- **NXDOMAIN vs 0.0.0.0.** NXDOMAIN ("no such name") is the default. Null-route mode answers
  `0.0.0.0` / `::`, which makes some apps fail fast instead of retrying.
- **Drop, don't refuse, when rate-limited.** A `REFUSED` reply still sends bytes to a possibly
  spoofed victim. Dropping reflects nothing, which matters for DNS amplification attacks.
- **Two limits, not one.** Per-IP limits stop one heavy client; a global queries/s cap is what
  still holds when every packet carries a different (spoofed) source address.
- **UDP replies capped at 1,232 bytes.** A client's EDNS size is honoured only up to that (DNS
  Flag Day 2020): no IP fragmentation, and a spoofed 60-byte query yields at most ~20× in reply
  bytes instead of ~68×. Bigger answers go TC=1 → TCP, which can't be spoofed.
- **Fail fast under load.** An instant SERVFAIL beats an answer after a 4.5 s wait: the client
  retries or tries its next resolver, and the worker is free for the next query.
- **The API is private by default.** The query log is browsing history. The API binds to
  127.0.0.1, refuses a wider bind without `DNSFILTER_API_TOKEN`, and with a token checks it
  (in constant time) on reads as well as writes. Browser attacks are blocked separately because
  they don't need the network at all: a cross-site POST gets 403 from the `Origin` check, a
  `text/plain` "simple request" gets 415, and a DNS-rebinding `Host` gets 403. No CORS headers are
  sent unless one origin is configured.
- **One process in production.** The Java server also serves the built dashboard, so there's one
  port, no CORS, and no mixed-content issues behind HTTPS.
- **Fail soft on startup.** If the blocklist download fails, the server uses the last cached copy,
  or skips the list. It always starts.
- **Reload = build aside, then swap.** `Blocklist.reload()` reads every source into new sets and
  swaps them in under the same lock the API edits take. Queries see either the old lists or the
  new ones, never half, and an edit made during a reload is replayed onto the new sets.
- **Dashboard edits are overrides, not file edits.** Block / unblock / allow / unallow are kept as
  four small sets, saved to `data/overrides.txt` (temp file + atomic move) and re-applied after
  every load. So an unblocked StevenBlack entry stays unblocked when the list is downloaded again.
- **Stats survive restarts.** Totals, top-N maps and the query log are saved to `data/stats.json`
  every 5 minutes and on shutdown, and added back at startup. The per-minute chart starts fresh:
  it's about the last hour.
- **The receive loop never dies.** A transient socket error is logged and counted; only `stop()`
  ends the loop. A shutdown hook stops the listeners and saves the stats on Ctrl+C / `docker stop`.

## Known limits / next steps

- No DNS-over-HTTPS / DNS-over-TLS to the upstream (would also get around networks that block
  outside DNS).
- No DNSSEC validation (the upstream resolver does it).
- Stats are a JSON snapshot, not a database. History beyond the last 500 queries and the last hour
  isn't kept.
- The blocklist could move to a reversed-label trie to share suffixes and cut memory.
- No request coalescing: 16 clients asking for the same uncached name send 16 upstream lookups
  (and use 16 in-flight permits). Sharing one pending lookup per `name:type` would fix both.
- Volumetric DDoS (more traffic than the link carries) can't be handled in the application. That
  is the firewall's and the hosting provider's job; see DEPLOY.md.
