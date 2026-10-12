# Architecture

```
            UDP :5300 (53 in prod)
 client ──────────────────────────► DnsServer
                                      │  per-IP token bucket (RateLimiter)     over limit -> drop
                                      │  bounded queue -> 16 worker threads    queue full -> drop
                                      ▼
                                 QueryHandler.resolve()
                                      │ 1. DnsParser.parseQuery          malformed -> FORMERR
                                      │ 2. Blocklist.check(name)         blocked   -> NXDOMAIN / 0.0.0.0
                                      │ 3. DnsCache.get(name:type)       hit       -> new ID, aged TTLs
                                      │ 4. UpstreamResolver.forward      timeout   -> SERVFAIL
                                      │    validate -> DnsCache.put(ttl)
                                      │ 5. StatsCollector.record
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
| `server` | `DnsServer`, `QueryHandler`, `RateLimiter` | UDP loop, back-pressure, the per-query pipeline |
| `filter` | `Blocklist`, `BlocklistLoader`, `RemoteBlocklist` | Domain matching, list formats, list download |
| `cache` | `LruCache`, `DnsCache`, `CacheEntry` | O(1) LRU with TTL expiry |
| `resolver` | `UpstreamResolver` | Forwarding with anti-spoofing checks and fallback |
| `stats` | `StatsCollector`, `TimeSeries`, `QueryLogEntry`, `DomainCount` | Counters, ring-buffer log, top-N, percentiles |
| `api` | `ApiServer`, `StaticFiles` | REST API + dashboard hosting |
| `config` | `Config` | Properties file with env-var / `-D` overrides |
| `bench` | `Benchmark` | UDP load generator |

## Threading model

- **One receiver thread** loops on `DatagramSocket.receive()`, applies the rate limiter, and hands
  each packet to a fixed pool of 16 workers. One slow upstream lookup never blocks other clients.
- The pool's queue is **bounded** (1,000). When it is full, packets are dropped and counted, not
  queued forever. An unbounded queue turns a flood into an out-of-memory crash, and DNS clients
  retry anyway.
- Workers send their reply on the shared socket. `DatagramSocket.send` is thread-safe.
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
| `RateLimiter` | Token bucket per IP | Allows short bursts but caps the sustained rate. Idle buckets are swept. |

## Design decisions

- **Block before cache.** Adding a domain through the API takes effect immediately, even if an
  answer for it is still cached.
- **Cache key = `name:type`.** A and AAAA answers differ. Names are lower-cased, so `Google.COM`
  hits the `google.com` entry.
- **TTL = minimum answer TTL, capped at `cache.maxTtl`.** Never serve a record longer than its owner
  allows. On a hit every TTL in the reply is reduced by the entry's age (`DnsWriter.adjustTtl`), so
  downstream caches don't extend the lifetime either.
- **Negative caching (RFC 2308).** NXDOMAIN / NODATA replies are cached for the SOA record's TTL
  (capped at 300 s), which stops a misbehaving app from hammering upstream for a name that doesn't exist.
- **Cached replies echo the client's casing.** Some resolvers randomise letter case as an
  anti-spoofing measure (DNS 0x20) and reject replies that don't match.
- **Anti-spoofing on the upstream side.** Each forward uses a fresh socket, so the OS picks a random
  source port. A reply is accepted only if it comes from the upstream's address, carries our
  transaction ID and has QR=1. Random port + ID is the standard defence against Kaminsky-style
  cache poisoning.
- **Most-specific rule wins; allow beats block at the same level.** Allowlisting `safe.example.com`
  un-blocks that subtree even if `example.com` is blocked. Blocking `bad.safe.example.com` still
  works. The walk stops before the bare TLD, so a stray `com` entry can't take down the internet.
- **NXDOMAIN vs 0.0.0.0.** NXDOMAIN ("no such name") is the default. Null-route mode answers
  `0.0.0.0` / `::`, which makes some apps fail fast instead of retrying.
- **Drop, don't refuse, when rate-limited.** A `REFUSED` reply still sends bytes to a possibly
  spoofed victim. Dropping reflects nothing, which matters for DNS amplification attacks.
- **Reads public, writes behind a token.** The dashboard demo works for anyone. Changing the
  blocklist or flushing the cache needs `DNSFILTER_API_TOKEN`, compared in constant time.
- **One process in production.** The Java server also serves the built dashboard, so there's one
  port, no CORS, and no mixed-content issues behind HTTPS.
- **Fail soft on startup.** If the blocklist download fails, the server uses the last cached copy,
  or skips the list. It always starts.

## Known limits / next steps

- UDP only. Replies over 512 bytes without EDNS should set TC and the client retries over TCP;
  TCP and DNS-over-HTTPS aren't implemented.
- No DNSSEC validation (the upstream resolver does it).
- Stats are in memory and reset on restart. Persisting them to SQLite would be the next step.
- The blocklist could move to a reversed-label trie to share suffixes and cut memory.
