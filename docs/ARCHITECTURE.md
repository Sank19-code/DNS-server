# Architecture

```
            UDP :5300 (53 in prod)
 laptop ───────────────────────────► DnsServer (DatagramSocket + thread pool)
                                          │
                                          ▼
                                     QueryHandler
                                          │ 1. DnsParser.parse(bytes)
                                          │ 2. Blocklist.check(name) ──► blocked → DnsWriter.buildBlockedResponse (NXDOMAIN / 0.0.0.0)
                                          │ 3. DnsCache.get(name:type) ─► hit → DnsWriter.rewriteId
                                          │ 4. UpstreamResolver.forward ─► 8.8.8.8 → DnsCache.put(ttl = min answer TTL)
                                          │ 5. StatsCollector.record
                                          ▼
                                     reply to client

 React dashboard (:5173) ──HTTP /api──► ApiServer (JDK HttpServer :8080) ──► StatsCollector / Blocklist / DnsCache
```

## Packages (`backend/src/main/java/com/sankar/dnsfilter/`)

| Package    | Responsibility |
|------------|----------------|
| `server`   | UDP socket loop, per-query pipeline |
| `protocol` | Byte-level DNS parsing and response building (RFC 1035) |
| `resolver` | Forwarding to the upstream resolver |
| `cache`    | Hand-written O(1) LRU (HashMap + doubly linked list) with TTL expiry |
| `filter`   | Blocklist with parent-domain matching, categories, allowlist |
| `stats`    | Atomic counters, ring-buffer query log, top-N |
| `api`      | REST API for the dashboard |
| `config`   | `config.properties` loader |

## Design decisions worth talking about in interviews
- **Why UDP + a thread pool**: one slow upstream lookup must not block other clients.
- **Why hand-written LRU**: O(1) get/put/evict; shows the DSA rather than hiding it in `LinkedHashMap`.
- **Cache key = name + type**: A and AAAA answers differ.
- **TTL = min TTL of answers**: never serve a record longer than its owner allows.
- **Rewrite transaction ID on cache hits**: the client matches replies by ID.
- **Parent-domain matching**: `doubleclick.net` blocks `ad.doubleclick.net`; O(#labels) lookups.
- **NXDOMAIN vs 0.0.0.0**: trade-offs between the two blocking styles.
