# DNS Filter — a mini Pi-hole in Java

A DNS server your laptop points to. It parses raw DNS packets byte by byte, blocks ad / tracker / malware
domains, caches answers using their TTL in a hand-written LRU cache, forwards everything else to 8.8.8.8,
and shows live stats on a React dashboard.

**Stack:** Java 17 (no frameworks — `DatagramSocket`, JDK `HttpServer`, Gson) · Maven · React + Vite · Recharts

## Folder layout
```
backend/      Java DNS server + REST API (Maven project)
frontend/     React dashboard (Vite)
blocklists/   ads.txt, trackers.txt, malware.txt, allowlist.txt
scripts/      run-backend.bat, run-frontend.bat, test-dns.ps1
docs/         ARCHITECTURE.md
logs/         query log output
```

## Prerequisites (Windows)
- JDK 17+  →  `java -version`
- Maven    →  `mvn -v`
- Node 18+ →  `node -v`

## Run
```bat
scripts\run-backend.bat      :: DNS on UDP 5300, API on http://localhost:8081/api
scripts\run-frontend.bat     :: dashboard on http://localhost:5173
nslookup -port=5300 google.com 127.0.0.1
```
To filter your whole laptop: set `dns.port=53` in `backend/src/main/resources/config.properties`, run the
terminal as Administrator, and set your Wi-Fi adapter's DNS to `127.0.0.1`. (Revert it when you stop the server!)

## 4-day plan

### Day 1 — UDP + packet parsing
- [ ] Install JDK 17, Maven, Node; `mvn package` builds
- [ ] Run as pass-through proxy (already wired) → `nslookup -port=5300 google.com 127.0.0.1` works
- [ ] `DnsParser`: header, QNAME labels, compression pointers, answers + TTLs
- [ ] Enable and pass `DnsParserTest`
- [ ] Capture a real query in Wireshark and compare bytes with your parser output

### Day 2 — Blocking + cache
- [ ] `BlocklistLoader` + `Blocklist.check` with parent-domain matching and allowlist
- [ ] `DnsWriter.buildBlockedResponse` (NXDOMAIN, or 0.0.0.0 for A)
- [ ] `LruCache` (HashMap + doubly linked list), enable `LruCacheTest`
- [ ] `DnsCache` with TTL expiry, rewrite ID on hits
- [ ] Full pipeline in `QueryHandler`

### Day 3 — Stats + API
- [ ] `StatsCollector`: counters, ring-buffer log, top-N domains, write `logs/queries.log`
- [ ] REST endpoints: `/queries`, `/top`, `/blocklist` (GET/POST/DELETE), `/allowlist`
- [ ] Load a real blocklist (e.g. StevenBlack hosts, ~100k domains) and measure lookup time

### Day 4 — Dashboard + polish
- [ ] Charts in `TopDomains` (Recharts), wire up `BlocklistManager`
- [ ] Point the laptop at it for real browsing; screenshot the dashboard
- [ ] Benchmark: cache hit vs miss latency, queries/sec (numbers for the resume)
- [ ] README screenshots, push to GitHub

## Resume bullet (fill in your numbers on Day 4)
> Built a DNS filtering server in Java from scratch (raw UDP, RFC 1035 packet parsing, name compression)
> that blocks ad/tracker/malware domains across a __k-domain blocklist, with an O(1) LRU + TTL cache cutting
> repeat-lookup latency from __ ms to __ ms, and a React dashboard for live query analytics.
