package com.sankar.dnsfilter.stats;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe counters + a bounded ring buffer of recent queries.
 * Feeds the dashboard: totals, block %, cache hit %, top domains, top blocked, recent log.
 */
public class StatsCollector {
    private static final int LOG_SIZE = 500;

    private final AtomicLong total = new AtomicLong();
    private final AtomicLong blocked = new AtomicLong();
    private final AtomicLong cached = new AtomicLong();
    private final AtomicLong forwarded = new AtomicLong();
    private final Map<String, AtomicLong> domainCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> blockedCounts = new ConcurrentHashMap<>();
    private final QueryLogEntry[] ring = new QueryLogEntry[LOG_SIZE];
    private int ringPos = 0;

    public void record(QueryLogEntry e) {
        // TODO (Day 3): bump counters by status, domain counts, write into ring buffer,
        //               optionally append to logs/queries.log
        total.incrementAndGet();
    }

    public synchronized List<QueryLogEntry> recent(int limit) {
        // TODO (Day 3): return newest-first from ring buffer
        return new ArrayList<>();
    }

    public long total() { return total.get(); }
    public long blocked() { return blocked.get(); }
    public long cached() { return cached.get(); }
    public long forwarded() { return forwarded.get(); }

    // TODO (Day 3): topDomains(n), topBlocked(n) - sort map entries or use a min-heap of size n
}
