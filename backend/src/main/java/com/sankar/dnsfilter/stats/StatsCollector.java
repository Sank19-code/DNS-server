package com.sankar.dnsfilter.stats;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.LongSupplier;

/**
 * Thread-safe counters + a bounded ring buffer of recent queries.
 * Feeds the dashboard: totals, block %, latency percentiles, top domains, top blocked,
 * top clients, blocked-by-category, queries per minute, and the live query log.
 *
 * Concurrency: counters are LongAdders (cheaper than AtomicLong when 16 worker threads
 * increment the same counter), maps are ConcurrentHashMaps, and only the ring buffer
 * takes a lock - a few array writes, so contention is negligible.
 *
 * Memory is bounded: the ring holds LOG_SIZE entries, the time series 60 buckets, and each
 * per-domain map stops admitting NEW keys after MAX_TRACKED distinct names (existing keys keep
 * counting). That cap matters because a random-subdomain flood (abc123.example.com, ...) would
 * otherwise grow the map forever.
 */
public class StatsCollector {
    public static final int LOG_SIZE = 500;
    public static final int MAX_TRACKED = 50_000;

    private final LongSupplier clock;
    private final long startedAt;
    private volatile long countingSince;   // earlier than startedAt once a saved snapshot is restored

    private final LongAdder total = new LongAdder();
    private final EnumMap<QueryLogEntry.Status, LongAdder> byStatus = new EnumMap<>(QueryLogEntry.Status.class);
    private final LongAdder rateLimited = new LongAdder();

    private final Map<String, LongAdder> domainCounts = new ConcurrentHashMap<>();   // allowed queries
    private final Map<String, LongAdder> blockedCounts = new ConcurrentHashMap<>();  // blocked queries
    private final Map<String, LongAdder> clientCounts = new ConcurrentHashMap<>();
    private final Map<String, LongAdder> categoryCounts = new ConcurrentHashMap<>(); // blocked queries per category

    private final QueryLogEntry[] ring = new QueryLogEntry[LOG_SIZE];
    private int ringPos = 0;    // next slot to write
    private int ringSize = 0;   // how many slots are filled (<= LOG_SIZE)

    private final TimeSeries perMinute;

    public StatsCollector() { this(System::currentTimeMillis); }

    public StatsCollector(LongSupplier clock) {
        this.clock = clock;
        this.startedAt = clock.getAsLong();
        this.countingSince = startedAt;
        this.perMinute = new TimeSeries(60, clock);
        for (QueryLogEntry.Status s : QueryLogEntry.Status.values()) byStatus.put(s, new LongAdder());
    }

    public void record(QueryLogEntry e) {
        total.increment();
        byStatus.get(e.status).increment();
        bump(clientCounts, e.clientIp);
        if (e.status == QueryLogEntry.Status.BLOCKED) {
            bump(blockedCounts, e.domain);
            bump(categoryCounts, e.category == null ? "unknown" : e.category);
        } else {
            bump(domainCounts, e.domain);
        }
        perMinute.record(e.status);
        append(e);
    }

    private void append(QueryLogEntry e) {
        synchronized (ring) {
            ring[ringPos] = e;
            ringPos = (ringPos + 1) % LOG_SIZE;
            if (ringSize < LOG_SIZE) ringSize++;
        }
    }

    /** A packet dropped by the per-client rate limiter (it never reaches the pipeline). */
    public void recordRateLimited() { rateLimited.increment(); }

    /** Newest first, at most `limit` entries. */
    public List<QueryLogEntry> recent(int limit) {
        synchronized (ring) {
            int n = Math.max(0, Math.min(limit, ringSize));
            List<QueryLogEntry> out = new ArrayList<>(n);
            for (int i = 1; i <= n; i++) out.add(ring[Math.floorMod(ringPos - i, LOG_SIZE)]);
            return out;
        }
    }

    public long total() { return total.sum(); }
    public long blocked() { return byStatus.get(QueryLogEntry.Status.BLOCKED).sum(); }
    public long cached() { return byStatus.get(QueryLogEntry.Status.CACHED).sum(); }
    public long forwarded() { return byStatus.get(QueryLogEntry.Status.FORWARDED).sum(); }
    public long errors() { return byStatus.get(QueryLogEntry.Status.ERROR).sum(); }
    public long rateLimited() { return rateLimited.sum(); }
    public long uptimeSeconds() { return (clock.getAsLong() - startedAt) / 1000; }
    public long startedAt() { return startedAt; }
    /** When the totals started counting: this process's start, or the first run of a restored snapshot. */
    public long countingSince() { return countingSince; }

    public List<DomainCount> topDomains(int n) { return topN(domainCounts, n); }
    public List<DomainCount> topBlocked(int n) { return topN(blockedCounts, n); }
    public List<DomainCount> topClients(int n) { return topN(clientCounts, n); }
    public List<DomainCount> blockedByCategory() { return topN(categoryCounts, Integer.MAX_VALUE); }
    public List<TimeSeries.Bucket> perMinute() { return perMinute.snapshot(); }

    /**
     * Latency percentiles (ms) per status over the queries currently in the ring buffer,
     * e.g. {"CACHED": {"count":120, "avg":0.08, "p50":0.06, "p95":0.2, "p99":0.4}, ...}.
     * Computed on demand by sorting at most LOG_SIZE numbers - cheap, and it reflects
     * recent behaviour instead of averaging over the whole uptime.
     */
    public Map<String, Map<String, Number>> latency() {
        List<QueryLogEntry> recent = recent(LOG_SIZE);
        Map<String, Map<String, Number>> out = new LinkedHashMap<>();
        for (QueryLogEntry.Status s : QueryLogEntry.Status.values()) {
            long[] micros = recent.stream().filter(e -> e.status == s).mapToLong(e -> e.latencyMicros).toArray();
            if (micros.length == 0) continue;
            Arrays.sort(micros);
            Map<String, Number> m = new LinkedHashMap<>();
            m.put("count", micros.length);
            m.put("avg", round(Arrays.stream(micros).average().orElse(0) / 1000.0));
            m.put("p50", round(percentile(micros, 50) / 1000.0));
            m.put("p95", round(percentile(micros, 95) / 1000.0));
            m.put("p99", round(percentile(micros, 99) / 1000.0));
            out.put(s.name(), m);
        }
        return out;
    }

    /** Nearest-rank percentile of a sorted array. */
    static long percentile(long[] sorted, double p) {
        if (sorted.length == 0) return 0;
        int rank = (int) Math.ceil(p / 100.0 * sorted.length);
        return sorted[Math.max(0, Math.min(sorted.length - 1, rank - 1))];
    }

    /**
     * Top n entries by count using a min-heap of size n: O(M log n) for M distinct keys,
     * instead of O(M log M) for sorting everything. The heap's root is the smallest of the
     * current top n, so each new key is compared against it and only replaces it if larger.
     * Ties are broken by name so the output is deterministic.
     */
    static List<DomainCount> topN(Map<String, LongAdder> counts, int n) {
        if (n <= 0) return Collections.emptyList();
        PriorityQueue<DomainCount> heap = new PriorityQueue<>(
                (a, b) -> a.count != b.count ? Long.compare(a.count, b.count) : b.name.compareTo(a.name));
        for (Map.Entry<String, LongAdder> e : counts.entrySet()) {
            DomainCount dc = new DomainCount(e.getKey(), e.getValue().sum());
            if (heap.size() < n) {
                heap.offer(dc);
            } else if (heap.comparator().compare(dc, heap.peek()) > 0) {
                heap.poll();
                heap.offer(dc);
            }
        }
        List<DomainCount> out = new ArrayList<>(heap);
        out.sort(heap.comparator().reversed()); // largest first
        return out;
    }

    // ---------------------------------------------------------------- save / restore

    /**
     * Everything worth keeping across a restart, as plain data for JSON (see StatsStore).
     * The per-minute series is left out: it describes the last hour, which a restart interrupts.
     */
    public static final class Snapshot {
        public int version = 1;
        public long countingSince;
        public long savedAt;
        public Map<String, Long> byStatus;
        public long rateLimited;
        public Map<String, Long> domains;
        public Map<String, Long> blocked;
        public Map<String, Long> clients;
        public Map<String, Long> categories;
        public List<QueryLogEntry> recent;     // oldest first
    }

    public Snapshot snapshot() {
        Snapshot s = new Snapshot();
        s.countingSince = countingSince;
        s.savedAt = clock.getAsLong();
        s.byStatus = new LinkedHashMap<>();
        for (Map.Entry<QueryLogEntry.Status, LongAdder> e : byStatus.entrySet()) s.byStatus.put(e.getKey().name(), e.getValue().sum());
        s.rateLimited = rateLimited.sum();
        s.domains = sums(domainCounts);
        s.blocked = sums(blockedCounts);
        s.clients = sums(clientCounts);
        s.categories = sums(categoryCounts);
        List<QueryLogEntry> recent = new ArrayList<>(recent(LOG_SIZE));
        Collections.reverse(recent);
        s.recent = recent;
        return s;
    }

    /** Adds a saved snapshot's counts to this collector (call once, at startup). */
    public void restore(Snapshot s) {
        if (s.byStatus != null) {
            for (Map.Entry<String, Long> e : s.byStatus.entrySet()) {
                QueryLogEntry.Status status;
                try { status = QueryLogEntry.Status.valueOf(e.getKey()); } catch (IllegalArgumentException x) { continue; }
                long n = e.getValue() == null ? 0 : e.getValue();
                byStatus.get(status).add(n);
                total.add(n);
            }
        }
        rateLimited.add(s.rateLimited);
        addAll(domainCounts, s.domains);
        addAll(blockedCounts, s.blocked);
        addAll(clientCounts, s.clients);
        addAll(categoryCounts, s.categories);
        if (s.recent != null) {
            for (QueryLogEntry e : s.recent) if (e != null && e.status != null && e.domain != null) append(e);
        }
        if (s.countingSince > 0 && s.countingSince < countingSince) countingSince = s.countingSince;
    }

    private static Map<String, Long> sums(Map<String, LongAdder> m) {
        Map<String, Long> out = new LinkedHashMap<>();
        for (Map.Entry<String, LongAdder> e : m.entrySet()) out.put(e.getKey(), e.getValue().sum());
        return out;
    }

    private static void addAll(Map<String, LongAdder> into, Map<String, Long> from) {
        if (from == null) return;
        for (Map.Entry<String, Long> e : from.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) continue;
            LongAdder a = into.get(e.getKey());
            if (a == null) {
                if (into.size() >= MAX_TRACKED) continue;
                a = into.computeIfAbsent(e.getKey(), k -> new LongAdder());
            }
            a.add(e.getValue());
        }
    }

    private static void bump(Map<String, LongAdder> map, String key) {
        if (key == null) return;
        LongAdder a = map.get(key);
        if (a == null) {
            if (map.size() >= MAX_TRACKED) return; // cap distinct keys, see class comment
            a = map.computeIfAbsent(key, k -> new LongAdder());
        }
        a.increment();
    }

    private static double round(double v) { return Math.round(v * 1000) / 1000.0; }
}
