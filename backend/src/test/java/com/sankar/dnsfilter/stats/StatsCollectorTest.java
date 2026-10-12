package com.sankar.dnsfilter.stats;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import static com.sankar.dnsfilter.stats.QueryLogEntry.Status.*;
import static org.junit.jupiter.api.Assertions.*;

class StatsCollectorTest {

    private final AtomicLong now = new AtomicLong(1_700_000_000_000L);
    private final StatsCollector stats = new StatsCollector(now::get);

    private static QueryLogEntry e(String domain, QueryLogEntry.Status s) {
        return new QueryLogEntry("10.0.0.1", domain, "A", s, s == BLOCKED ? "ads" : null, 1000);
    }

    @Test
    void countsByStatusAndKeepsBlockedSeparateFromTopDomains() {
        stats.record(e("google.com", FORWARDED));
        stats.record(e("google.com", CACHED));
        stats.record(e("doubleclick.net", BLOCKED));
        stats.record(e("slow.com", ERROR));
        stats.recordRateLimited();

        assertEquals(4, stats.total());
        assertEquals(1, stats.forwarded());
        assertEquals(1, stats.cached());
        assertEquals(1, stats.blocked());
        assertEquals(1, stats.errors());
        assertEquals(1, stats.rateLimited());

        assertEquals("google.com", stats.topDomains(1).get(0).name);
        assertEquals(2, stats.topDomains(1).get(0).count);
        assertEquals("doubleclick.net", stats.topBlocked(5).get(0).name);
        assertTrue(stats.topDomains(10).stream().noneMatch(d -> d.name.equals("doubleclick.net")));
        assertEquals("ads", stats.blockedByCategory().get(0).name);
        assertEquals(4, stats.topClients(1).get(0).count);
    }

    @Test
    void recentIsNewestFirstAndWrapsAround() {
        int n = StatsCollector.LOG_SIZE + 25;
        for (int i = 0; i < n; i++) stats.record(e("d" + i + ".com", FORWARDED));
        List<QueryLogEntry> recent = stats.recent(1000);
        assertEquals(StatsCollector.LOG_SIZE, recent.size());
        assertEquals("d" + (n - 1) + ".com", recent.get(0).domain);
        assertEquals("d25.com", recent.get(recent.size() - 1).domain); // oldest 25 overwritten
        assertEquals(3, stats.recent(3).size());
        assertTrue(new StatsCollector().recent(10).isEmpty());
    }

    @Test
    void topNMatchesAFullSort() {
        Map<String, LongAdder> counts = new HashMap<>();
        java.util.Random rnd = new java.util.Random(42);
        for (int i = 0; i < 2000; i++) {
            LongAdder a = new LongAdder();
            a.add(rnd.nextInt(10_000));
            counts.put("d" + i, a);
        }
        List<DomainCount> top = StatsCollector.topN(counts, 10);
        List<Long> expected = counts.values().stream().map(LongAdder::sum)
                .sorted((x, y) -> Long.compare(y, x)).limit(10).toList();
        assertEquals(expected, top.stream().map(d -> d.count).toList());
        assertTrue(StatsCollector.topN(counts, 0).isEmpty());
        assertEquals(2000, StatsCollector.topN(counts, 5000).size());
    }

    @Test
    void topNBreaksTiesByName() {
        Map<String, LongAdder> counts = new HashMap<>();
        for (String s : new String[]{"c.com", "a.com", "b.com"}) {
            LongAdder a = new LongAdder();
            a.add(5);
            counts.put(s, a);
        }
        assertEquals(List.of("a.com", "b.com"), StatsCollector.topN(counts, 2).stream().map(d -> d.name).toList());
    }

    @Test
    void percentilesUseNearestRank() {
        long[] v = new long[100];
        for (int i = 0; i < 100; i++) v[i] = i + 1;   // 1..100
        assertEquals(50, StatsCollector.percentile(v, 50));
        assertEquals(95, StatsCollector.percentile(v, 95));
        assertEquals(99, StatsCollector.percentile(v, 99));
        assertEquals(7, StatsCollector.percentile(new long[]{7}, 99));

        for (int i = 1; i <= 100; i++) {
            stats.record(new QueryLogEntry("c", "x.com", "A", CACHED, null, i * 1000L)); // 1..100 ms
        }
        Map<String, Number> cached = stats.latency().get("CACHED");
        assertEquals(100, cached.get("count").intValue());
        assertEquals(50.0, cached.get("p50").doubleValue(), 1e-9);
        assertEquals(99.0, cached.get("p99").doubleValue(), 1e-9);
        assertNull(stats.latency().get("BLOCKED"));
    }

    @Test
    void perMinuteSeriesBucketsAndZeroFills() {
        now.set(60_000L * 1_000_000);                 // start of a minute
        stats.record(e("a.com", FORWARDED));
        stats.record(e("b.com", BLOCKED));
        now.addAndGet(2 * 60_000);                    // two minutes later
        stats.record(e("c.com", CACHED));

        List<TimeSeries.Bucket> s = stats.perMinute();
        assertEquals(60, s.size());
        TimeSeries.Bucket last = s.get(59), twoAgo = s.get(57);
        assertEquals(1, last.total);
        assertEquals(1, last.cached);
        assertEquals(2, twoAgo.total);
        assertEquals(1, twoAgo.blocked);
        assertEquals(0, s.get(58).total);             // the quiet minute in between
        assertEquals(last.minute - 2, twoAgo.minute);

        now.addAndGet(61 * 60_000);                   // over an hour later: old data has aged out
        assertTrue(stats.perMinute().stream().allMatch(b -> b.total == 0));
    }

    @Test
    void distinctDomainCountIsCapped() {
        for (int i = 0; i < StatsCollector.MAX_TRACKED + 100; i++) stats.record(e("r" + i + ".flood.com", FORWARDED));
        stats.record(e("r0.flood.com", FORWARDED));   // existing keys keep counting
        assertEquals(StatsCollector.MAX_TRACKED + 101, stats.total());
        assertEquals(2, stats.topDomains(1).get(0).count);
    }

    @Test
    void concurrentRecordingLosesNothing() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        for (int t = 0; t < 8; t++) {
            pool.submit(() -> { for (int i = 0; i < 5000; i++) stats.record(e("x.com", FORWARDED)); });
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertEquals(40_000, stats.total());
        assertEquals(40_000, stats.topDomains(1).get(0).count);
        assertEquals(StatsCollector.LOG_SIZE, stats.recent(10_000).size());
    }
}
