package com.sankar.dnsfilter.stats;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class StatsStoreTest {

    @Test
    void statsSurviveARestart() throws Exception {
        Path file = Files.createTempDirectory("stats").resolve("sub/stats.json");
        StatsCollector before = new StatsCollector();
        before.record(new QueryLogEntry("10.0.0.1", "google.com", "A", QueryLogEntry.Status.FORWARDED, null, 900));
        before.record(new QueryLogEntry("10.0.0.1", "google.com", "A", QueryLogEntry.Status.CACHED, null, 50));
        before.record(new QueryLogEntry("10.0.0.2", "ads.com", "A", QueryLogEntry.Status.BLOCKED, "ads", 20));
        before.recordRateLimited();
        new StatsStore(file, before).save();

        StatsCollector after = new StatsCollector();
        new StatsStore(file, after).load();
        assertEquals(3, after.total());
        assertEquals(1, after.blocked());
        assertEquals(1, after.cached());
        assertEquals(1, after.rateLimited());
        assertEquals("google.com", after.topDomains(1).get(0).name);
        assertEquals(2, after.topDomains(1).get(0).count);
        assertEquals("10.0.0.1", after.topClients(1).get(0).name);
        assertEquals("ads", after.blockedByCategory().get(0).name);
        List<QueryLogEntry> log = after.recent(10);
        assertEquals(3, log.size());
        assertEquals("ads.com", log.get(0).domain, "newest first, same order as before the restart");
        assertTrue(after.countingSince() <= before.startedAt());

        after.record(new QueryLogEntry("10.0.0.1", "google.com", "A", QueryLogEntry.Status.CACHED, null, 40));
        assertEquals(4, after.total(), "new queries add to the restored totals");
    }

    @Test
    void corruptOrMissingFileStartsFromZero() throws Exception {
        Path file = Files.createTempFile("stats", ".json");
        Files.writeString(file, "{not json");
        StatsCollector s = new StatsCollector();
        new StatsStore(file, s).load();
        assertEquals(0, s.total());

        new StatsStore(file.resolveSibling("does-not-exist.json"), s).load();
        assertEquals(0, s.total());
    }
}
