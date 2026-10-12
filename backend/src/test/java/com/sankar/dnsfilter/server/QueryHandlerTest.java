package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.FakeUpstream;
import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsWriter;
import com.sankar.dnsfilter.protocol.DnsWriterEdnsTest;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.stats.QueryLogEntry;
import com.sankar.dnsfilter.stats.StatsCollector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** End-to-end pipeline tests against a fake upstream on localhost. */
class QueryHandlerTest {

    private FakeUpstream upstream;
    private Blocklist blocklist;
    private DnsCache cache;
    private QueryHandler handler;
    private QueryHandler.Settings settings;

    @BeforeEach
    void setUp() throws Exception {
        upstream = new FakeUpstream();
        blocklist = new Blocklist();
        blocklist.add("doubleclick.net", "ads");
        cache = new DnsCache(100);
        settings = new QueryHandler.Settings();
        settings.logQueries = false;
        handler = new QueryHandler(blocklist, cache,
                new UpstreamResolver(List.of(upstream.address()), 300), new StatsCollector(), settings);
    }

    @AfterEach
    void tearDown() { upstream.close(); }

    private DnsMessage ask(int id, String name, int type) {
        byte[] q = DnsWriter.buildQuery(id, name, type);
        return new DnsParser(handler.handle(q, "127.0.0.1")).parse();
    }

    @Test
    void blockedDomainGetsNxdomainWithoutTouchingUpstream() {
        DnsMessage m = ask(7, "ads.doubleclick.net", DnsQuestion.TYPE_A);
        assertEquals(7, m.header.id);
        assertTrue(m.header.isResponse());
        assertEquals(DnsHeader.RCODE_NXDOMAIN, m.header.getRcode());
        assertEquals("ads.doubleclick.net", m.questions.get(0).name);
        assertEquals(0, upstream.queries.get());
    }

    @Test
    void nullRouteModeAnswersZeroAddress() {
        settings.nullRoute = true;
        DnsMessage m = ask(7, "doubleclick.net", DnsQuestion.TYPE_A);
        assertEquals(DnsHeader.RCODE_NOERROR, m.header.getRcode());
        assertEquals(1, m.answers.size());
        assertEquals(60, m.answers.get(0).ttl);
    }

    @Test
    void secondQueryIsServedFromCache() {
        DnsMessage first = ask(1, "example.com", DnsQuestion.TYPE_A);
        DnsMessage second = ask(2, "EXAMPLE.com", DnsQuestion.TYPE_A);
        assertEquals(1, upstream.queries.get(), "second lookup must not reach upstream");
        assertEquals(2, second.header.id);
        assertEquals("EXAMPLE.com", second.questions.get(0).name);
        assertEquals(first.answers.size(), second.answers.size());
        assertEquals(1, cache.hits());

        ask(3, "example.com", DnsQuestion.TYPE_AAAA);   // different type = different cache key
        assertEquals(2, upstream.queries.get());
    }

    @Test
    void blocklistIsCheckedBeforeCache() {
        ask(1, "late-block.com", DnsQuestion.TYPE_A);   // now cached
        blocklist.add("late-block.com", "malware");
        DnsMessage m = ask(2, "late-block.com", DnsQuestion.TYPE_A);
        assertEquals(DnsHeader.RCODE_NXDOMAIN, m.header.getRcode());
    }

    @Test
    void zeroTtlAnswersAreNotCached() {
        upstream.answerTtl = 0;
        ask(1, "no-cache.com", DnsQuestion.TYPE_A);
        ask(2, "no-cache.com", DnsQuestion.TYPE_A);
        assertEquals(2, upstream.queries.get());
    }

    @Test
    void ttlIsCappedByMaxTtl() {
        settings.maxTtl = 30;
        upstream.answerTtl = 3600;
        ask(1, "capped.com", DnsQuestion.TYPE_A);
        assertEquals(1, cache.size());
        // cached for 30 s, but the reply itself still carries the upstream TTL
        assertEquals(3600, ask(2, "capped.com", DnsQuestion.TYPE_A).answers.get(0).ttl);
    }

    @Test
    void nxdomainIsNegativelyCachedUsingSoaTtl() {
        DnsMessage first = ask(1, "nx-missing.com", DnsQuestion.TYPE_A);
        assertEquals(DnsHeader.RCODE_NXDOMAIN, first.header.getRcode());
        DnsMessage second = ask(2, "nx-missing.com", DnsQuestion.TYPE_A);
        assertEquals(DnsHeader.RCODE_NXDOMAIN, second.header.getRcode());
        assertEquals(1, upstream.queries.get());
    }

    @Test
    void silentUpstreamGivesServfailAndIsNotCached() {
        upstream.mode = FakeUpstream.Mode.SILENT;
        DnsMessage m = ask(9, "slow.com", DnsQuestion.TYPE_A);
        assertEquals(DnsHeader.RCODE_SERVFAIL, m.header.getRcode());
        assertEquals(9, m.header.id);
        assertEquals(0, cache.size());
    }

    @Test
    void ednsVariantsAreCachedSeparately() {
        byte[] plain = DnsWriter.buildQuery(1, "variants.com", DnsQuestion.TYPE_A);
        handler.handle(plain, "127.0.0.1");
        handler.handle(DnsWriterEdnsTest.withOpt(plain, 1232, false), "127.0.0.1");
        handler.handle(DnsWriterEdnsTest.withOpt(plain, 1232, true), "127.0.0.1");
        assertEquals(3, upstream.queries.get(), "plain, EDNS and EDNS+DO each get their own cache entry");
        handler.handle(DnsWriterEdnsTest.withOpt(plain, 4096, true), "127.0.0.1");
        assertEquals(3, upstream.queries.get(), "same variant, different buffer size -> cache hit");
    }

    @Test
    void cachedBigAnswerIsTruncatedForPlainUdpButNotForTcp() {
        upstream.padding = 700;
        byte[] q = DnsWriter.buildQuery(1, "big.com", DnsQuestion.TYPE_A);
        byte[] viaTcp = handler.resolve(q, "127.0.0.1", QueryHandler.Transport.TCP).reply;  // fills the cache
        assertTrue(viaTcp.length > 512);
        assertEquals(1, upstream.tcpQueries.get());

        DnsMessage udp = new DnsParser(handler.handle(q, "127.0.0.1")).parse();
        assertTrue(udp.header.isTruncated());
        assertEquals(1, cache.hits(), "served from cache, just too big for UDP");
    }

    @Test
    void tooManyUpstreamLookupsInFlightFailFast() throws Exception {
        upstream.mode = FakeUpstream.Mode.SILENT;          // every lookup hangs until the 300 ms timeout
        QueryHandler.Settings s = new QueryHandler.Settings();
        s.logQueries = false;
        s.maxUpstreamInFlight = 2;
        QueryHandler capped = new QueryHandler(blocklist, cache,
                new UpstreamResolver(List.of(upstream.address()), 300), new StatsCollector(), s);

        Thread[] stuck = new Thread[2];
        for (int i = 0; i < 2; i++) {
            int id = i;
            stuck[i] = new Thread(() -> capped.handle(DnsWriter.buildQuery(id, "slow" + id + ".com", DnsQuestion.TYPE_A), "127.0.0.1"));
            stuck[i].start();
        }
        while (upstream.queries.get() < 2) Thread.sleep(5);  // both slots taken

        long start = System.nanoTime();
        DnsMessage third = new DnsParser(capped.handle(DnsWriter.buildQuery(3, "slow3.com", DnsQuestion.TYPE_A), "127.0.0.1")).parse();
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertEquals(DnsHeader.RCODE_SERVFAIL, third.header.getRcode());
        assertTrue(ms < 100, "answered at once, not after the upstream timeout: " + ms + " ms");
        assertEquals(1, capped.upstreamBusy());
        assertEquals(2, upstream.queries.get(), "the third lookup never went upstream");

        // blocked names don't need a slot at all
        assertEquals(DnsHeader.RCODE_NXDOMAIN, new DnsParser(capped.handle(
                DnsWriter.buildQuery(4, "ads.doubleclick.net", DnsQuestion.TYPE_A), "127.0.0.1")).parse().header.getRcode());

        for (Thread t : stuck) t.join(2000);
        upstream.mode = FakeUpstream.Mode.NORMAL;
        assertEquals(1, new DnsParser(capped.handle(DnsWriter.buildQuery(5, "free.com", DnsQuestion.TYPE_A), "127.0.0.1"))
                .parse().answers.size(), "slots are released after the timeouts");
    }

    /** A query whose wire labels are given explicitly, so a label can contain a literal '.'. */
    private static byte[] rawQuery(int id, String... labels) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(id >> 8); o.write(id); o.write(1); o.write(0); o.write(0); o.write(1);
        for (int i = 0; i < 6; i++) o.write(0);
        for (String l : labels) { o.write(l.length()); o.writeBytes(l.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)); }
        o.write(0); o.write(0); o.write(1); o.write(0); o.write(1);
        return o.toByteArray();
    }

    @Test
    void dottedLabelCannotPoisonTheRealName() {
        // attacker: ONE label "www.google" under com - a different name that reads the same as text
        handler.handle(rawQuery(1, "www.google", "com"), "10.0.0.66");
        // victim: the real www.google.com must get its own lookup, not the attacker's cached answer
        DnsMessage victim = new DnsParser(handler.handle(rawQuery(2, "www", "google", "com"), "10.0.0.7")).parse();
        assertEquals(2, upstream.queries.get(), "two different names, two cache entries");
        assertEquals("www.google.com", victim.questions.get(0).name);
        assertEquals(2, cache.size());
    }

    @Test
    void multiQuestionQueryIsRefusedNotForwarded() {
        byte[] first = DnsWriter.buildQuery(1, "example.com", DnsQuestion.TYPE_A);
        byte[] second = DnsWriter.buildQuery(0, "ads.doubleclick.net", DnsQuestion.TYPE_A);
        byte[] both = java.util.Arrays.copyOf(first, first.length + second.length - 12);
        System.arraycopy(second, 12, both, first.length, second.length - 12);
        both[5] = 2;                                             // QDCOUNT = 2
        byte[] reply = handler.handle(both, "10.0.0.66");
        assertEquals(DnsHeader.RCODE_FORMERR, reply[3] & 0x0F);
        assertEquals(0, upstream.queries.get(), "the blocked second question never reaches upstream");
    }

    @Test
    void bypassCanariesGetNxdomainEvenInNullRouteMode() {
        settings.nullRoute = true;
        for (String canary : new String[]{"use-application-dns.net", "mask.icloud.com", "MASK-H2.icloud.com"}) {
            DnsMessage m = ask(1, canary, DnsQuestion.TYPE_A);
            assertEquals(DnsHeader.RCODE_NXDOMAIN, m.header.getRcode(), canary);
            assertEquals(0, m.answers.size(), "a 0.0.0.0 answer would tell Firefox to go ahead with DoH");
        }
        assertEquals(0, upstream.queries.get());
        settings.blockBypassCanaries = false;
        assertEquals(DnsHeader.RCODE_NOERROR, ask(2, "use-application-dns.net", DnsQuestion.TYPE_A).header.getRcode());
    }

    @Test
    void cnameCloakedTrackerIsBlockedAlsoFromCache() {
        upstream.cnameTarget = "tracker.adobe-metrics.example";
        blocklist.add("adobe-metrics.example", "trackers");

        QueryHandler.Result first = handler.resolve(DnsWriter.buildQuery(1, "cloak.news-site.com", DnsQuestion.TYPE_A), "10.0.0.7");
        assertEquals(QueryLogEntry.Status.BLOCKED, first.status);
        assertEquals("trackers", first.category);
        assertEquals(DnsHeader.RCODE_NXDOMAIN, new DnsParser(first.reply).parse().header.getRcode());

        QueryHandler.Result again = handler.resolve(DnsWriter.buildQuery(2, "cloak.news-site.com", DnsQuestion.TYPE_A), "10.0.0.7");
        assertEquals(QueryLogEntry.Status.BLOCKED, again.status, "the cached answer's alias is re-checked");
        assertEquals(1, upstream.queries.get());

        blocklist.remove("adobe-metrics.example");               // unblocking the tracker...
        QueryHandler.Result after = handler.resolve(DnsWriter.buildQuery(3, "cloak.news-site.com", DnsQuestion.TYPE_A), "10.0.0.7");
        assertEquals(QueryLogEntry.Status.CACHED, after.status, "...takes effect at once, from the cache");
        assertEquals(2, new DnsParser(after.reply).parse().answers.size());
    }

    @Test
    void allowlistedNameSkipsCnameInspection() {
        upstream.cnameTarget = "cdn.tracker.example";
        blocklist.add("tracker.example", "trackers");
        blocklist.allow("cloak.shop.com");
        assertEquals(QueryLogEntry.Status.FORWARDED,
                handler.resolve(DnsWriter.buildQuery(1, "cloak.shop.com", DnsQuestion.TYPE_A), "10.0.0.7").status);
    }

    @Test
    void negativeTtlUsesTheSoaMinimumField() {
        byte[] q = DnsWriter.buildQuery(1, "nx-gone.com", DnsQuestion.TYPE_A);
        DnsMessage nx = new DnsParser(FakeUpstream.nxWithSoa(q)).parse();   // SOA TTL 900, MINIMUM 60
        assertEquals(60, handler.cacheTtl(nx, nx.questions.get(0)), "min(SOA TTL, MINIMUM, negativeTtl) per RFC 2308");
    }

    @Test
    void blockingDoesNotDependOnTheMachineLanguage() {
        java.util.Locale before = java.util.Locale.getDefault();
        java.util.Locale.setDefault(new java.util.Locale("tr", "TR"));    // "I".toLowerCase() = dotless "ı"
        try {
            DnsMessage m = ask(1, "AD.DOUBLECLICK.NET", DnsQuestion.TYPE_A);
            assertEquals(DnsHeader.RCODE_NXDOMAIN, m.header.getRcode(), "upper-case I must still match");
        } finally {
            java.util.Locale.setDefault(before);
        }
    }

    @Test
    void malformedQueryGetsFormerr() {
        byte[] bad = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x3F, 'a'};
        byte[] reply = handler.handle(bad, "127.0.0.1");
        assertEquals(DnsHeader.RCODE_FORMERR, reply[3] & 0x0F);
        assertNull(handler.handle(new byte[]{1, 2, 3}, "127.0.0.1"), "too short to answer -> dropped");
    }
}
