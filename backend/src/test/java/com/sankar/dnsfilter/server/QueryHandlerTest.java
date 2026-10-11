package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.FakeUpstream;
import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsWriter;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
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
    void malformedQueryGetsFormerr() {
        byte[] bad = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x3F, 'a'};
        byte[] reply = handler.handle(bad, "127.0.0.1");
        assertEquals(DnsHeader.RCODE_FORMERR, reply[3] & 0x0F);
        assertNull(handler.handle(new byte[]{1, 2, 3}, "127.0.0.1"), "too short to answer -> dropped");
    }
}
