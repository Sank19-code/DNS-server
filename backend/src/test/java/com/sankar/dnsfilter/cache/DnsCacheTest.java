package com.sankar.dnsfilter.cache;

import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsWriter;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class DnsCacheTest {

    private final AtomicLong now = new AtomicLong(1_000_000);
    private final DnsCache cache = new DnsCache(10, now::get);

    /** A real reply: example.com A 0.0.0.0 with the given TTL. */
    private static byte[] reply(long ttl) {
        byte[] q = DnsWriter.buildQuery(0x1111, "example.com", DnsQuestion.TYPE_A);
        return DnsWriter.buildNullRouteResponse(q, q.length, ttl);
    }

    @Test
    void keyIsCaseInsensitiveAndIncludesType() {
        assertEquals("example.com:1", DnsCache.key("Example.COM.", 1));
        assertNotEquals(DnsCache.key("example.com", 1), DnsCache.key("example.com", 28));
    }

    @Test
    void hitWithinTtlMissAfterExpiry() {
        String k = DnsCache.key("example.com", 1);
        assertNull(cache.get(k));
        cache.put(k, reply(300), 300);
        assertNotNull(cache.get(k));
        now.addAndGet(299_000);
        assertNotNull(cache.get(k));
        now.addAndGet(1_000);          // exactly 300 s -> expired
        assertNull(cache.get(k));
        assertEquals(0, cache.size(), "expired entry is removed lazily");
        assertEquals(2, cache.hits());
        assertEquals(2, cache.misses());
    }

    @Test
    void ttlZeroIsNotCached() {
        String k = DnsCache.key("example.com", 1);
        cache.put(k, reply(0), 0);
        assertNull(cache.get(k));
        assertEquals(0, cache.size());
    }

    @Test
    void cachedTtlCountsDown() {
        String k = DnsCache.key("example.com", 1);
        cache.put(k, reply(300), 300);
        now.addAndGet(120_500);        // 120.5 s later -> TTL 180
        byte[] hit = cache.get(k);
        DnsMessage m = new DnsParser(hit).parse();
        assertEquals(180, m.answers.get(0).ttl);
    }

    @Test
    void storesACopyNotTheCallersArray() {
        String k = DnsCache.key("example.com", 1);
        byte[] r = reply(300);
        cache.put(k, r, 300);
        r[0] = 0x7F;                   // caller mutates its buffer afterwards
        assertEquals(0x11, cache.get(k)[0]);
    }
}
