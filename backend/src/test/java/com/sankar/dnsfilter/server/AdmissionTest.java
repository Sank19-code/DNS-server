package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.stats.StatsCollector;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class AdmissionTest {

    private final AtomicLong now = new AtomicLong(0);
    private final StatsCollector stats = new StatsCollector(now::get);

    private static InetAddress ip(int i) throws Exception {
        return InetAddress.getByAddress(new byte[]{10, (byte) (i >> 16), (byte) (i >> 8), (byte) i});
    }

    @Test
    void globalCapHoldsWhenEveryPacketHasADifferentAddress() throws Exception {
        Admission a = new Admission(new RateLimiter(50, 100, 10_000, now::get),
                RateLimiter.global(1000, 200, now::get), true, stats);
        int admitted = 0;
        for (int i = 0; i < 5_000; i++) if (a.admit(ip(i))) admitted++;   // each IP well under its own limit
        assertEquals(200, admitted, "only the global burst gets through");
        assertEquals(4_800, stats.rateLimited());
    }

    @Test
    void ipv6ClientsAreLimitedPerSlash64() throws Exception {
        InetAddress a = InetAddress.getByName("2001:db8:1:2::1");
        InetAddress b = InetAddress.getByName("2001:db8:1:2:ffff:ffff:ffff:ffff");   // same /64, other address
        InetAddress c = InetAddress.getByName("2001:db8:1:3::1");                    // next /64
        assertEquals(Admission.clientKey(a), Admission.clientKey(b));
        assertNotEquals(Admission.clientKey(a), Admission.clientKey(c));
        assertEquals("10.1.2.3", Admission.clientKey(InetAddress.getByName("10.1.2.3")));

        Admission adm = new Admission(new RateLimiter(1, 2, 100, now::get),
                RateLimiter.global(1000, 1000, now::get), true, stats);
        assertTrue(adm.admit(a));
        assertTrue(adm.admit(b));
        assertFalse(adm.admit(InetAddress.getByName("2001:db8:1:2::abcd")), "rotating addresses in the /64 doesn't help");
        assertTrue(adm.admit(c));
    }

    @Test
    void perClientLimitAppliesFirstAndLoopbackIsExempt() throws Exception {
        Admission a = new Admission(new RateLimiter(1, 2, 100, now::get),
                RateLimiter.global(1000, 1000, now::get), true, stats);
        assertTrue(a.admit(ip(1)));
        assertTrue(a.admit(ip(1)));
        assertFalse(a.admit(ip(1)), "client burst of 2 used up");
        assertTrue(a.admit(ip(2)), "other clients unaffected");
        for (int i = 0; i < 100; i++) assertTrue(a.admit(InetAddress.getLoopbackAddress()));

        Admission strict = new Admission(new RateLimiter(1, 1, 100, now::get),
                RateLimiter.global(1000, 1000, now::get), false, stats);
        assertTrue(strict.admit(InetAddress.getLoopbackAddress()));
        assertFalse(strict.admit(InetAddress.getLoopbackAddress()), "exemptLoopback=false limits localhost too");
    }
}
