package com.sankar.dnsfilter.server;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    private final AtomicLong now = new AtomicLong(0);

    @Test
    void allowsBurstThenRefillsAtRate() {
        RateLimiter rl = new RateLimiter(10, 5, now::get);   // 10/s, burst 5
        for (int i = 0; i < 5; i++) assertTrue(rl.tryAcquire("1.2.3.4"));
        assertFalse(rl.tryAcquire("1.2.3.4"), "burst exhausted");

        now.addAndGet(100);                                  // 100 ms -> 1 token
        assertTrue(rl.tryAcquire("1.2.3.4"));
        assertFalse(rl.tryAcquire("1.2.3.4"));

        now.addAndGet(10_000);                               // long idle -> capped at burst, not 100
        for (int i = 0; i < 5; i++) assertTrue(rl.tryAcquire("1.2.3.4"));
        assertFalse(rl.tryAcquire("1.2.3.4"));
    }

    @Test
    void clientsAreIndependent() {
        RateLimiter rl = new RateLimiter(1, 1, now::get);
        assertTrue(rl.tryAcquire("a"));
        assertFalse(rl.tryAcquire("a"));
        assertTrue(rl.tryAcquire("b"));
    }

    @Test
    void zeroRateDisables() {
        RateLimiter rl = new RateLimiter(0, 0, now::get);
        assertFalse(rl.enabled());
        for (int i = 0; i < 1000; i++) assertTrue(rl.tryAcquire("x"));
        assertEquals(0, rl.trackedClients());
    }

    @Test
    void remembersAtMostMaxClientsLeastRecentlySeenFirst() {
        RateLimiter rl = new RateLimiter(1, 1, 3, now::get);
        rl.tryAcquire("a");
        rl.tryAcquire("b");
        rl.tryAcquire("c");
        assertFalse(rl.tryAcquire("a"), "a is still limited (and now the most recently seen)");
        rl.tryAcquire("d");                                  // evicts b, the least recently seen
        assertEquals(3, rl.trackedClients());
        assertEquals(1, rl.evictions());
        assertFalse(rl.tryAcquire("a"), "an active flooder keeps its empty bucket");
        assertTrue(rl.tryAcquire("b"), "b was forgotten, so it starts with a fresh bucket");
    }

    @Test
    void spoofedSourceFloodStaysBoundedAndCheap() {
        RateLimiter rl = new RateLimiter(50, 100, 1_000, now::get);
        long start = System.nanoTime();
        for (int i = 0; i < 1_000_000; i++) {               // a million different fake addresses
            rl.tryAcquire("10." + (i >> 16 & 255) + "." + (i >> 8 & 255) + "." + (i & 255));
        }
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertEquals(1_000, rl.trackedClients(), "memory stays at maxClients");
        assertTrue(ms < 5_000, "constant work per packet, not a scan of the whole map: took " + ms + " ms");
    }

    @Test
    void globalLimiterCapsEveryoneTogether() {
        RateLimiter global = RateLimiter.global(100, 10, now::get);
        int allowed = 0;
        for (int i = 0; i < 50; i++) if (global.tryAcquire()) allowed++;
        assertEquals(10, allowed, "burst of 10 shared by all clients");
        now.addAndGet(100);                                  // 100 ms at 100/s -> 10 more
        allowed = 0;
        for (int i = 0; i < 50; i++) if (global.tryAcquire()) allowed++;
        assertEquals(10, allowed);
    }
}
