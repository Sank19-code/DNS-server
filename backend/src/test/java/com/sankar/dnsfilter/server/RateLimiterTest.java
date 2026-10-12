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
    void idleBucketsAreSwept() {
        RateLimiter rl = new RateLimiter(10, 10, now::get);
        rl.tryAcquire("a");
        rl.tryAcquire("b");
        now.addAndGet(61_000);
        rl.tryAcquire("c");
        rl.sweep(now.get());
        assertEquals(1, rl.trackedClients());
    }
}
