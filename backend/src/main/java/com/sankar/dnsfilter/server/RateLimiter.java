package com.sankar.dnsfilter.server;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Per-client token bucket. Each client IP gets a bucket holding up to `burst` tokens that
 * refills at `ratePerSecond`; every query spends one token, and a query with no token left
 * is dropped.
 *
 * Why: a DNS server reachable from the internet can be abused as a DDoS amplifier (a spoofed
 * 60-byte query triggers a reply many times larger aimed at the victim) or simply flooded.
 * Dropping, rather than answering REFUSED, means an over-limit client gets nothing reflected.
 *
 * Idle buckets are swept occasionally so the map can't grow without bound.
 */
public class RateLimiter {
    private static final long IDLE_EVICT_MS = 60_000;
    private static final int SWEEP_THRESHOLD = 10_000;

    private static final class Bucket {
        double tokens;
        long lastRefill;
        Bucket(double tokens, long now) { this.tokens = tokens; this.lastRefill = now; }
    }

    private final double ratePerSecond;
    private final double burst;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimiter(double ratePerSecond, double burst) {
        this(ratePerSecond, burst, System::currentTimeMillis);
    }

    public RateLimiter(double ratePerSecond, double burst, LongSupplier clock) {
        this.ratePerSecond = ratePerSecond;
        this.burst = Math.max(1, burst);
        this.clock = clock;
    }

    /** Disabled when ratePerSecond <= 0: every query is allowed. */
    public boolean enabled() { return ratePerSecond > 0; }

    public boolean tryAcquire(String client) {
        if (!enabled()) return true;
        long now = clock.getAsLong();
        if (buckets.size() > SWEEP_THRESHOLD) sweep(now);
        Bucket b = buckets.computeIfAbsent(client, k -> new Bucket(burst, now));
        synchronized (b) {
            double elapsedSec = (now - b.lastRefill) / 1000.0;
            b.tokens = Math.min(burst, b.tokens + elapsedSec * ratePerSecond);
            b.lastRefill = now;
            if (b.tokens >= 1) {
                b.tokens -= 1;
                return true;
            }
            return false;
        }
    }

    public int trackedClients() { return buckets.size(); }

    void sweep(long now) {
        buckets.entrySet().removeIf(e -> now - e.getValue().lastRefill > IDLE_EVICT_MS);
    }
}
