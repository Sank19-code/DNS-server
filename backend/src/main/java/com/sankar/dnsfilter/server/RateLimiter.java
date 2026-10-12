package com.sankar.dnsfilter.server;

import java.util.LinkedHashMap;
import java.util.Map;
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
 * Bounded memory and constant work per packet, even under a spoofed-source flood: the buckets
 * live in an access-ordered LinkedHashMap (an LRU) capped at maxClients. A flood from millions
 * of random fake IPs just keeps recycling the least recently seen slots, and each packet costs one
 * hash lookup. (The previous version swept the whole map on every packet once it was big, which
 * turned exactly that flood into a CPU and memory problem.) An IP that is actively flooding is by
 * definition recently used, so it keeps its empty bucket and stays limited.
 *
 * `global()` builds a single shared bucket: a cap on total queries per second across all clients,
 * which is what still holds when every packet comes from a different (spoofed) address.
 */
public class RateLimiter {
    public static final int DEFAULT_MAX_CLIENTS = 10_000;
    private static final String GLOBAL_KEY = "*";

    private static final class Bucket {
        double tokens;
        long lastRefill;
        Bucket(double tokens, long now) { this.tokens = tokens; this.lastRefill = now; }
    }

    private final double ratePerSecond;
    private final double burst;
    private final int maxClients;
    private final LongSupplier clock;
    private final LinkedHashMap<String, Bucket> buckets;   // guarded by this
    private long evictions;                                 // guarded by this

    public RateLimiter(double ratePerSecond, double burst) {
        this(ratePerSecond, burst, DEFAULT_MAX_CLIENTS, System::currentTimeMillis);
    }

    public RateLimiter(double ratePerSecond, double burst, LongSupplier clock) {
        this(ratePerSecond, burst, DEFAULT_MAX_CLIENTS, clock);
    }

    public RateLimiter(double ratePerSecond, double burst, int maxClients, LongSupplier clock) {
        this.ratePerSecond = ratePerSecond;
        this.burst = Math.max(1, burst);
        this.maxClients = Math.max(1, maxClients);
        this.clock = clock;
        this.buckets = new LinkedHashMap<>(16, 0.75f, true) {   // true = access order -> LRU
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Bucket> eldest) {
                if (size() <= RateLimiter.this.maxClients) return false;
                evictions++;
                return true;
            }
        };
    }

    /** One bucket shared by everyone: a total queries-per-second cap. */
    public static RateLimiter global(double ratePerSecond, double burst, LongSupplier clock) {
        return new RateLimiter(ratePerSecond, burst, 1, clock);
    }

    public static RateLimiter global(double ratePerSecond, double burst) {
        return global(ratePerSecond, burst, System::currentTimeMillis);
    }

    /** Disabled when ratePerSecond <= 0: every query is allowed. */
    public boolean enabled() { return ratePerSecond > 0; }

    /** For a global() limiter. */
    public boolean tryAcquire() { return tryAcquire(GLOBAL_KEY); }

    public synchronized boolean tryAcquire(String client) {
        if (!enabled()) return true;
        long now = clock.getAsLong();
        Bucket b = buckets.get(client);
        if (b == null) {
            b = new Bucket(burst, now);
            buckets.put(client, b);           // may evict the least recently seen client
        }
        double elapsedSec = Math.max(0, now - b.lastRefill) / 1000.0;
        b.tokens = Math.min(burst, b.tokens + elapsedSec * ratePerSecond);
        b.lastRefill = now;
        if (b.tokens >= 1) {
            b.tokens -= 1;
            return true;
        }
        return false;
    }

    public synchronized int trackedClients() { return buckets.size(); }

    /** How many clients were forgotten to make room (non-zero = more distinct IPs than maxClients). */
    public synchronized long evictions() { return evictions; }
}
