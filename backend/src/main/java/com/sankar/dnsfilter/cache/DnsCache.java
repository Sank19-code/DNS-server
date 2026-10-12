package com.sankar.dnsfilter.cache;

import com.sankar.dnsfilter.protocol.DnsWriter;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * TTL-aware DNS cache on top of LruCache.
 * Key = name + ":" + type (e.g. "google.com:1"), since A and AAAA answers differ.
 *
 *  - Expired entries are dropped lazily on get() (no background sweeper thread needed;
 *    the LRU bound keeps memory capped even if stale entries are never read again).
 *  - On a hit, every TTL in the cached reply is decremented by the entry's age, so a
 *    client never caches an answer for longer than the upstream allowed (RFC 1035 §7.3).
 *  - TTL 0 means "do not cache" and is respected.
 */
public class DnsCache {
    private final LruCache<String, CacheEntry> lru;
    private final LongSupplier clock;
    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();

    public DnsCache(int maxEntries) { this(maxEntries, System::currentTimeMillis); }

    /** Clock is injectable so tests can fast-forward time instead of sleeping. */
    public DnsCache(int maxEntries, LongSupplier clock) {
        this.lru = new LruCache<>(maxEntries);
        this.clock = clock;
    }

    public static String key(String name, int type) {
        String n = name.toLowerCase();
        if (n.endsWith(".")) n = n.substring(0, n.length() - 1);
        return n + ":" + type;
    }

    /**
     * Key that also separates EDNS variants: "name:type" for plain queries, ":e" with EDNS, ":do"
     * with EDNS + DNSSEC OK. Replies differ between them (OPT record, RRSIGs, size), and a client
     * must not get an OPT record it didn't ask for or miss DNSSEC records it did ask for.
     */
    public static String key(String name, int type, DnsWriter.Edns edns) {
        String base = key(name, type);
        if (!edns.present) return base;
        return base + (edns.dnssecOk ? ":do" : ":e");
    }

    /** @return a copy of the cached reply with TTLs aged, or null on miss / expiry. */
    public byte[] get(String key) {
        long now = clock.getAsLong();
        CacheEntry e = lru.get(key);
        if (e == null) {
            misses.incrementAndGet();
            return null;
        }
        if (e.isExpired(now)) {
            lru.remove(key);
            misses.incrementAndGet();
            return null;
        }
        hits.incrementAndGet();
        return DnsWriter.adjustTtl(e.response, e.ageSeconds(now));
    }

    public void put(String key, byte[] response, long ttlSeconds) {
        if (ttlSeconds <= 0 || response == null) return;
        lru.put(key, new CacheEntry(response.clone(), ttlSeconds, clock.getAsLong()));
    }

    public void clear() { lru.clear(); }

    public long hits() { return hits.get(); }
    public long misses() { return misses.get(); }
    public int size() { return lru.size(); }
    public int capacity() { return lru.capacity(); }
    public long evictions() { return lru.evictions(); }

    /** Hit ratio in [0, 1]; 0 when nothing has been looked up yet. */
    public double hitRatio() {
        long h = hits.get(), total = h + misses.get();
        return total == 0 ? 0 : (double) h / total;
    }
}
