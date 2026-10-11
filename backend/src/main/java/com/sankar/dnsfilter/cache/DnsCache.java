package com.sankar.dnsfilter.cache;

import java.util.concurrent.atomic.AtomicLong;

/**
 * TTL-aware DNS cache on top of LruCache.
 * Key = name + ":" + type (e.g. "google.com:1"), since A and AAAA answers differ.
 * Expired entries are dropped lazily on get().
 */
public class DnsCache {
    private final LruCache<String, CacheEntry> lru;
    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();

    public DnsCache(int maxEntries) { this.lru = new LruCache<>(maxEntries); }

    public static String key(String name, int type) { return name.toLowerCase() + ":" + type; }

    public byte[] get(String key) {
        // TODO (Day 2): lru.get -> if expired remove + miss; else hit
        return null;
    }

    public void put(String key, byte[] response, long ttlSeconds) {
        // TODO (Day 2): skip ttl == 0; lru.put(key, new CacheEntry(...))
    }

    public long hits() { return hits.get(); }
    public long misses() { return misses.get(); }
}
