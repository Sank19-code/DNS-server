package com.sankar.dnsfilter.cache;

import java.util.List;

/**
 * A cached upstream response, when it was stored, its absolute expiry time (from the record TTL),
 * and the CNAME aliases in it (re-checked against the blocklist on every hit).
 */
public class CacheEntry {
    public final byte[] response;
    public final long storedAtMillis;
    public final long expiresAtMillis;
    public final List<String> aliases;

    public CacheEntry(byte[] response, long ttlSeconds, long nowMillis) {
        this(response, ttlSeconds, nowMillis, List.of());
    }

    public CacheEntry(byte[] response, long ttlSeconds, long nowMillis, List<String> aliases) {
        this.response = response;
        this.storedAtMillis = nowMillis;
        this.expiresAtMillis = nowMillis + ttlSeconds * 1000;
        this.aliases = List.copyOf(aliases);
    }

    public boolean isExpired(long nowMillis) { return nowMillis >= expiresAtMillis; }

    /** Whole seconds since the entry was stored - subtracted from every TTL in the cached reply. */
    public long ageSeconds(long nowMillis) { return Math.max(0, (nowMillis - storedAtMillis) / 1000); }

    public long remainingTtlSeconds(long nowMillis) {
        return Math.max(0, (expiresAtMillis - nowMillis) / 1000);
    }
}
