package com.sankar.dnsfilter.cache;

/** A cached upstream response, when it was stored, and its absolute expiry time (from the record TTL). */
public class CacheEntry {
    public final byte[] response;
    public final long storedAtMillis;
    public final long expiresAtMillis;

    public CacheEntry(byte[] response, long ttlSeconds, long nowMillis) {
        this.response = response;
        this.storedAtMillis = nowMillis;
        this.expiresAtMillis = nowMillis + ttlSeconds * 1000;
    }

    public boolean isExpired(long nowMillis) { return nowMillis >= expiresAtMillis; }

    /** Whole seconds since the entry was stored - subtracted from every TTL in the cached reply. */
    public long ageSeconds(long nowMillis) { return Math.max(0, (nowMillis - storedAtMillis) / 1000); }

    public long remainingTtlSeconds(long nowMillis) {
        return Math.max(0, (expiresAtMillis - nowMillis) / 1000);
    }
}
