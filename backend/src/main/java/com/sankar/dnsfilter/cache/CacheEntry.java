package com.sankar.dnsfilter.cache;

/** A cached upstream response plus its absolute expiry time (from the record TTL). */
public class CacheEntry {
    public final byte[] response;
    public final long expiresAtMillis;

    public CacheEntry(byte[] response, long ttlSeconds) {
        this.response = response;
        this.expiresAtMillis = System.currentTimeMillis() + ttlSeconds * 1000;
    }

    public boolean isExpired() { return System.currentTimeMillis() >= expiresAtMillis; }

    public long remainingTtlSeconds() {
        return Math.max(0, (expiresAtMillis - System.currentTimeMillis()) / 1000);
    }
}
