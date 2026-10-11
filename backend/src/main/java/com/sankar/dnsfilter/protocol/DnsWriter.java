package com.sankar.dnsfilter.protocol;

/**
 * Builds response packets.
 *
 * Day 1-2 tasks:
 *  - buildBlockedResponse(query): copy ID + question, set QR=1, RA=1, RCODE=NXDOMAIN
 *    (or answer 0.0.0.0 for A queries - "null routing", like Pi-hole)
 *  - rewriteId(cachedBytes, newId): cached responses must carry the NEW query's ID
 *  - adjustTtl(cachedBytes, remainingSeconds): decrement TTLs for cached answers (bonus)
 */
public class DnsWriter {

    public static byte[] buildBlockedResponse(byte[] query, int queryLength) {
        // TODO
        throw new UnsupportedOperationException("buildBlockedResponse not implemented yet");
    }

    /** Overwrites the first two bytes (transaction ID). */
    public static byte[] rewriteId(byte[] response, int newId) {
        byte[] copy = response.clone();
        copy[0] = (byte) ((newId >> 8) & 0xFF);
        copy[1] = (byte) (newId & 0xFF);
        return copy;
    }
}
