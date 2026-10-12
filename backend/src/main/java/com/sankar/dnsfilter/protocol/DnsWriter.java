package com.sankar.dnsfilter.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Builds response packets.
 *
 *  - buildBlockedResponse(query): copy ID + question, QR=1, RA=1, RCODE=NXDOMAIN
 *  - buildNullRouteResponse(query): answer A -> 0.0.0.0 / AAAA -> :: (Pi-hole style)
 *  - buildErrorResponse(query, rcode): SERVFAIL / FORMERR replies
 *  - rewriteId(cachedBytes, newId): cached responses must carry the NEW query's ID
 *  - adjustTtl(cachedBytes, ageSeconds): decrement every TTL in a cached reply by its age
 *  - prepareCachedReply(cached, query): new ID + the query's exact question bytes
 */
public class DnsWriter {

    /** Blocked domain -> "this domain does not exist". Echoes the question, no answers. */
    public static byte[] buildBlockedResponse(byte[] query, int queryLength) {
        return buildErrorResponse(query, queryLength, DnsHeader.RCODE_NXDOMAIN);
    }

    /**
     * Response with the given RCODE and no records: header + original question section only.
     * Any EDNS OPT record in the query (additional section) is dropped.
     */
    public static byte[] buildErrorResponse(byte[] query, int queryLength, int rcode) {
        DnsParser parser = new DnsParser(query, queryLength);
        DnsMessage q = parser.parseQuery();
        int questionEnd = parser.position();

        byte[] out = new byte[questionEnd];
        System.arraycopy(query, 0, out, 0, questionEnd);

        DnsHeader h = q.header;
        h.setResponseFlags(rcode);
        writeU16(out, 2, h.flags);
        writeU16(out, 4, h.qdCount);
        writeU16(out, 6, 0); // ANCOUNT
        writeU16(out, 8, 0); // NSCOUNT
        writeU16(out, 10, 0); // ARCOUNT
        return out;
    }

    /**
     * Blocked domain -> NOERROR with an answer of 0.0.0.0 (A) or :: (AAAA).
     * Some apps retry aggressively on NXDOMAIN; a null route makes them fail fast.
     * For other query types it falls back to NXDOMAIN.
     */
    public static byte[] buildNullRouteResponse(byte[] query, int queryLength, long ttl) {
        DnsParser parser = new DnsParser(query, queryLength);
        DnsMessage q = parser.parseQuery();
        if (q.questions.size() != 1) return buildBlockedResponse(query, queryLength);
        int type = q.questions.get(0).type;
        int rdLength;
        if (type == DnsQuestion.TYPE_A) rdLength = 4;
        else if (type == DnsQuestion.TYPE_AAAA) rdLength = 16;
        else return buildBlockedResponse(query, queryLength);

        int questionEnd = parser.position();
        ByteArrayOutputStream out = new ByteArrayOutputStream(questionEnd + 16 + rdLength);
        out.write(query, 0, questionEnd);
        // Answer: name = pointer to the question name at offset 12 (0xC00C)
        out.write(0xC0); out.write(0x0C);
        writeU16(out, type);
        writeU16(out, 1);                 // class IN
        writeU32(out, ttl);
        writeU16(out, rdLength);
        out.write(new byte[rdLength], 0, rdLength); // all zeros = 0.0.0.0 / ::

        byte[] bytes = out.toByteArray();
        DnsHeader h = q.header;
        h.setResponseFlags(DnsHeader.RCODE_NOERROR);
        writeU16(bytes, 2, h.flags);
        writeU16(bytes, 6, 1);  // ANCOUNT
        writeU16(bytes, 8, 0);
        writeU16(bytes, 10, 0);
        return bytes;
    }

    /** Builds a fresh query packet (used by tests and the HTTP "test a domain" endpoint). */
    public static byte[] buildQuery(int id, String name, int type) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        writeU16(out, id);
        writeU16(out, DnsHeader.FLAG_RD);
        writeU16(out, 1); writeU16(out, 0); writeU16(out, 0); writeU16(out, 0);
        writeName(out, name);
        writeU16(out, type);
        writeU16(out, 1);
        return out.toByteArray();
    }

    /** Overwrites the first two bytes (transaction ID). */
    public static byte[] rewriteId(byte[] response, int newId) {
        byte[] copy = response.clone();
        copy[0] = (byte) ((newId >> 8) & 0xFF);
        copy[1] = (byte) (newId & 0xFF);
        return copy;
    }

    /**
     * Returns a copy of a cached response with every RR TTL reduced by ageSeconds (floored at 0).
     * Walks the packet without a full parse: skip the header and questions, then for each record
     * skip the owner name and patch the 4 TTL bytes in place. OPT (EDNS0) pseudo-records are left
     * alone because their "TTL" field actually holds extended flags.
     * If the packet is malformed the original bytes are returned unchanged.
     */
    public static byte[] adjustTtl(byte[] response, long ageSeconds) {
        byte[] out = response.clone();
        if (ageSeconds <= 0 || out.length < DnsHeader.SIZE) return out;
        try {
            int qd = readU16(out, 4);
            int rr = readU16(out, 6) + readU16(out, 8) + readU16(out, 10);
            int pos = DnsHeader.SIZE;
            for (int i = 0; i < qd; i++) pos = skipName(out, pos) + 4; // QTYPE + QCLASS
            for (int i = 0; i < rr; i++) {
                pos = skipName(out, pos);
                int type = readU16(out, pos);
                int ttlPos = pos + 4;
                int rdLength = readU16(out, pos + 8);
                if (type != DnsQuestion.TYPE_OPT) {
                    long ttl = readU32(out, ttlPos);
                    writeU32(out, ttlPos, Math.max(0, ttl - ageSeconds));
                }
                pos += 10 + rdLength;
                if (pos > out.length) return response.clone();
            }
            return out;
        } catch (ArrayIndexOutOfBoundsException e) {
            return response.clone();
        }
    }

    /**
     * Turns a cached reply into the reply for a new query:
     *  - transaction ID = the new query's ID
     *  - question bytes copied from the new query when they match case-insensitively, so the
     *    client sees exactly the casing it sent (resolvers using DNS 0x20 randomization check this)
     */
    public static byte[] prepareCachedReply(byte[] cached, byte[] query, int queryLength) {
        byte[] out = rewriteId(cached, readU16(query, 0));
        try {
            int qEnd = skipName(query, DnsHeader.SIZE) + 4;
            int rEnd = skipName(out, DnsHeader.SIZE) + 4;
            if (qEnd == rEnd && qEnd <= queryLength && rEnd <= out.length) {
                boolean same = true;
                for (int i = DnsHeader.SIZE; i < qEnd && same; i++) {
                    same = asciiLower(query[i]) == asciiLower(out[i]);   // A-Z only (RFC 4343)
                }
                if (same) System.arraycopy(query, DnsHeader.SIZE, out, DnsHeader.SIZE, qEnd - DnsHeader.SIZE);
            }
        } catch (ArrayIndexOutOfBoundsException ignored) {
            // keep the cached question as-is
        }
        return out;
    }

    /**
     * True if the reply's question section is the query's (names compared case-insensitively, so
     * DNS 0x20 case randomisation is fine; type and class must match exactly). Error replies are
     * allowed to omit the question entirely, as some servers do for FORMERR / REFUSED.
     */
    public static boolean sameQuestion(byte[] query, byte[] reply) {
        try {
            int qd = readU16(query, 4);
            int rd = readU16(reply, 4);
            if (rd == 0) return (reply[3] & DnsHeader.MASK_RCODE) != DnsHeader.RCODE_NOERROR;
            if (qd != rd) return false;
            int q = DnsHeader.SIZE, r = DnsHeader.SIZE;
            for (int i = 0; i < qd; i++) {
                while (true) {                                  // labels, uncompressed in a question
                    int len = query[q] & 0xFF;
                    if (len != (reply[r] & 0xFF) || (len & 0xC0) != 0) return false;
                    q++; r++;
                    if (len == 0) break;
                    for (int k = 0; k < len; k++, q++, r++) {
                        if (asciiLower(query[q]) != asciiLower(reply[r])) return false;
                    }
                }
                for (int k = 0; k < 4; k++, q++, r++) {          // QTYPE + QCLASS
                    if (query[q] != reply[r]) return false;
                }
            }
            return true;
        } catch (ArrayIndexOutOfBoundsException e) {
            return false;
        }
    }

    /**
     * Reply for when the real answer doesn't fit the client's UDP limit: header + question, TC=1,
     * no records. The client is expected to retry over TCP (RFC 1035 section 4.2.1, RFC 7766).
     */
    public static byte[] buildTruncatedResponse(byte[] query, int queryLength, int rcode) {
        byte[] out = buildErrorResponse(query, queryLength, rcode);
        out[2] |= (byte) (DnsHeader.FLAG_TC >> 8);
        return out;
    }

    /** EDNS(0) info from a query's OPT record (RFC 6891). */
    public static final class Edns {
        public static final Edns NONE = new Edns(false, 512, false);
        public final boolean present;
        /** Largest UDP reply the client accepts: 512 without EDNS, never below 512 with it. */
        public final int udpSize;
        /** DO bit: the client wants DNSSEC records. */
        public final boolean dnssecOk;

        Edns(boolean present, int udpSize, boolean dnssecOk) {
            this.present = present; this.udpSize = udpSize; this.dnssecOk = dnssecOk;
        }
    }

    /** Finds the OPT pseudo-record in the additional section. Malformed or absent -> Edns.NONE. */
    public static Edns edns(byte[] msg, int length) {
        try {
            if (length < DnsHeader.SIZE) return Edns.NONE;
            int qd = readU16(msg, 4);
            int rr = readU16(msg, 6) + readU16(msg, 8);
            int ar = readU16(msg, 10);
            int pos = DnsHeader.SIZE;
            for (int i = 0; i < qd; i++) pos = skipName(msg, pos) + 4;
            for (int i = 0; i < rr; i++) {
                int p = skipName(msg, pos);
                pos = p + 10 + readU16(msg, p + 8);
            }
            for (int i = 0; i < ar; i++) {
                int p = skipName(msg, pos);
                if (p + 10 > length) return Edns.NONE;
                if (readU16(msg, p) == DnsQuestion.TYPE_OPT) {
                    int size = Math.max(512, readU16(msg, p + 2));         // CLASS field = UDP size
                    boolean dnssecOk = (msg[p + 6] & 0x80) != 0;           // TTL field: ext-rcode, version, DO|Z
                    return new Edns(true, size, dnssecOk);
                }
                pos = p + 10 + readU16(msg, p + 8);
            }
        } catch (ArrayIndexOutOfBoundsException ignored) {
            // fall through: treat as a plain (non-EDNS) query
        }
        return Edns.NONE;
    }

    // ---------------------------------------------------------------- helpers

    private static int asciiLower(byte b) {
        int c = b & 0xFF;
        return c >= 'A' && c <= 'Z' ? c + 32 : c;
    }

    /** Position just past a (possibly compressed) domain name starting at pos. */
    static int skipName(byte[] b, int pos) {
        while (true) {
            int len = b[pos] & 0xFF;
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2; // compression pointer ends the name
            pos += 1 + len;
        }
    }

    static int readU16(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
    }

    static long readU32(byte[] b, int offset) {
        return ((long) readU16(b, offset) << 16) | readU16(b, offset + 2);
    }

    static void writeU32(byte[] b, int offset, long v) {
        writeU16(b, offset, (int) ((v >> 16) & 0xFFFF));
        writeU16(b, offset + 2, (int) (v & 0xFFFF));
    }

    static void writeName(ByteArrayOutputStream out, String name) {
        if (name != null && !name.isEmpty() && !name.equals(".")) {
            for (String label : name.split("\\.")) {
                if (label.isEmpty()) continue;
                byte[] b = label.getBytes(StandardCharsets.ISO_8859_1);
                if (b.length > 63) throw new IllegalArgumentException("label too long: " + label);
                out.write(b.length);
                out.write(b, 0, b.length);
            }
        }
        out.write(0);
    }

    static void writeU16(byte[] b, int offset, int v) {
        b[offset] = (byte) ((v >> 8) & 0xFF);
        b[offset + 1] = (byte) (v & 0xFF);
    }

    static void writeU16(ByteArrayOutputStream out, int v) {
        out.write((v >> 8) & 0xFF);
        out.write(v & 0xFF);
    }

    static void writeU32(ByteArrayOutputStream out, long v) {
        writeU16(out, (int) ((v >> 16) & 0xFFFF));
        writeU16(out, (int) (v & 0xFFFF));
    }
}
