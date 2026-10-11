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
 *  - TODO (bonus): adjustTtl(cachedBytes, remainingSeconds) to decrement cached TTLs
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

    // ---------------------------------------------------------------- helpers

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
