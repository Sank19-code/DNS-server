package com.sankar.dnsfilter.protocol;

/**
 * Turns raw UDP bytes into a DnsMessage, byte by byte.
 *
 * Things to handle (Day 1):
 *  - read big-endian 16/32-bit ints: ((b[i] & 0xFF) << 8) | (b[i+1] & 0xFF)
 *  - QNAME labels: [3]www[6]google[3]com[0]
 *  - name COMPRESSION pointers: top two bits 11 -> 14-bit offset to jump to
 *  - bounds checks: never trust the packet length (malformed packets must not crash the server)
 */
public class DnsParser {

    private final byte[] buf;
    private int pos;

    public DnsParser(byte[] buf, int length) {
        this.buf = buf;
        this.pos = 0;
        // TODO keep `length` and bounds-check every read against it
    }

    public DnsMessage parse() {
        DnsMessage msg = new DnsMessage();
        // TODO 1: parse header (12 bytes)
        // TODO 2: parse qdCount questions
        // TODO 3: parse anCount answers (needed to read TTLs from upstream replies)
        throw new UnsupportedOperationException("DnsParser.parse not implemented yet");
    }

    int readU16() {
        int v = ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    long readU32() {
        long v = ((long) readU16() << 16) | readU16();
        return v;
    }

    String readName() {
        // TODO: labels + compression pointers
        throw new UnsupportedOperationException("readName not implemented yet");
    }
}
