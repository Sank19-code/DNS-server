package com.sankar.dnsfilter.protocol;

import java.util.List;

/**
 * Turns raw UDP bytes into a DnsMessage, byte by byte (RFC 1035 section 4).
 *
 * Security notes (packets come from the network, so never trust them):
 *  - every read is bounds-checked against the real packet length
 *  - compression pointers may only jump BACKWARDS, and at most MAX_JUMPS times,
 *    so a crafted packet can't send us into an infinite loop
 *  - names are capped at 255 bytes, labels at 63 bytes
 * Any violation throws DnsParseException instead of ArrayIndexOutOfBounds.
 */
public class DnsParser {
    private static final int MAX_JUMPS = 16;
    private static final int MAX_NAME_LENGTH = 255;
    private static final int MAX_LABEL_LENGTH = 63;

    private final byte[] buf;
    private final int length;
    private int pos;

    public DnsParser(byte[] buf, int length) {
        if (buf == null) throw new DnsParseException("null packet");
        this.buf = buf;
        this.length = Math.min(length, buf.length);
        this.pos = 0;
    }

    public DnsParser(byte[] buf) { this(buf, buf == null ? 0 : buf.length); }

    /** Parses header, questions and all three record sections. */
    public DnsMessage parse() {
        DnsMessage msg = new DnsMessage();
        msg.header = parseHeader();
        for (int i = 0; i < msg.header.qdCount; i++) msg.questions.add(parseQuestion());
        parseRecords(msg.header.anCount, msg.answers);
        parseRecords(msg.header.nsCount, msg.authorities);
        parseRecords(msg.header.arCount, msg.additionals);
        return msg;
    }

    /**
     * Parses only the header and question section. This is all the query path needs
     * (we decide block / cache / forward from the question), so it's cheaper.
     */
    public DnsMessage parseQuery() {
        DnsMessage msg = new DnsMessage();
        msg.header = parseHeader();
        for (int i = 0; i < msg.header.qdCount; i++) msg.questions.add(parseQuestion());
        return msg;
    }

    /** Byte offset just past the last parsed field (e.g. end of the question section). */
    public int position() { return pos; }

    // ---------------------------------------------------------------- sections

    DnsHeader parseHeader() {
        DnsHeader h = new DnsHeader();
        h.id = readU16();
        h.flags = readU16();
        h.qdCount = readU16();
        h.anCount = readU16();
        h.nsCount = readU16();
        h.arCount = readU16();
        return h;
    }

    DnsQuestion parseQuestion() {
        String name = readName();
        int type = readU16();
        int qclass = readU16();
        return new DnsQuestion(name, type, qclass);
    }

    private void parseRecords(int count, List<DnsRecord> out) {
        for (int i = 0; i < count; i++) out.add(parseRecord());
    }

    DnsRecord parseRecord() {
        DnsRecord r = new DnsRecord();
        r.name = readName();
        r.type = readU16();
        r.rrClass = readU16();
        r.ttl = readU32();
        int rdLength = readU16();
        require(rdLength);
        int rdStart = pos;
        r.rdata = new byte[rdLength];
        System.arraycopy(buf, pos, r.rdata, 0, rdLength);

        // Names inside RDATA can be compressed too, so decode them while we have the full packet.
        if (r.type == DnsQuestion.TYPE_CNAME || r.type == DnsQuestion.TYPE_NS
                || r.type == DnsQuestion.TYPE_PTR) {
            r.rdataText = readName();
        }
        pos = rdStart + rdLength;
        return r;
    }

    // ---------------------------------------------------------------- primitives

    private void require(int n) {
        if (n < 0 || pos + n > length) {
            throw new DnsParseException("truncated packet: need " + n + " byte(s) at offset "
                    + pos + ", packet length " + length);
        }
    }

    int readU8() {
        require(1);
        return buf[pos++] & 0xFF;
    }

    int readU16() {
        require(2);
        int v = ((buf[pos] & 0xFF) << 8) | (buf[pos + 1] & 0xFF);
        pos += 2;
        return v;
    }

    long readU32() {
        require(4);
        return ((long) readU16() << 16) | readU16();
    }

    /**
     * Reads a domain name at the current position.
     *
     *   plain:      [3]www[6]google[3]com[0]
     *   compressed: [3]www[0xC0 0x0C]   -> "www" + whatever name starts at offset 12
     *
     * A length byte with the top two bits set (0b11xxxxxx) is a pointer: the low 6 bits
     * plus the next byte form a 14-bit offset into the packet. After the FIRST jump,
     * the caller's position continues right after the 2-byte pointer, not after the
     * jumped-to name.
     *
     * A '.' or '\' byte INSIDE a label is escaped as "\." / "\\" (RFC 1035 presentation format).
     * Without that, the one-label name [10]www.google[3]com and the real [3]www[6]google[3]com
     * would both read as "www.google.com" - the same cache key - and anyone could plant an answer
     * (e.g. NXDOMAIN) for a name they didn't really ask about.
     */
    String readName() {
        StringBuilder name = new StringBuilder();
        int cursor = pos;
        int returnPos = -1;     // where to resume after following a pointer
        int jumps = 0;
        int wireLength = 0;

        while (true) {
            if (cursor >= length) throw new DnsParseException("name runs past end of packet");
            int len = buf[cursor] & 0xFF;

            if ((len & 0xC0) == 0xC0) {                         // compression pointer
                if (cursor + 1 >= length) throw new DnsParseException("truncated compression pointer");
                int target = ((len & 0x3F) << 8) | (buf[cursor + 1] & 0xFF);
                if (target >= cursor) throw new DnsParseException("forward/self compression pointer at " + cursor);
                if (++jumps > MAX_JUMPS) throw new DnsParseException("too many compression jumps");
                if (returnPos < 0) returnPos = cursor + 2;
                cursor = target;
                continue;
            }
            if ((len & 0xC0) != 0) throw new DnsParseException("unsupported label type 0x" + Integer.toHexString(len));

            cursor++;
            if (len == 0) break;                                // root label: end of name
            if (len > MAX_LABEL_LENGTH) throw new DnsParseException("label longer than 63 bytes");
            if (cursor + len > length) throw new DnsParseException("label runs past end of packet");
            wireLength += len + 1;
            if (wireLength > MAX_NAME_LENGTH) throw new DnsParseException("name longer than 255 bytes");

            if (name.length() > 0) name.append('.');
            for (int i = cursor; i < cursor + len; i++) {
                char c = (char) (buf[i] & 0xFF);                // ISO-8859-1: one byte, one char
                if (c == '.' || c == '\\') name.append('\\');
                name.append(c);
            }
            cursor += len;
        }

        pos = returnPos >= 0 ? returnPos : cursor;
        return name.toString();                                 // "" means the root (".")
    }
}
