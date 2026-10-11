package com.sankar.dnsfilter.protocol;

/**
 * The fixed 12-byte DNS header (RFC 1035 section 4.1.1).
 *
 *  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * |QR|  Opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
 * |                    QDCOUNT                    |
 * |                    ANCOUNT                    |
 * |                    NSCOUNT                    |
 * |                    ARCOUNT                    |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
public class DnsHeader {
    public static final int SIZE = 12;

    public int id;          // 16 bits, copied from query into response
    public int flags;       // 16 bits: QR, Opcode, AA, TC, RD, RA, Z, RCODE
    public int qdCount;     // number of questions
    public int anCount;     // number of answers
    public int nsCount;     // authority records
    public int arCount;     // additional records

    public static final int RCODE_NOERROR = 0;
    public static final int RCODE_FORMERR = 1;
    public static final int RCODE_SERVFAIL = 2;
    public static final int RCODE_NXDOMAIN = 3;

    // Bit masks inside the 16-bit flags field
    public static final int FLAG_QR = 0x8000;      // 1 = response
    public static final int MASK_OPCODE = 0x7800;  // 4 bits
    public static final int FLAG_AA = 0x0400;      // authoritative answer
    public static final int FLAG_TC = 0x0200;      // truncated
    public static final int FLAG_RD = 0x0100;      // recursion desired
    public static final int FLAG_RA = 0x0080;      // recursion available
    public static final int MASK_RCODE = 0x000F;

    public boolean isResponse()          { return (flags & FLAG_QR) != 0; }
    public int getOpcode()               { return (flags & MASK_OPCODE) >>> 11; }
    public boolean isTruncated()         { return (flags & FLAG_TC) != 0; }
    public boolean isRecursionDesired()  { return (flags & FLAG_RD) != 0; }
    public int getRcode()                { return flags & MASK_RCODE; }

    /**
     * Turns query flags into response flags: QR=1, RA=1, keeps Opcode and RD from the query,
     * clears AA/TC/Z, and sets the given RCODE.
     */
    public void setResponseFlags(int rcode) {
        flags = FLAG_QR | (flags & (MASK_OPCODE | FLAG_RD)) | FLAG_RA | (rcode & MASK_RCODE);
    }

    public static String rcodeName(int rcode) {
        switch (rcode) {
            case RCODE_NOERROR:  return "NOERROR";
            case RCODE_FORMERR:  return "FORMERR";
            case RCODE_SERVFAIL: return "SERVFAIL";
            case RCODE_NXDOMAIN: return "NXDOMAIN";
            default:             return "RCODE" + rcode;
        }
    }

    @Override
    public String toString() {
        return String.format("id=0x%04x %s opcode=%d rcode=%s qd=%d an=%d ns=%d ar=%d",
                id, isResponse() ? "RESPONSE" : "QUERY", getOpcode(), rcodeName(getRcode()),
                qdCount, anCount, nsCount, arCount);
    }
}
