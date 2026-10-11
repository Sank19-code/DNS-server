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
    public int id;          // 16 bits, copied from query into response
    public int flags;       // 16 bits: QR, Opcode, AA, TC, RD, RA, Z, RCODE
    public int qdCount;     // number of questions
    public int anCount;     // number of answers
    public int nsCount;     // authority records
    public int arCount;     // additional records

    public static final int RCODE_NOERROR = 0;
    public static final int RCODE_NXDOMAIN = 3;

    // TODO (Day 1): helpers like isResponse(), getRcode(), setResponseFlags(rcode)
}
