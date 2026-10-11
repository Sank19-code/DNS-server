package com.sankar.dnsfilter.protocol;

/** A resource record (answer / authority / additional section). */
public class DnsRecord {
    public String name;
    public int type;
    public int rrClass;
    public long ttl;        // 32-bit unsigned seconds -> drives cache expiry
    public byte[] rdata;    // raw RDATA (4 bytes for A, 16 for AAAA, ...)
}
