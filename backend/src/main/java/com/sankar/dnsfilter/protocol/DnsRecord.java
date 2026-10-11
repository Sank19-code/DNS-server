package com.sankar.dnsfilter.protocol;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** A resource record (answer / authority / additional section). */
public class DnsRecord {
    public String name;
    public int type;
    public int rrClass;
    public long ttl;        // 32-bit unsigned seconds -> drives cache expiry
    public byte[] rdata;    // raw RDATA (4 bytes for A, 16 for AAAA, ...)
    public String rdataText; // decoded form when we know how (IP address, CNAME target)

    @Override
    public String toString() {
        String data = rdataText;
        if (data == null && (type == DnsQuestion.TYPE_A || type == DnsQuestion.TYPE_AAAA) && rdata != null) {
            try { data = InetAddress.getByAddress(rdata).getHostAddress(); }
            catch (UnknownHostException e) { data = "?"; }
        }
        if (data == null) data = (rdata == null ? 0 : rdata.length) + " bytes";
        return name + " " + ttl + " " + DnsQuestion.typeName(type) + " " + data;
    }
}
