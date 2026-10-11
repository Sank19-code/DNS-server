package com.sankar.dnsfilter.protocol;

/** One entry in the question section: QNAME + QTYPE + QCLASS. */
public class DnsQuestion {
    public String name;     // e.g. "ads.example.com" (decoded from length-prefixed labels)
    public int type;        // 1 = A, 28 = AAAA, 5 = CNAME, ...
    public int qclass;      // 1 = IN

    public static final int TYPE_A = 1;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_AAAA = 28;

    public DnsQuestion() {}

    public DnsQuestion(String name, int type, int qclass) {
        this.name = name; this.type = type; this.qclass = qclass;
    }
}
