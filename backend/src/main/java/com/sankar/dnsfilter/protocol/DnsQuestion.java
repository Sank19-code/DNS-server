package com.sankar.dnsfilter.protocol;

/** One entry in the question section: QNAME + QTYPE + QCLASS. */
public class DnsQuestion {
    public String name;     // e.g. "ads.example.com" (decoded from length-prefixed labels)
    public int type;        // 1 = A, 28 = AAAA, 5 = CNAME, ...
    public int qclass;      // 1 = IN

    public static final int TYPE_A = 1;
    public static final int TYPE_NS = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA = 6;
    public static final int TYPE_PTR = 12;
    public static final int TYPE_MX = 15;
    public static final int TYPE_TXT = 16;
    public static final int TYPE_AAAA = 28;
    public static final int TYPE_SRV = 33;
    public static final int TYPE_OPT = 41;   // EDNS0 pseudo-record
    public static final int TYPE_HTTPS = 65;

    public DnsQuestion() {}

    public DnsQuestion(String name, int type, int qclass) {
        this.name = name; this.type = type; this.qclass = qclass;
    }

    /** Human-readable record type, used in logs and the dashboard. */
    public static String typeName(int type) {
        switch (type) {
            case TYPE_A:     return "A";
            case TYPE_NS:    return "NS";
            case TYPE_CNAME: return "CNAME";
            case TYPE_SOA:   return "SOA";
            case TYPE_PTR:   return "PTR";
            case TYPE_MX:    return "MX";
            case TYPE_TXT:   return "TXT";
            case TYPE_AAAA:  return "AAAA";
            case TYPE_SRV:   return "SRV";
            case TYPE_OPT:   return "OPT";
            case TYPE_HTTPS: return "HTTPS";
            default:         return "TYPE" + type;
        }
    }

    /** Inverse of typeName: "AAAA" -> 28, "TYPE99" or "99" -> 99, unknown -> -1. */
    public static int typeCode(String name) {
        String n = name.trim().toUpperCase();
        for (int t : new int[]{TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA, TYPE_PTR, TYPE_MX, TYPE_TXT,
                TYPE_AAAA, TYPE_SRV, TYPE_HTTPS}) {
            if (typeName(t).equals(n)) return t;
        }
        try {
            int v = Integer.parseInt(n.startsWith("TYPE") ? n.substring(4) : n);
            return v >= 1 && v <= 65535 ? v : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    @Override
    public String toString() { return name + " " + typeName(type); }
}
