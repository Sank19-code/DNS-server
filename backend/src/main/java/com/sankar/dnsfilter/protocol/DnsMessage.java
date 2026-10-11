package com.sankar.dnsfilter.protocol;

import java.util.ArrayList;
import java.util.List;

/** A full parsed DNS packet. */
public class DnsMessage {
    public DnsHeader header = new DnsHeader();
    public List<DnsQuestion> questions = new ArrayList<>();
    public List<DnsRecord> answers = new ArrayList<>();
    public List<DnsRecord> authorities = new ArrayList<>();
    public List<DnsRecord> additionals = new ArrayList<>();

    /** Smallest TTL across the answers, used as the cache lifetime. */
    public long minAnswerTtl() {
        long min = Long.MAX_VALUE;
        for (DnsRecord r : answers) min = Math.min(min, r.ttl);
        return answers.isEmpty() ? 0 : min;
    }
}
