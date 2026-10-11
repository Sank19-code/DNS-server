package com.sankar.dnsfilter.stats;

/** One row in the live query log shown on the dashboard. */
public class QueryLogEntry {
    public enum Status { BLOCKED, CACHED, FORWARDED, ERROR }

    public long timestamp;
    public String clientIp;
    public String domain;
    public String type;        // "A", "AAAA", ...
    public Status status;
    public String category;    // set when BLOCKED
    public long latencyMicros;

    public QueryLogEntry(String clientIp, String domain, String type, Status status,
                         String category, long latencyMicros) {
        this.timestamp = System.currentTimeMillis();
        this.clientIp = clientIp;
        this.domain = domain;
        this.type = type;
        this.status = status;
        this.category = category;
        this.latencyMicros = latencyMicros;
    }
}
