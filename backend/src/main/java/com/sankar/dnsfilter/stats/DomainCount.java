package com.sankar.dnsfilter.stats;

/** One row of a "top N" list: a key (domain, client IP, category) and its count. */
public class DomainCount {
    public final String name;
    public final long count;

    public DomainCount(String name, long count) {
        this.name = name;
        this.count = count;
    }

    @Override
    public String toString() { return name + "=" + count; }
}
