package com.sankar.dnsfilter.stats;

import java.util.ArrayList;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * Queries per minute for the last N minutes, for the dashboard's traffic chart.
 *
 * A circular array of N buckets indexed by (epochMinute % N). Each bucket remembers which
 * minute it holds; when a new minute lands on a bucket still holding an old minute, the bucket
 * is reset first. Memory is fixed (N buckets) no matter how long the server runs.
 */
public class TimeSeries {

    /** One minute of traffic. */
    public static class Bucket {
        public long minute;     // epoch minute; timestamp = minute * 60_000
        public long total;
        public long blocked;
        public long cached;
        public long forwarded;
        public long errors;

        Bucket copy() {
            Bucket b = new Bucket();
            b.minute = minute; b.total = total; b.blocked = blocked;
            b.cached = cached; b.forwarded = forwarded; b.errors = errors;
            return b;
        }
    }

    private final Bucket[] buckets;
    private final LongSupplier clock;

    public TimeSeries(int minutes, LongSupplier clock) {
        this.buckets = new Bucket[minutes];
        for (int i = 0; i < minutes; i++) buckets[i] = new Bucket();
        this.clock = clock;
    }

    public synchronized void record(QueryLogEntry.Status status) {
        Bucket b = bucketFor(clock.getAsLong() / 60_000);
        b.total++;
        switch (status) {
            case BLOCKED -> b.blocked++;
            case CACHED -> b.cached++;
            case FORWARDED -> b.forwarded++;
            case ERROR -> b.errors++;
        }
    }

    /** Oldest first, one entry per minute (zero-filled), ending with the current minute. */
    public synchronized List<Bucket> snapshot() {
        long now = clock.getAsLong() / 60_000;
        List<Bucket> out = new ArrayList<>(buckets.length);
        for (long m = now - buckets.length + 1; m <= now; m++) {
            Bucket b = buckets[(int) Math.floorMod(m, (long) buckets.length)];
            if (b.minute == m) {
                out.add(b.copy());
            } else {
                Bucket empty = new Bucket();
                empty.minute = m;
                out.add(empty);
            }
        }
        return out;
    }

    private Bucket bucketFor(long minute) {
        Bucket b = buckets[(int) Math.floorMod(minute, (long) buckets.length)];
        if (b.minute != minute) {          // stale bucket from an older lap -> reset
            b.minute = minute;
            b.total = b.blocked = b.cached = b.forwarded = b.errors = 0;
        }
        return b;
    }
}
