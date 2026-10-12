package com.sankar.dnsfilter.bench;

import com.sankar.dnsfilter.protocol.DnsWriter;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntFunction;

/**
 * Load generator for the DNS filter. Closed loop: each worker thread sends a query, waits for the
 * reply (or a timeout), records the round-trip time, and sends the next one.
 *
 * Scenarios, run in this order:
 *   1. warmup   - JIT warm-up + fills the cache with the "popular" names (not reported)
 *   2. cached   - the same popular names over and over -> every lookup is a cache hit
 *   3. blocked  - subdomains of blocklisted domains -> answered from the blocklist
 *   4. uncached - unique random names -> every lookup goes upstream (kept small and gentle,
 *                 so we don't hammer someone else's resolver)
 *
 * Usage (server must be running; localhost is exempt from the rate limiter):
 *   java -cp backend/target/dns-filter.jar com.sankar.dnsfilter.bench.Benchmark [options]
 *     --host 127.0.0.1  --port 5300  --queries 20000  --concurrency 16
 *     --uncached 300    --uncached-concurrency 4   --timeout-ms 2000
 *
 * Prints a Markdown table you can paste straight into the README.
 */
public class Benchmark {

    static final String[] POPULAR = {
            "google.com", "youtube.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
            "apple.com", "stackoverflow.com", "reddit.com", "linkedin.com", "netflix.com", "zscaler.com",
            "cloudflare.com", "mozilla.org", "openai.com", "whatsapp.com", "instagram.com", "x.com",
            "bing.com", "yahoo.com"};
    static final String[] BLOCKED = {"doubleclick.net", "googlesyndication.com", "googleadservices.com",
            "adnxs.com", "taboola.com", "outbrain.com"};

    /** Result of one scenario. */
    static final class Result {
        final String name;
        final int sent;
        final int ok;
        final int timeouts;
        final double seconds;
        final long[] micros; // successful round-trips, sorted

        Result(String name, int sent, int ok, int timeouts, double seconds, long[] micros) {
            this.name = name; this.sent = sent; this.ok = ok; this.timeouts = timeouts;
            this.seconds = seconds; this.micros = micros;
        }

        double qps() { return ok / seconds; }
        double pct(double p) {
            if (micros.length == 0) return 0;
            int rank = (int) Math.ceil(p / 100.0 * micros.length);
            return micros[Math.max(0, Math.min(micros.length - 1, rank - 1))] / 1000.0;
        }
        double avg() { return micros.length == 0 ? 0 : Arrays.stream(micros).average().orElse(0) / 1000.0; }
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> opt = parseArgs(args);
        InetAddress host = InetAddress.getByName(opt.getOrDefault("host", "127.0.0.1"));
        int port = Integer.parseInt(opt.getOrDefault("port", "5300"));
        int queries = Integer.parseInt(opt.getOrDefault("queries", "20000"));
        int conc = Integer.parseInt(opt.getOrDefault("concurrency", "16"));
        int uncached = Integer.parseInt(opt.getOrDefault("uncached", "300"));
        int uncachedConc = Integer.parseInt(opt.getOrDefault("uncached-concurrency", "4"));
        int timeoutMs = Integer.parseInt(opt.getOrDefault("timeout-ms", "2000"));

        System.out.printf("DNS filter benchmark -> %s:%d  (%d queries x %d threads per scenario)%n%n",
                host.getHostAddress(), port, queries, conc);

        run("warmup", host, port, Math.max(2000, POPULAR.length * 50), conc, timeoutMs,
                i -> POPULAR[i % POPULAR.length]);

        List<Result> results = new ArrayList<>();
        results.add(run("Cache hit", host, port, queries, conc, timeoutMs,
                i -> POPULAR[i % POPULAR.length]));
        results.add(run("Blocked", host, port, queries, conc, timeoutMs,
                i -> "ad" + (i % 1000) + "." + BLOCKED[i % BLOCKED.length]));
        if (uncached > 0) {
            String runId = Long.toString(System.currentTimeMillis() % 1_000_000, 36);
            results.add(run("Cache miss (upstream)", host, port, uncached, uncachedConc, timeoutMs,
                    i -> "bench-" + runId + "-" + i + "-" + ThreadLocalRandom.current().nextInt(1_000_000) + ".example.com"));
        }

        System.out.println();
        System.out.println("| Scenario | Queries | Throughput | p50 | p95 | p99 | Timeouts |");
        System.out.println("|---|---:|---:|---:|---:|---:|---:|");
        for (Result r : results) {
            System.out.printf(Locale.ROOT, "| %s | %,d | %,.0f q/s | %.3f ms | %.3f ms | %.3f ms | %d |%n",
                    r.name, r.sent, r.qps(), r.pct(50), r.pct(95), r.pct(99), r.timeouts);
        }
        Result hit = results.get(0), miss = results.size() > 2 ? results.get(2) : null;
        if (miss != null && hit.pct(50) > 0 && miss.ok > 0) {
            System.out.printf(Locale.ROOT, "%nCache speed-up at p50: %.0fx (%.3f ms -> %.3f ms)%n",
                    miss.pct(50) / hit.pct(50), miss.pct(50), hit.pct(50));
        }
        System.out.printf("%nMachine: %s, %d cores, Java %s%n", System.getProperty("os.name"),
                Runtime.getRuntime().availableProcessors(), System.getProperty("java.version"));
    }

    static Result run(String name, InetAddress host, int port, int total, int threads, int timeoutMs,
                      IntFunction<String> nameFor) throws InterruptedException {
        AtomicInteger next = new AtomicInteger();
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger timeouts = new AtomicInteger();
        long[][] perThread = new long[threads][];
        int[] counts = new int[threads];
        Thread[] workers = new Thread[threads];

        long start = System.nanoTime();
        for (int t = 0; t < threads; t++) {
            final int id = t;
            perThread[t] = new long[total / threads + 2];
            workers[t] = new Thread(() -> {
                byte[] buf = new byte[4096];
                try (DatagramSocket s = new DatagramSocket()) {
                    s.setSoTimeout(timeoutMs);
                    int i;
                    while ((i = next.getAndIncrement()) < total) {
                        int qid = ThreadLocalRandom.current().nextInt(0x10000);
                        byte[] q = DnsWriter.buildQuery(qid, nameFor.apply(i), 1);
                        long t0 = System.nanoTime();
                        s.send(new DatagramPacket(q, q.length, host, port));
                        try {
                            while (true) {          // skip any late reply to an earlier, timed-out query
                                DatagramPacket p = new DatagramPacket(buf, buf.length);
                                s.receive(p);
                                if (p.getLength() >= 2 && (((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF)) == qid) break;
                            }
                            long us = (System.nanoTime() - t0) / 1000;
                            if (counts[id] == perThread[id].length) perThread[id] = Arrays.copyOf(perThread[id], counts[id] * 2);
                            perThread[id][counts[id]++] = us;
                            ok.incrementAndGet();
                        } catch (SocketTimeoutException e) {
                            timeouts.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    System.err.println(name + " worker failed: " + e);
                }
            }, "bench-" + t);
            workers[t].start();
        }
        for (Thread w : workers) w.join();
        double seconds = (System.nanoTime() - start) / 1e9;

        long[] all = new long[ok.get()];
        int pos = 0;
        for (int t = 0; t < threads; t++) {
            System.arraycopy(perThread[t], 0, all, pos, counts[t]);
            pos += counts[t];
        }
        Arrays.sort(all);
        Result r = new Result(name, total, ok.get(), timeouts.get(), seconds, all);
        System.out.printf(Locale.ROOT, "%-22s %,7d queries  %8.2fs  %,9.0f q/s  p50 %.3f ms  p99 %.3f ms  timeouts %d%n",
                name, total, seconds, r.qps(), r.pct(50), r.pct(99), r.timeouts);
        return r;
    }

    static Map<String, String> parseArgs(String[] args) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--") && i + 1 < args.length) m.put(args[i].substring(2), args[++i]);
        }
        return m;
    }
}
