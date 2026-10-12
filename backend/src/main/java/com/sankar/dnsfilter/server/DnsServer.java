package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.stats.StatsCollector;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * UDP listener. Receives each query and hands it to a worker thread so one slow
 * upstream lookup never blocks other clients.
 *
 * Back-pressure, in order:
 *   1. per-client token bucket (RateLimiter) - drops floods from a single IP
 *   2. bounded work queue - if all workers are busy and the queue is full, the packet is
 *      dropped instead of queueing forever (an unbounded queue is a memory DoS)
 * Clients retry DNS over UDP anyway, so dropping under overload is the normal behaviour.
 */
public class DnsServer {
    /** Run with -Ddns.debug=true to log every packet in/out. */
    private static final boolean DEBUG = Boolean.getBoolean("dns.debug");

    private final Config config;
    private final QueryHandler handler;
    private final StatsCollector stats;
    private final RateLimiter limiter;
    private final boolean exemptLoopback;
    private final ThreadPoolExecutor workers;
    private final AtomicLong overloadDrops = new AtomicLong();

    public DnsServer(Config config, QueryHandler handler, StatsCollector stats) {
        this.config = config;
        this.handler = handler;
        this.stats = stats;
        this.limiter = new RateLimiter(
                config.getInt("dns.rateLimit.qps", 50),
                config.getInt("dns.rateLimit.burst", 100));
        // Local tools (nslookup, the benchmark script) shouldn't trip the limiter.
        this.exemptLoopback = Boolean.parseBoolean(config.get("dns.rateLimit.exemptLoopback", "true").trim());
        int threads = config.getInt("dns.workers", 16);
        this.workers = new ThreadPoolExecutor(threads, threads, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(config.getInt("dns.queueSize", 1000)),
                (task, pool) -> overloadDrops.incrementAndGet()); // reject = drop + count
    }

    public void start() throws Exception {
        int port = config.getInt("dns.port", 5300);
        String bind = config.get("dns.bind", "0.0.0.0");
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(bind, port))) {
            System.out.println("DNS server listening on " + bind + ":" + port + " (UDP)"
                    + (limiter.enabled() ? ", rate limit " + config.getInt("dns.rateLimit.qps", 50)
                    + " qps/client (burst " + config.getInt("dns.rateLimit.burst", 100) + ")" : ", no rate limit"));
            while (true) {
                byte[] buf = new byte[4096];
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);
                String clientIp = packet.getAddress().getHostAddress();
                boolean exempt = exemptLoopback && packet.getAddress().isLoopbackAddress();
                if (!exempt && !limiter.tryAcquire(clientIp)) {
                    stats.recordRateLimited();
                    if (DEBUG) System.out.println("RATE-LIMITED " + clientIp);
                    continue;
                }
                byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
                if (DEBUG) System.out.println("RECV " + data.length + " bytes from " + packet.getSocketAddress());
                workers.execute(() -> {
                    try {
                        byte[] reply = handler.handle(data, clientIp);
                        if (reply != null) {
                            socket.send(new DatagramPacket(reply, reply.length, packet.getSocketAddress()));
                            if (DEBUG) System.out.println("SENT " + reply.length + " bytes to " + packet.getSocketAddress());
                        }
                    } catch (Exception e) {
                        System.err.println("Error handling query: " + e);
                        e.printStackTrace();
                    }
                });
            }
        }
    }

    public long overloadDrops() { return overloadDrops.get(); }
}
