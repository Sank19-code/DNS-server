package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.stats.StatsCollector;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
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
 *   1. Admission: per-client token bucket, then a global queries/sec cap - drops floods
 *   2. bounded work queue - if all workers are busy and the queue is full, the packet is
 *      dropped instead of queueing forever (an unbounded queue is a memory DoS)
 * Clients retry DNS over UDP anyway, so dropping under overload is the normal behaviour.
 *
 * The receive loop never dies on a bad packet or a transient socket error (on Windows, for
 * example, an ICMP "port unreachable" from a client that already left can surface as an
 * exception on the next receive). Only stop() ends it.
 */
public class DnsServer {
    /** Run with -Ddns.debug=true to log every packet in/out. */
    private static final boolean DEBUG = Boolean.getBoolean("dns.debug");

    private final Config config;
    private final QueryHandler handler;
    private final Admission admission;
    private final ThreadPoolExecutor workers;
    private final AtomicLong overloadDrops = new AtomicLong();
    private final AtomicLong receiveErrors = new AtomicLong();
    private volatile DatagramSocket socket;

    public DnsServer(Config config, QueryHandler handler, StatsCollector stats) {
        this(config, handler, Admission.from(config, stats));
    }

    /** @param admission shared with TcpDnsServer so a client's budget covers both transports */
    public DnsServer(Config config, QueryHandler handler, Admission admission) {
        this.config = config;
        this.handler = handler;
        this.admission = admission;
        int threads = config.getInt("dns.workers", 16);
        this.workers = new ThreadPoolExecutor(threads, threads, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(config.getInt("dns.queueSize", 1000)),
                (task, pool) -> {                                   // reject = drop + count
                    overloadDrops.incrementAndGet();
                    admission.stats().recordOverloadDrop();
                });
    }

    /** Binds the socket and returns the bound port (useful with dns.port=0 in tests). */
    public int bind() throws SocketException {
        int port = config.getInt("dns.port", 5300);
        // "::" = IPv6 and IPv4 on one socket (Java sockets are dual-stack by default). Hosts and
        // containers with IPv6 switched off can't bind it, so fall back to IPv4 only.
        String bind = config.get("dns.bind", "::").trim();
        try {
            socket = new DatagramSocket(new InetSocketAddress(bind, port));
        } catch (SocketException e) {
            if (!bind.equals("::")) throw e;
            System.err.println("IPv6 unavailable (" + e.getMessage() + "), UDP listening on IPv4 only");
            bind = "0.0.0.0";
            socket = new DatagramSocket(new InetSocketAddress(bind, port));
        }
        System.out.println("DNS server listening on " + bind + ":" + socket.getLocalPort() + " (UDP), "
                + admission.describe());
        return socket.getLocalPort();
    }

    /** Binds and serves until stop(). */
    public void start() throws IOException {
        bind();
        serve();
    }

    /** The receive loop. Blocks until stop() closes the socket. */
    public void serve() {
        DatagramSocket s = socket;
        // One buffer for the loop: each packet is copied out before the next receive, so a single
        // 64 KB buffer can take any datagram without truncating it and without per-packet garbage.
        byte[] buf = new byte[65_535];
        while (!s.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                s.receive(packet);
                if (!admission.admit(packet.getAddress())) {
                    if (DEBUG) System.out.println("RATE-LIMITED " + packet.getAddress().getHostAddress());
                    continue;
                }
                String clientIp = packet.getAddress().getHostAddress();
                SocketAddress from = packet.getSocketAddress();  // captured now: the packet object is reused
                byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
                if (DEBUG) System.out.println("RECV " + data.length + " bytes from " + from);
                workers.execute(() -> {
                    try {
                        byte[] reply = handler.handle(data, clientIp);
                        if (reply != null) {
                            s.send(new DatagramPacket(reply, reply.length, from));
                            if (DEBUG) System.out.println("SENT " + reply.length + " bytes to " + from);
                        }
                    } catch (Exception e) {
                        System.err.println("Error handling query from " + clientIp + ": " + e);
                        if (DEBUG) e.printStackTrace();
                    }
                });
            } catch (IOException | RuntimeException e) {
                if (s.isClosed()) break;                   // stop() was called
                receiveErrors.incrementAndGet();
                System.err.println("UDP receive error (continuing): " + e);
            }
        }
    }

    /** Closes the socket (ending serve()) and lets in-flight queries finish for up to 2 s. */
    public void stop() {
        if (socket != null) socket.close();
        workers.shutdown();
        try {
            if (!workers.awaitTermination(2, TimeUnit.SECONDS)) workers.shutdownNow();
        } catch (InterruptedException e) {
            workers.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public long overloadDrops() { return overloadDrops.get(); }
    public long receiveErrors() { return receiveErrors.get(); }
}
