package com.sankar.dnsfilter.resolver;

import com.sankar.dnsfilter.config.Config;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Forwards a raw query to the upstream resolver and returns its raw reply.
 *
 * Anti-spoofing: each query goes out from a fresh socket (random OS-chosen source port), and a
 * reply is only accepted if it comes from the upstream we asked AND carries our transaction ID
 * AND has QR=1. Anything else is dropped and we keep waiting until the deadline. Together with
 * the random port this is the standard defence against cache-poisoning (Kaminsky-style) replies.
 *
 * Packet loss: UDP has no delivery guarantee, so if no reply has arrived after retransmitMs the
 * same query is sent again on the same socket (same ID and port, so either reply is accepted).
 * Real stub resolvers do the same. Without it, one lost packet = a SERVFAIL for the client.
 *
 * Fallback: upstreams are tried in order (upstream.host, then upstream.fallback); each gets its
 * own timeout. The first good reply wins, and that upstream is tried FIRST from then on. So a
 * laptop moving between networks (campus resolver vs. home) pays the timeout once, not on
 * every query.
 */
public class UpstreamResolver {
    private final List<InetSocketAddress> upstreams;
    private final int timeoutMs;
    private final int retransmitMs;
    private final AtomicLong retransmits = new AtomicLong();
    private final AtomicInteger preferred = new AtomicInteger(); // index of the last upstream that answered

    public UpstreamResolver(Config config) throws Exception {
        this(buildList(config), config.getInt("upstream.timeoutMs", 1500), config.getInt("upstream.retransmitMs", 500));
    }

    public UpstreamResolver(List<InetSocketAddress> upstreams, int timeoutMs) {
        this(upstreams, timeoutMs, 0);
    }

    /** @param retransmitMs resend the query if nothing arrived after this long; 0 disables. */
    public UpstreamResolver(List<InetSocketAddress> upstreams, int timeoutMs, int retransmitMs) {
        if (upstreams.isEmpty()) throw new IllegalArgumentException("no upstream resolvers configured");
        this.upstreams = List.copyOf(upstreams);
        this.timeoutMs = timeoutMs;
        this.retransmitMs = retransmitMs;
    }

    public List<InetSocketAddress> upstreams() { return upstreams; }

    /** How many queries had to be resent because the first packet got no reply. */
    public long retransmits() { return retransmits.get(); }

    public byte[] forward(byte[] query) throws Exception {
        Exception last = null;
        int start = preferred.get();
        for (int i = 0; i < upstreams.size(); i++) {
            int idx = (start + i) % upstreams.size();
            InetSocketAddress upstream = upstreams.get(idx);
            try {
                byte[] reply = ask(upstream, query);
                if (idx != start && preferred.compareAndSet(start, idx)) {
                    System.out.println("Upstream " + upstream + " is answering; using it first from now on");
                }
                return reply;
            } catch (Exception e) {
                last = e;
                if (upstreams.size() > 1) {
                    System.err.println("Upstream " + upstream + " failed (" + e.getMessage() + "), trying next");
                }
            }
        }
        throw last;
    }

    /** The upstream currently tried first. */
    public InetSocketAddress preferredUpstream() { return upstreams.get(preferred.get()); }

    private byte[] ask(InetSocketAddress upstream, byte[] query) throws Exception {
        int queryId = ((query[0] & 0xFF) << 8) | (query[1] & 0xFF);
        try (DatagramSocket socket = new DatagramSocket()) {
            DatagramPacket out = new DatagramPacket(query, query.length, upstream);
            socket.send(out);
            long start = System.currentTimeMillis();
            long deadline = start + timeoutMs;
            long resendAt = retransmitMs > 0 && retransmitMs < timeoutMs ? start + retransmitMs : Long.MAX_VALUE;
            byte[] buf = new byte[4096];
            while (true) {
                long now = System.currentTimeMillis();
                if (now >= deadline) throw new SocketTimeoutException("no valid reply within " + timeoutMs + " ms");
                if (now >= resendAt) {
                    socket.send(out);
                    retransmits.incrementAndGet();
                    resendAt = Long.MAX_VALUE;        // one retransmit per upstream is enough
                }
                socket.setSoTimeout((int) Math.max(1, Math.min(deadline, resendAt) - now));
                DatagramPacket reply = new DatagramPacket(buf, buf.length);
                try {
                    socket.receive(reply);
                } catch (SocketTimeoutException e) {
                    continue;                         // loop decides: resend or give up
                }

                if (!upstream.equals(reply.getSocketAddress())) {
                    System.err.println("Dropped reply from unexpected source " + reply.getSocketAddress());
                    continue;
                }
                if (reply.getLength() < 12) continue;
                int replyId = ((buf[0] & 0xFF) << 8) | (buf[1] & 0xFF);
                boolean isResponse = (buf[2] & 0x80) != 0;
                if (replyId != queryId || !isResponse) {
                    System.err.printf("Dropped reply with wrong ID 0x%04x (expected 0x%04x)%n", replyId, queryId);
                    continue;
                }
                return Arrays.copyOf(buf, reply.getLength());
            }
        }
    }

    private static List<InetSocketAddress> buildList(Config config) throws Exception {
        int port = config.getInt("upstream.port", 53);
        List<InetSocketAddress> list = new ArrayList<>();
        list.add(new InetSocketAddress(InetAddress.getByName(config.get("upstream.host", "8.8.8.8").trim()), port));
        for (String h : config.get("upstream.fallback", "").split(",")) {
            if (!h.isBlank()) list.add(new InetSocketAddress(InetAddress.getByName(h.trim()), port));
        }
        return list;
    }
}
