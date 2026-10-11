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

/**
 * Forwards a raw query to the upstream resolver and returns its raw reply.
 *
 * Anti-spoofing: each query goes out from a fresh socket (random OS-chosen source port), and a
 * reply is only accepted if it comes from the upstream we asked AND carries our transaction ID
 * AND has QR=1. Anything else is dropped and we keep waiting until the deadline. Together with
 * the random port this is the standard defence against cache-poisoning (Kaminsky-style) replies.
 *
 * Fallback: upstreams are tried in order (upstream.host, then upstream.fallback); each gets its
 * own timeout. The first good reply wins.
 */
public class UpstreamResolver {
    private final List<InetSocketAddress> upstreams;
    private final int timeoutMs;

    public UpstreamResolver(Config config) throws Exception {
        this(buildList(config), config.getInt("upstream.timeoutMs", 2000));
    }

    public UpstreamResolver(List<InetSocketAddress> upstreams, int timeoutMs) {
        if (upstreams.isEmpty()) throw new IllegalArgumentException("no upstream resolvers configured");
        this.upstreams = List.copyOf(upstreams);
        this.timeoutMs = timeoutMs;
    }

    public List<InetSocketAddress> upstreams() { return upstreams; }

    public byte[] forward(byte[] query) throws Exception {
        Exception last = null;
        for (InetSocketAddress upstream : upstreams) {
            try {
                return ask(upstream, query);
            } catch (Exception e) {
                last = e;
                if (upstreams.size() > 1) {
                    System.err.println("Upstream " + upstream + " failed (" + e.getMessage() + "), trying next");
                }
            }
        }
        throw last;
    }

    private byte[] ask(InetSocketAddress upstream, byte[] query) throws Exception {
        int queryId = ((query[0] & 0xFF) << 8) | (query[1] & 0xFF);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.send(new DatagramPacket(query, query.length, upstream));
            long deadline = System.currentTimeMillis() + timeoutMs;
            byte[] buf = new byte[4096];
            while (true) {
                int remaining = (int) (deadline - System.currentTimeMillis());
                if (remaining <= 0) throw new SocketTimeoutException("no valid reply within " + timeoutMs + " ms");
                socket.setSoTimeout(remaining);
                DatagramPacket reply = new DatagramPacket(buf, buf.length);
                socket.receive(reply);

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
