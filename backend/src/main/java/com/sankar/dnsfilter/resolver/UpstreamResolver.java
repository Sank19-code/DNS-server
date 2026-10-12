package com.sankar.dnsfilter.resolver;

import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.protocol.DnsWriter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Forwards a raw query to the upstream resolver and returns its raw reply.
 *
 * Anti-spoofing: each query goes out from a fresh socket (random OS-chosen source port) with a
 * fresh random transaction ID that WE choose - never the client's, which an attacker who is also
 * a client would know. A reply is only accepted if it comes from the upstream we asked, carries
 * our ID, has QR=1 and echoes our question. Anything else is dropped and we keep waiting until the
 * deadline. Random port x random ID is the standard defence against cache-poisoning (Kaminsky)
 * replies; the client's own ID is put back before the reply leaves this class.
 *
 * Packet loss: UDP has no delivery guarantee, so if no reply has arrived after retransmitMs the
 * same query is sent again on the same socket (same ID and port, so either reply is accepted).
 * Real stub resolvers do the same. Without it, one lost packet = a SERVFAIL for the client.
 *
 * Fallback: upstreams are tried in order (upstream.host, then upstream.fallback); each gets its
 * own timeout. The first good reply wins, and that upstream is tried FIRST from then on. So a
 * laptop moving between networks (campus resolver vs. home) pays the timeout once, not on
 * every query.
 *
 * TCP: forwardTcp() does the same over TCP (RFC 7766, 2-byte length prefix). It is used for
 * clients that came to us over TCP, typically after a truncated (TC=1) UDP answer.
 */
public class UpstreamResolver {
    /** Largest possible DNS message; a smaller UDP buffer would silently cut big replies in half. */
    private static final int MAX_MESSAGE = 65_535;

    private final List<InetSocketAddress> upstreams;
    private final int timeoutMs;
    private final int retransmitMs;
    private final SecureRandom random = new SecureRandom();
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

    /** Forwards over UDP. */
    public byte[] forward(byte[] query) throws Exception {
        return forward(query, false);
    }

    /** Forwards over TCP (no size limit, no truncation). */
    public byte[] forwardTcp(byte[] query) throws Exception {
        return forward(query, true);
    }

    private byte[] forward(byte[] query, boolean tcp) throws Exception {
        if (query.length < 12) throw new IllegalArgumentException("query shorter than a DNS header");
        Exception last = null;
        int start = preferred.get();
        for (int i = 0; i < upstreams.size(); i++) {
            int idx = (start + i) % upstreams.size();
            InetSocketAddress upstream = upstreams.get(idx);
            try {
                byte[] reply = tcp ? askTcp(upstream, query) : ask(upstream, query);
                if (idx != start && preferred.compareAndSet(start, idx)) {
                    System.out.println("Upstream " + upstream + " is answering; using it first from now on");
                }
                return reply;
            } catch (Exception e) {
                last = e;
                if (upstreams.size() > 1) {
                    System.err.println("Upstream " + upstream + (tcp ? " (TCP)" : "") + " failed ("
                            + e.getMessage() + "), trying next");
                }
            }
        }
        throw last;
    }

    /** The upstream currently tried first. */
    public InetSocketAddress preferredUpstream() { return upstreams.get(preferred.get()); }

    private byte[] ask(InetSocketAddress upstream, byte[] query) throws Exception {
        int clientId = readId(query, 0);
        int ourId = random.nextInt(0x10000);
        byte[] outBytes = DnsWriter.rewriteId(query, ourId);
        try (DatagramSocket socket = new DatagramSocket()) {
            DatagramPacket out = new DatagramPacket(outBytes, outBytes.length, upstream);
            socket.send(out);
            // nanoTime, not currentTimeMillis: a wall-clock jump (NTP sync) must not stretch or cut the timeout
            long start = System.nanoTime();
            long deadline = start + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
            long resendAt = retransmitMs > 0 && retransmitMs < timeoutMs
                    ? start + TimeUnit.MILLISECONDS.toNanos(retransmitMs) : Long.MAX_VALUE;
            byte[] buf = new byte[MAX_MESSAGE];
            while (true) {
                long now = System.nanoTime();
                if (now - deadline >= 0) throw new SocketTimeoutException("no valid reply within " + timeoutMs + " ms");
                if (resendAt != Long.MAX_VALUE && now - resendAt >= 0) {
                    socket.send(out);
                    retransmits.incrementAndGet();
                    resendAt = Long.MAX_VALUE;        // one retransmit per upstream is enough
                }
                long waitUntil = resendAt == Long.MAX_VALUE ? deadline : Math.min(deadline, resendAt);
                socket.setSoTimeout((int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(waitUntil - now)));
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
                byte[] r = Arrays.copyOf(buf, reply.getLength());
                if (!acceptable(outBytes, r, ourId)) continue;
                return DnsWriter.rewriteId(r, clientId);
            }
        }
    }

    private byte[] askTcp(InetSocketAddress upstream, byte[] query) throws IOException {
        int clientId = readId(query, 0);
        int ourId = random.nextInt(0x10000);
        byte[] outBytes = DnsWriter.rewriteId(query, ourId);
        try (Socket socket = new Socket()) {
            long start = System.nanoTime();
            socket.connect(upstream, timeoutMs);
            int left = timeoutMs - (int) TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            if (left <= 0) throw new SocketTimeoutException("no valid reply within " + timeoutMs + " ms");
            socket.setSoTimeout(left);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeShort(outBytes.length);
            out.write(outBytes);
            out.flush();
            DataInputStream in = new DataInputStream(socket.getInputStream());
            int len = in.readUnsignedShort();
            byte[] r = in.readNBytes(len);
            if (r.length != len) throw new IOException("upstream closed the connection mid-reply");
            // Over TCP the peer is authenticated by the handshake, but still insist it answers our question.
            if (!acceptable(outBytes, r, ourId)) throw new IOException("upstream sent a mismatched TCP reply");
            return DnsWriter.rewriteId(r, clientId);
        }
    }

    /** Our ID, QR=1, and the same question we asked (DNS 0x20-style case differences allowed). */
    private static boolean acceptable(byte[] query, byte[] reply, int ourId) {
        if (reply.length < 12) return false;
        int replyId = readId(reply, 0);
        boolean isResponse = (reply[2] & 0x80) != 0;
        if (replyId != ourId || !isResponse) {
            System.err.printf("Dropped reply with wrong ID 0x%04x (expected 0x%04x)%n", replyId, ourId);
            return false;
        }
        if (!DnsWriter.sameQuestion(query, reply)) {
            System.err.println("Dropped reply that doesn't answer our question");
            return false;
        }
        return true;
    }

    private static int readId(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
    }

    private static List<InetSocketAddress> buildList(Config config) throws Exception {
        int port = config.getInt("upstream.port", 53);
        List<InetSocketAddress> list = new ArrayList<>();
        list.add(new InetSocketAddress(InetAddress.getByName(config.get("upstream.host", "1.1.1.1").trim()), port));
        for (String h : config.get("upstream.fallback", "").split(",")) {
            if (!h.isBlank()) list.add(new InetSocketAddress(InetAddress.getByName(h.trim()), port));
        }
        return list;
    }
}
