package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.protocol.DnsHeader;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DNS over TCP on the same port as UDP (RFC 1035 section 4.2.2, RFC 7766).
 *
 * Why it's needed: when an answer is too big for UDP we reply with TC=1 ("truncated"), and the
 * client is expected to ask again over TCP. Without a TCP listener those lookups (big TXT records,
 * DNSSEC answers, names with many addresses) simply fail.
 *
 * Wire format: every message is prefixed with a 2-byte length. A connection may carry several
 * queries one after another; we answer them in order.
 *
 * A TCP connection pins a thread, so a slow or idle client is a cheap way to exhaust the server
 * (Slowloris). Limits:
 *  - at most dns.tcp.maxConnections at once, and dns.tcp.maxConnectionsPerClient from one IP;
 *    extra connections are closed immediately
 *  - waiting for the next query: dns.tcp.idleTimeoutMs, then the connection is closed
 *  - once a query starts arriving, ALL of it must arrive within dns.tcp.messageTimeoutMs. A
 *    socket timeout alone applies per read(), so one byte every 9 s would keep it alive forever.
 *  - writing a reply must finish within dns.tcp.writeTimeoutMs. Java has no write timeout, so a
 *    watchdog closes the socket of a client that stopped reading (its send buffer is full).
 *  - the same Admission (per-client + global rate limit) as UDP, per query
 */
public class TcpDnsServer {
    private final Config config;
    private final QueryHandler handler;
    private final Admission admission;
    private final int idleTimeoutMs;
    private final long messageTimeoutNanos;
    private final long writeTimeoutNanos;
    private final int maxPerClient;
    private final ThreadPoolExecutor connections;
    private final ScheduledExecutorService watchdog;
    private final Map<String, Integer> perClient = new ConcurrentHashMap<>();   // open connections per IP
    private final Map<Socket, Long> writeDeadlines = new ConcurrentHashMap<>();   // nanoTime deadline
    private final AtomicLong refused = new AtomicLong();
    private final AtomicLong timedOut = new AtomicLong();
    private volatile ServerSocket server;

    public TcpDnsServer(Config config, QueryHandler handler, Admission admission) {
        this.config = config;
        this.handler = handler;
        this.admission = admission;
        this.idleTimeoutMs = config.getInt("dns.tcp.idleTimeoutMs", 10_000);
        this.messageTimeoutNanos = TimeUnit.MILLISECONDS.toNanos(config.getInt("dns.tcp.messageTimeoutMs", 2_000));
        this.writeTimeoutNanos = TimeUnit.MILLISECONDS.toNanos(config.getInt("dns.tcp.writeTimeoutMs", 5_000));
        this.maxPerClient = config.getInt("dns.tcp.maxConnectionsPerClient", 8);
        int max = config.getInt("dns.tcp.maxConnections", 64);
        // SynchronousQueue: no waiting room. If all threads are busy, the connection is refused now.
        this.connections = new ThreadPoolExecutor(max, max, 30, TimeUnit.SECONDS, new SynchronousQueue<>());
        this.connections.allowCoreThreadTimeOut(true);
        this.watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dns-tcp-watchdog");
            t.setDaemon(true);
            return t;
        });
    }

    /** Binds and starts accepting in a background thread. Returns the bound port. */
    public int start() throws IOException {
        int port = config.getInt("dns.port", 5300);
        String bind = config.get("dns.bind", "0.0.0.0").trim();
        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(bind, port), 50);
        Thread acceptor = new Thread(this::acceptLoop, "dns-tcp-accept");
        acceptor.setDaemon(true);
        acceptor.start();
        watchdog.scheduleWithFixedDelay(this::closeStuckWriters, 250, 250, TimeUnit.MILLISECONDS);
        System.out.println("DNS server listening on " + bind + ":" + server.getLocalPort() + " (TCP)");
        return server.getLocalPort();
    }

    private void acceptLoop() {
        ServerSocket s = server;
        while (!s.isClosed()) {
            try {
                Socket client = s.accept();
                String ip = client.getInetAddress().getHostAddress();
                int open = perClient.merge(ip, 1, Integer::sum);   // atomic per key
                if (open > maxPerClient) {                           // one IP can't take every slot
                    release(ip);
                    refuse(client);
                    continue;
                }
                try {
                    connections.execute(() -> {
                        try {
                            serve(client);
                        } finally {
                            release(ip);
                        }
                    });
                } catch (RejectedExecutionException full) {      // all connection slots taken
                    release(ip);
                    refuse(client);
                }
            } catch (IOException | RuntimeException e) {
                if (s.isClosed()) break;
                System.err.println("TCP accept error (continuing): " + e);
            }
        }
    }

    private void serve(Socket client) {
        String clientIp = client.getInetAddress().getHostAddress();
        try (client) {
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();
            while (true) {
                byte[] query = readMessage(client, in);
                if (query == null) return;                    // client done, or idle too long
                if (query.length < DnsHeader.SIZE) return;    // can't even hold a header
                if (!admission.admit(client.getInetAddress())) return;   // over the limit: hang up
                byte[] reply = handler.resolve(query, clientIp, QueryHandler.Transport.TCP).reply;
                if (reply == null) return;                    // unanswerable garbage: hang up
                byte[] framed = new byte[reply.length + 2];
                framed[0] = (byte) (reply.length >> 8);
                framed[1] = (byte) reply.length;
                System.arraycopy(reply, 0, framed, 2, reply.length);
                writeDeadlines.put(client, System.nanoTime() + writeTimeoutNanos);
                try {
                    out.write(framed);
                    out.flush();
                } finally {
                    writeDeadlines.remove(client);
                }
            }
        } catch (SocketTimeoutException e) {
            timedOut.incrementAndGet();                       // query trickled in too slowly
        } catch (IOException e) {
            // connection reset, or closed by the write watchdog - nothing to answer
        } catch (RuntimeException e) {
            System.err.println("Error handling TCP query from " + clientIp + ": " + e);
        }
    }

    /**
     * Reads one length-prefixed message. Waiting for its first byte uses the idle timeout (returns
     * null when it expires or the client closes); after that the whole message has to arrive
     * before one fixed deadline, however the bytes are spread out.
     */
    private byte[] readMessage(Socket s, InputStream in) throws IOException {
        s.setSoTimeout(idleTimeoutMs);
        int first;
        try {
            first = in.read();
        } catch (SocketTimeoutException idle) {
            return null;
        }
        if (first < 0) return null;
        long deadline = System.nanoTime() + messageTimeoutNanos;
        byte[] low = new byte[1];
        readFully(s, in, low, deadline);
        byte[] msg = new byte[(first << 8) | (low[0] & 0xFF)];
        readFully(s, in, msg, deadline);
        return msg;
    }

    private static void readFully(Socket s, InputStream in, byte[] buf, long deadline) throws IOException {
        int off = 0;
        while (off < buf.length) {
            long left = deadline - System.nanoTime();
            if (left <= 0) throw new SocketTimeoutException("query not received in time");
            s.setSoTimeout((int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(left)));
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) throw new EOFException("closed mid-message");
            off += n;
        }
    }

    /** Closing the socket makes the blocked write() throw, which frees the thread. */
    private void closeStuckWriters() {
        long now = System.nanoTime();
        writeDeadlines.forEach((socket, deadline) -> {
            if (now - deadline > 0 && writeDeadlines.remove(socket, deadline)) {
                timedOut.incrementAndGet();
                closeQuietly(socket);
            }
        });
    }

    private void release(String ip) {
        perClient.computeIfPresent(ip, (k, c) -> c <= 1 ? null : c - 1);   // drop the key at zero
    }

    private void refuse(Socket client) {
        refused.incrementAndGet();
        closeQuietly(client);
    }

    public void stop() {
        if (server != null) closeQuietly(server);
        watchdog.shutdownNow();
        connections.shutdownNow();
    }

    public long refusedConnections() { return refused.get(); }
    public long timedOutConnections() { return timedOut.get(); }
    int openConnectionsFrom(String ip) { return perClient.getOrDefault(ip, 0); }

    private static void closeQuietly(AutoCloseable c) {
        try { c.close(); } catch (Exception ignored) { /* closing anyway */ }
    }
}
