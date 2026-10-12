package com.sankar.dnsfilter;

import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsWriter;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A fake upstream DNS server on 127.0.0.1 for tests, on UDP and TCP (same port). Answers every
 * query with 0.0.0.0 (TTL = answerTtl), or NXDOMAIN + SOA for names starting with "nx", and can
 * misbehave: stay silent, send a spoofed wrong-ID or wrong-question reply before the real one, or
 * answer UDP with a truncated (TC=1) reply so the client has to come back over TCP.
 */
public class FakeUpstream implements AutoCloseable {
    public enum Mode { NORMAL, SILENT, WRONG_ID_FIRST, WRONG_QUESTION_FIRST, DROP_FIRST, TRUNCATE_UDP }

    private final DatagramSocket socket;
    private final ServerSocket tcp;
    public final AtomicInteger queries = new AtomicInteger();
    public final AtomicInteger tcpQueries = new AtomicInteger();
    /** Transaction ID of the last query received (to check the resolver picks its own). */
    public volatile int lastId = -1;
    public volatile Mode mode = Mode.NORMAL;
    public volatile long answerTtl = 300;
    /** Extra bytes of padding appended to every answer (to make replies larger than 512 bytes). */
    public volatile int padding = 0;

    public FakeUpstream() throws Exception {
        socket = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        tcp = new ServerSocket(socket.getLocalPort(), 50, InetAddress.getLoopbackAddress());
        Thread udpThread = new Thread(this::loop, "fake-upstream-udp");
        udpThread.setDaemon(true);
        udpThread.start();
        Thread tcpThread = new Thread(this::tcpLoop, "fake-upstream-tcp");
        tcpThread.setDaemon(true);
        tcpThread.start();
    }

    public InetSocketAddress address() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), socket.getLocalPort());
    }

    private void loop() {
        byte[] buf = new byte[4096];
        while (!socket.isClosed()) {
            try {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                socket.receive(p);
                int n = queries.incrementAndGet();
                byte[] q = Arrays.copyOf(p.getData(), p.getLength());
                lastId = ((q[0] & 0xFF) << 8) | (q[1] & 0xFF);
                if (mode == Mode.SILENT) continue;
                if (mode == Mode.DROP_FIRST && n == 1) continue;   // simulate one lost packet
                byte[] reply = answer(q);
                if (mode == Mode.TRUNCATE_UDP) {
                    reply = DnsWriter.buildTruncatedResponse(q, q.length, DnsHeader.RCODE_NOERROR);
                }
                if (mode == Mode.WRONG_ID_FIRST) {
                    byte[] spoof = DnsWriter.rewriteId(reply, (lastId + 1) & 0xFFFF);
                    spoof[spoof.length - 1] = 66; // would answer 0.0.0.66 if accepted
                    socket.send(new DatagramPacket(spoof, spoof.length, p.getSocketAddress()));
                }
                if (mode == Mode.WRONG_QUESTION_FIRST) {
                    byte[] other = DnsWriter.buildQuery(lastId, "other.example", 1);
                    byte[] spoof = DnsWriter.buildNullRouteResponse(other, other.length, answerTtl);
                    spoof[spoof.length - 1] = 66; // right ID, wrong question
                    socket.send(new DatagramPacket(spoof, spoof.length, p.getSocketAddress()));
                }
                socket.send(new DatagramPacket(reply, reply.length, p.getSocketAddress()));
            } catch (Exception e) {
                if (!socket.isClosed()) e.printStackTrace();
            }
        }
    }

    private void tcpLoop() {
        while (!tcp.isClosed()) {
            try (Socket s = tcp.accept()) {
                tcpQueries.incrementAndGet();
                DataInputStream in = new DataInputStream(s.getInputStream());
                byte[] q = in.readNBytes(in.readUnsignedShort());
                lastId = ((q[0] & 0xFF) << 8) | (q[1] & 0xFF);
                if (mode == Mode.SILENT) continue;
                byte[] reply = answer(q);
                DataOutputStream out = new DataOutputStream(s.getOutputStream());
                out.writeShort(reply.length);
                out.write(reply);
                out.flush();
            } catch (Exception e) {
                if (!tcp.isClosed()) e.printStackTrace();
            }
        }
    }

    private byte[] answer(byte[] q) {
        byte[] reply = isNx(q) ? nxWithSoa(q) : DnsWriter.buildNullRouteResponse(q, q.length, answerTtl);
        if (padding <= 0) return reply;
        // pad with a TXT-ish additional record so the reply gets big
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(reply, 0, reply.length);
        out.write(0);                                         // root name
        out.write(0); out.write(16); out.write(0); out.write(1); // TXT IN
        out.write(0); out.write(0); out.write(0); out.write(60); // TTL 60
        out.write((padding >> 8) & 0xFF); out.write(padding & 0xFF);
        out.write(new byte[padding], 0, padding);
        byte[] r = out.toByteArray();
        r[11] = (byte) (r[11] + 1);                           // ARCOUNT + 1
        return r;
    }

    private static boolean isNx(byte[] q) {
        return q.length > 14 && q[13] == 'n' && q[14] == 'x';
    }

    /** NXDOMAIN with an SOA (TTL 900) in the authority section, like real resolvers send. */
    public static byte[] nxWithSoa(byte[] q) {
        byte[] base = DnsWriter.buildErrorResponse(q, q.length, DnsHeader.RCODE_NXDOMAIN);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(base, 0, base.length);
        byte[] soa = {
                (byte) 0xC0, 0x0C,             // owner name -> question name
                0x00, 0x06, 0x00, 0x01,        // SOA, IN
                0x00, 0x00, 0x03, (byte) 0x84, // TTL 900
                0x00, 0x16,                    // rdlength 22
                0x00, 0x00,                    // mname = root, rname = root
                0, 0, 0, 1,  0, 0, 0, 2,  0, 0, 0, 3,  0, 0, 0, 4,  0, 0, 0, 60 // serial..minimum
        };
        out.write(soa, 0, soa.length);
        byte[] r = out.toByteArray();
        r[9] = 1; // NSCOUNT = 1
        return r;
    }

    @Override
    public void close() {
        socket.close();
        try { tcp.close(); } catch (Exception ignored) { /* closing */ }
    }
}
