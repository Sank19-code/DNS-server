package com.sankar.dnsfilter;

import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsWriter;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A fake upstream DNS server on 127.0.0.1 for tests. Answers every query with 0.0.0.0
 * (TTL = answerTtl), or NXDOMAIN + SOA for names starting with "nx", and can misbehave:
 * stay silent, or send a spoofed wrong-ID reply before the real one.
 */
public class FakeUpstream implements AutoCloseable {
    public enum Mode { NORMAL, SILENT, WRONG_ID_FIRST }

    private final DatagramSocket socket;
    private final Thread thread;
    public final AtomicInteger queries = new AtomicInteger();
    public volatile Mode mode = Mode.NORMAL;
    public volatile long answerTtl = 300;

    public FakeUpstream() throws SocketException {
        socket = new DatagramSocket(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        thread = new Thread(this::loop, "fake-upstream");
        thread.setDaemon(true);
        thread.start();
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
                queries.incrementAndGet();
                byte[] q = Arrays.copyOf(p.getData(), p.getLength());
                if (mode == Mode.SILENT) continue;
                byte[] reply = isNx(q) ? nxWithSoa(q) : DnsWriter.buildNullRouteResponse(q, q.length, answerTtl);
                if (mode == Mode.WRONG_ID_FIRST) {
                    int id = ((q[0] & 0xFF) << 8) | (q[1] & 0xFF);
                    byte[] spoof = DnsWriter.rewriteId(reply, (id + 1) & 0xFFFF);
                    spoof[spoof.length - 1] = 66; // would answer 0.0.0.66 if accepted
                    socket.send(new DatagramPacket(spoof, spoof.length, p.getSocketAddress()));
                }
                socket.send(new DatagramPacket(reply, reply.length, p.getSocketAddress()));
            } catch (Exception e) {
                if (!socket.isClosed()) e.printStackTrace();
            }
        }
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
    }
}
