package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.FakeUpstream;
import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsWriter;
import com.sankar.dnsfilter.protocol.DnsWriterEdnsTest;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.stats.StatsCollector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** The real UDP and TCP listeners on random localhost ports, talking to a fake upstream. */
class DnsServerTest {

    private FakeUpstream upstream;
    private StatsCollector stats;
    private DnsServer udp;
    private TcpDnsServer tcp;
    private Thread udpThread;
    private int port;

    @BeforeEach
    void setUp() throws Exception {
        upstream = new FakeUpstream();
        Blocklist blocklist = new Blocklist();
        blocklist.add("doubleclick.net", "ads");
        stats = new StatsCollector();
        QueryHandler.Settings s = new QueryHandler.Settings();
        s.logQueries = false;
        QueryHandler handler = new QueryHandler(blocklist, new DnsCache(100),
                new UpstreamResolver(List.of(upstream.address()), 1000), stats, s);

        udp = new DnsServer(config("dns.port=0\ndns.bind=127.0.0.1\n"), handler, stats);
        port = udp.bind();
        udpThread = new Thread(udp::serve, "test-dns-udp");
        udpThread.start();
        // short TCP limits so the Slowloris tests run in well under a second each
        tcp = new TcpDnsServer(config("dns.port=" + port + "\ndns.bind=127.0.0.1\n"
                + "dns.tcp.maxConnectionsPerClient=3\ndns.tcp.idleTimeoutMs=1500\n"
                + "dns.tcp.messageTimeoutMs=300\ndns.tcp.writeTimeoutMs=300\n"),
                handler, Admission.from(config(""), stats));
        tcp.start();
    }

    @AfterEach
    void tearDown() throws Exception {
        udp.stop();
        tcp.stop();
        udpThread.join(3000);
        upstream.close();
    }

    private static Config config(String props) throws Exception {
        Path f = Files.createTempFile("dns", ".properties");
        Files.writeString(f, props);
        return Config.load(f.toString());
    }

    private byte[] askUdp(byte[] query) throws Exception {
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(3000);
            s.send(new DatagramPacket(query, query.length, InetAddress.getLoopbackAddress(), port));
            byte[] buf = new byte[65_535];
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            s.receive(p);
            return Arrays.copyOf(buf, p.getLength());
        }
    }

    private byte[] askTcp(byte[] query) throws Exception {
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), port)) {
            s.setSoTimeout(3000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            out.writeShort(query.length);
            out.write(query);
            out.flush();
            DataInputStream in = new DataInputStream(s.getInputStream());
            return in.readNBytes(in.readUnsignedShort());
        }
    }

    @Test
    void answersOverUdp() throws Exception {
        DnsMessage m = new DnsParser(askUdp(DnsWriter.buildQuery(5, "example.com", DnsQuestion.TYPE_A))).parse();
        assertEquals(5, m.header.id);
        assertEquals(1, m.answers.size());
        DnsMessage blocked = new DnsParser(askUdp(DnsWriter.buildQuery(6, "x.doubleclick.net", DnsQuestion.TYPE_A))).parse();
        assertEquals(DnsHeader.RCODE_NXDOMAIN, blocked.header.getRcode());
    }

    @Test
    void bigAnswerIsTruncatedOverUdpAndWholeOverTcp() throws Exception {
        upstream.padding = 700;                       // reply ~750 bytes > 512
        byte[] query = DnsWriter.buildQuery(7, "big.example.com", DnsQuestion.TYPE_A);

        DnsMessage overUdp = new DnsParser(askUdp(query)).parse();
        assertTrue(overUdp.header.isTruncated(), "a plain UDP client only accepts 512 bytes");
        assertEquals(0, overUdp.answers.size());
        assertEquals("big.example.com", overUdp.questions.get(0).name);

        byte[] whole = askTcp(query);
        assertTrue(whole.length > 512);
        DnsMessage overTcp = new DnsParser(whole).parse();
        assertFalse(overTcp.header.isTruncated());
        assertEquals(7, overTcp.header.id);
        assertEquals(1, overTcp.answers.size());
    }

    @Test
    void ednsClientGetsTheBigAnswerOverUdp() throws Exception {
        upstream.padding = 700;
        byte[] query = DnsWriterEdnsTest.withOpt(DnsWriter.buildQuery(8, "big.example.com", DnsQuestion.TYPE_A), 1232, false);
        DnsMessage m = new DnsParser(askUdp(query)).parse();
        assertFalse(m.header.isTruncated(), "advertised 1232 bytes, the ~750-byte reply fits");
        assertEquals(1, m.answers.size());
    }

    @Test
    void tcpConnectionCarriesSeveralQueries() throws Exception {
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), port)) {
            s.setSoTimeout(3000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            DataInputStream in = new DataInputStream(s.getInputStream());
            for (int id = 1; id <= 3; id++) {
                byte[] q = DnsWriter.buildQuery(id, "multi" + id + ".example.com", DnsQuestion.TYPE_A);
                out.writeShort(q.length);
                out.write(q);
                out.flush();
                assertEquals(id, new DnsParser(in.readNBytes(in.readUnsignedShort())).parse().header.id);
            }
        }
    }

    @Test
    void ednsSizeAboveMaxUdpSizeIsNotHonoured() throws Exception {
        upstream.padding = 2000;                      // ~2 KB reply
        byte[] query = DnsWriterEdnsTest.withOpt(DnsWriter.buildQuery(3, "huge.example.com", DnsQuestion.TYPE_A), 4096, false);
        DnsMessage m = new DnsParser(askUdp(query)).parse();
        assertTrue(m.header.isTruncated(), "client asked for 4096, but we cap UDP at 1232 (amplification)");
    }

    @Test
    void oneClientCannotTakeEveryTcpSlot() throws Exception {
        Socket[] held = new Socket[3];
        for (int i = 0; i < 3; i++) held[i] = new Socket(InetAddress.getLoopbackAddress(), port);
        try (Socket fourth = new Socket(InetAddress.getLoopbackAddress(), port)) {
            fourth.setSoTimeout(2000);
            assertEquals(-1, fourth.getInputStream().read(), "connection over the per-client cap is closed");
        } finally {
            for (Socket s : held) s.close();
        }
        assertTrue(tcp.refusedConnections() >= 1);
        // slots are given back: a new connection works again
        waitUntil(() -> tcp.openConnectionsFrom("127.0.0.1") == 0);
        assertEquals(1, new DnsParser(askTcp(DnsWriter.buildQuery(4, "after.example.com", DnsQuestion.TYPE_A))).parse().answers.size());
    }

    @Test
    void slowDripQueryIsCutOffAtTheMessageDeadline() throws Exception {
        byte[] q = DnsWriter.buildQuery(5, "drip.example.com", DnsQuestion.TYPE_A);
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), port)) {
            s.setSoTimeout(3000);
            OutputStream out = s.getOutputStream();
            out.write(0);
            out.write(q.length);                      // length prefix, then one byte every 100 ms
            try {
                for (int i = 0; i < 8; i++) {         // 800 ms of dripping: well past the 300 ms deadline,
                    out.write(q[i]);                  // though each gap is under any per-read timeout
                    out.flush();
                    Thread.sleep(100);
                }
            } catch (IOException closedByServer) {
                // expected once the server gives up
            }
            int r;
            try {
                r = s.getInputStream().read();
            } catch (IOException reset) {
                r = -1;
            }
            assertEquals(-1, r, "server hung up without answering");
        }
        assertTrue(tcp.timedOutConnections() >= 1);
    }

    @Test
    void clientThatStopsReadingRepliesIsDisconnected() throws Exception {
        upstream.padding = 60_000;                    // ~60 KB per reply
        byte[] q = DnsWriter.buildQuery(6, "fat.example.com", DnsQuestion.TYPE_A);
        try (Socket s = new Socket()) {
            s.setReceiveBufferSize(4096);             // small window: our writes block quickly
            s.connect(new java.net.InetSocketAddress(InetAddress.getLoopbackAddress(), port));
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            try {
                for (int i = 0; i < 200; i++) {       // ask, never read
                    out.writeShort(q.length);
                    out.write(q);
                    out.flush();
                }
            } catch (IOException closedByServer) {
                // fine: the server may already have dropped us
            }
            waitUntil(() -> tcp.timedOutConnections() >= 1);
        }
    }

    private static void waitUntil(java.util.function.BooleanSupplier condition) throws Exception {
        long end = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) fail("condition not met within 5 s");
            Thread.sleep(20);
        }
    }

    @Test
    void garbageDoesNotStopTheServerAndStopDoes() throws Exception {
        try (DatagramSocket s = new DatagramSocket()) {
            s.send(new DatagramPacket(new byte[]{1, 2, 3}, 3, InetAddress.getLoopbackAddress(), port));
        }
        assertEquals(1, new DnsParser(askUdp(DnsWriter.buildQuery(9, "still.example.com", DnsQuestion.TYPE_A))).parse().answers.size());

        udp.stop();
        udpThread.join(3000);
        assertFalse(udpThread.isAlive(), "stop() ends the receive loop");
    }
}
