package com.sankar.dnsfilter.resolver;

import com.sankar.dnsfilter.FakeUpstream;
import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsWriter;
import org.junit.jupiter.api.Test;

import java.net.SocketTimeoutException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UpstreamResolverTest {

    private static final byte[] QUERY = DnsWriter.buildQuery(0x4242, "example.com", DnsQuestion.TYPE_A);

    @Test
    void ignoresSpoofedWrongIdReply() throws Exception {
        try (FakeUpstream up = new FakeUpstream()) {
            up.mode = FakeUpstream.Mode.WRONG_ID_FIRST;
            UpstreamResolver r = new UpstreamResolver(List.of(up.address()), 1000);
            DnsMessage m = new DnsParser(r.forward(QUERY)).parse();
            assertEquals(0x4242, m.header.id);
            assertEquals("0.0.0.0", m.answers.get(0).toString().split(" ")[3], "spoofed 0.0.0.66 must be ignored");
        }
    }

    @Test
    void timesOutWhenUpstreamIsSilent() throws Exception {
        try (FakeUpstream up = new FakeUpstream()) {
            up.mode = FakeUpstream.Mode.SILENT;
            UpstreamResolver r = new UpstreamResolver(List.of(up.address()), 200);
            long t = System.currentTimeMillis();
            assertThrows(SocketTimeoutException.class, () -> r.forward(QUERY));
            assertTrue(System.currentTimeMillis() - t < 1000);
        }
    }

    @Test
    void fallsBackToSecondUpstream() throws Exception {
        try (FakeUpstream dead = new FakeUpstream(); FakeUpstream alive = new FakeUpstream()) {
            dead.mode = FakeUpstream.Mode.SILENT;
            UpstreamResolver r = new UpstreamResolver(List.of(dead.address(), alive.address()), 200);
            DnsMessage m = new DnsParser(r.forward(QUERY)).parse();
            assertEquals(1, m.answers.size());
            assertEquals(1, dead.queries.get());
            assertEquals(1, alive.queries.get());
        }
    }
}
