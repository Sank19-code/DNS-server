package com.sankar.dnsfilter.protocol;

import com.sankar.dnsfilter.FakeUpstream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DnsWriterTest {

    @Test
    void adjustTtlDecrementsEveryRecordAndFloorsAtZero() {
        byte[] q = DnsWriter.buildQuery(1, "nx.example.com", DnsQuestion.TYPE_A);
        byte[] r = FakeUpstream.nxWithSoa(q);           // SOA authority record, TTL 900

        DnsMessage aged = new DnsParser(DnsWriter.adjustTtl(r, 100)).parse();
        assertEquals(800, aged.authorities.get(0).ttl);

        DnsMessage expired = new DnsParser(DnsWriter.adjustTtl(r, 5000)).parse();
        assertEquals(0, expired.authorities.get(0).ttl);

        // original untouched
        assertEquals(900, new DnsParser(r).parse().authorities.get(0).ttl);
    }

    @Test
    void adjustTtlHandlesCompressedNamesAcrossAnswers() {
        byte[] q = DnsWriter.buildQuery(1, "example.com", DnsQuestion.TYPE_A);
        byte[] r = DnsWriter.buildNullRouteResponse(q, q.length, 300);
        DnsMessage m = new DnsParser(DnsWriter.adjustTtl(r, 45)).parse();
        assertEquals(255, m.answers.get(0).ttl);
        assertEquals("example.com", m.answers.get(0).name);
    }

    @Test
    void adjustTtlReturnsOriginalOnGarbage() {
        byte[] junk = {0, 1, (byte) 0x81, (byte) 0x80, 0, 1, 0, 5, 0, 0, 0, 0, 3, 'a', 'b'};
        assertArrayEquals(junk, DnsWriter.adjustTtl(junk, 10));
    }

    @Test
    void prepareCachedReplyUsesNewIdAndClientCasing() {
        byte[] first = DnsWriter.buildQuery(0x1111, "example.com", DnsQuestion.TYPE_A);
        byte[] cached = DnsWriter.buildNullRouteResponse(first, first.length, 300);

        byte[] second = DnsWriter.buildQuery(0xBEEF, "ExAmPlE.CoM", DnsQuestion.TYPE_A);
        byte[] reply = DnsWriter.prepareCachedReply(cached, second, second.length);

        DnsMessage m = new DnsParser(reply).parse();
        assertEquals(0xBEEF, m.header.id);
        assertEquals("ExAmPlE.CoM", m.questions.get(0).name);
        assertEquals(1, m.answers.size());
    }
}
