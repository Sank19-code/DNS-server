package com.sankar.dnsfilter.protocol;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class DnsParserTest {

    // Real query for "example.com" type A, ID 0x1234, RD=1
    private static final byte[] QUERY = bytes(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
            0x00, 0x01, 0x00, 0x01
    );

    /**
     * Response for www.example.com A, shaped like a real resolver reply:
     *   answer 1: www.example.com  CNAME example.com   (name = pointer 0xC00C, rdata = pointer 0xC010)
     *   answer 2: example.com      A     93.184.216.34 (name = pointer 0xC010), TTL 300
     */
    private static final byte[] RESPONSE = bytes(
            0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            // question @12: [3]www @16: [7]example[3]com[0]
            0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // answer 1: CNAME, TTL 3600, rdlength 2, rdata = pointer to offset 16
            0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x02, 0xC0, 0x10,
            // answer 2: A, TTL 300, rdlength 4
            0xC0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 93, 184, 216, 34
    );

    @Test
    void parsesSimpleQuery() {
        DnsMessage m = new DnsParser(QUERY, QUERY.length).parse();
        assertEquals(0x1234, m.header.id);
        assertFalse(m.header.isResponse());
        assertTrue(m.header.isRecursionDesired());
        assertEquals(1, m.header.qdCount);
        assertEquals("example.com", m.questions.get(0).name);
        assertEquals(DnsQuestion.TYPE_A, m.questions.get(0).type);
        assertEquals(1, m.questions.get(0).qclass);
    }

    @Test
    void parsesResponseWithCompressionPointers() {
        DnsMessage m = new DnsParser(RESPONSE).parse();
        assertTrue(m.header.isResponse());
        assertEquals(DnsHeader.RCODE_NOERROR, m.header.getRcode());
        assertEquals("www.example.com", m.questions.get(0).name);
        assertEquals(2, m.answers.size());

        DnsRecord cname = m.answers.get(0);
        assertEquals("www.example.com", cname.name);
        assertEquals(DnsQuestion.TYPE_CNAME, cname.type);
        assertEquals("example.com", cname.rdataText);
        assertEquals(3600, cname.ttl);

        DnsRecord a = m.answers.get(1);
        assertEquals("example.com", a.name);
        assertEquals(300, a.ttl);
        assertArrayEquals(new byte[]{93, (byte) 184, (byte) 216, 34}, a.rdata);
        assertEquals("example.com 300 A 93.184.216.34", a.toString());

        assertEquals(300, m.minAnswerTtl());
    }

    @Test
    void readsUnsigned32BitTtl() {
        byte[] r = RESPONSE.clone();
        int ttlOffset = RESPONSE.length - 10; // answer 2 TTL
        r[ttlOffset] = (byte) 0xFF; r[ttlOffset + 1] = (byte) 0xFF;
        r[ttlOffset + 2] = (byte) 0xFF; r[ttlOffset + 3] = (byte) 0xFF;
        assertEquals(0xFFFFFFFFL, new DnsParser(r).parse().answers.get(1).ttl);
    }

    @Test
    void truncatedPacketThrowsInsteadOfCrashing() {
        for (int len = 0; len < QUERY.length; len++) {
            byte[] cut = Arrays.copyOf(QUERY, len);
            assertThrows(DnsParseException.class, () -> new DnsParser(cut).parse(), "length " + len);
        }
        for (int len = 0; len < RESPONSE.length; len++) {
            byte[] cut = Arrays.copyOf(RESPONSE, len);
            assertThrows(DnsParseException.class, () -> new DnsParser(cut).parse(), "length " + len);
        }
    }

    @Test
    void compressionPointerLoopIsRejected() {
        // question name is a pointer to itself at offset 12
        byte[] loop = bytes(
                0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01);
        assertThrows(DnsParseException.class, () -> new DnsParser(loop).parse());
    }

    @Test
    void forwardPointerIsRejected() {
        byte[] fwd = bytes(
                0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xC0, 0x20, 0x00, 0x01, 0x00, 0x01);
        assertThrows(DnsParseException.class, () -> new DnsParser(fwd).parse());
    }

    @Test
    void lyingQuestionCountThrows() {
        byte[] q = QUERY.clone();
        q[5] = 5; // claims 5 questions, contains 1
        assertThrows(DnsParseException.class, () -> new DnsParser(q).parse());
    }

    @Test
    void blockedResponseIsNxdomainWithSameIdAndQuestion() {
        byte[] resp = DnsWriter.buildBlockedResponse(QUERY, QUERY.length);
        DnsMessage m = new DnsParser(resp).parse();
        assertEquals(0x1234, m.header.id);
        assertTrue(m.header.isResponse());
        assertTrue(m.header.isRecursionDesired());
        assertEquals(DnsHeader.RCODE_NXDOMAIN, m.header.getRcode());
        assertEquals("example.com", m.questions.get(0).name);
        assertTrue(m.answers.isEmpty());
        assertEquals(QUERY.length, resp.length);
    }

    @Test
    void nullRouteResponseAnswersZeroAddress() {
        byte[] resp = DnsWriter.buildNullRouteResponse(QUERY, QUERY.length, 60);
        DnsMessage m = new DnsParser(resp).parse();
        assertEquals(DnsHeader.RCODE_NOERROR, m.header.getRcode());
        assertEquals(1, m.answers.size());
        assertEquals("example.com 60 A 0.0.0.0", m.answers.get(0).toString());
    }

    @Test
    void buildQueryRoundTrips() {
        byte[] q = DnsWriter.buildQuery(0x4242, "ads.Tracker.example.org", DnsQuestion.TYPE_AAAA);
        DnsMessage m = new DnsParser(q).parse();
        assertEquals(0x4242, m.header.id);
        assertEquals("ads.Tracker.example.org", m.questions.get(0).name);
        assertEquals(DnsQuestion.TYPE_AAAA, m.questions.get(0).type);
    }

    @Test
    void rewriteIdChangesOnlyTheId() {
        byte[] r = DnsWriter.rewriteId(RESPONSE, 0x0102);
        assertEquals(0x0102, new DnsParser(r).parse().header.id);
        assertArrayEquals(Arrays.copyOfRange(RESPONSE, 2, RESPONSE.length), Arrays.copyOfRange(r, 2, r.length));
    }

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }
}
