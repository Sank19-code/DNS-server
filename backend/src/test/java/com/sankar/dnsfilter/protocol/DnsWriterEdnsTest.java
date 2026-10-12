package com.sankar.dnsfilter.protocol;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/** EDNS(0) detection, truncated replies and question matching. */
public class DnsWriterEdnsTest {

    /** Appends an OPT record (RFC 6891) advertising udpSize, with the DO bit if dnssecOk. */
    public static byte[] withOpt(byte[] query, int udpSize, boolean dnssecOk) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(query, 0, query.length);
        out.write(0);                                            // root name
        out.write(0); out.write(DnsQuestion.TYPE_OPT);
        out.write((udpSize >> 8) & 0xFF); out.write(udpSize & 0xFF);
        out.write(0); out.write(0);                              // ext-rcode, version
        out.write(dnssecOk ? 0x80 : 0); out.write(0);            // DO | Z
        out.write(0); out.write(0);                              // rdlength 0
        byte[] b = out.toByteArray();
        b[11] = (byte) (b[11] + 1);                              // ARCOUNT + 1
        return b;
    }

    private static final byte[] PLAIN = DnsWriter.buildQuery(1, "example.com", DnsQuestion.TYPE_A);

    @Test
    void detectsEdnsSizeAndDoBit() {
        DnsWriter.Edns none = DnsWriter.edns(PLAIN, PLAIN.length);
        assertFalse(none.present);
        assertEquals(512, none.udpSize);

        byte[] q = withOpt(PLAIN, 1232, true);
        DnsWriter.Edns e = DnsWriter.edns(q, q.length);
        assertTrue(e.present);
        assertEquals(1232, e.udpSize);
        assertTrue(e.dnssecOk);

        byte[] tiny = withOpt(PLAIN, 100, false);
        assertEquals(512, DnsWriter.edns(tiny, tiny.length).udpSize, "sizes below 512 are treated as 512");
    }

    @Test
    void malformedOptIsIgnored() {
        byte[] q = withOpt(PLAIN, 4096, false);
        byte[] cut = java.util.Arrays.copyOf(q, q.length - 5);
        assertFalse(DnsWriter.edns(cut, cut.length).present);
    }

    @Test
    void truncatedResponseHasTcAndQuestionOnly() {
        byte[] r = DnsWriter.buildTruncatedResponse(PLAIN, PLAIN.length, DnsHeader.RCODE_NOERROR);
        DnsMessage m = new DnsParser(r).parse();
        assertTrue(m.header.isTruncated());
        assertTrue(m.header.isResponse());
        assertEquals(1, m.questions.size());
        assertEquals(0, m.answers.size());
    }

    @Test
    void sameQuestionIgnoresCaseButNotType() {
        byte[] reply = DnsWriter.buildNullRouteResponse(PLAIN, PLAIN.length, 60);
        assertTrue(DnsWriter.sameQuestion(PLAIN, reply));

        byte[] mixedCase = DnsWriter.buildQuery(1, "ExAmPlE.CoM", DnsQuestion.TYPE_A);
        assertTrue(DnsWriter.sameQuestion(mixedCase, reply));

        byte[] aaaa = DnsWriter.buildQuery(1, "example.com", DnsQuestion.TYPE_AAAA);
        assertFalse(DnsWriter.sameQuestion(aaaa, reply));

        byte[] other = DnsWriter.buildQuery(1, "example.org", DnsQuestion.TYPE_A);
        assertFalse(DnsWriter.sameQuestion(other, reply));

        // error replies may leave the question out
        byte[] refused = {0, 1, (byte) 0x81, 0x05, 0, 0, 0, 0, 0, 0, 0, 0};
        assertTrue(DnsWriter.sameQuestion(PLAIN, refused));
        byte[] emptyNoError = {0, 1, (byte) 0x81, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
        assertFalse(DnsWriter.sameQuestion(PLAIN, emptyNoError));
    }
}
