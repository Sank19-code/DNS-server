package com.sankar.dnsfilter.protocol;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DnsParserTest {

    // Real query for "example.com" type A, ID 0x1234, RD=1
    private static final byte[] QUERY = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
            0x00, 0x01, 0x00, 0x01
    };

    @Test
    @Disabled("Enable on Day 1 once DnsParser is implemented")
    void parsesSimpleQuery() {
        DnsMessage m = new DnsParser(QUERY, QUERY.length).parse();
        assertEquals(0x1234, m.header.id);
        assertEquals(1, m.header.qdCount);
        assertEquals("example.com", m.questions.get(0).name);
        assertEquals(DnsQuestion.TYPE_A, m.questions.get(0).type);
    }
}
