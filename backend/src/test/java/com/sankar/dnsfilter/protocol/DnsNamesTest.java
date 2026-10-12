package com.sankar.dnsfilter.protocol;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class DnsNamesTest {

    @Test
    void dotsAndBackslashesInsideALabelAreEscaped() {
        // [10]www.google[3]com[0] is ONE label "www.google" plus "com", not www / google / com
        byte[] q = {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                10, 'w', 'w', 'w', '.', 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
        assertEquals("www\\.google.com", new DnsParser(q).parseQuery().questions.get(0).name);

        byte[] slash = {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', '\\', 'b', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
        assertEquals("a\\\\b.com", new DnsParser(slash).parseQuery().questions.get(0).name);
    }

    @Test
    void firstDotSkipsEscapedDots() {
        assertEquals(3, DnsNames.firstDot("www.google.com"));
        assertEquals(11, DnsNames.firstDot("www\\.google.com"));   // w w w \ . g o o g l e [.]
        assertEquals(-1, DnsNames.firstDot("com"));
        assertEquals(-1, DnsNames.firstDot("a\\.b"));
    }

    @Test
    void lowerFoldsAsciiOnlyWhateverTheLocale() {
        Locale before = Locale.getDefault();
        Locale.setDefault(new Locale("tr", "TR"));
        try {
            assertEquals("ads.linkedin.com", DnsNames.lower("ADS.LINKEDIN.COM"));
        } finally {
            Locale.setDefault(before);
        }
        // non-ASCII bytes stay distinct: DNS case-insensitivity is A-Z only (RFC 4343)
        assertEquals("Àb", DnsNames.lower("ÀB"));
        assertTrue(DnsNames.equalsIgnoreCase("ExAmPlE.com", "example.COM"));
        assertFalse(DnsNames.equalsIgnoreCase("À.com", "à.com"));
    }
}
