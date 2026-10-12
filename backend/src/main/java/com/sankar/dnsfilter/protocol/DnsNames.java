package com.sankar.dnsfilter.protocol;

/**
 * Helpers for domain names as text.
 *
 * DNS compares names case-insensitively for ASCII A-Z only (RFC 4343). Java's toLowerCase() is
 * wrong for that in two ways: it depends on the machine's language (in Turkish, "I" becomes a
 * dotless "ı", so "ADS.EXAMPLE" would no longer match "ads.example"), and it also folds non-ASCII
 * letters, which would make two different names share one cache key. So we fold A-Z by hand.
 *
 * Names come out of DnsParser in presentation format: a '.' or '\' INSIDE a label is escaped as
 * "\." or "\\", so the text maps back to exactly one name on the wire. firstDot() skips escapes.
 */
public final class DnsNames {
    private DnsNames() {}

    /** Lower-cases A-Z only; everything else is left alone. */
    public static String lower(String s) {
        int i = 0;
        while (i < s.length() && (s.charAt(i) < 'A' || s.charAt(i) > 'Z')) i++;
        if (i == s.length()) return s;                    // common case: already lower-case
        char[] c = s.toCharArray();
        for (; i < c.length; i++) if (c[i] >= 'A' && c[i] <= 'Z') c[i] += 32;
        return new String(c);
    }

    public static boolean equalsIgnoreCase(String a, String b) {
        return a.length() == b.length() && lower(a).equals(lower(b));
    }

    /** Index of the first label separator - a '.' that isn't escaped - or -1 for a single label. */
    public static int firstDot(String name) {
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '\\') i++;                            // skip the escaped character
            else if (c == '.') return i;
        }
        return -1;
    }
}
