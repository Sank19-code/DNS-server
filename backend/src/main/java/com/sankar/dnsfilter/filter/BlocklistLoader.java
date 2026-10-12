package com.sankar.dnsfilter.filter;

import com.sankar.dnsfilter.protocol.DnsNames;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Reads blocklist files. Supports the three formats you'll find online:
 *   plain:      doubleclick.net
 *   hosts file: 0.0.0.0 doubleclick.net   (one IP, then one or more names)
 *   adblock:    ||doubleclick.net^         (domain-anchored rules only)
 * Ignores blank lines, # and ! comments, and placeholder host names like "localhost".
 */
public class BlocklistLoader {

    /** Lowercase LDH labels, 1-63 chars each, at least two labels, max 253 chars. */
    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$");

    /** Entries every hosts file contains that must never be treated as blocked domains. */
    private static final Set<String> HOSTS_NOISE = Set.of(
            "localhost", "localhost.localdomain", "local", "broadcasthost",
            "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
            "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0");

    public static List<String> load(Path file) throws IOException {
        return parse(Files.readAllLines(file, StandardCharsets.UTF_8));
    }

    public static List<String> parse(List<String> lines) {
        List<String> domains = new ArrayList<>();
        for (String raw : lines) {
            String line = raw;
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            line = line.trim();
            if (line.isEmpty() || line.startsWith("!") || line.startsWith("[")) continue;

            if (line.startsWith("||")) {                       // adblock: ||example.com^
                int end = line.indexOf('^');
                if (end < 0 || end != line.length() - 1) continue; // skip rules with paths/options
                add(domains, line.substring(2, end));
                continue;
            }

            String[] tokens = line.split("\\s+");
            if (tokens.length == 1) {                           // plain: example.com
                add(domains, tokens[0]);
            } else if (looksLikeIp(tokens[0])) {                // hosts: 0.0.0.0 a.com b.com
                for (int i = 1; i < tokens.length; i++) add(domains, tokens[i]);
            }
        }
        return domains;
    }

    /** Normalizes a single domain; returns null if it isn't a valid blockable domain. */
    public static String clean(String d) {
        d = DnsNames.lower(d.trim());                        // A-Z only, locale-independent
        if (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        if (d.startsWith("*.")) d = d.substring(2); // wildcard = parent match, which we do anyway
        if (HOSTS_NOISE.contains(d) || !DOMAIN.matcher(d).matches()) return null;
        return d;
    }

    private static void add(List<String> out, String token) {
        String d = clean(token);
        if (d != null) out.add(d);
    }

    private static boolean looksLikeIp(String s) {
        return s.indexOf(':') >= 0 || s.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }
}
