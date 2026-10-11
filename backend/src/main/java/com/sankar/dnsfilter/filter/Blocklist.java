package com.sankar.dnsfilter.filter;

import com.sankar.dnsfilter.config.Config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Domain blocklist with category tags (ads / malware / trackers) and an allowlist.
 *
 * Matching rule: a domain is blocked if it OR any parent domain is listed.
 *   listed: doubleclick.net  ->  blocks ad.doubleclick.net, x.y.doubleclick.net
 * Walk the labels: a.b.c.com -> b.c.com -> c.com  (O(#labels) hash lookups, no regex)
 *
 * Precedence: the most specific listed name wins, and at the same level the allowlist beats
 * the blocklist. So allowing "ads.example.com" un-blocks just that subtree even though
 * "example.com" is blocked, and blocking "x.allowed.com" still works under an allowed parent.
 *
 * Stretch goal: replace with a reversed-label Trie (another DSA talking point).
 */
public class Blocklist {
    private final ConcurrentHashMap<String, String> blocked = new ConcurrentHashMap<>(); // domain -> category
    private final Set<String> allowed = ConcurrentHashMap.newKeySet();

    public void loadFromConfig(Config config) {
        long start = System.currentTimeMillis();

        // 1. Remote lists first (big, generic), so hand-curated local files can override categories.
        for (RemoteBlocklist.Source src : RemoteBlocklist.parseSources(config.get("blocklist.remote", ""))) {
            List<String> domains = RemoteBlocklist.fetch(src,
                    Paths.get(config.get("blocklist.cacheDir", "../blocklists/downloaded")),
                    config.getInt("blocklist.refreshHours", 24),
                    config.getInt("blocklist.downloadTimeoutMs", 15000));
            for (String d : domains) blocked.put(d, src.category);
        }

        // 2. Local files: category = file name without extension (ads.txt -> "ads").
        for (String f : splitList(config.get("blocklist.files", ""))) {
            Path path = Paths.get(f);
            String category = categoryFromFile(path);
            try {
                List<String> domains = BlocklistLoader.load(path);
                for (String d : domains) blocked.put(d, category);
                System.out.printf("Blocklist: %,d domains from %s [%s]%n", domains.size(), path, category);
            } catch (IOException e) {
                System.err.println("Blocklist: could not read " + path.toAbsolutePath() + " (" + e.getMessage() + ")");
            }
        }

        // 3. Allowlist.
        String allowFile = config.get("allowlist.file", "");
        if (!allowFile.isBlank()) {
            Path path = Paths.get(allowFile.trim());
            if (Files.exists(path)) {
                try {
                    List<String> domains = BlocklistLoader.load(path);
                    allowed.addAll(domains);
                    System.out.printf("Allowlist: %,d domains from %s%n", domains.size(), path);
                } catch (IOException e) {
                    System.err.println("Allowlist: could not read " + path + " (" + e.getMessage() + ")");
                }
            }
        }

        System.out.printf("Blocklist ready: %,d blocked, %,d allowed (%d ms) %s%n",
                blocked.size(), allowed.size(), System.currentTimeMillis() - start, categoryCounts());
    }

    /** @return category if blocked ("ads", "malware", ...), or null if the domain may resolve. */
    public String check(String domain) {
        if (domain == null || domain.isEmpty()) return null;
        String d = normalize(domain);
        // Most specific first: a.b.c.com, b.c.com, c.com. Stop before the bare TLD so a
        // stray "com" entry can never take down the whole internet.
        while (true) {
            if (allowed.contains(d)) return null;
            String category = blocked.get(d);
            if (category != null) return category;
            int dot = d.indexOf('.');
            if (dot < 0) return null;
            String parent = d.substring(dot + 1);
            if (parent.indexOf('.') < 0) return null; // parent is a TLD
            d = parent;
        }
    }

    public void add(String domain, String category) { blocked.put(normalize(domain), category); }
    public String remove(String domain) { return blocked.remove(normalize(domain)); }
    public void allow(String domain) { allowed.add(normalize(domain)); }
    public boolean unallow(String domain) { return allowed.remove(normalize(domain)); }
    public boolean isListed(String domain) { return blocked.containsKey(normalize(domain)); }
    public int size() { return blocked.size(); }
    public int allowedSize() { return allowed.size(); }
    public Set<String> allowedDomains() { return Set.copyOf(allowed); }

    /** Blocked-domain count per category, sorted by name - for the dashboard. */
    public Map<String, Integer> categoryCounts() {
        Map<String, Integer> counts = new TreeMap<>();
        for (String c : blocked.values()) counts.merge(c, 1, Integer::sum);
        return counts;
    }

    static String normalize(String d) {
        d = d.trim().toLowerCase();
        return d.endsWith(".") ? d.substring(0, d.length() - 1) : d;
    }

    static String categoryFromFile(Path path) {
        String name = path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    static List<String> splitList(String csv) {
        return java.util.Arrays.stream(csv.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
