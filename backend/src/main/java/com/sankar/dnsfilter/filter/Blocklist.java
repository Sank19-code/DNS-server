package com.sankar.dnsfilter.filter;

import com.sankar.dnsfilter.config.Config;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Domain blocklist with category tags (ads / malware / trackers) and an allowlist.
 *
 * Matching rule: a domain is blocked if it OR any parent domain is listed.
 *   listed: doubleclick.net  ->  blocks ad.doubleclick.net, x.y.doubleclick.net
 * Walk the labels: a.b.c.com -> b.c.com -> c.com -> com  (O(#labels) HashSet lookups)
 * Stretch goal: replace with a reversed-label Trie (another DSA talking point).
 */
public class Blocklist {
    private final ConcurrentHashMap<String, String> blocked = new ConcurrentHashMap<>(); // domain -> category
    private final Set<String> allowed = ConcurrentHashMap.newKeySet();

    public void loadFromConfig(Config config) {
        // TODO (Day 2): BlocklistLoader.load(file) for each file in blocklist.files,
        //               category = file name without .txt
        // TODO: load allowlist.file into `allowed`
    }

    /** @return category if blocked ("ads", "malware", ...), or null if allowed. */
    public String check(String domain) {
        // TODO (Day 2): allowlist first, then walk parent domains
        return null;
    }

    public void add(String domain, String category) { blocked.put(normalize(domain), category); }
    public void remove(String domain) { blocked.remove(normalize(domain)); }
    public void allow(String domain) { allowed.add(normalize(domain)); }
    public int size() { return blocked.size(); }

    static String normalize(String d) {
        d = d.trim().toLowerCase();
        return d.endsWith(".") ? d.substring(0, d.length() - 1) : d;
    }
}
