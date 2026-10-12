package com.sankar.dnsfilter.filter;

import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.protocol.DnsNames;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
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
 * Sources, applied in this order on every (re)load:
 *   1. remote lists (downloaded, cached on disk)   2. local list files   3. allowlist file
 *   4. overrides: the changes made through the API / dashboard (block, unblock, allow, unallow).
 * The overrides are saved to blocklist.overridesFile on every change, so they survive a restart
 * and a list refresh. Unblocking a domain that a list contains is remembered as "unblock", so it
 * stays unblocked when the list is downloaded again.
 *
 * Reload: reload() builds complete new sets off to the side and swaps them in at once, so queries
 * never see a half-loaded list. API edits made while a reload is running are replayed onto the
 * new sets during the swap (both hold the same lock), so none are lost.
 *
 * Stretch goal: replace with a reversed-label Trie (another DSA talking point).
 */
public class Blocklist {
    private volatile ConcurrentHashMap<String, String> blocked = new ConcurrentHashMap<>(); // domain -> category
    private volatile Set<String> allowed = ConcurrentHashMap.newKeySet();

    // Overrides from the API, guarded by `this`. Sorted so the saved file is stable and diffable.
    private final Map<String, String> addedBlocks = new TreeMap<>();
    private final Set<String> removedBlocks = new TreeSet<>();
    private final Set<String> addedAllows = new TreeSet<>();
    private final Set<String> removedAllows = new TreeSet<>();
    private Path overridesFile;                         // null = keep overrides in memory only

    private final Object reloadLock = new Object();     // one reload at a time

    /** Reads the overrides file, then loads every list (using fresh cached downloads if any). */
    public void loadFromConfig(Config config) {
        String f = config.get("blocklist.overridesFile", "").trim();
        if (!f.isEmpty()) {
            overridesFile = Paths.get(f);
            readOverrides();
        }
        reload(config, false);
    }

    /**
     * Re-reads all sources and swaps them in atomically.
     * @param forceDownload true = download remote lists even if the cached copy is still fresh
     */
    public void reload(Config config, boolean forceDownload) {
        synchronized (reloadLock) {
            long start = System.currentTimeMillis();
            ConcurrentHashMap<String, String> newBlocked = new ConcurrentHashMap<>();
            Set<String> newAllowed = ConcurrentHashMap.newKeySet();

            // 1. Remote lists first (big, generic), so hand-curated local files can override categories.
            for (RemoteBlocklist.Source src : RemoteBlocklist.parseSources(config.get("blocklist.remote", ""))) {
                List<String> domains = RemoteBlocklist.fetch(src,
                        Paths.get(config.get("blocklist.cacheDir", "../blocklists/downloaded")),
                        forceDownload ? 0 : config.getInt("blocklist.refreshHours", 24),
                        config.getInt("blocklist.downloadTimeoutMs", 15000),
                        config.getInt("blocklist.maxDownloadMb", 50) * 1024L * 1024L,
                        config.getInt("blocklist.minKeepPercent", 50) / 100.0);
                for (String d : domains) newBlocked.put(d, src.category);
            }

            // 2. Local files: category = file name without extension (ads.txt -> "ads").
            for (String f : splitList(config.get("blocklist.files", ""))) {
                Path path = Paths.get(f);
                String category = categoryFromFile(path);
                try {
                    List<String> domains = BlocklistLoader.load(path);
                    for (String d : domains) newBlocked.put(d, category);
                    System.out.printf("Blocklist: %,d domains from %s [%s]%n", domains.size(), path, category);
                } catch (IOException e) {
                    System.err.println("Blocklist: could not read " + path.toAbsolutePath() + " (" + e.getMessage() + ")");
                }
            }

            // 3. Allowlist file.
            String allowFile = config.get("allowlist.file", "");
            if (!allowFile.isBlank()) {
                Path path = Paths.get(allowFile.trim());
                if (Files.exists(path)) {
                    try {
                        List<String> domains = BlocklistLoader.load(path);
                        newAllowed.addAll(domains);
                        System.out.printf("Allowlist: %,d domains from %s%n", domains.size(), path);
                    } catch (IOException e) {
                        System.err.println("Allowlist: could not read " + path + " (" + e.getMessage() + ")");
                    }
                }
            }

            // 4. Overrides, then swap. Same lock as add/remove, so no API edit slips between the two.
            synchronized (this) {
                applyOverrides(newBlocked, newAllowed);
                blocked = newBlocked;
                allowed = newAllowed;
            }
            System.out.printf("Blocklist ready: %,d blocked, %,d allowed, %d override(s) (%d ms) %s%n",
                    newBlocked.size(), newAllowed.size(), overrideCount(),
                    System.currentTimeMillis() - start, categoryCounts());
        }
    }

    /** @return category if blocked ("ads", "malware", ...), or null if the domain may resolve. */
    public String check(String domain) {
        if (domain == null || domain.isEmpty()) return null;
        Map<String, String> b = blocked;   // one consistent snapshot for the whole walk
        Set<String> a = allowed;
        String d = normalize(domain);
        // Most specific first: a.b.c.com, b.c.com, c.com. Stop before the bare TLD so a
        // stray "com" entry can never take down the whole internet.
        while (true) {
            if (a.contains(d)) return null;
            String category = b.get(d);
            if (category != null) return category;
            int dot = DnsNames.firstDot(d);               // skips an escaped "\." inside a label
            if (dot < 0) return null;
            String parent = d.substring(dot + 1);
            if (DnsNames.firstDot(parent) < 0) return null; // parent is a TLD
            d = parent;
        }
    }

    // ------------------------------------------------------------ API edits (persisted)

    public synchronized void add(String domain, String category) {
        String d = normalize(domain);
        blocked.put(d, category);
        addedBlocks.put(d, category);
        removedBlocks.remove(d);
        saveOverrides();
    }

    public synchronized String remove(String domain) {
        String d = normalize(domain);
        String category = blocked.remove(d);
        if (category != null) {
            addedBlocks.remove(d);
            removedBlocks.add(d);       // keep it unblocked even if a list brings it back
            saveOverrides();
        }
        return category;
    }

    public synchronized void allow(String domain) {
        String d = normalize(domain);
        allowed.add(d);
        addedAllows.add(d);
        removedAllows.remove(d);
        saveOverrides();
    }

    public synchronized boolean unallow(String domain) {
        String d = normalize(domain);
        boolean removed = allowed.remove(d);
        if (removed) {
            addedAllows.remove(d);
            removedAllows.add(d);
            saveOverrides();
        }
        return removed;
    }

    public boolean isListed(String domain) { return blocked.containsKey(normalize(domain)); }

    /** True if the domain or one of its parents is on the allowlist. */
    public boolean isAllowlisted(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        Set<String> a = allowed;
        String d = normalize(domain);
        while (true) {
            if (a.contains(d)) return true;
            int dot = DnsNames.firstDot(d);
            if (dot < 0) return false;
            d = d.substring(dot + 1);
        }
    }
    public int size() { return blocked.size(); }
    public int allowedSize() { return allowed.size(); }
    public Set<String> allowedDomains() { return Set.copyOf(allowed); }
    public synchronized int overrideCount() {
        return addedBlocks.size() + removedBlocks.size() + addedAllows.size() + removedAllows.size();
    }

    /** Blocked-domain count per category, sorted by name - for the dashboard. */
    public Map<String, Integer> categoryCounts() {
        Map<String, Integer> counts = new TreeMap<>();
        for (String c : blocked.values()) counts.merge(c, 1, Integer::sum);
        return counts;
    }

    // ------------------------------------------------------------ overrides file

    private void applyOverrides(Map<String, String> b, Set<String> a) {
        for (String d : removedBlocks) b.remove(d);
        b.putAll(addedBlocks);
        a.removeAll(removedAllows);
        a.addAll(addedAllows);
    }

    /**
     * File format, one change per line (lines starting with # are comments):
     *   block ads tracker.example.com
     *   unblock doubleclick.net
     *   allow safe.example.com
     *   unallow example.org
     */
    private synchronized void readOverrides() {
        if (overridesFile == null || !Files.exists(overridesFile)) return;
        try {
            int lineNo = 0;
            for (String raw : Files.readAllLines(overridesFile, StandardCharsets.UTF_8)) {
                lineNo++;
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] t = line.split("\\s+");
                String domain = BlocklistLoader.clean(t[t.length - 1]);
                if (domain == null) {
                    System.err.println("Overrides: skipping line " + lineNo + " (" + line + ")");
                    continue;
                }
                switch (t[0]) {
                    case "block":
                        addedBlocks.put(domain, t.length == 3 ? t[1] : "custom");
                        break;
                    case "unblock": removedBlocks.add(domain); break;
                    case "allow":   addedAllows.add(domain); break;
                    case "unallow": removedAllows.add(domain); break;
                    default: System.err.println("Overrides: unknown action on line " + lineNo + " (" + line + ")");
                }
            }
            System.out.printf("Overrides: %d change(s) from %s%n", overrideCount(), overridesFile);
        } catch (IOException e) {
            System.err.println("Overrides: could not read " + overridesFile + " (" + e.getMessage() + ")");
        }
    }

    /** Rewrites the whole file via a temp file + atomic move, so a crash never leaves half a file. */
    private void saveOverrides() {
        if (overridesFile == null) return;
        List<String> lines = new ArrayList<>();
        lines.add("# Blocklist changes made from the dashboard / API, applied on top of the list files.");
        lines.add("# Rewritten by the server on every change. Edit by hand only while it is stopped.");
        addedBlocks.forEach((d, c) -> lines.add("block " + c + " " + d));
        removedBlocks.forEach(d -> lines.add("unblock " + d));
        addedAllows.forEach(d -> lines.add("allow " + d));
        removedAllows.forEach(d -> lines.add("unallow " + d));
        try {
            Path dir = overridesFile.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            Path tmp = Files.createTempFile(dir, "overrides-", ".tmp");
            Files.write(tmp, lines, StandardCharsets.UTF_8);
            Files.move(tmp, overridesFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            System.err.println("Overrides: could not save " + overridesFile.toAbsolutePath()
                    + " - this change is live but will be lost on restart (" + e.getMessage() + ")");
        }
    }

    // ------------------------------------------------------------ helpers

    static String normalize(String d) {
        d = DnsNames.lower(d.trim());                        // A-Z only, locale-independent
        return d.endsWith(".") && !d.endsWith("\\.") ? d.substring(0, d.length() - 1) : d;
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
