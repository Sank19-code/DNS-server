package com.sankar.dnsfilter.filter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Downloads public blocklists (e.g. StevenBlack/hosts) at startup and caches them on disk.
 *
 *   config:  blocklist.remote=ads|https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
 *
 * - A cached copy younger than refreshHours is used without touching the network.
 * - If the download fails (offline, campus firewall), the last cached copy is used even if stale.
 * - If there's no cached copy either, the list is skipped - the server still starts.
 * - A download is only accepted if it's under the size limit and not suspiciously smaller than
 *   the cached copy; otherwise the cached copy stays (see fetch).
 * Downloaded files live in blocklists/downloaded/, which is git-ignored.
 */
public class RemoteBlocklist {
    public static final long DEFAULT_MAX_BYTES = 50L * 1024 * 1024;
    public static final double DEFAULT_MIN_KEEP_FRACTION = 0.5;

    public static final class Source {
        public final String category;
        public final String url;
        Source(String category, String url) { this.category = category; this.url = url; }
    }

    /** Parses "cat|url,cat|url". A bare URL gets category "remote". */
    public static List<Source> parseSources(String csv) {
        List<Source> out = new ArrayList<>();
        for (String item : Blocklist.splitList(csv)) {
            int bar = item.indexOf('|');
            if (bar > 0) out.add(new Source(item.substring(0, bar).trim(), item.substring(bar + 1).trim()));
            else out.add(new Source("remote", item));
        }
        return out;
    }

    public static List<String> fetch(Source src, Path cacheDir, int refreshHours, int timeoutMs) {
        return fetch(src, cacheDir, refreshHours, timeoutMs, DEFAULT_MAX_BYTES, DEFAULT_MIN_KEEP_FRACTION);
    }

    /**
     * @param maxBytes          a download bigger than this is aborted (a list is a few MB; this stops
     *                          a broken or hostile URL from filling memory or disk)
     * @param minKeepFraction   a download with fewer domains than this fraction of the cached copy is
     *                          rejected and the cached copy kept. A "200 OK" error page or a cut-off
     *                          file would otherwise silently shrink a 72k-domain list to almost nothing.
     */
    public static List<String> fetch(Source src, Path cacheDir, int refreshHours, int timeoutMs,
                                     long maxBytes, double minKeepFraction) {
        Path cached = cacheDir.resolve(src.category + "-" + Integer.toHexString(src.url.hashCode()) + ".txt");
        try {
            if (Files.exists(cached) && isFresh(cached, refreshHours)) {
                List<String> d = BlocklistLoader.load(cached);
                System.out.printf("Blocklist: %,d domains from cached %s [%s]%n", d.size(), cached.getFileName(), src.category);
                return d;
            }
            Files.createDirectories(cacheDir);
            Path tmp = Files.createTempFile(cacheDir, "dl-", ".tmp");
            try {
                download(src.url, tmp, timeoutMs, maxBytes);
                List<String> d = BlocklistLoader.load(tmp);
                if (d.isEmpty()) throw new IOException("the download contains no domains");
                if (Files.exists(cached)) {
                    int previous = BlocklistLoader.load(cached).size();
                    if (d.size() < previous * minKeepFraction) {
                        throw new IOException(String.format("the download has only %,d domains, the cached copy %,d"
                                + " - looks broken, keeping the cached copy", d.size(), previous));
                    }
                }
                // Only now replace the cache: a half-finished or rejected download never touches it.
                Files.move(tmp, cached, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                System.out.printf("Blocklist: %,d domains downloaded from %s [%s]%n", d.size(), src.url, src.category);
                return d;
            } finally {
                Files.deleteIfExists(tmp);              // our own temp file, if it wasn't moved
            }
        } catch (Exception e) {
            System.err.println("Blocklist: download failed for " + src.url + " (" + e + ")");
            if (Files.exists(cached)) {
                try {
                    List<String> d = BlocklistLoader.load(cached);
                    System.err.printf("Blocklist: using stale cached copy, %,d domains%n", d.size());
                    return d;
                } catch (IOException ignored) { /* fall through */ }
            }
            return Collections.emptyList();
        }
    }

    private static boolean isFresh(Path file, int refreshHours) throws IOException {
        Instant modified = Files.getLastModifiedTime(file).toInstant();
        return modified.isAfter(Instant.now().minus(Duration.ofHours(refreshHours)));
    }

    /**
     * Streams the body to `target`, stopping at maxBytes. Each read waits at most timeoutMs, and
     * the whole transfer must finish within 4 x timeoutMs, so a server that trickles bytes can't
     * hang a reload forever.
     */
    private static void download(String url, Path target, int timeoutMs, long maxBytes) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        conn.setInstanceFollowRedirects(true);           // same protocol only: https never drops to http
        conn.setRequestProperty("User-Agent", "dns-filter/1.0");
        try {
            int status = conn.getResponseCode();
            if (status != 200) throw new IOException("HTTP " + status);
            long declared = conn.getContentLengthLong();
            if (declared > maxBytes) throw new IOException("list is " + declared + " bytes, limit " + maxBytes);
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs * 4L);
            try (InputStream in = conn.getInputStream(); OutputStream out = Files.newOutputStream(target)) {
                byte[] buf = new byte[64 * 1024];
                long total = 0;
                int n;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                    if (total > maxBytes) throw new IOException("list is larger than the " + maxBytes + "-byte limit");
                    if (System.nanoTime() - deadline > 0) throw new IOException("download took longer than " + timeoutMs * 4L + " ms");
                    out.write(buf, 0, n);
                }
            }
        } finally {
            conn.disconnect();
        }
    }
}
