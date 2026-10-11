package com.sankar.dnsfilter.filter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Downloads public blocklists (e.g. StevenBlack/hosts) at startup and caches them on disk.
 *
 *   config:  blocklist.remote=ads|https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
 *
 * - A cached copy younger than refreshHours is used without touching the network.
 * - If the download fails (offline, campus firewall), the last cached copy is used even if stale.
 * - If there's no cached copy either, the list is skipped - the server still starts.
 * Downloaded files live in blocklists/downloaded/, which is git-ignored.
 */
public class RemoteBlocklist {

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
        Path cached = cacheDir.resolve(src.category + "-" + Integer.toHexString(src.url.hashCode()) + ".txt");
        try {
            if (Files.exists(cached) && isFresh(cached, refreshHours)) {
                List<String> d = BlocklistLoader.load(cached);
                System.out.printf("Blocklist: %,d domains from cached %s [%s]%n", d.size(), cached.getFileName(), src.category);
                return d;
            }
            download(src.url, cached, timeoutMs);
            List<String> d = BlocklistLoader.load(cached);
            System.out.printf("Blocklist: %,d domains downloaded from %s [%s]%n", d.size(), src.url, src.category);
            return d;
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

    private static void download(String url, Path target, int timeoutMs) throws IOException, InterruptedException {
        Files.createDirectories(target.getParent());
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs * 2L))
                .header("User-Agent", "dns-filter/1.0")
                .GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (resp.statusCode() != 200) throw new IOException("HTTP " + resp.statusCode());
        // Write to a temp file and move, so a half-finished download never replaces a good cache.
        Path tmp = Files.createTempFile(target.getParent(), "dl-", ".tmp");
        Files.writeString(tmp, resp.body(), StandardCharsets.UTF_8);
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
}
