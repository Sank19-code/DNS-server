package com.sankar.dnsfilter.stats;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Saves the dashboard numbers (totals, top domains / clients, the recent query log) to a JSON
 * file and restores them at startup, so a restart doesn't reset everything to zero.
 *
 *   stats.file=../data/stats.json      empty = don't persist
 *   stats.saveIntervalSec=300          also saved on a clean shutdown
 *
 * Writes go to a temp file that is then moved over the old one, so a crash mid-write leaves the
 * previous snapshot intact. A missing or unreadable file just means starting from zero.
 * Privacy note: the file contains client IPs and domain names, like the dashboard itself.
 */
public class StatsStore {
    private final Path file;
    private final StatsCollector stats;
    private final Gson gson = new Gson();

    public StatsStore(Path file, StatsCollector stats) {
        this.file = file;
        this.stats = stats;
    }

    /** Restores the saved snapshot, if there is one. Never throws. */
    public void load() {
        if (!Files.exists(file)) return;
        try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            StatsCollector.Snapshot s = gson.fromJson(in, StatsCollector.Snapshot.class);
            if (s == null || s.version != 1) {
                System.err.println("Stats: ignoring " + file + " (unknown format)");
                return;
            }
            stats.restore(s);
            System.out.printf("Stats: restored %,d queries from %s%n", stats.total(), file);
        } catch (IOException | JsonParseException e) {
            System.err.println("Stats: could not read " + file + ", starting from zero (" + e.getMessage() + ")");
        }
    }

    /** Writes the current numbers. Safe to call from several threads (scheduler, shutdown hook). */
    public synchronized void save() {
        try {
            Path dir = file.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            Path tmp = Files.createTempFile(dir, "stats-", ".tmp");
            try (Writer out = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                gson.toJson(stats.snapshot(), out);
            }
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            System.err.println("Stats: could not save " + file.toAbsolutePath() + " (" + e.getMessage() + ")");
        }
    }

    public Path file() { return file; }
}
