package com.sankar.dnsfilter;

import com.sankar.dnsfilter.api.ApiServer;
import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.server.DnsServer;
import com.sankar.dnsfilter.server.Admission;
import com.sankar.dnsfilter.server.QueryHandler;
import com.sankar.dnsfilter.server.TcpDnsServer;
import com.sankar.dnsfilter.stats.StatsCollector;
import com.sankar.dnsfilter.stats.StatsStore;

import java.nio.file.Paths;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Entry point. Wires everything together:
 *
 *   client --UDP/TCP--> DnsServer / TcpDnsServer --> QueryHandler --> Blocklist?  -> NXDOMAIN / 0.0.0.0
 *                       (rate limit)                              --> DnsCache?   -> cached answer
 *                                                                 --> UpstreamResolver -> cache + reply
 *   React dashboard --HTTP--> ApiServer --> StatsCollector / Blocklist / DnsCache
 *                                       --> QueryHandler (for /api/resolve)
 *
 * Background jobs (one daemon thread): re-download the remote blocklists every
 * blocklist.refreshHours, and save the dashboard stats every stats.saveIntervalSec.
 * Ctrl+C / docker stop runs the shutdown hook: stop accepting queries, save the stats.
 */
public class Main {
    public static void main(String[] args) throws Exception {
        Config config = Config.load(args.length > 0 ? args[0] : null);

        Blocklist blocklist = new Blocklist();
        blocklist.loadFromConfig(config);

        DnsCache cache = new DnsCache(config.getInt("cache.maxEntries", 10_000));
        UpstreamResolver upstream = new UpstreamResolver(config);
        StatsCollector stats = new StatsCollector();
        String statsFile = config.get("stats.file", "").trim();
        StatsStore statsStore = statsFile.isEmpty() ? null : new StatsStore(Paths.get(statsFile), stats);
        if (statsStore != null) statsStore.load();
        QueryHandler handler = new QueryHandler(blocklist, cache, upstream, stats, QueryHandler.Settings.from(config));

        ApiServer api = new ApiServer(config, stats, blocklist, cache, handler);
        api.onReloadBlocklists(() -> blocklist.reload(config, true));
        api.start();

        ScheduledExecutorService jobs = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "background-jobs");
            t.setDaemon(true);
            return t;
        });
        int refreshHours = config.getInt("blocklist.refreshHours", 24);
        if (refreshHours > 0) {
            jobs.scheduleWithFixedDelay(() -> {
                try {
                    blocklist.reload(config, false);   // the cached download is now stale -> re-download
                } catch (RuntimeException e) {
                    System.err.println("Blocklist refresh failed, keeping the current lists: " + e);
                }
            }, refreshHours, refreshHours, TimeUnit.HOURS);
        }
        int saveSec = config.getInt("stats.saveIntervalSec", 300);
        if (statsStore != null && saveSec > 0) {
            jobs.scheduleWithFixedDelay(statsStore::save, saveSec, saveSec, TimeUnit.SECONDS);
        }

        Admission admission = Admission.from(config, stats);   // one budget per client across UDP + TCP
        DnsServer dns = new DnsServer(config, handler, admission);
        TcpDnsServer tcp = Boolean.parseBoolean(config.get("dns.tcp.enabled", "true").trim())
                ? new TcpDnsServer(config, handler, admission) : null;

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down...");
            jobs.shutdownNow();
            dns.stop();
            if (tcp != null) tcp.stop();
            api.stop();
            if (statsStore != null) {
                statsStore.save();
                System.out.println("Stats saved to " + statsStore.file());
            }
        }, "shutdown"));

        System.out.println("DNS filter starting... DNS port " + config.getInt("dns.port", 5300)
                + ", API port " + config.getInt("api.port", 8081));
        dns.bind();
        if (tcp != null) tcp.start();
        dns.serve(); // blocks until shutdown
    }
}
