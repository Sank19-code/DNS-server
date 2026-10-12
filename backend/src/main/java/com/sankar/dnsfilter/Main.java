package com.sankar.dnsfilter;

import com.sankar.dnsfilter.api.ApiServer;
import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.server.DnsServer;
import com.sankar.dnsfilter.server.QueryHandler;
import com.sankar.dnsfilter.stats.StatsCollector;

/**
 * Entry point. Wires everything together:
 *
 *   client --UDP--> DnsServer --> QueryHandler --> Blocklist?  -> NXDOMAIN / 0.0.0.0
 *                  (rate limit)               --> DnsCache?   -> cached answer
 *                                             --> UpstreamResolver (8.8.8.8) -> cache + reply
 *   React dashboard --HTTP--> ApiServer --> StatsCollector / Blocklist / DnsCache
 *                                       --> QueryHandler (for /api/resolve)
 */
public class Main {
    public static void main(String[] args) throws Exception {
        Config config = Config.load(args.length > 0 ? args[0] : null);

        Blocklist blocklist = new Blocklist();
        blocklist.loadFromConfig(config);

        DnsCache cache = new DnsCache(config.getInt("cache.maxEntries", 1000));
        UpstreamResolver upstream = new UpstreamResolver(config);
        StatsCollector stats = new StatsCollector();
        QueryHandler handler = new QueryHandler(blocklist, cache, upstream, stats, QueryHandler.Settings.from(config));

        ApiServer api = new ApiServer(config, stats, blocklist, cache, handler);
        api.start();

        DnsServer dns = new DnsServer(config, handler, stats);
        System.out.println("DNS filter starting... DNS port " + config.getInt("dns.port", 5300)
                + ", API port " + config.getInt("api.port", 8081));
        dns.start(); // blocks forever
    }
}
