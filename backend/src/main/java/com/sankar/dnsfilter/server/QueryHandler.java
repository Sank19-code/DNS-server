package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.stats.StatsCollector;

/**
 * The core pipeline for a single query:
 *   1. parse      -> DnsParser
 *   2. blocked?   -> Blocklist.isBlocked(name)  -> DnsWriter.buildBlockedResponse
 *   3. cached?    -> DnsCache.get(key)          -> DnsWriter.rewriteId
 *   4. forward    -> UpstreamResolver.forward   -> parse TTL -> DnsCache.put
 *   5. record     -> StatsCollector.record(...)
 */
public class QueryHandler {
    private final Blocklist blocklist;
    private final DnsCache cache;
    private final UpstreamResolver upstream;
    private final StatsCollector stats;

    public QueryHandler(Blocklist blocklist, DnsCache cache, UpstreamResolver upstream, StatsCollector stats) {
        this.blocklist = blocklist;
        this.cache = cache;
        this.upstream = upstream;
        this.stats = stats;
    }

    public byte[] handle(byte[] query, String clientIp) throws Exception {
        // Day 1 milestone: pure pass-through proxy (proves UDP plumbing works end to end)
        // TODO Day 1-2: replace with the full pipeline described above
        return upstream.forward(query);
    }
}
