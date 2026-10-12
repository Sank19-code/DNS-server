package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsParseException;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsRecord;
import com.sankar.dnsfilter.protocol.DnsWriter;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.stats.QueryLogEntry;
import com.sankar.dnsfilter.stats.StatsCollector;

/**
 * The core pipeline for a single query:
 *   1. parse      -> DnsParser               malformed -> FORMERR
 *   2. blocked?   -> Blocklist.check(name)   -> NXDOMAIN (or 0.0.0.0 in nullroute mode)
 *   3. cached?    -> DnsCache.get(key)       -> cached reply, new ID, TTLs aged
 *   4. forward    -> UpstreamResolver        -> validate -> DnsCache.put(TTL)   timeout -> SERVFAIL
 *   5. record     -> StatsCollector.record(...)
 *
 * Blocking is checked BEFORE the cache, so adding a domain to the blocklist takes effect
 * immediately even if an answer for it is still cached.
 */
public class QueryHandler {
    private static final int RCODE_NOTIMP = 4;

    /** Tunables, read from config.properties (defaults in brackets). */
    public static final class Settings {
        /** blocking.mode = nxdomain | nullroute   [nxdomain] */
        public boolean nullRoute = false;
        /** blocking.ttl - TTL on null-route answers, seconds   [60] */
        public long blockedTtl = 60;
        /** cache.maxTtl - cap positive answers, seconds   [86400] */
        public long maxTtl = 86_400;
        /** cache.negativeTtl - cap NXDOMAIN / NODATA caching, seconds; 0 disables   [300] */
        public long negativeTtl = 300;
        /** dns.logQueries - print one line per query   [true] */
        public boolean logQueries = true;

        public static Settings from(Config c) {
            Settings s = new Settings();
            s.nullRoute = c.get("blocking.mode", "nxdomain").trim().equalsIgnoreCase("nullroute");
            s.blockedTtl = c.getInt("blocking.ttl", 60);
            s.maxTtl = c.getInt("cache.maxTtl", 86_400);
            s.negativeTtl = c.getInt("cache.negativeTtl", 300);
            s.logQueries = Boolean.parseBoolean(c.get("dns.logQueries", "true").trim());
            return s;
        }
    }

    private final Blocklist blocklist;
    private final DnsCache cache;
    private final UpstreamResolver upstream;
    private final StatsCollector stats;
    private final Settings settings;

    public QueryHandler(Blocklist blocklist, DnsCache cache, UpstreamResolver upstream, StatsCollector stats) {
        this(blocklist, cache, upstream, stats, new Settings());
    }

    public QueryHandler(Blocklist blocklist, DnsCache cache, UpstreamResolver upstream, StatsCollector stats,
                        Settings settings) {
        this.blocklist = blocklist;
        this.cache = cache;
        this.upstream = upstream;
        this.stats = stats;
        this.settings = settings;
    }

    /** Outcome of one query: the reply bytes (null = drop) plus what the pipeline decided. */
    public static final class Result {
        public final byte[] reply;
        public final QueryLogEntry.Status status;   // null when the packet was dropped/FORMERR
        public final String category;
        public final long latencyMicros;

        Result(byte[] reply, QueryLogEntry.Status status, String category, long latencyMicros) {
            this.reply = reply;
            this.status = status;
            this.category = category;
            this.latencyMicros = latencyMicros;
        }
    }

    public UpstreamResolver upstream() { return upstream; }

    /** Called by DnsServer for every UDP packet. */
    public byte[] handle(byte[] query, String clientIp) {
        return resolve(query, clientIp).reply;
    }

    /** Same pipeline, but also reports the decision - used by the HTTP "test a domain" endpoint. */
    public Result resolve(byte[] query, String clientIp) {
        long start = System.nanoTime();

        // 1. Parse. Malformed packets get FORMERR (if we can at least read the header) or are dropped.
        DnsMessage msg;
        try {
            msg = new DnsParser(query, query.length).parseQuery();
        } catch (DnsParseException e) {
            System.err.println("Malformed query from " + clientIp + ": " + e.getMessage());
            return new Result(formErr(query), null, null, (System.nanoTime() - start) / 1000);
        }
        if (msg.header.isResponse() || msg.questions.isEmpty()) {
            System.err.println("Ignoring non-query packet from " + clientIp + ": " + msg.header);
            return new Result(null, null, null, (System.nanoTime() - start) / 1000);
        }

        DnsQuestion q = msg.questions.get(0);
        String domain = q.name.toLowerCase();
        String type = DnsQuestion.typeName(q.type);

        if (msg.header.getOpcode() != 0) { // only standard QUERY; no IQUERY/STATUS/NOTIFY/UPDATE
            byte[] reply = DnsWriter.buildErrorResponse(query, query.length, RCODE_NOTIMP);
            return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.ERROR, null,
                    "NOTIMP (opcode " + msg.header.getOpcode() + ")");
        }

        // 2. Blocklist.
        String category = blocklist.check(domain);
        if (category != null) {
            byte[] reply = settings.nullRoute
                    ? DnsWriter.buildNullRouteResponse(query, query.length, settings.blockedTtl)
                    : DnsWriter.buildBlockedResponse(query, query.length);
            return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.BLOCKED, category,
                    "BLOCKED [" + category + "]");
        }

        // 3. Cache. Only single-question queries are cacheable (multi-question is ~never used).
        String key = msg.questions.size() == 1 ? DnsCache.key(domain, q.type) : null;
        if (key != null) {
            byte[] cached = cache.get(key);
            if (cached != null) {
                byte[] reply = DnsWriter.prepareCachedReply(cached, query, query.length);
                return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.CACHED, null, "CACHED");
            }
        }

        // 4. Forward to upstream; on timeout/error answer SERVFAIL so the client doesn't hang.
        byte[] reply;
        try {
            reply = upstream.forward(query);
        } catch (Exception e) {
            reply = DnsWriter.buildErrorResponse(query, query.length, DnsHeader.RCODE_SERVFAIL);
            return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.ERROR, null,
                    "SERVFAIL (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
        }

        String outcome;
        try {
            DnsMessage resp = new DnsParser(reply, reply.length).parse();
            long ttl = key == null ? 0 : cacheTtl(resp, q);
            if (ttl > 0) cache.put(key, reply, ttl);
            outcome = DnsHeader.rcodeName(resp.header.getRcode()) + ", " + resp.answers.size()
                    + " answer(s), " + (ttl > 0 ? "cached " + ttl + "s" : "not cached");
        } catch (DnsParseException e) {
            // We can't fully parse it, but the client might - relay it anyway (uncached) and log why.
            outcome = "unparsed reply, not cached (" + e.getMessage() + ")";
        }
        return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.FORWARDED, null, outcome);
    }

    /**
     * How long to cache an upstream reply, or 0 to skip caching.
     *  - must answer the question we asked (guards against a mismatched reply poisoning another key)
     *  - never cache truncated replies or errors like SERVFAIL / REFUSED
     *  - NOERROR with answers: smallest answer TTL, capped at maxTtl
     *  - NXDOMAIN / NODATA: negative caching per RFC 2308 - TTL of the SOA in the authority
     *    section, capped at negativeTtl; no SOA means don't cache
     */
    long cacheTtl(DnsMessage resp, DnsQuestion asked) {
        if (resp.header.isTruncated() || resp.questions.size() != 1) return 0;
        DnsQuestion rq = resp.questions.get(0);
        if (!rq.name.equalsIgnoreCase(asked.name) || rq.type != asked.type) return 0;

        int rcode = resp.header.getRcode();
        if (rcode == DnsHeader.RCODE_NOERROR && !resp.answers.isEmpty()) {
            return Math.min(resp.minAnswerTtl(), settings.maxTtl);
        }
        if (rcode == DnsHeader.RCODE_NXDOMAIN || rcode == DnsHeader.RCODE_NOERROR) {
            for (DnsRecord r : resp.authorities) {
                if (r.type == DnsQuestion.TYPE_SOA) return Math.min(r.ttl, settings.negativeTtl);
            }
        }
        return 0;
    }

    private Result finish(byte[] reply, long start, String clientIp, String domain, String type,
                          QueryLogEntry.Status status, String category, String outcome) {
        long micros = (System.nanoTime() - start) / 1000;
        if (settings.logQueries) {
            System.out.printf("QUERY %-40s %-5s from %-15s -> %s [%.2f ms]%n",
                    domain, type, clientIp, outcome, micros / 1000.0);
        }
        // 5. Record for the dashboard.
        stats.record(new QueryLogEntry(clientIp, domain, type, status, category, micros));
        return new Result(reply, status, category, micros);
    }

    /** FORMERR reply if the 12-byte header is readable, otherwise drop the packet. */
    private static byte[] formErr(byte[] query) {
        if (query.length < DnsHeader.SIZE) return null;
        byte[] out = new byte[DnsHeader.SIZE];
        System.arraycopy(query, 0, out, 0, 4);
        DnsHeader h = new DnsHeader();
        h.flags = ((query[2] & 0xFF) << 8) | (query[3] & 0xFF);
        h.setResponseFlags(DnsHeader.RCODE_FORMERR);
        out[2] = (byte) (h.flags >> 8);
        out[3] = (byte) h.flags;
        // counts stay 0: we can't echo a question we couldn't parse
        return out;
    }
}
