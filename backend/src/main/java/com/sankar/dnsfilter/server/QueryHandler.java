package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsNames;
import com.sankar.dnsfilter.protocol.DnsParseException;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsRecord;
import com.sankar.dnsfilter.protocol.DnsWriter;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.stats.QueryLogEntry;
import com.sankar.dnsfilter.stats.StatsCollector;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;

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
 *
 * Size limits: a UDP client only accepts replies up to 512 bytes, or the size it advertised in an
 * EDNS(0) OPT record. A bigger reply (from the cache or upstream) is replaced by an empty TC=1
 * reply, and the client retries over TCP, where TcpDnsServer calls us with Transport.TCP and we
 * forward over TCP too. The cache key includes the EDNS variant (none / EDNS / EDNS+DO), so an
 * answer fetched with DNSSEC records for one client is never handed to a plain client.
 */
public class QueryHandler {
    private static final int RCODE_NOTIMP = 4;

    /** How the query reached us; decides the reply size limit and how we talk to upstream. */
    public enum Transport {
        /** Size limit from EDNS (512 without); oversize -> TC=1. Upstream over UDP. */
        UDP,
        /** No size limit. Upstream over TCP, so a big answer arrives whole. */
        TCP,
        /** The dashboard's "test a domain" box: no size limit, upstream over UDP. */
        HTTP
    }

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
        /**
         * upstream.maxInFlight - upstream lookups allowed at once; more -> immediate SERVFAIL; 0 = no cap   [12]
         * Kept below dns.workers so a flood of never-seen names can't occupy every worker waiting on
         * upstream: the rest stay free for cached and blocked names, which answer in microseconds.
         */
        public int maxUpstreamInFlight = 12;
        /**
         * dns.maxUdpSize - largest UDP reply we send even if the client's EDNS asks for more   [1232]
         * 1232 is the DNS Flag Day 2020 value: avoids IP fragmentation, and limits how much a spoofed
         * 60-byte query can be amplified (about 20x instead of 4096 / 60 = 68x). Bigger -> TC=1 -> TCP.
         */
        public int maxUdpSize = 1232;
        /**
         * blocking.cnameInspection - also block when an answer's CNAME alias is blocked   [true]
         * Catches "CNAME cloaking": metrics.news-site.com -> CNAME -> tracker.adobe.com.
         */
        public boolean cnameInspection = true;
        /**
         * dns.blockBypassCanaries - answer NXDOMAIN for the names that tell Firefox (DNS-over-HTTPS)
         * and iCloud Private Relay to switch themselves off on this network   [true]
         * Both send DNS around this server, which would bypass every block.
         */
        public boolean blockBypassCanaries = true;

        public static Settings from(Config c) {
            Settings s = new Settings();
            s.nullRoute = c.get("blocking.mode", "nxdomain").trim().equalsIgnoreCase("nullroute");
            s.blockedTtl = c.getInt("blocking.ttl", 60);
            s.maxTtl = c.getInt("cache.maxTtl", 86_400);
            s.negativeTtl = c.getInt("cache.negativeTtl", 300);
            s.logQueries = Boolean.parseBoolean(c.get("dns.logQueries", "true").trim());
            s.maxUpstreamInFlight = c.getInt("upstream.maxInFlight", 12);
            s.maxUdpSize = Math.max(512, c.getInt("dns.maxUdpSize", 1232));
            s.cnameInspection = Boolean.parseBoolean(c.get("blocking.cnameInspection", "true").trim());
            s.blockBypassCanaries = Boolean.parseBoolean(c.get("dns.blockBypassCanaries", "true").trim());
            return s;
        }
    }

    /**
     * Canary domains: a network that answers NXDOMAIN for these asks the client not to bypass it.
     *   use-application-dns.net   Firefox turns off its built-in DNS-over-HTTPS
     *   mask.icloud.com, mask-h2.icloud.com   Apple turns off iCloud Private Relay
     * Always NXDOMAIN, even in null-route mode: a 0.0.0.0 answer would count as "go ahead".
     */
    static final Set<String> BYPASS_CANARIES = Set.of("use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com");

    private final Blocklist blocklist;
    private final DnsCache cache;
    private final UpstreamResolver upstream;
    private final StatsCollector stats;
    private final Settings settings;
    private final Semaphore upstreamSlots;           // null = unlimited
    private final AtomicLong upstreamBusy = new AtomicLong();

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
        this.upstreamSlots = settings.maxUpstreamInFlight > 0 ? new Semaphore(settings.maxUpstreamInFlight) : null;
    }

    /** Queries answered SERVFAIL at once because maxUpstreamInFlight lookups were already running. */
    public long upstreamBusy() { return upstreamBusy.get(); }

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
        return resolve(query, clientIp, Transport.UDP).reply;
    }

    /** Same pipeline, but also reports the decision - used by the HTTP "test a domain" endpoint. */
    public Result resolve(byte[] query, String clientIp) {
        return resolve(query, clientIp, Transport.HTTP);
    }

    public Result resolve(byte[] query, String clientIp, Transport transport) {
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
        String domain = DnsNames.lower(q.name);              // A-Z only: locale-independent (RFC 4343)
        String type = DnsQuestion.typeName(q.type);

        // Exactly one question (RFC 9619). Only the first would be checked against the blocklist,
        // so a second question could carry a blocked name straight to the upstream.
        if (msg.questions.size() > 1) {
            byte[] reply = DnsWriter.buildErrorResponse(query, query.length, DnsHeader.RCODE_FORMERR);
            return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.ERROR, null,
                    "FORMERR (" + msg.questions.size() + " questions)");
        }

        if (msg.header.getOpcode() != 0) { // only standard QUERY; no IQUERY/STATUS/NOTIFY/UPDATE
            byte[] reply = DnsWriter.buildErrorResponse(query, query.length, RCODE_NOTIMP);
            return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.ERROR, null,
                    "NOTIMP (opcode " + msg.header.getOpcode() + ")");
        }

        // 2. Blocklist (and the canaries that would let browsers route DNS around us).
        if (settings.blockBypassCanaries && BYPASS_CANARIES.contains(domain)) {
            return finish(DnsWriter.buildBlockedResponse(query, query.length), start, clientIp, domain, type,
                    QueryLogEntry.Status.BLOCKED, "bypass-canary", "BLOCKED [bypass-canary]");
        }
        String category = blocklist.check(domain);
        if (category != null) {
            return finish(blockedReply(query), start, clientIp, domain, type, QueryLogEntry.Status.BLOCKED, category,
                    "BLOCKED [" + category + "]");
        }

        // 3. Cache. Aliases are re-checked on every hit, so blocking a tracker also stops
        //    cached answers that point at it.
        DnsWriter.Edns edns = DnsWriter.edns(query, query.length);
        String key = DnsCache.key(domain, q.type, edns);
        DnsCache.Hit hit = cache.lookup(key);
        if (hit != null) {
            String[] cloaked = blockedAlias(domain, hit.aliases);
            if (cloaked != null) {
                return finish(blockedReply(query), start, clientIp, domain, type, QueryLogEntry.Status.BLOCKED,
                        cloaked[1], "BLOCKED via CNAME " + cloaked[0] + " [" + cloaked[1] + "] (cached)");
            }
            byte[] reply = fit(DnsWriter.prepareCachedReply(hit.reply, query, query.length), query, edns, transport);
            return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.CACHED, null,
                    reply.length < hit.reply.length ? "CACHED, truncated (TC) for UDP" : "CACHED");
        }

        // 4. Forward to upstream; on timeout/error answer SERVFAIL so the client doesn't hang.
        //    If too many lookups are already waiting on upstream, fail fast instead of queueing.
        if (upstreamSlots != null && !upstreamSlots.tryAcquire()) {
            upstreamBusy.incrementAndGet();
            byte[] reply = DnsWriter.buildErrorResponse(query, query.length, DnsHeader.RCODE_SERVFAIL);
            return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.ERROR, null,
                    "SERVFAIL (upstream busy: " + settings.maxUpstreamInFlight + " lookups in flight)");
        }
        byte[] reply;
        try {
            reply = transport == Transport.TCP ? upstream.forwardTcp(query) : upstream.forward(query);
        } catch (Exception e) {
            reply = DnsWriter.buildErrorResponse(query, query.length, DnsHeader.RCODE_SERVFAIL);
            return finish(reply, start, clientIp, domain, type, QueryLogEntry.Status.ERROR, null,
                    "SERVFAIL (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
        } finally {
            if (upstreamSlots != null) upstreamSlots.release();
        }

        String outcome;
        try {
            DnsMessage resp = new DnsParser(reply, reply.length).parse();
            List<String> aliases = aliases(resp);
            long ttl = cacheTtl(resp, q);
            if (ttl > 0) cache.put(key, reply, ttl, aliases);   // cached even if blocked: re-checked per hit
            String[] cloaked = blockedAlias(domain, aliases);
            if (cloaked != null) {
                return finish(blockedReply(query), start, clientIp, domain, type, QueryLogEntry.Status.BLOCKED,
                        cloaked[1], "BLOCKED via CNAME " + cloaked[0] + " [" + cloaked[1] + "]");
            }
            outcome = DnsHeader.rcodeName(resp.header.getRcode()) + ", " + resp.answers.size()
                    + " answer(s), " + (ttl > 0 ? "cached " + ttl + "s" : "not cached");
        } catch (DnsParseException e) {
            // We can't fully parse it, but the client might - relay it anyway (uncached) and log why.
            outcome = "unparsed reply, not cached (" + e.getMessage() + ")";
        }
        byte[] fitted = fit(reply, query, edns, transport);
        if (fitted != reply) outcome += ", truncated (TC) for UDP";
        return finish(fitted, start, clientIp, domain, type, QueryLogEntry.Status.FORWARDED, null, outcome);
    }

    /**
     * A UDP reply bigger than the client accepts would be cut off by the network stack (or dropped),
     * so send an empty TC=1 reply instead and let the client retry over TCP. The limit is the
     * client's (512, or its EDNS size) but never above maxUdpSize, whatever the client claims.
     */
    private byte[] fit(byte[] reply, byte[] query, DnsWriter.Edns edns, Transport transport) {
        int limit = Math.min(edns.udpSize, settings.maxUdpSize);
        if (transport != Transport.UDP || reply.length <= limit) return reply;
        int rcode = reply.length > 3 ? reply[3] & DnsHeader.MASK_RCODE : DnsHeader.RCODE_NOERROR;
        return DnsWriter.buildTruncatedResponse(query, query.length, rcode);
    }

    /**
     * How long to cache an upstream reply, or 0 to skip caching.
     *  - must answer the question we asked (guards against a mismatched reply poisoning another key)
     *  - never cache truncated replies or errors like SERVFAIL / REFUSED
     *  - NOERROR with answers: smallest answer TTL, capped at maxTtl
     *  - NXDOMAIN / NODATA: negative caching per RFC 2308 section 5 - the smaller of the SOA
     *    record's TTL and its MINIMUM field, capped at negativeTtl; no SOA means don't cache
     */
    long cacheTtl(DnsMessage resp, DnsQuestion asked) {
        if (resp.header.isTruncated() || resp.questions.size() != 1) return 0;
        DnsQuestion rq = resp.questions.get(0);
        if (!DnsNames.equalsIgnoreCase(rq.name, asked.name) || rq.type != asked.type) return 0;

        int rcode = resp.header.getRcode();
        if (rcode == DnsHeader.RCODE_NOERROR && !resp.answers.isEmpty()) {
            return Math.min(resp.minAnswerTtl(), settings.maxTtl);
        }
        if (rcode == DnsHeader.RCODE_NXDOMAIN || rcode == DnsHeader.RCODE_NOERROR) {
            for (DnsRecord r : resp.authorities) {
                if (r.type != DnsQuestion.TYPE_SOA) continue;
                long ttl = r.ttl;
                if (r.rdata != null && r.rdata.length >= 22) {     // MINIMUM = last 4 bytes of SOA RDATA
                    int p = r.rdata.length - 4;
                    long minimum = ((r.rdata[p] & 0xFFL) << 24) | ((r.rdata[p + 1] & 0xFFL) << 16)
                            | ((r.rdata[p + 2] & 0xFFL) << 8) | (r.rdata[p + 3] & 0xFFL);
                    ttl = Math.min(ttl, minimum);
                }
                return Math.min(ttl, settings.negativeTtl);
            }
        }
        return 0;
    }

    private byte[] blockedReply(byte[] query) {
        return settings.nullRoute
                ? DnsWriter.buildNullRouteResponse(query, query.length, settings.blockedTtl)
                : DnsWriter.buildBlockedResponse(query, query.length);
    }

    /** CNAME targets in the answer section (the names the queried name is an alias for). */
    private static List<String> aliases(DnsMessage resp) {
        List<String> out = new ArrayList<>();
        for (DnsRecord r : resp.answers) {
            if (r.type == DnsQuestion.TYPE_CNAME && r.rdataText != null) out.add(DnsNames.lower(r.rdataText));
        }
        return out;
    }

    /**
     * {alias, category} if CNAME inspection is on and one of the aliases is blocked, else null.
     * Skipped when the queried name is allowlisted: allowing a site means allowing its CDN aliases.
     */
    private String[] blockedAlias(String domain, List<String> aliases) {
        if (!settings.cnameInspection || aliases.isEmpty() || blocklist.isAllowlisted(domain)) return null;
        for (String alias : aliases) {
            String category = blocklist.check(alias);
            if (category != null) return new String[]{alias, category};
        }
        return null;
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
