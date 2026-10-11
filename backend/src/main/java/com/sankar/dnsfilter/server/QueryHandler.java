package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsParseException;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsWriter;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.stats.QueryLogEntry;
import com.sankar.dnsfilter.stats.StatsCollector;

/**
 * The core pipeline for a single query:
 *   1. parse      -> DnsParser                                   (Day 1: done)
 *   2. blocked?   -> Blocklist.check(name)  -> DnsWriter.buildBlockedResponse   (Day 2)
 *   3. cached?    -> DnsCache.get(key)      -> DnsWriter.rewriteId              (Day 2)
 *   4. forward    -> UpstreamResolver.forward -> parse TTL -> DnsCache.put      (Day 2)
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
        long start = System.nanoTime();

        // 1. Parse. Malformed packets get FORMERR (if we can at least read the header) or are dropped.
        DnsMessage msg;
        try {
            msg = new DnsParser(query, query.length).parseQuery();
        } catch (DnsParseException e) {
            System.err.println("Malformed query from " + clientIp + ": " + e.getMessage());
            return formErr(query);
        }
        if (msg.header.isResponse() || msg.questions.isEmpty()) {
            System.err.println("Ignoring non-query packet from " + clientIp + ": " + msg.header);
            return null;
        }

        DnsQuestion q = msg.questions.get(0);
        String domain = q.name.toLowerCase();
        String type = DnsQuestion.typeName(q.type);

        // 2-3. Blocklist + cache come on Day 2.

        // 4. Forward to upstream; on timeout/error answer SERVFAIL so the client doesn't hang.
        byte[] reply;
        String outcome;
        QueryLogEntry.Status status = QueryLogEntry.Status.FORWARDED;
        try {
            reply = upstream.forward(query);
        } catch (Exception e) {
            reply = DnsWriter.buildErrorResponse(query, query.length, DnsHeader.RCODE_SERVFAIL);
            status = QueryLogEntry.Status.ERROR;
            outcome = "SERVFAIL (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")";
            return finish(reply, start, clientIp, domain, type, status, outcome);
        }

        // Parse the upstream reply: answers + TTL (the TTL drives the cache on Day 2).
        try {
            DnsMessage resp = new DnsParser(reply, reply.length).parse();
            outcome = DnsHeader.rcodeName(resp.header.getRcode()) + ", " + resp.answers.size()
                    + " answer(s), min TTL " + resp.minAnswerTtl() + "s";
        } catch (DnsParseException e) {
            // We can't fully parse it, but the client might - relay it anyway and log the reason.
            outcome = "unparsed reply (" + e.getMessage() + ")";
        }
        return finish(reply, start, clientIp, domain, type, status, outcome);
    }

    private byte[] finish(byte[] reply, long start, String clientIp, String domain, String type,
                          QueryLogEntry.Status status, String outcome) {
        long micros = (System.nanoTime() - start) / 1000;
        System.out.printf("QUERY %-40s %-5s from %-15s -> %s [%.1f ms]%n",
                domain, type, clientIp, outcome, micros / 1000.0);

        // 5. Record for the dashboard.
        stats.record(new QueryLogEntry(clientIp, domain, type, status, null, micros));
        return reply;
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
