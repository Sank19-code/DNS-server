package com.sankar.dnsfilter.api;

import com.google.gson.Gson;
import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.stats.StatsCollector;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Tiny REST API for the React dashboard, using the JDK's built-in HttpServer (no Spring).
 *
 *   GET    /api/health
 *   GET    /api/stats              totals, block %, cache hit %
 *   GET    /api/queries?limit=100  recent query log            (TODO Day 3)
 *   GET    /api/top                top domains / top blocked     (TODO Day 3)
 *   GET    /api/blocklist          size + categories             (TODO Day 3)
 *   POST   /api/blocklist          {domain, category}            (TODO Day 3)
 *   DELETE /api/blocklist?domain=  remove a domain               (TODO Day 3)
 *   POST   /api/allowlist          {domain}                      (TODO Day 3)
 */
public class ApiServer {
    private final Config config;
    private final StatsCollector stats;
    private final Blocklist blocklist;
    private final DnsCache cache;
    private final Gson gson = new Gson();

    public ApiServer(Config config, StatsCollector stats, Blocklist blocklist, DnsCache cache) {
        this.config = config;
        this.stats = stats;
        this.blocklist = blocklist;
        this.cache = cache;
    }

    public void start() throws IOException {
        int port = config.getInt("api.port", 8081);
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));

        server.createContext("/api/health", ex -> sendJson(ex, 200, Map.of("status", "ok")));

        server.createContext("/api/stats", ex -> {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("totalQueries", stats.total());
            body.put("blocked", stats.blocked());
            body.put("cached", stats.cached());
            body.put("forwarded", stats.forwarded());
            body.put("blocklistSize", blocklist.size());
            body.put("cacheHits", cache.hits());
            body.put("cacheMisses", cache.misses());
            sendJson(ex, 200, body);
        });

        server.createContext("/api/queries", ex -> sendJson(ex, 200, stats.recent(100)));

        server.start();
        System.out.println("REST API listening on http://localhost:" + port + "/api");
    }

    private void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*"); // dev: Vite runs on :5173
        ex.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        ex.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
        if ("OPTIONS".equals(ex.getRequestMethod())) {
            ex.sendResponseHeaders(204, -1);
            ex.close();
            return;
        }
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }
}
