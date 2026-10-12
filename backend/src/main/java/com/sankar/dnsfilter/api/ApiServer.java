package com.sankar.dnsfilter.api;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.filter.BlocklistLoader;
import com.sankar.dnsfilter.protocol.DnsHeader;
import com.sankar.dnsfilter.protocol.DnsMessage;
import com.sankar.dnsfilter.protocol.DnsParseException;
import com.sankar.dnsfilter.protocol.DnsParser;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsRecord;
import com.sankar.dnsfilter.protocol.DnsWriter;
import com.sankar.dnsfilter.server.QueryHandler;
import com.sankar.dnsfilter.server.RateLimiter;
import com.sankar.dnsfilter.stats.QueryLogEntry;
import com.sankar.dnsfilter.stats.StatsCollector;
import com.sankar.dnsfilter.stats.TimeSeries;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * REST API for the React dashboard, using the JDK's built-in HttpServer (no Spring).
 *
 *   GET    /api/health
 *   GET    /api/stats                      totals, block %, cache stats, latency p50/p95/p99, uptime
 *   GET    /api/queries?limit=&status=&search=   recent query log (newest first, max 500)
 *   GET    /api/top?n=10                   top domains, top blocked, top clients, blocked by category
 *   GET    /api/timeseries                 queries per minute, last 60 minutes
 *   GET    /api/resolve?name=&type=A       run a lookup through the real pipeline ("test a domain")
 *   GET    /api/blocklist                  size + categories
 *   GET    /api/blocklist?domain=x         is x blocked, and by which rule category
 *   POST   /api/blocklist   {domain, category}   *
 *   DELETE /api/blocklist?domain=x               *
 *   GET    /api/allowlist
 *   POST   /api/allowlist   {domain}             *
 *   DELETE /api/allowlist?domain=x               *
 *   GET    /api/cache                      cache size / hit ratio / evictions
 *   DELETE /api/cache                      flush the cache                 *
 *   GET    /                               the built dashboard (frontend/dist), if present
 *
 *  * = mutating. If an admin token is configured (env DNSFILTER_API_TOKEN or api.token), these
 *      require "Authorization: Bearer <token>". Reads stay public so the dashboard demo works.
 *
 * Errors are JSON: {"error": "..."} with a proper status (400, 401, 404, 405, 413, 429).
 */
public class ApiServer {
    private static final int MAX_BODY_BYTES = 4096;
    private static final Pattern CATEGORY = Pattern.compile("^[a-z0-9_-]{1,32}$");

    private final Config config;
    private final StatsCollector stats;
    private final Blocklist blocklist;
    private final DnsCache cache;
    private final QueryHandler handler;
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final SecureRandom random = new SecureRandom();
    private final RateLimiter resolveLimiter;
    private final String adminToken;
    private final String corsOrigin;

    private HttpServer server;
    private ExecutorService executor;

    public ApiServer(Config config, StatsCollector stats, Blocklist blocklist, DnsCache cache, QueryHandler handler) {
        this.config = config;
        this.stats = stats;
        this.blocklist = blocklist;
        this.cache = cache;
        this.handler = handler;
        // /api/resolve makes the server query upstream, so a public demo must not be a free proxy.
        this.resolveLimiter = new RateLimiter(config.getInt("api.resolve.qps", 5), config.getInt("api.resolve.burst", 20));
        String token = config.get("api.token", ""); // env DNSFILTER_API_TOKEN overrides (see Config)
        this.adminToken = token.isBlank() ? null : token.trim();
        this.corsOrigin = config.get("api.corsOrigin", "*").trim();
    }

    /** Starts the server and returns the bound port (useful with api.port=0 in tests). */
    public int start() throws IOException {
        String bind = config.get("api.bind", "0.0.0.0").trim();
        int port = config.getInt("api.port", 8081);
        server = HttpServer.create(new InetSocketAddress(bind, port), 0);
        executor = Executors.newFixedThreadPool(4);
        server.setExecutor(executor);

        route("/api/health", Map.of("GET", r -> Map.of("status", "ok")));
        route("/api/stats", Map.of("GET", r -> statsBody()));
        route("/api/queries", Map.of("GET", this::queries));
        route("/api/top", Map.of("GET", this::top));
        route("/api/timeseries", Map.of("GET", r -> timeseries()));
        route("/api/resolve", Map.of("GET", this::resolve));
        route("/api/blocklist", Map.of(
                "GET", this::getBlocklist,
                "POST", this::addBlocked,
                "DELETE", this::removeBlocked));
        route("/api/allowlist", Map.of(
                "GET", r -> Map.of("size", blocklist.allowedSize(), "domains", sorted(blocklist.allowedDomains())),
                "POST", this::addAllowed,
                "DELETE", this::removeAllowed));
        route("/api/cache", Map.of(
                "GET", r -> cacheBody(),
                "DELETE", this::flushCache));

        // Production: serve the built dashboard from the same port (see StaticFiles).
        java.nio.file.Path staticDir = java.nio.file.Paths.get(config.get("api.staticDir", "../frontend/dist").trim());
        boolean servingUi = java.nio.file.Files.isRegularFile(staticDir.resolve("index.html"));
        if (servingUi) server.createContext("/", new StaticFiles(staticDir));

        server.start();
        int bound = server.getAddress().getPort();
        if (servingUi) System.out.println("Dashboard served from " + staticDir.toAbsolutePath().normalize()
                + " at http://localhost:" + bound + "/");
        System.out.println("REST API listening on http://" + bind + ":" + bound + "/api"
                + (adminToken == null ? " (no admin token: mutating endpoints are open - dev mode)"
                                      : " (admin token required for POST/DELETE)"));
        return bound;
    }

    public void stop() {
        if (server != null) server.stop(0);
        if (executor != null) executor.shutdownNow();
    }

    // ================================================================== endpoints

    private Map<String, Object> statsBody() {
        long total = stats.total();
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("totalQueries", total);
        b.put("blocked", stats.blocked());
        b.put("cached", stats.cached());
        b.put("forwarded", stats.forwarded());
        b.put("errors", stats.errors());
        b.put("rateLimited", stats.rateLimited());
        b.put("blockedPercent", percent(stats.blocked(), total));
        b.put("blocklistSize", blocklist.size());
        b.put("allowlistSize", blocklist.allowedSize());
        b.put("blocklistCategories", blocklist.categoryCounts());
        b.put("cacheHits", cache.hits());
        b.put("cacheMisses", cache.misses());
        b.put("cacheHitRatio", round(cache.hitRatio()));
        b.put("cacheSize", cache.size());
        b.put("cacheCapacity", cache.capacity());
        b.put("latencyMs", stats.latency());
        b.put("uptimeSeconds", stats.uptimeSeconds());
        b.put("startedAt", stats.startedAt());
        b.put("upstreams", handler.upstream().upstreams().stream().map(a -> a.getHostString() + ":" + a.getPort()).toList());
        return b;
    }

    private Object queries(Request r) {
        int limit = r.intParam("limit", 100, 1, StatsCollector.LOG_SIZE);
        String status = r.param("status");
        String search = r.param("search");
        QueryLogEntry.Status wanted = null;
        if (status != null && !status.isBlank()) {
            try {
                wanted = QueryLogEntry.Status.valueOf(status.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new ApiException(400, "status must be one of BLOCKED, CACHED, FORWARDED, ERROR");
            }
        }
        String needle = search == null ? null : search.trim().toLowerCase(Locale.ROOT);
        List<QueryLogEntry> out = new ArrayList<>();
        for (QueryLogEntry e : stats.recent(StatsCollector.LOG_SIZE)) {
            if (wanted != null && e.status != wanted) continue;
            if (needle != null && !needle.isEmpty() && !e.domain.contains(needle)
                    && (e.clientIp == null || !e.clientIp.contains(needle))) continue;
            out.add(e);
            if (out.size() >= limit) break;
        }
        return out;
    }

    private Object top(Request r) {
        int n = r.intParam("n", 10, 1, 100);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("topDomains", stats.topDomains(n));
        b.put("topBlocked", stats.topBlocked(n));
        b.put("topClients", stats.topClients(n));
        b.put("blockedByCategory", stats.blockedByCategory());
        return b;
    }

    private Object timeseries() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (TimeSeries.Bucket bk : stats.perMinute()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("time", bk.minute * 60_000);
            m.put("total", bk.total);
            m.put("blocked", bk.blocked);
            m.put("cached", bk.cached);
            m.put("forwarded", bk.forwarded);
            m.put("errors", bk.errors);
            out.add(m);
        }
        return out;
    }

    /** Builds a real DNS query and pushes it through the same pipeline as UDP clients. */
    private Object resolve(Request r) {
        if (!resolveLimiter.tryAcquire(r.clientIp())) throw new ApiException(429, "too many lookups, slow down");
        String domain = cleanDomainParam(r.param("name"));
        String typeParam = r.param("type");
        int type = typeParam == null || typeParam.isBlank() ? DnsQuestion.TYPE_A : DnsQuestion.typeCode(typeParam);
        if (type < 0) throw new ApiException(400, "unknown record type: " + typeParam);

        byte[] query = DnsWriter.buildQuery(random.nextInt(0x10000), domain, type);
        QueryHandler.Result res = handler.resolve(query, "web:" + r.clientIp());

        Map<String, Object> b = new LinkedHashMap<>();
        b.put("domain", domain);
        b.put("type", DnsQuestion.typeName(type));
        b.put("status", res.status);
        b.put("category", res.category);
        b.put("latencyMs", res.latencyMicros / 1000.0);
        try {
            DnsMessage m = new DnsParser(res.reply).parse();
            b.put("rcode", DnsHeader.rcodeName(m.header.getRcode()));
            List<Map<String, Object>> answers = new ArrayList<>();
            for (DnsRecord rec : m.answers) {
                Map<String, Object> a = new LinkedHashMap<>();
                a.put("name", rec.name);
                a.put("type", DnsQuestion.typeName(rec.type));
                a.put("ttl", rec.ttl);
                a.put("data", rec.data());
                answers.add(a);
            }
            b.put("answers", answers);
        } catch (DnsParseException | NullPointerException e) {
            b.put("rcode", "UNPARSEABLE");
            b.put("answers", List.of());
        }
        return b;
    }

    private Object getBlocklist(Request r) {
        String q = r.param("domain");
        if (q != null) {
            String domain = cleanDomainParam(q);
            String category = blocklist.check(domain);
            Map<String, Object> b = new LinkedHashMap<>();
            b.put("domain", domain);
            b.put("blocked", category != null);
            b.put("category", category);
            b.put("listedExactly", blocklist.isListed(domain));
            return b;
        }
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("size", blocklist.size());
        b.put("categories", blocklist.categoryCounts());
        b.put("allowlistSize", blocklist.allowedSize());
        return b;
    }

    private Object addBlocked(Request r) {
        r.requireAdmin();
        JsonObject body = r.jsonBody();
        String domain = cleanDomainParam(str(body, "domain"));
        String category = str(body, "category");
        category = category == null || category.isBlank() ? "custom" : category.trim().toLowerCase(Locale.ROOT);
        if (!CATEGORY.matcher(category).matches()) {
            throw new ApiException(400, "category must be 1-32 chars of a-z, 0-9, _ or -");
        }
        boolean existed = blocklist.isListed(domain);
        blocklist.add(domain, category);
        System.out.println("API: blocked " + domain + " [" + category + "]");
        return new Reply(existed ? 200 : 201, Map.of("domain", domain, "category", category, "created", !existed));
    }

    private Object removeBlocked(Request r) {
        r.requireAdmin();
        String domain = cleanDomainParam(r.param("domain"));
        String category = blocklist.remove(domain);
        if (category == null) throw new ApiException(404, domain + " is not on the blocklist");
        System.out.println("API: unblocked " + domain);
        return Map.of("domain", domain, "removed", true, "category", category);
    }

    private Object addAllowed(Request r) {
        r.requireAdmin();
        String domain = cleanDomainParam(str(r.jsonBody(), "domain"));
        boolean existed = blocklist.allowedDomains().contains(domain);
        blocklist.allow(domain);
        System.out.println("API: allowlisted " + domain);
        return new Reply(existed ? 200 : 201, Map.of("domain", domain, "created", !existed));
    }

    private Object removeAllowed(Request r) {
        r.requireAdmin();
        String domain = cleanDomainParam(r.param("domain"));
        if (!blocklist.unallow(domain)) throw new ApiException(404, domain + " is not on the allowlist");
        return Map.of("domain", domain, "removed", true);
    }

    private Map<String, Object> cacheBody() {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("size", cache.size());
        b.put("capacity", cache.capacity());
        b.put("hits", cache.hits());
        b.put("misses", cache.misses());
        b.put("hitRatio", round(cache.hitRatio()));
        b.put("evictions", cache.evictions());
        return b;
    }

    private Object flushCache(Request r) {
        r.requireAdmin();
        int n = cache.size();
        cache.clear();
        System.out.println("API: cache flushed (" + n + " entries)");
        return Map.of("flushed", n);
    }

    // ================================================================== plumbing

    @FunctionalInterface
    private interface Handler {
        Object handle(Request r) throws Exception;
    }

    /** Return this from a handler to choose the status code (default is 200). */
    private static final class Reply {
        final int status;
        final Object body;
        Reply(int status, Object body) { this.status = status; this.body = body; }
    }

    static final class ApiException extends RuntimeException {
        final int status;
        ApiException(int status, String message) { super(message); this.status = status; }
    }

    private final class Request {
        final HttpExchange ex;
        final Map<String, String> query;

        Request(HttpExchange ex) {
            this.ex = ex;
            this.query = parseQuery(ex.getRequestURI().getRawQuery());
        }

        String param(String name) { return query.get(name); }

        int intParam(String name, int def, int min, int max) {
            String v = query.get(name);
            if (v == null || v.isBlank()) return def;
            try {
                return Math.max(min, Math.min(max, Integer.parseInt(v.trim())));
            } catch (NumberFormatException e) {
                throw new ApiException(400, name + " must be a number");
            }
        }

        String clientIp() {
            java.net.InetAddress a = ex.getRemoteAddress().getAddress();
            return a.isLoopbackAddress() ? "localhost" : a.getHostAddress();
        }

        JsonObject jsonBody() {
            String body;
            try (InputStream in = ex.getRequestBody()) {
                byte[] bytes = in.readNBytes(MAX_BODY_BYTES + 1);
                if (bytes.length > MAX_BODY_BYTES) throw new ApiException(413, "body too large (max " + MAX_BODY_BYTES + " bytes)");
                body = new String(bytes, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new ApiException(400, "could not read body");
            }
            try {
                JsonElement el = JsonParser.parseString(body);
                if (!el.isJsonObject()) throw new ApiException(400, "body must be a JSON object");
                return el.getAsJsonObject();
            } catch (JsonParseException | IllegalStateException e) {
                throw new ApiException(400, "malformed JSON");
            }
        }

        /** Constant-time token comparison so the token can't be guessed byte by byte from timing. */
        void requireAdmin() {
            if (adminToken == null) return;
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            String given = auth != null && auth.startsWith("Bearer ") ? auth.substring(7).trim() : "";
            if (!MessageDigest.isEqual(given.getBytes(StandardCharsets.UTF_8), adminToken.getBytes(StandardCharsets.UTF_8))) {
                throw new ApiException(401, "admin token required");
            }
        }
    }

    private void route(String path, Map<String, Handler> handlers) {
        server.createContext(path, ex -> {
            try {
                // HttpServer contexts match by prefix; insist on the exact path.
                if (!ex.getRequestURI().getPath().equals(path)) {
                    send(ex, 404, Map.of("error", "not found"));
                    return;
                }
                if ("OPTIONS".equals(ex.getRequestMethod())) {     // CORS preflight
                    addCors(ex);
                    ex.sendResponseHeaders(204, -1);
                    return;
                }
                Handler h = handlers.get(ex.getRequestMethod());
                if (h == null) {
                    ex.getResponseHeaders().add("Allow", String.join(", ", handlers.keySet()));
                    send(ex, 405, Map.of("error", "method not allowed"));
                    return;
                }
                Object result = h.handle(new Request(ex));
                if (result instanceof Reply rep) send(ex, rep.status, rep.body);
                else send(ex, 200, result);
            } catch (ApiException e) {
                send(ex, e.status, Map.of("error", e.getMessage()));
            } catch (Exception e) {
                System.err.println("API error on " + ex.getRequestMethod() + " " + ex.getRequestURI() + ": " + e);
                send(ex, 500, Map.of("error", "internal error"));
            } finally {
                ex.close();
            }
        });
    }

    private void send(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = gson.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        addCors(ex);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    private void addCors(HttpExchange ex) {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", corsOrigin);
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

    // ================================================================== helpers

    private static String cleanDomainParam(String raw) {
        if (raw == null || raw.isBlank()) throw new ApiException(400, "domain is required");
        String d = BlocklistLoader.clean(raw);
        if (d == null) throw new ApiException(400, "not a valid domain name: " + truncate(raw));
        return d;
    }

    private static String str(JsonObject o, String key) {
        JsonElement e = o.get(key);
        if (e == null || e.isJsonNull()) return null;
        if (!e.isJsonPrimitive()) throw new ApiException(400, key + " must be a string");
        return e.getAsString();
    }

    static Map<String, String> parseQuery(String raw) {
        Map<String, String> out = new HashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            try {
                out.putIfAbsent(URLDecoder.decode(k, StandardCharsets.UTF_8), URLDecoder.decode(v, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException e) {
                throw new ApiException(400, "malformed query string");
            }
        }
        return out;
    }

    private static List<String> sorted(java.util.Set<String> s) {
        List<String> l = new ArrayList<>(s);
        l.sort(null);
        return l.size() > 1000 ? l.subList(0, 1000) : l;
    }

    private static double percent(long part, long whole) {
        return whole == 0 ? 0 : Math.round(part * 1000.0 / whole) / 10.0;
    }

    private static double round(double v) { return Math.round(v * 1000) / 1000.0; }

    private static String truncate(String s) { return s.length() > 80 ? s.substring(0, 80) + "..." : s; }
}
