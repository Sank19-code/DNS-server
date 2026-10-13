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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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
 *   POST   /api/blocklist/reload           re-download remote lists, re-read local files   *
 *   GET    /api/allowlist
 *   POST   /api/allowlist   {domain}             *
 *   DELETE /api/allowlist?domain=x               *
 *   GET    /api/cache                      cache size / hit ratio / evictions
 *   DELETE /api/cache                      flush the cache                 *
 *   GET    /                               the built dashboard (frontend/dist), if present
 *
 *  * = mutating.
 *
 * Access control (the query log is the user's browsing history, and the lists decide what resolves):
 *  - Admin token (env DNSFILTER_API_TOKEN or api.token): when set, every endpoint except /api/health
 *    needs "Authorization: Bearer <token>". api.publicReads=true makes GETs public again (public demo).
 *  - No token is only allowed while the API is bound to loopback (api.bind=127.0.0.1, the default).
 *    Binding to another address without a token refuses to start, unless api.insecure=true.
 *  - Cross-site requests: a mutating request whose Origin is neither this server nor api.corsOrigin
 *    gets 403, and POST bodies must be application/json (so a plain HTML form can't send one).
 *    Without this, any web page you visit could POST to http://localhost:8081/api/allowlist.
 *  - DNS rebinding: without a token, the Host header must be an IP literal, localhost, or listed in
 *    api.allowedHosts, so evil.example re-pointed at 127.0.0.1 can't read the API as "same origin".
 *  - CORS headers are only sent for the single origin in api.corsOrigin. "*" is ignored without a token.
 *
 * Errors are JSON: {"error": "..."} with a proper status (400, 401, 403, 404, 405, 413, 415, 429).
 */
public class ApiServer {
    private static final int MAX_BODY_BYTES = 4096;
    static final int MIN_TOKEN_LENGTH = 16;
    private static final Pattern CATEGORY = Pattern.compile("^[a-z0-9_-]{1,32}$");
    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    private final Config config;
    private final StatsCollector stats;
    private final Blocklist blocklist;
    private final DnsCache cache;
    private final QueryHandler handler;
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final SecureRandom random = new SecureRandom();
    private final RateLimiter resolveLimiter;
    private final String adminToken;
    private final String corsOrigin;      // null = no CORS headers (same-origin only)
    private final boolean publicReads;
    private final boolean insecure;
    private final Set<String> allowedHosts;
    private Runnable reloadBlocklists = () -> { throw new ApiException(501, "blocklist reload not configured"); };

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
        if (adminToken != null && adminToken.length() < MIN_TOKEN_LENGTH) {
            // Nothing slows down guessing (no lockout), so the token itself has to be strong.
            throw new IllegalStateException("api.token is too short (" + adminToken.length() + " characters, need "
                    + MIN_TOKEN_LENGTH + "+). Generate one with: openssl rand -hex 24");
        }
        this.publicReads = Boolean.parseBoolean(config.get("api.publicReads", "false").trim());
        this.insecure = Boolean.parseBoolean(config.get("api.insecure", "false").trim());
        this.allowedHosts = new HashSet<>();
        for (String h : config.get("api.allowedHosts", "").split(",")) {
            if (!h.isBlank()) allowedHosts.add(h.trim().toLowerCase(Locale.ROOT));
        }
        String origin = config.get("api.corsOrigin", "").trim();
        if (origin.endsWith("/")) origin = origin.substring(0, origin.length() - 1);
        if (origin.equals("*") && adminToken == null) {
            System.err.println("API: ignoring api.corsOrigin=* because no admin token is set "
                    + "(any web page could read and change this server)");
            origin = "";
        }
        this.corsOrigin = origin.isEmpty() ? null : origin;
    }

    /** Wires POST /api/blocklist/reload (re-download remote lists, re-read local files). */
    public void onReloadBlocklists(Runnable action) { this.reloadBlocklists = action; }

    /** Starts the server and returns the bound port (useful with api.port=0 in tests). */
    public int start() throws IOException {
        String bind = config.get("api.bind", "127.0.0.1").trim();
        int port = config.getInt("api.port", 8081);
        InetSocketAddress address = new InetSocketAddress(bind, port);
        if (adminToken == null && !address.getAddress().isLoopbackAddress() && !insecure) {
            throw new IllegalStateException("Refusing to expose the API on " + bind + " without an admin token: "
                    + "anyone who can reach it could read your query log and edit the blocklist. "
                    + "Set DNSFILTER_API_TOKEN, or bind to 127.0.0.1, or set api.insecure=true if you really mean it.");
        }
        applyHttpServerLimits(config);
        server = HttpServer.create(address, 0);
        // Fixed pool; waiting exchanges are bounded by jdk.httpserver.maxConnections (one per connection).
        executor = Executors.newFixedThreadPool(config.getInt("api.threads", 8));
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
        route("/api/blocklist/reload", Map.of("POST", r -> {
            r.requireAdmin();
            reloadBlocklists.run();
            return getBlocklist(r);
        }));
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
                + (adminToken == null ? " (no admin token: open to this machine only - dev mode)"
                   : publicReads ? " (admin token required for POST/DELETE; reads are public)"
                   : " (admin token required)"));
        if (adminToken == null && insecure && !address.getAddress().isLoopbackAddress()) {
            System.err.println("WARNING: api.insecure=true - the API on " + bind + " has no token. "
                    + "Anyone who can reach port " + bound + " can see every query and edit the lists.");
        }
        return bound;
    }

    /**
     * The JDK HttpServer has no limits by default: unlimited connections, and a client may take
     * forever to send its headers (Slowloris). It reads these JVM properties once, when the first
     * server is created, so they're set here unless already given with -D.
     *   jdk.httpserver.maxConnections   api.maxConnections   [100]  extra connections are closed
     *   sun.net.httpserver.maxReqTime   api.maxHeaderSec     [10]   seconds to send request headers
     *   sun.net.httpserver.maxRspTime   api.maxResponseSec   [30]   seconds to read our response
     *   sun.net.httpserver.idleInterval api.idleSec          [30]   keep-alive connections closed after
     * The header timer stops before our handler runs, so a slow /api/blocklist/reload isn't cut off.
     * Request bodies are only read after the token check, so an anonymous client can't drip-feed one.
     * Main calls this before anything else: ANY HttpServer created earlier in the JVM would freeze
     * the JDK's settings without these limits.
     * Limit: the JDK server spends a worker thread on each client still sending headers, so many
     * slow clients can stall the API until maxReqTime drops them. Internet-facing, put Caddy (or
     * another reverse proxy) in front - it reads whole requests before passing them on.
     */
    public static void applyHttpServerLimits(Config config) {
        setIfAbsent("jdk.httpserver.maxConnections", config.getInt("api.maxConnections", 100));
        setIfAbsent("sun.net.httpserver.maxReqTime", config.getInt("api.maxHeaderSec", 10));
        setIfAbsent("sun.net.httpserver.maxRspTime", config.getInt("api.maxResponseSec", 30));
        setIfAbsent("sun.net.httpserver.idleInterval", config.getInt("api.idleSec", 30));
    }

    private static void setIfAbsent(String property, int value) {
        if (System.getProperty(property) == null) System.setProperty(property, String.valueOf(value));
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
        b.put("upstreamBusy", handler.upstreamBusy());
        b.put("overloadDrops", stats.overloadDrops());
        b.put("tcpRefused", stats.tcpRefused());
        b.put("tcpTimedOut", stats.tcpTimedOut());
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
        b.put("countingSince", stats.countingSince());
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
        b.put("overrides", blocklist.overrideCount());
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
            // A cross-site <form> or a "simple" fetch can only send text/plain, form-urlencoded or
            // multipart without a CORS preflight. Requiring JSON forces the preflight, which we refuse.
            String type = ex.getRequestHeaders().getFirst("Content-Type");
            if (type == null || !type.trim().toLowerCase(Locale.ROOT).startsWith("application/json")) {
                throw new ApiException(415, "Content-Type must be application/json");
            }
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

        void requireAdmin() { checkToken(ex); }
    }

    /** Constant-time token comparison so the token can't be guessed byte by byte from timing. */
    private void checkToken(HttpExchange ex) {
        if (adminToken == null) return;
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        String given = auth != null && auth.startsWith("Bearer ") ? auth.substring(7).trim() : "";
        if (!MessageDigest.isEqual(given.getBytes(StandardCharsets.UTF_8), adminToken.getBytes(StandardCharsets.UTF_8))) {
            throw new ApiException(401, "admin token required");
        }
    }

    /**
     * Rejects requests a browser was tricked into sending (see the class comment):
     *  - without a token, the Host must be an IP literal, localhost or in api.allowedHosts (DNS rebinding)
     *  - a mutating request may only come from our own origin or the configured api.corsOrigin (CSRF)
     */
    private void checkBrowserRequest(HttpExchange ex) {
        String host = ex.getRequestHeaders().getFirst("Host");
        if (adminToken == null && !trustedHost(host)) {
            throw new ApiException(403, "unexpected Host header; add it to api.allowedHosts or set an admin token");
        }
        String method = ex.getRequestMethod();
        if (method.equals("GET") || method.equals("HEAD")) return;
        String origin = ex.getRequestHeaders().getFirst("Origin");
        if (origin == null) return;                       // not a browser (curl, scripts, tests)
        if (!allowedOrigin(origin, host)) throw new ApiException(403, "cross-origin request refused");
    }

    private boolean allowedOrigin(String origin, String host) {
        if (corsOrigin != null && (corsOrigin.equals("*") || corsOrigin.equalsIgnoreCase(origin))) return true;
        try {
            java.net.URI u = new java.net.URI(origin);
            if (u.getHost() == null) return false;        // "null" origin: sandboxed frame, file://
            String authority = u.getHost() + (u.getPort() >= 0 ? ":" + u.getPort() : "");
            if (host != null && authority.equalsIgnoreCase(host.trim())) return true; // same origin
            // Dev mode: the Vite dev server on another localhost port talks to us directly.
            return adminToken == null && isLoopbackName(u.getHost());
        } catch (java.net.URISyntaxException e) {
            return false;
        }
    }

    private boolean trustedHost(String hostHeader) {
        if (hostHeader == null || hostHeader.isBlank()) return true;   // HTTP/1.0 client, not a browser
        String h = hostHeader.trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("[")) return true;                            // [IPv6]:port literal
        int colon = h.lastIndexOf(':');
        if (colon >= 0) h = h.substring(0, colon);
        return IPV4.matcher(h).matches() || isLoopbackName(h) || allowedHosts.contains(h);
    }

    private static boolean isLoopbackName(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);
        // "127.evil.com" is a hostname an attacker controls, so 127.x must be a real IP literal.
        return h.equals("localhost") || h.endsWith(".localhost") || h.equals("::1")
                || (h.startsWith("127.") && IPV4.matcher(h).matches());
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
                    addCors(ex);   // no headers unless api.corsOrigin is set -> the browser gives up
                    ex.sendResponseHeaders(204, -1);
                    return;
                }
                checkBrowserRequest(ex);
                Handler h = handlers.get(ex.getRequestMethod());
                if (h == null) {
                    ex.getResponseHeaders().add("Allow", String.join(", ", handlers.keySet()));
                    send(ex, 405, Map.of("error", "method not allowed"));
                    return;
                }
                // Reads need the token too (the query log is browsing history), unless publicReads.
                if (!path.equals("/api/health") && !(publicReads && ex.getRequestMethod().equals("GET"))) {
                    checkToken(ex);
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
        StaticFiles.securityHeaders(ex);
        addCors(ex);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    private void addCors(HttpExchange ex) {
        if (corsOrigin == null) return;
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", corsOrigin);
        ex.getResponseHeaders().set("Vary", "Origin");
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
