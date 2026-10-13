package com.sankar.dnsfilter.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sankar.dnsfilter.FakeUpstream;
import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.protocol.DnsQuestion;
import com.sankar.dnsfilter.protocol.DnsWriter;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.server.QueryHandler;
import com.sankar.dnsfilter.stats.StatsCollector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Starts the real HTTP server on a random port and talks to it over HTTP. */
class ApiServerTest {

    private final HttpClient http = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY)
            .connectTimeout(java.time.Duration.ofSeconds(5)).build();
    private FakeUpstream upstream;

    /** Every test request gets a timeout: a server that never answers fails the test, not the build. */
    private static HttpRequest.Builder req(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(java.time.Duration.ofSeconds(20));
    }
    private Blocklist blocklist;
    private DnsCache cache;
    private StatsCollector stats;
    private QueryHandler handler;
    private ApiServer api;
    private String base;

    @BeforeEach
    void setUp() throws Exception {
        upstream = new FakeUpstream();
        blocklist = new Blocklist();
        blocklist.add("doubleclick.net", "ads");
        cache = new DnsCache(100);
        stats = new StatsCollector();
        QueryHandler.Settings s = new QueryHandler.Settings();
        s.logQueries = false;
        handler = new QueryHandler(blocklist, cache, new UpstreamResolver(List.of(upstream.address()), 500), stats, s);
        base = startApi("");
    }

    @AfterEach
    void tearDown() {
        if (api != null) api.stop();
        if (upstream != null) upstream.close();
    }

    private String startApi(String extraConfig) throws Exception {
        if (api != null) api.stop();
        Path cfg = Files.createTempFile("api", ".properties");
        Files.writeString(cfg, "api.port=0\napi.bind=127.0.0.1\napi.resolve.qps=1000\napi.resolve.burst=1000\n" + extraConfig);
        api = new ApiServer(Config.load(cfg.toString()), stats, blocklist, cache, handler);
        return "http://127.0.0.1:" + api.start() + "/api";
    }

    private HttpResponse<String> send(String method, String path, String body, String token) throws Exception {
        HttpRequest.Builder b = req(base + path)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/json");
        if (token != null) b.header("Authorization", "Bearer " + token);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private JsonElement get(String path) throws Exception {
        HttpResponse<String> r = send("GET", path, null, null);
        assertEquals(200, r.statusCode(), r.body());
        return JsonParser.parseString(r.body());
    }

    private void dns(String name) {
        handler.handle(DnsWriter.buildQuery(1, name, DnsQuestion.TYPE_A), "10.0.0.7");
    }

    @Test
    void healthAndStats() throws Exception {
        assertEquals("ok", get("/health").getAsJsonObject().get("status").getAsString());
        dns("google.com");
        dns("google.com");
        dns("ads.doubleclick.net");

        JsonObject s = get("/stats").getAsJsonObject();
        assertEquals(3, s.get("totalQueries").getAsLong());
        assertEquals(1, s.get("blocked").getAsLong());
        assertEquals(1, s.get("cached").getAsLong());
        assertEquals(1, s.get("forwarded").getAsLong());
        assertEquals(33.3, s.get("blockedPercent").getAsDouble(), 1e-9);
        assertEquals(1, s.get("blocklistSize").getAsInt());
        assertEquals(0.5, s.get("cacheHitRatio").getAsDouble(), 1e-9);
        assertTrue(s.getAsJsonObject("latencyMs").has("CACHED"));
        assertEquals(1, s.getAsJsonArray("upstreams").size());
    }

    @Test
    void queriesSupportsLimitStatusAndSearch() throws Exception {
        dns("a.example.com");
        dns("b.example.com");
        dns("doubleclick.net");

        JsonArray all = get("/queries?limit=2").getAsJsonArray();
        assertEquals(2, all.size());
        assertEquals("doubleclick.net", all.get(0).getAsJsonObject().get("domain").getAsString()); // newest first

        JsonArray blocked = get("/queries?status=blocked").getAsJsonArray();
        assertEquals(1, blocked.size());
        assertEquals("ads", blocked.get(0).getAsJsonObject().get("category").getAsString());

        assertEquals(1, get("/queries?search=b.example").getAsJsonArray().size());
        assertEquals(400, send("GET", "/queries?status=nope", null, null).statusCode());
        assertEquals(400, send("GET", "/queries?limit=abc", null, null).statusCode());
    }

    @Test
    void topAndTimeseries() throws Exception {
        dns("google.com");
        dns("google.com");
        dns("github.com");
        dns("doubleclick.net");

        JsonObject top = get("/top?n=5").getAsJsonObject();
        JsonObject first = top.getAsJsonArray("topDomains").get(0).getAsJsonObject();
        assertEquals("google.com", first.get("name").getAsString());
        assertEquals(2, first.get("count").getAsLong());
        assertEquals("doubleclick.net", top.getAsJsonArray("topBlocked").get(0).getAsJsonObject().get("name").getAsString());
        assertEquals("ads", top.getAsJsonArray("blockedByCategory").get(0).getAsJsonObject().get("name").getAsString());

        JsonArray ts = get("/timeseries").getAsJsonArray();
        assertEquals(60, ts.size());
        long lastTwoMinutes = ts.get(58).getAsJsonObject().get("total").getAsLong()
                + ts.get(59).getAsJsonObject().get("total").getAsLong(); // robust to a minute boundary
        assertEquals(4, lastTwoMinutes);
    }

    @Test
    void blocklistCrudTakesEffectImmediately() throws Exception {
        dns("tracker.example.org");                                    // cached as allowed
        HttpResponse<String> add = send("POST", "/blocklist", "{\"domain\":\"Tracker.Example.org\",\"category\":\"trackers\"}", null);
        assertEquals(201, add.statusCode(), add.body());
        assertEquals(200, send("POST", "/blocklist", "{\"domain\":\"tracker.example.org\"}", null).statusCode()); // already there

        JsonObject check = get("/blocklist?domain=x.tracker.example.org").getAsJsonObject();
        assertTrue(check.get("blocked").getAsBoolean());
        assertFalse(check.get("listedExactly").getAsBoolean());          // blocked via its parent

        JsonObject r = get("/resolve?name=tracker.example.org").getAsJsonObject();
        assertEquals("BLOCKED", r.get("status").getAsString());          // block beats the cached answer

        assertEquals(200, send("DELETE", "/blocklist?domain=tracker.example.org", null, null).statusCode());
        assertEquals(404, send("DELETE", "/blocklist?domain=tracker.example.org", null, null).statusCode());
        assertFalse(get("/blocklist?domain=tracker.example.org").getAsJsonObject().get("blocked").getAsBoolean());
    }

    @Test
    void allowlistOverridesBlock() throws Exception {
        assertEquals(201, send("POST", "/allowlist", "{\"domain\":\"safe.doubleclick.net\"}", null).statusCode());
        assertFalse(get("/blocklist?domain=safe.doubleclick.net").getAsJsonObject().get("blocked").getAsBoolean());
        assertEquals(1, get("/allowlist").getAsJsonObject().get("size").getAsInt());
        assertEquals(200, send("DELETE", "/allowlist?domain=safe.doubleclick.net", null, null).statusCode());
        assertEquals(404, send("DELETE", "/allowlist?domain=safe.doubleclick.net", null, null).statusCode());
    }

    @Test
    void validationErrorsAreJson400s() throws Exception {
        for (String body : new String[]{"not json", "[1,2]", "{}", "{\"domain\":\"no spaces allowed.com x\"}",
                "{\"domain\":\"localhost\"}", "{\"domain\":{\"x\":1}}", "{\"domain\":\"ok.com\",\"category\":\"Bad Category!\"}"}) {
            HttpResponse<String> r = send("POST", "/blocklist", body, null);
            assertEquals(400, r.statusCode(), body + " -> " + r.body());
            assertTrue(JsonParser.parseString(r.body()).getAsJsonObject().has("error"));
        }
        assertEquals(413, send("POST", "/blocklist", "{\"domain\":\"" + "a".repeat(5000) + ".com\"}", null).statusCode());
        assertEquals(400, send("GET", "/resolve", null, null).statusCode());
        assertEquals(400, send("GET", "/resolve?name=google.com&type=BOGUS", null, null).statusCode());
    }

    @Test
    void wrongMethodAndUnknownPath() throws Exception {
        HttpResponse<String> r = send("DELETE", "/stats", null, null);
        assertEquals(405, r.statusCode());
        assertTrue(r.headers().firstValue("Allow").isPresent());
        assertEquals(404, send("GET", "/statsXYZ", null, null).statusCode());
        assertEquals(204, send("OPTIONS", "/blocklist", null, null).statusCode());
    }

    @Test
    void resolveRunsTheRealPipeline() throws Exception {
        JsonObject first = get("/resolve?name=example.com&type=A").getAsJsonObject();
        assertEquals("FORWARDED", first.get("status").getAsString());
        assertEquals("NOERROR", first.get("rcode").getAsString());
        assertEquals("0.0.0.0", first.getAsJsonArray("answers").get(0).getAsJsonObject().get("data").getAsString());

        assertEquals("CACHED", get("/resolve?name=example.com").getAsJsonObject().get("status").getAsString());

        JsonObject blocked = get("/resolve?name=ad.doubleclick.net").getAsJsonObject();
        assertEquals("BLOCKED", blocked.get("status").getAsString());
        assertEquals("ads", blocked.get("category").getAsString());
        assertEquals("NXDOMAIN", blocked.get("rcode").getAsString());

        assertEquals("AAAA", get("/resolve?name=example.com&type=aaaa").getAsJsonObject().get("type").getAsString());
        assertEquals(4, stats.total(), "web lookups show up in the stats like any other query");
    }

    @Test
    void cacheEndpoints() throws Exception {
        dns("google.com");
        assertEquals(1, get("/cache").getAsJsonObject().get("size").getAsInt());
        HttpResponse<String> r = send("DELETE", "/cache", null, null);
        assertEquals(200, r.statusCode());
        assertEquals(1, JsonParser.parseString(r.body()).getAsJsonObject().get("flushed").getAsInt());
        assertEquals(0, cache.size());
    }

    @Test
    void adminTokenProtectsMutationsAndReads() throws Exception {
        base = startApi("api.token=s3cret-token-0123456789\n");
        String body = "{\"domain\":\"evil.com\"}";
        assertEquals(401, send("POST", "/blocklist", body, null).statusCode());
        assertEquals(401, send("POST", "/blocklist", body, "wrong").statusCode());
        assertEquals(401, send("DELETE", "/cache", null, null).statusCode());
        assertEquals(201, send("POST", "/blocklist", body, "s3cret-token-0123456789").statusCode());
        // the query log is browsing history: reads need the token too
        assertEquals(401, send("GET", "/queries", null, null).statusCode());
        assertEquals(401, send("GET", "/stats", null, null).statusCode());
        assertEquals(200, send("GET", "/stats", null, "s3cret-token-0123456789").statusCode());
        assertEquals(200, send("GET", "/health", null, null).statusCode(), "health stays open for monitoring");
    }

    @Test
    void publicReadsKeepsGetsOpenButNotMutations() throws Exception {
        base = startApi("api.token=s3cret-token-0123456789\napi.publicReads=true\n");
        assertEquals(200, send("GET", "/queries", null, null).statusCode());
        assertEquals(401, send("POST", "/blocklist", "{\"domain\":\"evil.com\"}", null).statusCode());
    }

    @Test
    void crossSiteBrowserRequestsAreRefused() throws Exception {
        String body = "{\"domain\":\"malware.example\"}";
        // a page on another site POSTing to our localhost API
        assertEquals(403, sendWithOrigin("POST", "/allowlist", body, "https://evil.example").statusCode());
        assertEquals(403, sendWithOrigin("DELETE", "/cache", null, "null").statusCode());
        assertEquals(0, blocklist.allowedSize());
        // the dashboard itself (same origin) and the Vite dev server on another localhost port are fine
        String self = base.substring(0, base.length() - "/api".length());
        assertEquals(201, sendWithOrigin("POST", "/allowlist", body, self).statusCode());
        assertEquals(200, sendWithOrigin("DELETE", "/cache", null, "http://localhost:5173").statusCode());
    }

    @Test
    void postBodyMustBeJson() throws Exception {
        // text/plain is a "simple" request: browsers send it cross-site without asking first
        HttpResponse<String> r = http.send(req(base + "/blocklist")
                .POST(HttpRequest.BodyPublishers.ofString("{\"domain\":\"evil.com\"}"))
                .header("Content-Type", "text/plain").build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(415, r.statusCode());
        assertFalse(blocklist.isListed("evil.com"));
    }

    @Test
    void noCorsHeadersUnlessAnOriginIsConfigured() throws Exception {
        HttpResponse<String> r = sendWithOrigin("OPTIONS", "/blocklist", null, "https://evil.example");
        assertTrue(r.headers().firstValue("Access-Control-Allow-Origin").isEmpty());

        base = startApi("api.corsOrigin=https://dash.example.com\n");
        r = sendWithOrigin("OPTIONS", "/blocklist", null, "https://dash.example.com");
        assertEquals("https://dash.example.com", r.headers().firstValue("Access-Control-Allow-Origin").orElse(""));
        assertEquals(201, sendWithOrigin("POST", "/blocklist", "{\"domain\":\"x.com\"}", "https://dash.example.com").statusCode());

        base = startApi("api.corsOrigin=*\n");   // ignored without a token
        r = sendWithOrigin("GET", "/health", null, "https://evil.example");
        assertTrue(r.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    }

    @Test
    void dnsRebindingHostIsRefusedWithoutToken() throws Exception {
        int port = Integer.parseInt(base.replaceAll(".*:(\\d+)/api", "$1"));
        assertTrue(rawHttp(port, "evil.example:" + port).startsWith("HTTP/1.1 403"));
        assertTrue(rawHttp(port, "127.evil.example").startsWith("HTTP/1.1 403"));
        assertTrue(rawHttp(port, "localhost:" + port).startsWith("HTTP/1.1 200"));
        assertTrue(rawHttp(port, "192.168.1.5:" + port).startsWith("HTTP/1.1 200"));

        base = startApi("api.allowedHosts=mypc.lan\n");
        port = Integer.parseInt(base.replaceAll(".*:(\\d+)/api", "$1"));
        assertTrue(rawHttp(port, "mypc.lan:" + port).startsWith("HTTP/1.1 200"));
    }

    @Test
    void refusesToExposeTheApiWithoutAToken() throws Exception {
        Path cfg = Files.createTempFile("api", ".properties");
        Files.writeString(cfg, "api.port=0\napi.bind=0.0.0.0\n");
        ApiServer open = new ApiServer(Config.load(cfg.toString()), stats, blocklist, cache, handler);
        IllegalStateException e = assertThrows(IllegalStateException.class, open::start);
        assertTrue(e.getMessage().contains("DNSFILTER_API_TOKEN"));

        Files.writeString(cfg, "api.port=0\napi.bind=0.0.0.0\napi.token=s3cret-token-0123456789\n");
        ApiServer withToken = new ApiServer(Config.load(cfg.toString()), stats, blocklist, cache, handler);
        withToken.start();
        withToken.stop();
    }

    private HttpResponse<String> sendWithOrigin(String method, String path, String body, String origin) throws Exception {
        HttpRequest request = req(base + path)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/json")
                .header("Origin", origin).build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    /** GET /api/queries with a hand-written Host header (HttpClient won't let us set one). */
    private static String rawHttp(int port, String host) throws Exception {
        try (Socket s = new Socket("127.0.0.1", port)) {
            s.setSoTimeout(10_000);
            s.getOutputStream().write(("GET /api/queries HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void servesDashboardWithSpaFallbackAndNoTraversal() throws Exception {
        Path dist = Files.createTempDirectory("dist");
        Files.writeString(dist.resolve("index.html"), "<html>dashboard</html>");
        Files.createDirectories(dist.resolve("assets"));
        Files.writeString(dist.resolve("assets/app.js"), "console.log(1)");
        Files.writeString(dist.getParent().resolve("secret-" + dist.getFileName() + ".txt"), "do not serve");
        base = startApi("api.staticDir=" + dist.toAbsolutePath().toString().replace('\\', '/') + "\n");
        String root = base.substring(0, base.length() - "/api".length());

        HttpResponse<String> index = get200(root + "/");
        assertTrue(index.body().contains("dashboard"));
        assertEquals("no-cache", index.headers().firstValue("Cache-Control").orElse(""));

        HttpResponse<String> js = get200(root + "/assets/app.js");
        assertTrue(js.headers().firstValue("Content-Type").orElse("").startsWith("text/javascript"));
        assertTrue(js.headers().firstValue("Cache-Control").orElse("").contains("immutable"));

        // client-side route -> index.html; missing asset -> real 404; API routes still win over "/"
        assertTrue(get200(root + "/some/page").body().contains("dashboard"));
        assertEquals(404, raw(root + "/assets/nope.js").statusCode());
        assertEquals(200, send("GET", "/health", null, null).statusCode());

        // ../ escapes are refused (percent-encoded so the HTTP client can't normalize them away)
        HttpResponse<String> evil = raw(root + "/%2e%2e/secret-" + dist.getFileName() + ".txt");
        assertEquals(403, evil.statusCode());
        assertFalse(evil.body().contains("do not serve"));

        HttpResponse<String> post = http.send(req(root + "/")
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(405, post.statusCode());
    }

    private HttpResponse<String> raw(String url) throws Exception {
        return http.send(req(url).build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get200(String url) throws Exception {
        HttpResponse<String> r = raw(url);
        assertEquals(200, r.statusCode(), url);
        return r;
    }

    @Test
    void reloadEndpointRunsTheReloadAndNeedsTheToken() throws Exception {
        int[] reloads = {0};
        base = startApi("api.token=s3cret-token-0123456789\n");
        api.onReloadBlocklists(() -> reloads[0]++);
        assertEquals(401, send("POST", "/blocklist/reload", null, null).statusCode());
        HttpResponse<String> r = send("POST", "/blocklist/reload", null, "s3cret-token-0123456789");
        assertEquals(200, r.statusCode(), r.body());
        assertEquals(1, reloads[0]);
        assertEquals(1, JsonParser.parseString(r.body()).getAsJsonObject().get("size").getAsInt());
        assertEquals(405, send("GET", "/blocklist/reload", null, "s3cret-token-0123456789").statusCode());
    }

    @Test
    void responsesCannotBeFramedByOtherSites() throws Exception {
        HttpResponse<String> r = send("GET", "/health", null, null);
        assertEquals("DENY", r.headers().firstValue("X-Frame-Options").orElse(""));
        assertEquals("frame-ancestors 'none'", r.headers().firstValue("Content-Security-Policy").orElse(""));

        Path dist = Files.createTempDirectory("dist");
        Files.writeString(dist.resolve("index.html"), "<html>dashboard</html>");
        base = startApi("api.staticDir=" + dist.toAbsolutePath().toString().replace('\\', '/') + "\n");
        HttpResponse<String> page = raw(base.substring(0, base.length() - "/api".length()) + "/");
        assertEquals("DENY", page.headers().firstValue("X-Frame-Options").orElse(""), "the dashboard page itself");
    }

    @Test
    void shortTokensAreRefused() throws Exception {
        Path cfg = Files.createTempFile("api", ".properties");
        Files.writeString(cfg, "api.port=0\napi.bind=127.0.0.1\napi.token=abc123\n");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new ApiServer(Config.load(cfg.toString()), stats, blocklist, cache, handler));
        assertTrue(e.getMessage().contains("too short"));
    }

    @Test
    void statsExposeDropAndRefusalCounters() throws Exception {
        stats.recordOverloadDrop();
        stats.recordTcpRefused();
        JsonObject s = get("/stats").getAsJsonObject();
        assertEquals(1, s.get("overloadDrops").getAsLong());
        assertEquals(1, s.get("tcpRefused").getAsLong());
        assertEquals(0, s.get("tcpTimedOut").getAsLong());
    }

    @Test
    void httpServerLimitsAreAppliedUnlessAlreadySet() throws Exception {
        String before = System.getProperty("sun.net.httpserver.idleInterval");
        try {
            Path cfg = Files.createTempFile("api", ".properties");
            Files.writeString(cfg, "api.idleSec=7\n");
            System.clearProperty("sun.net.httpserver.idleInterval");
            ApiServer.applyHttpServerLimits(Config.load(cfg.toString()));
            assertEquals("7", System.getProperty("sun.net.httpserver.idleInterval"), "set from config when absent");

            System.setProperty("sun.net.httpserver.idleInterval", "77");
            ApiServer.applyHttpServerLimits(Config.load(cfg.toString()));
            assertEquals("77", System.getProperty("sun.net.httpserver.idleInterval"), "a -D value wins");
        } finally {
            if (before == null) System.clearProperty("sun.net.httpserver.idleInterval");
            else System.setProperty("sun.net.httpserver.idleInterval", before);
        }
    }

    @Test
    void stalledRequestHeadersAreDroppedAndTheServerRecovers() throws Exception {
        // Slowloris: many connections that never finish their headers. The JDK server spends a
        // worker thread on each until sun.net.httpserver.maxReqTime (2 s in tests, set in pom.xml;
        // 10 s by default in production) closes it - then normal requests are served again.
        // So the API stalls for at most that long; on the internet, Caddy in front absorbs this.
        int port = Integer.parseInt(base.replaceAll(".*:(\\d+)/api", "$1"));
        Socket[] slow = new Socket[20];
        try {
            for (int i = 0; i < slow.length; i++) {
                slow[i] = new Socket("127.0.0.1", port);
                slow[i].getOutputStream().write("GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: ".getBytes(StandardCharsets.US_ASCII));
            }
            long start = System.nanoTime();
            assertEquals(200, send("GET", "/health", null, null).statusCode());
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertTrue(ms < 10_000, "answered once the header limit dropped the slow clients: " + ms + " ms");
        } finally {
            for (Socket s : slow) if (s != null) s.close();
        }
    }

    @Test
    void resolveIsRateLimited() throws Exception {
        base = startApi("api.resolve.qps=1\napi.resolve.burst=2\n");
        assertEquals(200, send("GET", "/resolve?name=a.com", null, null).statusCode());
        assertEquals(200, send("GET", "/resolve?name=b.com", null, null).statusCode());
        assertEquals(429, send("GET", "/resolve?name=c.com", null, null).statusCode());
    }
}
