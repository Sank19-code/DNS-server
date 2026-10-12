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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Starts the real HTTP server on a random port and talks to it over HTTP. */
class ApiServerTest {

    private final HttpClient http = HttpClient.newBuilder().proxy(HttpClient.Builder.NO_PROXY).build();
    private FakeUpstream upstream;
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
        upstream.close();
    }

    private String startApi(String extraConfig) throws Exception {
        if (api != null) api.stop();
        Path cfg = Files.createTempFile("api", ".properties");
        Files.writeString(cfg, "api.port=0\napi.bind=127.0.0.1\napi.resolve.qps=1000\napi.resolve.burst=1000\n" + extraConfig);
        api = new ApiServer(Config.load(cfg.toString()), stats, blocklist, cache, handler);
        return "http://127.0.0.1:" + api.start() + "/api";
    }

    private HttpResponse<String> send(String method, String path, String body, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
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
    void adminTokenProtectsMutationsButNotReads() throws Exception {
        base = startApi("api.token=s3cret\n");
        String body = "{\"domain\":\"evil.com\"}";
        assertEquals(401, send("POST", "/blocklist", body, null).statusCode());
        assertEquals(401, send("POST", "/blocklist", body, "wrong").statusCode());
        assertEquals(401, send("DELETE", "/cache", null, null).statusCode());
        assertEquals(201, send("POST", "/blocklist", body, "s3cret").statusCode());
        assertEquals(200, send("GET", "/stats", null, null).statusCode());
    }

    @Test
    void resolveIsRateLimited() throws Exception {
        base = startApi("api.resolve.qps=1\napi.resolve.burst=2\n");
        assertEquals(200, send("GET", "/resolve?name=a.com", null, null).statusCode());
        assertEquals(200, send("GET", "/resolve?name=b.com", null, null).statusCode());
        assertEquals(429, send("GET", "/resolve?name=c.com", null, null).statusCode());
    }
}
