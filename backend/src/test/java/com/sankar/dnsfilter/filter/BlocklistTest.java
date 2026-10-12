package com.sankar.dnsfilter.filter;

import com.sankar.dnsfilter.config.Config;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class BlocklistTest {

    @Test
    void loaderHandlesPlainHostsAndAdblockFormats() {
        List<String> d = BlocklistLoader.parse(List.of(
                "# comment line",
                "",
                "doubleclick.net",
                "0.0.0.0 ads.example.com   # inline comment",
                "127.0.0.1 localhost",
                "0.0.0.0 0.0.0.0",
                "::1 ip6-localhost",
                "0.0.0.0 a.tracker.io b.tracker.io",
                "||adblock-style.com^",
                "||with-path.com/banner.js",
                "! adblock comment",
                "Mixed.Case.COM.",
                "not a domain at all",
                "bad_label-.com",
                "*.wild.org"));
        assertEquals(List.of("doubleclick.net", "ads.example.com", "a.tracker.io", "b.tracker.io",
                "adblock-style.com", "mixed.case.com", "wild.org"), d);
    }

    @Test
    void blocksDomainAndAllSubdomains() {
        Blocklist b = new Blocklist();
        b.add("doubleclick.net", "ads");
        assertEquals("ads", b.check("doubleclick.net"));
        assertEquals("ads", b.check("ad.doubleclick.net"));
        assertEquals("ads", b.check("x.y.z.DoubleClick.NET."));
        assertNull(b.check("notdoubleclick.net"), "suffix match must be on a label boundary");
        assertNull(b.check("doubleclick.net.evil.com"));
        assertNull(b.check("google.com"));
    }

    @Test
    void neverBlocksOnABareTld() {
        Blocklist b = new Blocklist();
        b.add("com", "oops");
        assertNull(b.check("google.com"));
    }

    @Test
    void mostSpecificRuleWinsAndAllowBeatsBlockAtSameLevel() {
        Blocklist b = new Blocklist();
        b.add("example.com", "ads");
        b.allow("safe.example.com");
        b.add("bad.safe.example.com", "malware");
        b.add("both.com", "ads");
        b.allow("both.com");

        assertEquals("ads", b.check("www.example.com"));
        assertNull(b.check("safe.example.com"));
        assertNull(b.check("cdn.safe.example.com"));
        assertEquals("malware", b.check("x.bad.safe.example.com"));
        assertNull(b.check("both.com"));
    }

    @Test
    void addRemoveAllow() {
        Blocklist b = new Blocklist();
        b.add("Tracker.io.", "trackers");
        assertTrue(b.isListed("tracker.io"));
        assertEquals("trackers", b.remove("TRACKER.IO"));
        assertNull(b.check("tracker.io"));
        b.add("tracker.io", "trackers");
        b.allow("tracker.io");
        assertNull(b.check("tracker.io"));
        assertTrue(b.unallow("tracker.io"));
        assertEquals("trackers", b.check("tracker.io"));
    }

    @Test
    void loadsFilesFromConfigWithCategoryFromFileName() throws Exception {
        Path dir = Files.createTempDirectory("bl");
        Path ads = Files.writeString(dir.resolve("ads.txt"), "doubleclick.net\n0.0.0.0 adnxs.com\n");
        Path mal = Files.writeString(dir.resolve("malware.txt"), "evil.example\n");
        Path allow = Files.writeString(dir.resolve("allowlist.txt"), "good.adnxs.com\n");
        Path cfgFile = Files.writeString(dir.resolve("test.properties"),
                "blocklist.files=" + slash(ads) + ", " + slash(mal) + ", " + slash(dir.resolve("missing.txt")) + "\n"
                        + "allowlist.file=" + slash(allow) + "\n"
                        + "blocklist.remote=\n");

        Blocklist b = new Blocklist();
        b.loadFromConfig(Config.load(cfgFile.toString()));

        assertEquals(3, b.size());
        assertEquals(1, b.allowedSize());
        assertEquals("ads", b.check("ads.doubleclick.net"));
        assertEquals("malware", b.check("www.evil.example"));
        assertNull(b.check("good.adnxs.com"));
        assertEquals(Map.of("ads", 2, "malware", 1), b.categoryCounts());
    }

    @Test
    void apiEditsAreSavedAndSurviveRestartAndReload() throws Exception {
        Path dir = Files.createTempDirectory("bl");
        Path ads = Files.writeString(dir.resolve("ads.txt"), "doubleclick.net\nadnxs.com\n");
        Path allow = Files.writeString(dir.resolve("allowlist.txt"), "good.adnxs.com\n");
        Path overrides = dir.resolve("data/overrides.txt");
        Path cfgFile = Files.writeString(dir.resolve("test.properties"),
                "blocklist.files=" + slash(ads) + "\nallowlist.file=" + slash(allow) + "\nblocklist.remote=\n"
                        + "blocklist.overridesFile=" + slash(overrides) + "\n");
        Config config = Config.load(cfgFile.toString());

        Blocklist first = new Blocklist();
        first.loadFromConfig(config);
        first.add("tracker.example.org", "trackers");
        first.remove("doubleclick.net");                 // listed in ads.txt
        first.allow("safe.example.org");
        first.unallow("good.adnxs.com");                 // listed in allowlist.txt
        assertTrue(Files.exists(overrides), "saved on change, parent directory created");

        Blocklist restarted = new Blocklist();
        restarted.loadFromConfig(config);
        assertEquals("trackers", restarted.check("x.tracker.example.org"));
        assertNull(restarted.check("ad.doubleclick.net"), "the list still has it, the unblock wins");
        assertTrue(restarted.allowedDomains().contains("safe.example.org"));
        assertEquals("ads", restarted.check("good.adnxs.com"), "un-allowed, so the parent block applies");
        assertEquals(4, restarted.overrideCount());

        // a list refresh brings doubleclick.net back from the file, but the unblock is re-applied
        Files.writeString(ads, "doubleclick.net\nadnxs.com\nnew-ad.com\n");
        restarted.reload(config, false);
        assertEquals("ads", restarted.check("new-ad.com"));
        assertNull(restarted.check("doubleclick.net"));
        assertEquals("trackers", restarted.check("tracker.example.org"));

        // re-blocking clears the unblock
        restarted.add("doubleclick.net", "ads");
        Blocklist third = new Blocklist();
        third.loadFromConfig(config);
        assertEquals("ads", third.check("doubleclick.net"));
    }

    @Test
    void reloadSwapsInNewListsWithoutLosingApiEdits() throws Exception {
        Path dir = Files.createTempDirectory("bl");
        Path ads = Files.writeString(dir.resolve("ads.txt"), "old-ad.com\n");
        Path cfgFile = Files.writeString(dir.resolve("test.properties"),
                "blocklist.files=" + slash(ads) + "\nblocklist.remote=\n");
        Config config = Config.load(cfgFile.toString());
        Blocklist b = new Blocklist();
        b.loadFromConfig(config);
        b.add("manual.com", "custom");                   // in-memory override (no overrides file)

        Files.writeString(ads, "new-ad.com\n");
        b.reload(config, false);
        assertNull(b.check("old-ad.com"), "removed from the file -> gone after reload");
        assertEquals("ads", b.check("new-ad.com"));
        assertEquals("custom", b.check("manual.com"));
    }

    @Test
    void remoteSourcesParse() {
        List<RemoteBlocklist.Source> s = RemoteBlocklist.parseSources("ads|https://a/hosts, https://b/list");
        assertEquals(2, s.size());
        assertEquals("ads", s.get(0).category);
        assertEquals("https://a/hosts", s.get(0).url);
        assertEquals("remote", s.get(1).category);
        assertTrue(RemoteBlocklist.parseSources("").isEmpty());
    }

    @Test
    void remoteFetchUsesFreshCacheWithoutNetwork() throws Exception {
        Path dir = Files.createTempDirectory("dl");
        RemoteBlocklist.Source src = RemoteBlocklist.parseSources("ads|http://127.0.0.1:1/never-contacted").get(0);
        Path cached = dir.resolve("ads-" + Integer.toHexString(src.url.hashCode()) + ".txt");
        Files.writeString(cached, "0.0.0.0 cached-ad.com\n");
        assertEquals(List.of("cached-ad.com"), RemoteBlocklist.fetch(src, dir, 24, 500));
    }

    @Test
    void remoteFetchFailureWithNoCacheIsEmptyNotFatal() throws Exception {
        Path dir = Files.createTempDirectory("dl");
        RemoteBlocklist.Source src = RemoteBlocklist.parseSources("ads|http://127.0.0.1:1/unreachable").get(0);
        assertTrue(RemoteBlocklist.fetch(src, dir, 24, 500).isEmpty());
    }

    /** Properties files treat backslashes as escapes, so use forward slashes (fine on Windows too). */
    private static String slash(Path p) { return p.toAbsolutePath().toString().replace('\\', '/'); }
}
