package com.sankar.dnsfilter.config;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class ConfigTest {

    @Test
    void envBeatsSystemPropertyBeatsFile() {
        Properties p = new Properties();
        p.setProperty("upstream.host", "172.17.18.2");
        p.setProperty("dns.port", "5300");
        p.setProperty("cfgtest.only.file", "file");

        Config c = Config.of(Map.of("DNSFILTER_UPSTREAM_HOST", " 1.1.1.1 ", "DNSFILTER_DNS_PORT", "53"), p);
        assertEquals("1.1.1.1", c.get("upstream.host", null));
        assertEquals(53, c.getInt("dns.port", 0));
        assertEquals("file", c.get("cfgtest.only.file", null));
        assertEquals("dflt", c.get("cfgtest.missing", "dflt"));
        assertEquals(7, c.getInt("cfgtest.missing", 7));

        System.setProperty("cfgtest.only.file", "sysprop");
        try {
            assertEquals("sysprop", c.get("cfgtest.only.file", null));
        } finally {
            System.clearProperty("cfgtest.only.file");
        }
    }

    @Test
    void blankEnvIsIgnoredAndBadNumbersFailClearly() {
        Properties p = new Properties();
        p.setProperty("api.port", "80x");
        Config c = Config.of(Map.of("DNSFILTER_API_TOKEN", "  "), p);
        assertEquals("", c.get("api.token", ""));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> c.getInt("api.port", 8081));
        assertTrue(e.getMessage().contains("api.port"));
        assertEquals("DNSFILTER_UPSTREAM_TIMEOUTMS", Config.envName("upstream.timeoutMs"));
    }

    @Test
    void localFileOverridesTheBundledDefaults() throws Exception {
        Path local = Files.createTempFile("config.local", ".properties");
        Files.writeString(local, "cache.maxEntries=12345\n");
        Config c = Config.load(null, local);
        assertEquals(12345, c.getInt("cache.maxEntries", 0), "from the local file");
        assertEquals(5300, c.getInt("dns.port", 0), "everything else still from config.properties");

        Config withoutLocal = Config.load(null, local.resolveSibling("missing.properties"));
        assertEquals(10_000, withoutLocal.getInt("cache.maxEntries", 0), "the bundled default");
    }
}
