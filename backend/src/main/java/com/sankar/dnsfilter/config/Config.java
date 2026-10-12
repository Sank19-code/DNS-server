package com.sankar.dnsfilter.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * Loads config.properties (from the classpath by default, or a file path passed on the command line).
 *
 * Any key can be overridden without editing the file - handy for Docker and servers:
 *   1. environment variable  DNSFILTER_ + key upper-cased with dots -> underscores
 *        upstream.host  ->  DNSFILTER_UPSTREAM_HOST=1.1.1.1
 *        api.token      ->  DNSFILTER_API_TOKEN=...      (keep secrets out of files)
 *   2. JVM system property   -Dupstream.host=1.1.1.1
 *   3. config.local.properties in the working directory (git-ignored: your machine's settings,
 *      e.g. a campus resolver), only when no explicit file path is given
 *   4. the properties file
 */
public class Config {
    public static final String LOCAL_FILE = "config.local.properties";

    private final Properties props = new Properties();
    private final Map<String, String> env;

    Config(Map<String, String> env) { this.env = env; }

    public static Config load(String path) throws IOException {
        return load(path, Paths.get(LOCAL_FILE));
    }

    static Config load(String path, Path localOverrides) throws IOException {
        Config c = new Config(System.getenv());
        if (path != null) {
            try (InputStream in = new FileInputStream(path)) { c.props.load(in); }
            return c;
        }
        try (InputStream in = Config.class.getResourceAsStream("/config.properties")) {
            if (in != null) c.props.load(in);
        }
        if (localOverrides != null && Files.isRegularFile(localOverrides)) {
            Properties local = new Properties();
            try (InputStream in = Files.newInputStream(localOverrides)) { local.load(in); }
            c.props.putAll(local);
            System.out.println("Config: " + local.size() + " setting(s) from " + localOverrides.toAbsolutePath());
        }
        return c;
    }

    public static String envName(String key) {
        return "DNSFILTER_" + key.toUpperCase(Locale.ROOT).replace('.', '_');
    }

    public String get(String key, String def) {
        String v = env.get(envName(key));
        if (v != null && !v.isBlank()) return v.trim();
        v = System.getProperty(key);
        if (v != null && !v.isBlank()) return v.trim();
        return props.getProperty(key, def);
    }

    public int getInt(String key, int def) {
        String v = get(key, null);
        if (v == null || v.isBlank()) return def;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Config " + key + " must be a whole number, got '" + v + "'");
        }
    }

    /** For tests: a config with the given env map and properties. */
    static Config of(Map<String, String> env, Properties p) {
        Config c = new Config(env);
        c.props.putAll(p);
        return c;
    }
}
