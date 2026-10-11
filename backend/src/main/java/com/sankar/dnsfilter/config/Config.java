package com.sankar.dnsfilter.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** Loads config.properties (from classpath by default, or a file path passed on the command line). */
public class Config {
    private final Properties props = new Properties();

    public static Config load(String path) throws IOException {
        Config c = new Config();
        if (path != null) {
            try (InputStream in = new FileInputStream(path)) { c.props.load(in); }
        } else {
            try (InputStream in = Config.class.getResourceAsStream("/config.properties")) {
                if (in != null) c.props.load(in);
            }
        }
        return c;
    }

    public String get(String key, String def) { return props.getProperty(key, def); }

    public int getInt(String key, int def) {
        String v = props.getProperty(key);
        return v == null ? def : Integer.parseInt(v.trim());
    }
}
