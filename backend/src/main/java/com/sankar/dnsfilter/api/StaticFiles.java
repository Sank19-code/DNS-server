package com.sankar.dnsfilter.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Serves the built React dashboard (frontend/dist) from the Java server, so production is a
 * single process on a single port: no separate web host, no CORS, no mixed-content problems.
 *
 *  - only GET / HEAD
 *  - path traversal is impossible: the resolved path must stay inside the root directory
 *  - unknown paths fall back to index.html (single-page-app routing)
 *  - hashed assets (/assets/*) are cached for a year, index.html never
 */
class StaticFiles implements HttpHandler {
    private static final Map<String, String> TYPES = Map.ofEntries(
            Map.entry("html", "text/html; charset=utf-8"),
            Map.entry("js", "text/javascript; charset=utf-8"),
            Map.entry("css", "text/css; charset=utf-8"),
            Map.entry("json", "application/json"),
            Map.entry("svg", "image/svg+xml"),
            Map.entry("png", "image/png"),
            Map.entry("jpg", "image/jpeg"),
            Map.entry("gif", "image/gif"),
            Map.entry("ico", "image/x-icon"),
            Map.entry("woff2", "font/woff2"),
            Map.entry("txt", "text/plain; charset=utf-8"));

    private final Path root;

    StaticFiles(Path root) {
        this.root = root.toAbsolutePath().normalize();
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        try {
            String method = ex.getRequestMethod();
            if (!method.equals("GET") && !method.equals("HEAD")) {
                ex.getResponseHeaders().set("Allow", "GET, HEAD");
                ex.sendResponseHeaders(405, -1);
                return;
            }
            String rawPath = ex.getRequestURI().getRawPath();
            String decoded;
            try {
                decoded = URLDecoder.decode(rawPath.replace("+", "%2B"), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                ex.sendResponseHeaders(400, -1);
                return;
            }
            if (decoded.indexOf('\0') >= 0) {
                ex.sendResponseHeaders(400, -1);
                return;
            }
            String rel = decoded.startsWith("/") ? decoded.substring(1) : decoded;
            Path file = root.resolve(rel).normalize();
            if (!file.startsWith(root)) {                       // ../../etc/passwd
                ex.sendResponseHeaders(403, -1);
                return;
            }
            if (rel.isEmpty() || Files.isDirectory(file) || !Files.isRegularFile(file)) {
                if (rel.startsWith("api/") || rel.startsWith("assets/")) {   // real 404s, not SPA routes
                    ex.sendResponseHeaders(404, -1);
                    return;
                }
                file = root.resolve("index.html");
                if (!Files.isRegularFile(file)) {
                    ex.sendResponseHeaders(404, -1);
                    return;
                }
            }
            String name = file.getFileName().toString();
            String ext = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1).toLowerCase() : "";
            ex.getResponseHeaders().set("Content-Type", TYPES.getOrDefault(ext, "application/octet-stream"));
            ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            ex.getResponseHeaders().set("Cache-Control",
                    rel.startsWith("assets/") ? "public, max-age=31536000, immutable" : "no-cache");
            byte[] body = Files.readAllBytes(file);
            if (method.equals("HEAD")) {
                ex.sendResponseHeaders(200, -1);
                return;
            }
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(body); }
        } finally {
            ex.close();
        }
    }
}
