package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.stats.StatsCollector;

import java.net.Inet6Address;
import java.net.InetAddress;

/**
 * Decides whether a DNS query gets processed at all. Shared by the UDP and TCP listeners, so a
 * client's budget covers both transports.
 *
 *   1. loopback (nslookup, the benchmark) is exempt, unless dns.rateLimit.exemptLoopback=false
 *   2. per-client token bucket: dns.rateLimit.qps / .burst, at most dns.rateLimit.maxClients tracked
 *   3. global token bucket: dns.rateLimit.globalQps / .globalBurst - the cap that still holds
 *      when a flood comes from thousands of different (or spoofed) addresses
 * Rejected queries are dropped without a reply and counted as rate-limited.
 */
public class Admission {
    private final RateLimiter perClient;
    private final RateLimiter global;
    private final boolean exemptLoopback;
    private final StatsCollector stats;

    public Admission(RateLimiter perClient, RateLimiter global, boolean exemptLoopback, StatsCollector stats) {
        this.perClient = perClient;
        this.global = global;
        this.exemptLoopback = exemptLoopback;
        this.stats = stats;
    }

    public static Admission from(Config config, StatsCollector stats) {
        RateLimiter perClient = new RateLimiter(
                config.getInt("dns.rateLimit.qps", 50),
                config.getInt("dns.rateLimit.burst", 100),
                config.getInt("dns.rateLimit.maxClients", RateLimiter.DEFAULT_MAX_CLIENTS),
                System::currentTimeMillis);
        RateLimiter global = RateLimiter.global(
                config.getInt("dns.rateLimit.globalQps", 2000),
                config.getInt("dns.rateLimit.globalBurst", 4000));
        boolean exempt = Boolean.parseBoolean(config.get("dns.rateLimit.exemptLoopback", "true").trim());
        return new Admission(perClient, global, exempt, stats);
    }

    public boolean admit(InetAddress client) {
        if (exemptLoopback && client.isLoopbackAddress()) return true;
        if (perClient.tryAcquire(clientKey(client)) && global.tryAcquire()) return true;
        stats.recordRateLimited();
        return false;
    }

    /**
     * Who counts as "one client". IPv4: the address. IPv6: the /64 network, because one home or
     * server is normally given a whole /64 (2^64 addresses) - limiting per address would let a
     * single attacker rotate through fresh addresses for ever.
     */
    public static String clientKey(InetAddress client) {
        if (!(client instanceof Inet6Address)) return client.getHostAddress();
        byte[] a = client.getAddress();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i += 2) {
            sb.append(Integer.toHexString(((a[i] & 0xFF) << 8) | (a[i + 1] & 0xFF))).append(':');
        }
        return sb.append(":/64").toString();
    }

    public String describe() {
        return (perClient.enabled() ? "rate limit per client on" : "no per-client limit")
                + (global.enabled() ? ", global cap on" : ", no global cap");
    }

    public RateLimiter perClient() { return perClient; }

    StatsCollector stats() { return stats; }
}
