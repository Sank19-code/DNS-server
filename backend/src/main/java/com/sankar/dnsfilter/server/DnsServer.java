package com.sankar.dnsfilter.server;

import com.sankar.dnsfilter.cache.DnsCache;
import com.sankar.dnsfilter.config.Config;
import com.sankar.dnsfilter.filter.Blocklist;
import com.sankar.dnsfilter.resolver.UpstreamResolver;
import com.sankar.dnsfilter.stats.StatsCollector;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * UDP listener. Receives each query and hands it to a worker thread so one slow
 * upstream lookup never blocks other clients.
 */
public class DnsServer {
    private static final int MAX_UDP = 512; // classic DNS-over-UDP limit (EDNS can go bigger)

    private final Config config;
    private final QueryHandler handler;
    private final ExecutorService workers = Executors.newFixedThreadPool(16);

    public DnsServer(Config config, Blocklist blocklist, DnsCache cache,
                     UpstreamResolver upstream, StatsCollector stats) {
        this.config = config;
        this.handler = new QueryHandler(blocklist, cache, upstream, stats);
    }

    public void start() throws Exception {
        int port = config.getInt("dns.port", 5300);
        String bind = config.get("dns.bind", "0.0.0.0");
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(bind, port))) {
            System.out.println("DNS server listening on " + bind + ":" + port + " (UDP)");
            while (true) {
                byte[] buf = new byte[4096];
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);
                byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
                workers.submit(() -> {
                    try {
                        byte[] reply = handler.handle(data, packet.getAddress().getHostAddress());
                        if (reply != null) {
                            socket.send(new DatagramPacket(reply, reply.length, packet.getSocketAddress()));
                        }
                    } catch (Exception e) {
                        System.err.println("Error handling query: " + e.getMessage());
                    }
                });
            }
        }
    }
}
