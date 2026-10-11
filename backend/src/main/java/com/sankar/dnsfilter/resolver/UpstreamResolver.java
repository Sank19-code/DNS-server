package com.sankar.dnsfilter.resolver;

import com.sankar.dnsfilter.config.Config;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;

/** Forwards a raw query to the upstream resolver (8.8.8.8 by default) and returns its raw reply. */
public class UpstreamResolver {
    private final InetAddress host;
    private final int port;
    private final int timeoutMs;

    public UpstreamResolver(Config config) throws Exception {
        this.host = InetAddress.getByName(config.get("upstream.host", "8.8.8.8"));
        this.port = config.getInt("upstream.port", 53);
        this.timeoutMs = config.getInt("upstream.timeoutMs", 2000);
    }

    public byte[] forward(byte[] query) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            socket.send(new DatagramPacket(query, query.length, host, port));
            byte[] buf = new byte[4096];
            DatagramPacket reply = new DatagramPacket(buf, buf.length);
            socket.receive(reply);
            // TODO: verify reply ID matches query ID; retry / fallback upstream (1.1.1.1) on timeout
            return Arrays.copyOf(reply.getData(), reply.getLength());
        }
    }
}
