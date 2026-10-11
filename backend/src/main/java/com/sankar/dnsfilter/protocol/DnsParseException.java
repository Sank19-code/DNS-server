package com.sankar.dnsfilter.protocol;

/**
 * Thrown when a packet is malformed (truncated, bad label, pointer loop, ...).
 * Callers catch this and drop / FORMERR the packet instead of crashing the server.
 */
public class DnsParseException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public DnsParseException(String message) { super(message); }
}
