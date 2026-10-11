package com.sankar.dnsfilter.filter;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads blocklist files. Supports both formats you'll find online:
 *   plain:      doubleclick.net
 *   hosts file: 0.0.0.0 doubleclick.net
 * Ignores blank lines and # comments.
 */
public class BlocklistLoader {
    public static List<String> load(Path file) throws IOException {
        List<String> domains = new ArrayList<>();
        // TODO (Day 2): Files.readAllLines, strip comments, take last token of each line
        return domains;
    }
}
