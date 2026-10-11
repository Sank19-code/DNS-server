package com.sankar.dnsfilter.cache;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LruCacheTest {

    @Test
    @Disabled("Enable on Day 2 once LruCache is implemented")
    void evictsLeastRecentlyUsed() {
        LruCache<String, Integer> c = new LruCache<>(2);
        c.put("a", 1);
        c.put("b", 2);
        c.get("a");          // a is now most recent
        c.put("c", 3);       // evicts b
        assertNull(c.get("b"));
        assertEquals(1, c.get("a"));
        assertEquals(3, c.get("c"));
    }
}
