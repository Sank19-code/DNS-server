package com.sankar.dnsfilter.cache;

import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class LruCacheTest {

    @Test
    void evictsLeastRecentlyUsed() {
        LruCache<String, Integer> c = new LruCache<>(2);
        c.put("a", 1);
        c.put("b", 2);
        c.get("a");          // a is now most recent
        c.put("c", 3);       // evicts b
        assertNull(c.get("b"));
        assertEquals(1, c.get("a"));
        assertEquals(3, c.get("c"));
        assertEquals(1, c.evictions());
    }

    @Test
    void putExistingKeyUpdatesValueAndRecency() {
        LruCache<String, Integer> c = new LruCache<>(2);
        c.put("a", 1);
        c.put("b", 2);
        c.put("a", 10);      // update, a becomes most recent, size unchanged
        assertEquals(2, c.size());
        c.put("c", 3);       // evicts b, not a
        assertEquals(10, c.get("a"));
        assertNull(c.get("b"));
    }

    @Test
    void removeAndSize() {
        LruCache<String, Integer> c = new LruCache<>(3);
        assertNull(c.get("missing"));
        assertNull(c.remove("missing"));
        c.put("a", 1);
        c.put("b", 2);
        assertEquals(2, c.size());
        assertEquals(1, c.remove("a"));
        assertEquals(1, c.size());
        assertNull(c.get("a"));
        c.put("c", 3);
        c.put("d", 4);       // capacity 3: b, c, d fit after removing a
        assertEquals(3, c.size());
        assertEquals(2, c.get("b"));
    }

    @Test
    void capacityOneAlwaysHoldsLatest() {
        LruCache<String, Integer> c = new LruCache<>(1);
        c.put("a", 1);
        c.put("b", 2);
        assertNull(c.get("a"));
        assertEquals(2, c.get("b"));
        assertEquals(1, c.size());
    }

    @Test
    void rejectsNonPositiveCapacity() {
        assertThrows(IllegalArgumentException.class, () -> new LruCache<String, Integer>(0));
    }

    @Test
    void concurrentAccessKeepsSizeBounded() throws Exception {
        LruCache<Integer, Integer> c = new LruCache<>(100);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        for (int t = 0; t < 8; t++) {
            int base = t * 10_000;
            pool.submit(() -> {
                for (int i = 0; i < 10_000; i++) {
                    c.put(base + i, i);
                    c.get(base + i / 2);
                }
            });
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        assertEquals(100, c.size());
    }
}
