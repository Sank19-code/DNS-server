package com.sankar.dnsfilter.cache;

import java.util.HashMap;
import java.util.Map;

/**
 * Hand-written LRU cache: HashMap + doubly linked list -> O(1) get/put/evict.
 * (Written by hand instead of LinkedHashMap on purpose - it's the DSA talking point.)
 *
 *   head <-> [most recent] <-> ... <-> [least recent] <-> tail
 *
 * head and tail are sentinel nodes, so insert/unlink never need null checks.
 * Thread safety: every public method is synchronized. Simple and correct; DNS lookups
 * spend microseconds in here vs. milliseconds waiting on the network, so the lock
 * is not the bottleneck. (Upgrade path: lock striping / segment the cache by key hash.)
 */
public class LruCache<K, V> {

    private static class Node<K, V> {
        K key;
        V value;
        Node<K, V> prev, next;
        Node(K key, V value) { this.key = key; this.value = value; }
    }

    private final int capacity;
    private final Map<K, Node<K, V>> map;
    private final Node<K, V> head = new Node<>(null, null); // sentinel: head.next = most recent
    private final Node<K, V> tail = new Node<>(null, null); // sentinel: tail.prev = least recent
    private long evictions = 0;

    public LruCache(int capacity) {
        if (capacity <= 0) throw new IllegalArgumentException("capacity must be > 0, got " + capacity);
        this.capacity = capacity;
        // Pre-size so the HashMap never rehashes while the cache fills up (load factor 0.75).
        this.map = new HashMap<>((int) (capacity / 0.75f) + 1);
        head.next = tail;
        tail.prev = head;
    }

    /** @return the value, or null if absent. A hit marks the entry as most recently used. */
    public synchronized V get(K key) {
        Node<K, V> node = map.get(key);
        if (node == null) return null;
        moveToFront(node);
        return node.value;
    }

    /** Inserts or updates; evicts the least recently used entry when over capacity. */
    public synchronized void put(K key, V value) {
        Node<K, V> node = map.get(key);
        if (node != null) {
            node.value = value;
            moveToFront(node);
            return;
        }
        node = new Node<>(key, value);
        map.put(key, node);
        addFront(node);
        if (map.size() > capacity) {
            Node<K, V> lru = tail.prev;
            unlink(lru);
            map.remove(lru.key);
            evictions++;
        }
    }

    /** @return the removed value, or null if absent. */
    public synchronized V remove(K key) {
        Node<K, V> node = map.remove(key);
        if (node == null) return null;
        unlink(node);
        return node.value;
    }

    public synchronized int size() { return map.size(); }

    public synchronized void clear() {
        map.clear();
        head.next = tail;
        tail.prev = head;
    }

    public synchronized long evictions() { return evictions; }

    public int capacity() { return capacity; }

    // ------------------------------------------------------------ list helpers (caller holds lock)

    private void addFront(Node<K, V> node) {
        node.prev = head;
        node.next = head.next;
        head.next.prev = node;
        head.next = node;
    }

    private void unlink(Node<K, V> node) {
        node.prev.next = node.next;
        node.next.prev = node.prev;
        node.prev = node.next = null;
    }

    private void moveToFront(Node<K, V> node) {
        if (head.next == node) return;
        unlink(node);
        addFront(node);
    }
}
