package com.sankar.dnsfilter.cache;

/**
 * Hand-written LRU cache: HashMap + doubly linked list -> O(1) get/put/evict.
 * (Written by hand instead of LinkedHashMap on purpose - it's the DSA talking point.)
 *
 *   head <-> [most recent] <-> ... <-> [least recent] <-> tail
 *
 * TODO (Day 2): implement get / put / remove / size, then make it thread-safe
 * (synchronized methods are fine for v1).
 */
public class LruCache<K, V> {

    private static class Node<K, V> {
        K key;
        V value;
        Node<K, V> prev, next;
        Node(K key, V value) { this.key = key; this.value = value; }
    }

    private final int capacity;

    public LruCache(int capacity) {
        this.capacity = capacity;
        // TODO: HashMap<K, Node<K,V>> map; sentinel head/tail nodes
    }

    public synchronized V get(K key) {
        // TODO: lookup, move node to front, return value (null if absent)
        throw new UnsupportedOperationException("LruCache.get not implemented yet");
    }

    public synchronized void put(K key, V value) {
        // TODO: insert/update at front; if size > capacity evict node before tail
        throw new UnsupportedOperationException("LruCache.put not implemented yet");
    }

    public synchronized V remove(K key) {
        throw new UnsupportedOperationException("LruCache.remove not implemented yet");
    }

    public synchronized int size() {
        throw new UnsupportedOperationException("LruCache.size not implemented yet");
    }

    public int capacity() { return capacity; }
}
