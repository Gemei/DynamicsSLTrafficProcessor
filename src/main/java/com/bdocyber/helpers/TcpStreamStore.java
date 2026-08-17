package com.bdocyber.helpers;

import com.bdocyber.models.TcpStream;
import com.bdocyber.models.TcpStreamFrame;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Thread-safe store of TCP conversations keyed by stream key (per connection).
 */
public class TcpStreamStore {

    /** Coalesce UI notifications under load (was 200ms — too chatty for large captures). */
    private static final long NOTIFY_INTERVAL_MS = 500;

    private final Map<String, TcpStream> streams = new LinkedHashMap<>();
    private final AtomicLong globalSeq = new AtomicLong(0);
    private final CopyOnWriteArrayList<Consumer<TcpStreamStore>> listeners = new CopyOnWriteArrayList<>();
    private final Object lock = new Object();
    private final AtomicBoolean notifyScheduled = new AtomicBoolean(false);
    private volatile long lastNotifyMs;
    /** Stream key that most recently received a frame (for UI “last updated” tint). */
    private volatile String lastUpdatedStreamKey;

    public void addListener(Consumer<TcpStreamStore> listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(Consumer<TcpStreamStore> listener) {
        listeners.remove(listener);
    }

    public void addFrame(TcpStreamFrame frame) {
        if (frame == null) {
            return;
        }
        addFrames(List.of(frame));
    }

    /** Batch insert (capture loop) — one notify for the whole batch. */
    public void addFrames(List<TcpStreamFrame> batch) {
        if (batch == null || batch.isEmpty()) {
            return;
        }
        String lastKey = null;
        synchronized (lock) {
            for (TcpStreamFrame frame : batch) {
                if (frame == null) {
                    continue;
                }
                String key = frame.getStreamKey();
                if (key == null || key.isEmpty()) {
                    key = frame.getPeer();
                }
                if (key == null || key.isEmpty()) {
                    continue;
                }
                String peer = frame.getPeer() != null && !frame.getPeer().isEmpty()
                        ? frame.getPeer() : key;
                TcpStream stream = streams.computeIfAbsent(key, k -> new TcpStream(k, peer));
                long seq = globalSeq.incrementAndGet();
                stream.addFrame(frame.withSeq(seq));
                lastKey = key;
            }
            if (lastKey != null) {
                lastUpdatedStreamKey = lastKey;
            }
        }
        scheduleNotify();
    }

    /**
     * Stream key that most recently had frames added via capture ({@code null} if none yet / cleared).
     * Not updated by project {@link #replaceAll} loads.
     */
    public String getLastUpdatedStreamKey() {
        return lastUpdatedStreamKey;
    }

    public List<String> getPeerKeys() {
        synchronized (lock) {
            return new ArrayList<>(streams.keySet());
        }
    }

    public TcpStream getStream(String streamKey) {
        synchronized (lock) {
            return streams.get(streamKey);
        }
    }

    public List<TcpStream> getStreams() {
        synchronized (lock) {
            return new ArrayList<>(streams.values());
        }
    }

    public void clearPeer(String streamKey) {
        synchronized (lock) {
            streams.remove(streamKey);
            if (streamKey != null && streamKey.equals(lastUpdatedStreamKey)) {
                lastUpdatedStreamKey = null;
            }
        }
        fireChangedNow();
    }

    public void clearAll() {
        synchronized (lock) {
            streams.clear();
            globalSeq.set(0);
            lastUpdatedStreamKey = null;
        }
        fireChangedNow();
    }

    /**
     * Replace store contents from a snapshot (e.g. project load). Frames should already have seq set.
     */
    public void replaceAll(List<TcpStreamFrame> frames) {
        synchronized (lock) {
            streams.clear();
            globalSeq.set(0);
            if (frames != null) {
                long maxSeq = 0;
                for (TcpStreamFrame frame : frames) {
                    if (frame == null) {
                        continue;
                    }
                    String key = frame.getStreamKey();
                    if (key == null || key.isEmpty()) {
                        key = frame.getPeer();
                    }
                    if (key == null || key.isEmpty()) {
                        continue;
                    }
                    String peer = frame.getPeer() != null && !frame.getPeer().isEmpty()
                            ? frame.getPeer() : key;
                    TcpStream stream = streams.computeIfAbsent(key, k -> new TcpStream(k, peer));
                    stream.addFrame(frame);
                    if (frame.getSeq() > maxSeq) {
                        maxSeq = frame.getSeq();
                    }
                }
                globalSeq.set(maxSeq);
            }
        }
        fireChangedNow();
    }

    /** Flatten all frames in store order (stream key order, then frame order). */
    public List<TcpStreamFrame> getAllFrames() {
        synchronized (lock) {
            List<TcpStreamFrame> out = new ArrayList<>();
            for (TcpStream s : streams.values()) {
                out.addAll(s.copyFrames());
            }
            return out;
        }
    }

    /** Highest assigned frame sequence (0 if empty). Used to wait for S→C after live inject. */
    public long getCurrentSeq() {
        return globalSeq.get();
    }

    /**
     * Collect server-to-client frames for a stream with seq &gt; afterSeq (capture after an inject).
     */
    public List<TcpStreamFrame> getServerFramesAfter(String streamKey, long afterSeq) {
        List<TcpStreamFrame> out = new ArrayList<>();
        if (streamKey == null) {
            return out;
        }
        synchronized (lock) {
            TcpStream s = streams.get(streamKey);
            if (s == null) {
                return out;
            }
            for (TcpStreamFrame f : s.getFrames()) {
                if (f.getSeq() > afterSeq
                        && f.getDirection() == TcpStreamFrame.Direction.SERVER_TO_CLIENT) {
                    out.add(f);
                }
            }
        }
        return out;
    }

    public int streamCount() {
        synchronized (lock) {
            return streams.size();
        }
    }

    public int frameCount() {
        synchronized (lock) {
            int n = 0;
            for (TcpStream s : streams.values()) {
                n += s.getFrameCount();
            }
            return n;
        }
    }

    public void setStreamHighlight(String streamKey, String highlight) {
        if (streamKey == null) {
            return;
        }
        synchronized (lock) {
            TcpStream s = streams.get(streamKey);
            if (s != null) {
                s.setHighlight(highlight);
            }
        }
        fireChangedNow();
    }

    public void setStreamUserName(String streamKey, String userName) {
        if (streamKey == null) {
            return;
        }
        synchronized (lock) {
            TcpStream s = streams.get(streamKey);
            if (s != null) {
                s.setUserName(userName);
            }
        }
        fireChangedNow();
    }

    public void setFrameUserName(String streamKey, long seq, String userName) {
        if (streamKey == null) {
            return;
        }
        synchronized (lock) {
            TcpStream s = streams.get(streamKey);
            if (s == null) {
                return;
            }
            for (TcpStreamFrame f : s.getFrames()) {
                if (f.getSeq() == seq) {
                    f.setUserName(userName);
                    break;
                }
            }
        }
        fireChangedNow();
    }

    public void setFrameHighlight(String streamKey, long seq, String highlight) {
        if (streamKey == null) {
            return;
        }
        synchronized (lock) {
            TcpStream s = streams.get(streamKey);
            if (s == null) {
                return;
            }
            for (TcpStreamFrame f : s.getFrames()) {
                if (f.getSeq() == seq) {
                    f.setHighlight(highlight);
                    break;
                }
            }
        }
        fireChangedNow();
    }

    public void setFrameHighlights(String streamKey, long[] seqs, String highlight) {
        if (streamKey == null || seqs == null || seqs.length == 0) {
            return;
        }
        java.util.HashSet<Long> want = new java.util.HashSet<>();
        for (long seq : seqs) {
            want.add(seq);
        }
        synchronized (lock) {
            TcpStream s = streams.get(streamKey);
            if (s == null) {
                return;
            }
            for (TcpStreamFrame f : s.getFrames()) {
                if (want.contains(f.getSeq())) {
                    f.setHighlight(highlight);
                }
            }
        }
        fireChangedNow();
    }

    /** Apply stream-level highlights after restore (key → color name). */
    public void applyStreamHighlights(java.util.Map<String, String> map) {
        if (map == null || map.isEmpty()) {
            return;
        }
        synchronized (lock) {
            for (java.util.Map.Entry<String, String> e : map.entrySet()) {
                TcpStream s = streams.get(e.getKey());
                if (s != null) {
                    s.setHighlight(e.getValue());
                }
            }
        }
        fireChangedNow();
    }

    /** Apply stream-level user names after restore (key → name). */
    public void applyStreamNames(java.util.Map<String, String> map) {
        if (map == null || map.isEmpty()) {
            return;
        }
        synchronized (lock) {
            for (java.util.Map.Entry<String, String> e : map.entrySet()) {
                TcpStream s = streams.get(e.getKey());
                if (s != null) {
                    s.setUserName(e.getValue());
                }
            }
        }
        fireChangedNow();
    }

    public java.util.Map<String, String> getStreamHighlights() {
        synchronized (lock) {
            java.util.LinkedHashMap<String, String> out = new java.util.LinkedHashMap<>();
            for (TcpStream s : streams.values()) {
                if (s.getHighlight() != null && !s.getHighlight().isEmpty()) {
                    out.put(s.getStreamKey(), s.getHighlight());
                }
            }
            return out;
        }
    }

    public java.util.Map<String, String> getStreamNames() {
        synchronized (lock) {
            java.util.LinkedHashMap<String, String> out = new java.util.LinkedHashMap<>();
            for (TcpStream s : streams.values()) {
                if (s.getUserName() != null && !s.getUserName().isEmpty()) {
                    out.put(s.getStreamKey(), s.getUserName());
                }
            }
            return out;
        }
    }

    private void scheduleNotify() {
        long now = System.currentTimeMillis();
        if (now - lastNotifyMs >= NOTIFY_INTERVAL_MS) {
            lastNotifyMs = now;
            fireChangedNow();
            return;
        }
        if (notifyScheduled.compareAndSet(false, true)) {
            Thread t = new Thread(() -> {
                try {
                    Thread.sleep(NOTIFY_INTERVAL_MS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
                notifyScheduled.set(false);
                lastNotifyMs = System.currentTimeMillis();
                fireChangedNow();
            }, "dsl-stream-store-notify");
            t.setDaemon(true);
            t.start();
        }
    }

    private void fireChangedNow() {
        for (Consumer<TcpStreamStore> l : listeners) {
            try {
                l.accept(this);
            } catch (Exception ignored) {
            }
        }
    }
}
