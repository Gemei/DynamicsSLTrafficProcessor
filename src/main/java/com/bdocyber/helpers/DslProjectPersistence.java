package com.bdocyber.helpers;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import com.bdocyber.models.StreamStep;
import com.bdocyber.models.TcpStreamFrame;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Project-scoped persistence via Burp {@code Persistence.extensionData()}.
 * Data is stored in the open Burp project file (temporary projects lose it when discarded).
 *
 * <p>TCP Streams capture is stored compressed to shrink project files:
 * <ul>
 *   <li>Frame bodies are packed as length-prefixed raw bytes, GZIP'd once, then Base64
 *       ({@code enc=bodies-gzip-v1}) — avoids per-frame Base64 and compresses TDS/SQL well.</li>
 *   <li>The whole JSON document is then GZIP'd and stored as {@code DSLZx1:&lt;base64&gt;}
 *       so repeated keys (streamKey, peer, …) compress too.</li>
 *   <li>Legacy plain JSON with per-frame {@code b64} still loads.</li>
 * </ul>
 */
public final class DslProjectPersistence {

    private static final int SCHEMA_VERSION = 1;
    private static final String KEY_VERSION = "schemaVersion";
    private static final String KEY_MATCH_REPLACE = "matchReplaceJson";
    private static final String KEY_INTERCEPT = "interceptJson";
    private static final String KEY_RELAY = "relayJson";
    private static final String KEY_STREAMS = "tcpStreamsJson";
    private static final String KEY_REPLAY = "streamReplayJson";

    /**
     * Magic prefix for GZIP-compressed UTF-8 JSON stored in a Burp string key.
     * Format: {@code DSLZx1} + Base64(GZIP(utf8)).
     */
    static final String STORAGE_GZIP_PREFIX = "DSLZx1:";
    /** Frame body packing: GZIP of repeated {@code int32 BE length + body bytes}. */
    static final String STREAMS_ENC_BODIES_GZIP = "bodies-gzip-v1";
    private static final int STREAMS_JSON_VERSION = 2;

    /**
     * Cap persisted TCP Streams capture so Burp project files stay usable.
     * Caps apply to uncompressed in-memory body size / frame count before encode.
     */
    public static final int MAX_PERSISTED_FRAMES = 500_000;
    public static final long MAX_PERSISTED_BODY_BYTES = 5L * 1024 * 1024;
    /** Stream Replay steps — kept separately so queries survive even when capture is trimmed. */
    public static final int MAX_REPLAY_STEPS = 500;
    public static final long MAX_REPLAY_BODY_BYTES = 8L * 1024 * 1024;
    /** Per-step body cap (bytes) when encoding Stream Replay. */
    public static final int MAX_REPLAY_STEP_BODY_BYTES = 512 * 1024;

    private final Persistence persistence;
    private final Logging logging;
    private final AtomicBoolean saveScheduled = new AtomicBoolean(false);
    /** Set when a snapshot should be written; cleared only after a successful flush attempt. */
    private final AtomicBoolean dirty = new AtomicBoolean(false);
    private volatile Supplier<Snapshot> snapshotSupplier;
    /** Longer debounce reduces project-file churn during heavy capture. */
    private volatile long debounceMs = 4_000;

    public DslProjectPersistence(Persistence persistence, Logging logging) {
        this.persistence = persistence;
        this.logging = logging;
    }

    public void setSnapshotSupplier(Supplier<Snapshot> supplier) {
        this.snapshotSupplier = supplier;
    }

    public void setDebounceMs(long debounceMs) {
        this.debounceMs = Math.max(200, debounceMs);
    }

    public PersistedObject root() {
        return persistence.extensionData();
    }

    /** Schedule a debounced save (safe to call from UI / hot paths). */
    public void scheduleSave() {
        if (snapshotSupplier == null || persistence == null) {
            return;
        }
        dirty.set(true);
        if (saveScheduled.compareAndSet(false, true)) {
            Thread t = new Thread(() -> {
                try {
                    Thread.sleep(debounceMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    saveScheduled.set(false);
                }
                flushIfDirty();
            }, "dsl-project-save");
            t.setDaemon(true);
            t.start();
        }
    }

    /** Immediate save (extension unload / plugin refresh). */
    public void saveNow() {
        dirty.set(true);
        flushIfDirty();
    }

    /**
     * Write until clean. If capture mutates during a write, loop once more so frames are not lost.
     */
    private void flushIfDirty() {
        if (snapshotSupplier == null || persistence == null) {
            return;
        }
        // At most a few passes if traffic keeps arriving during save
        for (int pass = 0; pass < 4; pass++) {
            if (!dirty.compareAndSet(true, false)) {
                return;
            }
            try {
                Snapshot snap = snapshotSupplier.get();
                if (snap != null) {
                    save(snap);
                }
            } catch (Exception ex) {
                dirty.set(true); // retry later
                logError("Project save failed: " + ex.getMessage());
                return;
            }
        }
        if (dirty.get()) {
            // Still dirty after max passes — schedule another debounced flush
            scheduleSave();
        }
    }

    public void save(Snapshot snap) {
        if (snap == null || persistence == null) {
            return;
        }
        PersistedObject data = root();
        data.setInteger(KEY_VERSION, SCHEMA_VERSION);
        data.setString(KEY_MATCH_REPLACE, encodeMatchReplace(snap));
        data.setString(KEY_INTERCEPT, encodeIntercept(snap));
        data.setString(KEY_RELAY, encodeRelay(snap));
        data.setString(KEY_STREAMS, encodeStreams(snap));
        data.setString(KEY_REPLAY, encodeReplayTabs(snap));
        int frameN = snap.streamFrames != null ? snap.streamFrames.size() : 0;
        int stepN = 0;
        if (snap.replayTabs != null) {
            for (var t : snap.replayTabs) {
                if (t != null && t.steps != null) {
                    stepN += t.steps.size();
                }
            }
        } else if (snap.replaySteps != null) {
            stepN = snap.replaySteps.size();
        }
        logInfo("[+] DSL project state saved (capture frames in mem=" + frameN
                + ", replay steps=" + stepN
                + "; match/replace, intercept, relay)."
                + " TCP Streams stored GZIP-compressed (bodies-gzip-v1 + DSLZx1)."
                + " Caps: last " + MAX_PERSISTED_FRAMES + " frames / "
                + (MAX_PERSISTED_BODY_BYTES / (1024 * 1024)) + " MB capture; "
                + MAX_REPLAY_STEPS + " replay steps / "
                + (MAX_REPLAY_BODY_BYTES / (1024 * 1024)) + " MB replay.");
    }

    public Snapshot load() {
        Snapshot snap = new Snapshot();
        if (persistence == null) {
            return snap;
        }
        PersistedObject data = root();
        Integer ver = data.getInteger(KEY_VERSION);
        if (ver == null) {
            // try reading any key; first run has nothing
            if (data.getString(KEY_MATCH_REPLACE) == null
                    && data.getString(KEY_RELAY) == null
                    && data.getString(KEY_STREAMS) == null) {
                return snap;
            }
        }
        try {
            decodeMatchReplace(data.getString(KEY_MATCH_REPLACE), snap);
            decodeIntercept(data.getString(KEY_INTERCEPT), snap);
            decodeRelay(data.getString(KEY_RELAY), snap);
            decodeStreams(data.getString(KEY_STREAMS), snap);
            decodeReplayIntoSnapshot(data.getString(KEY_REPLAY), snap);
            snap.loaded = true;
            int tabN = snap.replayTabs != null ? snap.replayTabs.size() : 0;
            int stepN = snap.replaySteps != null ? snap.replaySteps.size() : 0;
            logInfo("[+] DSL project state loaded"
                    + " (streams=" + snap.streamFrames.size()
                    + ", replayTabs=" + tabN
                    + ", replaySteps=" + stepN
                    + ", m/r=" + snap.matchReplaceRules.size()
                    + ", intercept=" + snap.interceptRules.size() + ").");
        } catch (Exception ex) {
            logError("Project load failed: " + ex.getMessage());
        }
        return snap;
    }

    public void applyToEngines(Snapshot snap, MatchReplaceEngine matchReplace,
                               InterceptEngine intercept, TcpStreamStore streamStore) {
        if (snap == null || !snap.loaded) {
            return;
        }
        matchReplace.setEnabled(snap.matchReplaceEnabled);

        matchReplace.setRules(snap.matchReplaceRules);

        intercept.setEnabled(snap.interceptEnabled);
        intercept.setTimeoutSeconds(snap.interceptTimeoutSec);
        intercept.setRules(snap.interceptRules);

        // Always replace so a saved empty capture clears in-memory store after reload
        if (snap.streamFrames != null) {
            streamStore.replaceAll(snap.streamFrames);
        }
        if (snap.streamHighlights != null && !snap.streamHighlights.isEmpty()) {
            streamStore.applyStreamHighlights(snap.streamHighlights);
        }
        if (snap.streamNames != null && !snap.streamNames.isEmpty()) {
            streamStore.applyStreamNames(snap.streamNames);
        }
    }

    // --- encoding ---

    private static String encodeMatchReplace(Snapshot s) {
        JSONObject o = new JSONObject();
        o.put("enabled", s.matchReplaceEnabled);

        JSONArray rules = new JSONArray();
        for (MatchReplaceRule r : s.matchReplaceRules) {
            JSONObject jr = new JSONObject();
            jr.put("enabled", r.isEnabled());
            jr.put("target", r.getTarget());
            jr.put("match", r.getMatch());
            jr.put("replace", r.getReplace());
            jr.put("regex", r.isRegex());
            jr.put("encoding", r.getEncoding());
            jr.put("comment", r.getComment());
            rules.put(jr);
        }
        o.put("rules", rules);
        return o.toString();
    }

    private static void decodeMatchReplace(String json, Snapshot s) {
        if (json == null || json.isBlank()) {
            return;
        }
        JSONObject o = new JSONObject(json);
        s.matchReplaceEnabled = o.optBoolean("enabled", true);

        JSONArray rules = o.optJSONArray("rules");
        s.matchReplaceRules = new ArrayList<>();
        if (rules != null) {
            for (int i = 0; i < rules.length(); i++) {
                JSONObject jr = rules.getJSONObject(i);
                s.matchReplaceRules.add(new MatchReplaceRule(
                        jr.optBoolean("enabled", true),
                        jr.optString("target", "BOTH"),
                        jr.optString("match", ""),
                        jr.optString("replace", ""),
                        jr.optBoolean("regex", false),
                        jr.optString("encoding", "UTF16LE"),
                        jr.optString("comment", "")));
            }
        }
    }

    private static String encodeIntercept(Snapshot s) {
        JSONObject o = new JSONObject();
        o.put("enabled", s.interceptEnabled);
        o.put("timeoutSeconds", s.interceptTimeoutSec);
        JSONArray rules = new JSONArray();
        for (InterceptRule r : s.interceptRules) {
            JSONObject jr = new JSONObject();
            jr.put("enabled", r.isEnabled());
            jr.put("target", r.getTarget());
            jr.put("match", r.getMatch());
            jr.put("regex", r.isRegex());
            jr.put("encoding", r.getEncoding());
            jr.put("comment", r.getComment());
            rules.put(jr);
        }
        o.put("rules", rules);
        return o.toString();
    }

    private static void decodeIntercept(String json, Snapshot s) {
        if (json == null || json.isBlank()) {
            return;
        }
        JSONObject o = new JSONObject(json);
        s.interceptEnabled = o.optBoolean("enabled", false);
        s.interceptTimeoutSec = o.optLong("timeoutSeconds", 120);
        JSONArray rules = o.optJSONArray("rules");
        s.interceptRules = new ArrayList<>();
        if (rules != null) {
            for (int i = 0; i < rules.length(); i++) {
                JSONObject jr = rules.getJSONObject(i);
                s.interceptRules.add(new InterceptRule(
                        jr.optBoolean("enabled", true),
                        jr.optString("target", "BOTH"),
                        jr.optString("match", ""),
                        jr.optBoolean("regex", false),
                        jr.optString("encoding", "UTF16LE"),
                        jr.optString("comment", "")));
            }
        }
    }

    private static String encodeRelay(Snapshot s) {
        JSONObject o = new JSONObject();
        o.put("listenHost", s.listenHost != null ? s.listenHost : "0.0.0.0");
        o.put("listenPort", s.listenPort);
        o.put("targetHost", s.targetHost != null ? s.targetHost : "");
        o.put("targetPort", s.targetPort);
        return o.toString();
    }

    private static void decodeRelay(String json, Snapshot s) {
        if (json == null || json.isBlank()) {
            return;
        }
        JSONObject o = new JSONObject(json);
        s.listenHost = o.optString("listenHost", "0.0.0.0");
        s.listenPort = o.optInt("listenPort", 1433);
        s.targetHost = o.optString("targetHost", "192.0.2.1");
        s.targetPort = o.optInt("targetPort", 1433);
        s.relayLoaded = true;
    }

    /**
     * Encode TCP Streams for project storage (compressed). Package-visible for tests.
     */
    static String encodeStreams(Snapshot snap) {
        List<TcpStreamFrame> frames = snap.streamFrames;
        if (frames == null) {
            frames = List.of();
        }
        long bodyBytes = 0;
        int count = 0;
        List<TcpStreamFrame> ordered = frames;
        int start = 0;
        if (ordered.size() > MAX_PERSISTED_FRAMES) {
            start = ordered.size() - MAX_PERSISTED_FRAMES;
        }
        long totalFromStart = 0;
        for (int i = start; i < ordered.size(); i++) {
            totalFromStart += ordered.get(i).getBodyLength();
        }
        while (start < ordered.size() - 1 && totalFromStart > MAX_PERSISTED_BODY_BYTES) {
            totalFromStart -= ordered.get(start).getBodyLength();
            start++;
        }

        JSONArray arr = new JSONArray();
        ByteArrayOutputStream rawBodies = new ByteArrayOutputStream(Math.max(256, (int) Math.min(totalFromStart + 64L, Integer.MAX_VALUE / 4)));
        try (DataOutputStream dos = new DataOutputStream(rawBodies)) {
            for (int i = start; i < ordered.size(); i++) {
                TcpStreamFrame f = ordered.get(i);
                byte[] body = f.bodyRef() != null ? f.bodyRef() : new byte[0];
                JSONObject o = new JSONObject();
                o.put("seq", f.getSeq());
                o.put("ts", f.getTimestamp() != null ? f.getTimestamp().toEpochMilli() : 0L);
                o.put("streamKey", f.getStreamKey());
                o.put("peer", f.getPeer());
                o.put("dir", f.getDirection() == TcpStreamFrame.Direction.CLIENT_TO_SERVER ? "C2S" : "S2C");
                o.put("mod", f.isMatchReplaced());
                o.put("src", f.getSource());
                o.put("len", body.length);
                String hl = HighlightColors.normalize(f.getHighlight());
                if (!hl.isEmpty()) {
                    o.put("hl", hl);
                }
                if (f.getUserName() != null && !f.getUserName().isEmpty()) {
                    o.put("name", f.getUserName());
                }
                arr.put(o);
                dos.writeInt(body.length);
                if (body.length > 0) {
                    dos.write(body);
                }
                bodyBytes += body.length;
                count++;
            }
        } catch (IOException e) {
            // ByteArray streams do not throw; keep empty blob on unexpected failure
            rawBodies.reset();
        }

        JSONObject wrap = new JSONObject();
        wrap.put("v", STREAMS_JSON_VERSION);
        wrap.put("enc", STREAMS_ENC_BODIES_GZIP);
        wrap.put("frames", arr);
        wrap.put("count", count);
        wrap.put("bodyBytes", bodyBytes);
        wrap.put("truncated", start > 0 || frames.size() > MAX_PERSISTED_FRAMES);
        wrap.put("blob", Base64.getEncoder().encodeToString(gzipBytes(rawBodies.toByteArray())));
        if (snap.streamHighlights != null && !snap.streamHighlights.isEmpty()) {
            JSONObject sh = new JSONObject();
            for (var e : snap.streamHighlights.entrySet()) {
                String hl = HighlightColors.normalize(e.getValue());
                if (!hl.isEmpty() && e.getKey() != null) {
                    sh.put(e.getKey(), hl);
                }
            }
            wrap.put("streamHighlights", sh);
        }
        if (snap.streamNames != null && !snap.streamNames.isEmpty()) {
            JSONObject sn = new JSONObject();
            for (var e : snap.streamNames.entrySet()) {
                if (e.getKey() != null && e.getValue() != null && !e.getValue().isBlank()) {
                    sn.put(e.getKey(), e.getValue().trim());
                }
            }
            wrap.put("streamNames", sn);
        }
        return compressForStorage(wrap.toString());
    }

    /**
     * Decode TCP Streams from project storage (compressed or legacy). Package-visible for tests.
     */
    static void decodeStreams(String stored, Snapshot snap) {
        List<TcpStreamFrame> out = new ArrayList<>();
        snap.streamFrames = out;
        if (stored == null || stored.isBlank()) {
            return;
        }
        String json = decompressFromStorage(stored);
        JSONObject wrap;
        JSONArray arr;
        if (json.trim().startsWith("[")) {
            wrap = new JSONObject();
            arr = new JSONArray(json);
        } else {
            wrap = new JSONObject(json);
            arr = wrap.optJSONArray("frames");
            if (arr == null) {
                return;
            }
        }

        String enc = wrap.optString("enc", "");
        List<byte[]> packedBodies = null;
        if (STREAMS_ENC_BODIES_GZIP.equals(enc)) {
            try {
                byte[] gz = Base64.getDecoder().decode(wrap.optString("blob", ""));
                packedBodies = unpackBodiesBlob(gunzipBytes(gz), arr.length());
            } catch (Exception e) {
                packedBodies = List.of();
            }
        }

        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            byte[] body;
            if (packedBodies != null) {
                body = i < packedBodies.size() ? packedBodies.get(i) : new byte[0];
            } else {
                try {
                    body = Base64.getDecoder().decode(o.optString("b64", ""));
                } catch (Exception e) {
                    body = new byte[0];
                }
            }
            String dir = o.optString("dir", "C2S");
            TcpStreamFrame.Direction direction = "S2C".equalsIgnoreCase(dir)
                    || "SERVER_TO_CLIENT".equalsIgnoreCase(dir)
                    || "SERVER_RESPONSE".equalsIgnoreCase(dir)
                    ? TcpStreamFrame.Direction.SERVER_TO_CLIENT
                    : TcpStreamFrame.Direction.CLIENT_TO_SERVER;
            Instant ts = Instant.ofEpochMilli(o.optLong("ts", System.currentTimeMillis()));
            TcpStreamFrame frame = TcpStreamFrame.restore(
                    o.optLong("seq", i + 1L),
                    ts,
                    o.optString("streamKey", o.optString("peer", "")),
                    o.optString("peer", ""),
                    direction,
                    body,
                    o.optBoolean("mod", false),
                    o.optString("src", "restored"));
            frame.setHighlight(HighlightColors.normalize(o.optString("hl", "")));
            if (o.has("name")) {
                frame.setUserName(o.optString("name", ""));
            }
            out.add(frame);
        }
        JSONObject sh = wrap.optJSONObject("streamHighlights");
        if (sh != null) {
            for (String key : sh.keySet()) {
                snap.streamHighlights.put(key, HighlightColors.normalize(sh.optString(key, "")));
            }
        }
        JSONObject sn = wrap.optJSONObject("streamNames");
        if (sn != null) {
            for (String key : sn.keySet()) {
                String name = sn.optString(key, "");
                if (!name.isBlank()) {
                    snap.streamNames.put(key, name.trim());
                }
            }
        }
    }

    /**
     * GZIP + Base64 wrapper for Burp string persistence. Plain JSON (legacy) is returned unchanged
     * by {@link #decompressFromStorage(String)}.
     */
    static String compressForStorage(String plainUtf8) {
        if (plainUtf8 == null) {
            return null;
        }
        byte[] gz = gzipBytes(plainUtf8.getBytes(StandardCharsets.UTF_8));
        return STORAGE_GZIP_PREFIX + Base64.getEncoder().encodeToString(gz);
    }

    /**
     * Inverse of {@link #compressForStorage(String)}. Accepts {@code DSLZx1:} payloads or legacy plain JSON.
     */
    static String decompressFromStorage(String stored) {
        if (stored == null || stored.isEmpty()) {
            return stored;
        }
        if (!stored.startsWith(STORAGE_GZIP_PREFIX)) {
            return stored;
        }
        try {
            byte[] gz = Base64.getDecoder().decode(stored.substring(STORAGE_GZIP_PREFIX.length()));
            return new String(gunzipBytes(gz), StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Corrupt prefix payload — try as plain so load does not wipe project state silently wrong
            return stored;
        }
    }

    static byte[] gzipBytes(byte[] raw) {
        if (raw == null) {
            raw = new byte[0];
        }
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(64, raw.length / 2));
            try (GZIPOutputStream gos = new GZIPOutputStream(bos)) {
                gos.write(raw);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("gzip failed", e);
        }
    }

    static byte[] gunzipBytes(byte[] gz) throws IOException {
        if (gz == null || gz.length == 0) {
            return new byte[0];
        }
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(gz));
             ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(64, gz.length * 2))) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = gis.read(buf)) >= 0) {
                bos.write(buf, 0, n);
            }
            return bos.toByteArray();
        }
    }

    /** Unpack length-prefixed body blob produced by {@link #encodeStreams}. */
    static List<byte[]> unpackBodiesBlob(byte[] raw, int expectedCount) throws IOException {
        List<byte[]> bodies = new ArrayList<>(Math.max(0, expectedCount));
        if (raw == null || raw.length == 0) {
            return bodies;
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(raw))) {
            while (in.available() > 0) {
                int len = in.readInt();
                if (len < 0 || len > MAX_PERSISTED_BODY_BYTES) {
                    throw new IOException("invalid body length: " + len);
                }
                byte[] body = new byte[len];
                if (len > 0) {
                    in.readFully(body);
                }
                bodies.add(body);
            }
        }
        return bodies;
    }

    private static String encodeReplayTabs(Snapshot snap) {
        JSONObject root = new JSONObject();
        root.put("v", 2);
        root.put("selected", snap.replaySelectedTab);
        JSONArray tabs = new JSONArray();
        long bodyBytes = 0;
        List<com.bdocyber.views.StreamReplayPanel.TabSnapshot> list = snap.replayTabs;
        if (list == null || list.isEmpty()) {
            // Legacy single list
            if (snap.replaySteps != null && !snap.replaySteps.isEmpty()) {
                JSONObject t = new JSONObject();
                t.put("number", 1);
                t.put("title", "");
                t.put("highlight", "");
                StepsEnc se = encodeStepsArray(snap.replaySteps, bodyBytes);
                t.put("steps", se.arr);
                tabs.put(t);
            }
        } else {
            for (com.bdocyber.views.StreamReplayPanel.TabSnapshot tab : list) {
                if (tab == null) {
                    continue;
                }
                JSONObject t = new JSONObject();
                t.put("number", tab.number);
                t.put("title", tab.title != null ? tab.title : "");
                t.put("highlight", HighlightColors.normalize(tab.highlight));
                StepsEnc se = encodeStepsArray(tab.steps, bodyBytes);
                bodyBytes = se.bodyBytes;
                t.put("steps", se.arr);
                tabs.put(t);
                if (bodyBytes > MAX_REPLAY_BODY_BYTES) {
                    break;
                }
            }
        }
        root.put("tabs", tabs);
        return root.toString();
    }

    private static final class StepsEnc {
        final JSONArray arr;
        final long bodyBytes;

        StepsEnc(JSONArray arr, long bodyBytes) {
            this.arr = arr;
            this.bodyBytes = bodyBytes;
        }
    }

    private static StepsEnc encodeStepsArray(List<StreamStep> steps, long bodyBytesStart) {
        JSONArray arr = new JSONArray();
        long bodyBytes = bodyBytesStart;
        if (steps == null) {
            return new StepsEnc(arr, bodyBytes);
        }
        int stepCount = 0;
        for (StreamStep s : steps) {
            if (stepCount >= MAX_REPLAY_STEPS || bodyBytes > MAX_REPLAY_BODY_BYTES) {
                break;
            }
            JSONObject o = new JSONObject();
            o.put("mode", s.getMode().name());
            o.put("direction", s.getDirection());
            o.put("peer", s.getPeer() != null ? s.getPeer() : "");
            o.put("streamKey", s.getStreamKey() != null ? s.getStreamKey() : "");
            o.put("path", s.getPath() != null ? s.getPath() : "");
            o.put("include", s.isInclude());
            o.put("summary", s.getSummary() != null ? s.getSummary() : "");
            byte[] body = s.getRawBody();
            if (body == null) {
                body = new byte[0];
            }
            boolean truncatedBody = false;
            if (body.length > MAX_REPLAY_STEP_BODY_BYTES) {
                body = Arrays.copyOf(body, MAX_REPLAY_STEP_BODY_BYTES);
                truncatedBody = true;
            }
            o.put("b64", Base64.getEncoder().encodeToString(body));
            o.put("bodyLen", s.getBodyLength());
            if (truncatedBody) {
                o.put("bodyTruncated", true);
            }
            if (s.getMode() == StreamStep.Mode.HTTP && s.getRequest() != null) {
                try {
                    o.put("httpB64", Base64.getEncoder().encodeToString(s.getRequest().toByteArray().getBytes()));
                } catch (Exception ignored) {
                }
            }
            arr.put(o);
            bodyBytes += body.length;
            stepCount++;
        }
        return new StepsEnc(arr, bodyBytes);
    }

    private static void decodeReplayIntoSnapshot(String json, Snapshot snap) {
        snap.replaySteps = new ArrayList<>();
        snap.replayTabs = new ArrayList<>();
        snap.replaySelectedTab = 0;
        if (json == null || json.isBlank()) {
            return;
        }
        JSONObject wrap = new JSONObject(json);
        // v2 multi-tab
        JSONArray tabs = wrap.optJSONArray("tabs");
        if (tabs != null) {
            snap.replaySelectedTab = wrap.optInt("selected", 0);
            for (int i = 0; i < tabs.length(); i++) {
                JSONObject t = tabs.getJSONObject(i);
                com.bdocyber.views.StreamReplayPanel.TabSnapshot tab =
                        new com.bdocyber.views.StreamReplayPanel.TabSnapshot();
                tab.number = t.optInt("number", i + 1);
                tab.title = t.optString("title", "");
                tab.highlight = HighlightColors.normalize(t.optString("highlight", ""));
                tab.steps = decodeStepsArray(t.optJSONArray("steps"));
                snap.replayTabs.add(tab);
                snap.replaySteps.addAll(tab.steps);
            }
            return;
        }
        // Legacy single-list format
        List<StreamStep> steps = decodeStepsArray(wrap.optJSONArray("steps"));
        snap.replaySteps = steps;
        if (!steps.isEmpty()) {
            com.bdocyber.views.StreamReplayPanel.TabSnapshot tab =
                    new com.bdocyber.views.StreamReplayPanel.TabSnapshot();
            tab.number = 1;
            tab.steps = steps;
            snap.replayTabs.add(tab);
        }
    }

    private static List<StreamStep> decodeStepsArray(JSONArray arr) {
        List<StreamStep> out = new ArrayList<>();
        if (arr == null) {
            return out;
        }
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            byte[] body;
            try {
                String b64 = o.optString("b64", "");
                body = b64.isEmpty() ? new byte[0] : Base64.getDecoder().decode(b64);
            } catch (Exception e) {
                body = new byte[0];
            }
            String peer = o.optString("peer", "");
            String streamKey = o.optString("streamKey", "");
            if (streamKey.isEmpty()) {
                streamKey = peer;
            }
            String direction = o.optString("direction", "CLIENT_REQUEST");
            String path = o.optString("path", "");
            String summary = o.optString("summary", "");
            boolean include = o.optBoolean("include", true);

            if ("HTTP".equalsIgnoreCase(o.optString("mode")) && o.has("httpB64")) {
                try {
                    byte[] http = Base64.getDecoder().decode(o.getString("httpB64"));
                    burp.api.montoya.http.message.requests.HttpRequest req =
                            burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                                    burp.api.montoya.core.ByteArray.byteArray(http));
                    StreamStep httpStep = new StreamStep(req);
                    httpStep.setInclude(include);
                    if (body.length > 0) {
                        httpStep.setRawBody(body);
                    }
                    if (!summary.isEmpty()) {
                        httpStep.setSummary(summary);
                    }
                    out.add(httpStep);
                    continue;
                } catch (Exception ignored) {
                }
            }

            StreamStep step = StreamStep.restoreRaw(
                    direction, peer, streamKey, path, body, include, summary);
            out.add(step);
        }
        return out;
    }

    private void logInfo(String msg) {
        if (logging != null) {
            logging.logToOutput(msg);
        }
    }

    private void logError(String msg) {
        if (logging != null) {
            logging.logToError("[-] " + msg);
        }
    }

    /** In-memory project snapshot. */
    public static final class Snapshot {
        public boolean loaded;
        public boolean matchReplaceEnabled = true;

        public List<MatchReplaceRule> matchReplaceRules = new ArrayList<>();
        public boolean interceptEnabled;
        public long interceptTimeoutSec = 120;
        public List<InterceptRule> interceptRules = new ArrayList<>();
        public boolean relayLoaded;
        public String listenHost = "0.0.0.0";
        public int listenPort = 1433;
        public String targetHost = "192.0.2.1";
        public int targetPort = 1433;
        public List<TcpStreamFrame> streamFrames = new ArrayList<>();
        /** streamKey → highlight color name */
        public java.util.Map<String, String> streamHighlights = new java.util.LinkedHashMap<>();
        /** streamKey → user name/note */
        public java.util.Map<String, String> streamNames = new java.util.LinkedHashMap<>();
        /** Flattened steps (legacy / convenience). */
        public List<StreamStep> replaySteps = new ArrayList<>();
        /** Multi-tab Stream Replay (Burp Repeater-style). */
        public java.util.List<com.bdocyber.views.StreamReplayPanel.TabSnapshot> replayTabs = new java.util.ArrayList<>();
        public int replaySelectedTab;
    }
}
