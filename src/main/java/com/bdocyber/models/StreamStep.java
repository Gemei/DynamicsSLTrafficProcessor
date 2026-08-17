package com.bdocyber.models;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bdocyber.helpers.TdsHelper;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * One step in Stream Replay — raw TCP frames from TCP Streams (optional HTTP body import).
 * Body is mutable so the user can edit steps before replay.
 */
public class StreamStep {
    public enum Mode {
        /** Legacy import of an HTTP message body as a TCP step (not used for live capture). */
        HTTP,
        RAW_TCP
    }

    private final Mode mode;
    private HttpRequest request;
    private byte[] rawBody;
    private final String path;
    private final String direction;
    private final String peer;
    /** Original TCP stream key (for live relay inject). Empty for HTTP-imported steps. */
    private final String streamKey;
    private String summary;
    private boolean include = true;

    public StreamStep(HttpRequest request) {
        this.mode = Mode.HTTP;
        this.request = request;
        this.rawBody = request.body() != null ? request.body().getBytes() : new byte[0];
        this.path = request.path() != null ? request.path() : "";
        this.direction = "CLIENT_REQUEST";
        this.peer = TdsHelper.extractPeer(path);
        this.streamKey = "";
        this.summary = buildSummary(rawBody, peer, isClientRequest());
    }

    public StreamStep(TcpStreamFrame frame) {
        this.mode = Mode.RAW_TCP;
        this.request = null;
        this.rawBody = frame.getBody();
        this.path = frame.getDirection().legacyName() + "/" + frame.getPeer();
        this.direction = frame.getDirection().legacyName();
        this.peer = frame.getPeer();
        this.streamKey = frame.getStreamKey() != null ? frame.getStreamKey() : "";
        this.summary = frame.getSummary();
    }

    /**
     * Restore a RAW_TCP step from project persistence (preserves stream key + body + summary).
     */
    public static StreamStep restoreRaw(String direction, String peer, String streamKey,
                                        String path, byte[] body, boolean include, String summary) {
        String dir = direction != null && !direction.isEmpty() ? direction : "CLIENT_REQUEST";
        String p = peer != null ? peer : "";
        String sk = streamKey != null && !streamKey.isEmpty() ? streamKey : p;
        String pth = path != null && !path.isEmpty() ? path : (dir + "/" + p);
        byte[] b = body != null ? Arrays.copyOf(body, body.length) : new byte[0];
        StreamStep step = new StreamStep(Mode.RAW_TCP, null, b, pth, dir, p, sk,
                summary != null ? summary : "", include);
        if ((step.summary == null || step.summary.isEmpty()) && b.length > 0) {
            step.summary = buildSummary(b, p, step.isClientRequest());
        }
        return step;
    }

    private StreamStep(Mode mode, HttpRequest request, byte[] rawBody, String path, String direction,
                       String peer, String streamKey, String summary, boolean include) {
        this.mode = mode;
        this.request = request;
        this.rawBody = rawBody != null ? rawBody : new byte[0];
        this.path = path != null ? path : "";
        this.direction = direction != null ? direction : "CLIENT_REQUEST";
        this.peer = peer != null ? peer : "";
        this.streamKey = streamKey != null ? streamKey : "";
        this.summary = summary != null ? summary : "";
        this.include = include;
    }

    public Mode getMode() {
        return mode;
    }

    public HttpRequest getRequest() {
        return request;
    }

    public byte[] getRawBody() {
        return Arrays.copyOf(rawBody, rawBody.length);
    }

    /**
     * Replace body; for HTTP steps also updates the Burp request object.
     */
    public void setRawBody(byte[] body) {
        this.rawBody = body != null ? Arrays.copyOf(body, body.length) : new byte[0];
        if (mode == Mode.HTTP && request != null) {
            request = request.withBody(ByteArray.byteArray(this.rawBody));
        }
        this.summary = buildSummary(this.rawBody, peer, isClientRequest());
    }

    /**
     * Apply string replace on body. Prefer TDS re-pack when body is TDS and length changes.
     *
     * @return true if body changed
     */
    public boolean replaceString(String find, String replace, boolean utf16, boolean raw) {
        if (find == null || find.isEmpty() || rawBody == null || rawBody.length == 0) {
            return false;
        }
        if (replace == null) {
            replace = "";
        }
        byte[] original = rawBody;
        byte[] next = original;

        // Try TDS-aware string edit first (safe length changes)
        try {
            TdsHelper tds = new TdsHelper();
            if (tds.looksLikeTds(original)) {
                JSONArray packets = tds.unpack(original);
                boolean changed = applyReplaceToPackets(packets, find, replace);
                if (changed) {
                    next = tds.pack(packets);
                    if (!Arrays.equals(original, next)) {
                        setRawBody(next);
                        return true;
                    }
                }
            }
        } catch (Exception ignored) {
            // fall through to byte replace
        }

        if (utf16) {
            next = replaceBytes(next, find.getBytes(StandardCharsets.UTF_16LE),
                    replace.getBytes(StandardCharsets.UTF_16LE));
        }
        if (raw) {
            next = replaceBytes(next, find.getBytes(StandardCharsets.ISO_8859_1),
                    replace.getBytes(StandardCharsets.ISO_8859_1));
        }
        if (!utf16 && !raw) {
            next = replaceBytes(next, find.getBytes(StandardCharsets.UTF_16LE),
                    replace.getBytes(StandardCharsets.UTF_16LE));
        }
        if (!Arrays.equals(original, next)) {
            setRawBody(next);
            return true;
        }
        return false;
    }

    private static boolean applyReplaceToPackets(JSONArray packets, String find, String replace) {
        boolean changed = false;
        for (int i = 0; i < packets.length(); i++) {
            JSONObject pkt = packets.getJSONObject(i);
            if (pkt.has("rpc")) {
                JSONObject rpc = pkt.getJSONObject("rpc");
                if (rpc.has("sql") && !rpc.isNull("sql")) {
                    String sql = rpc.getString("sql");
                    if (sql.contains(find)) {
                        rpc.put("sql", sql.replace(find, replace));
                        changed = true;
                    }
                }
                if (rpc.has("params")) {
                    JSONArray params = rpc.getJSONArray("params");
                    for (int p = 0; p < params.length(); p++) {
                        JSONObject param = params.getJSONObject(p);
                        if (param.has("value") && !param.isNull("value") && param.get("value") instanceof String) {
                            String v = param.getString("value");
                            if (v.contains(find)) {
                                String nv = v.replace(find, replace);
                                param.put("value", nv);
                                if (param.has("maxLen")) {
                                    int need = nv.getBytes(StandardCharsets.UTF_16LE).length;
                                    if (param.optInt("maxLen") < need) {
                                        param.put("maxLen", need);
                                    }
                                }
                                changed = true;
                            }
                        }
                    }
                }
            }
            if (pkt.has("sql") && !pkt.isNull("sql") && "SQL_BATCH".equals(pkt.optString("typeName"))) {
                String sql = pkt.getString("sql");
                if (sql.contains(find)) {
                    pkt.put("sql", sql.replace(find, replace));
                    changed = true;
                }
            }
        }
        return changed;
    }

    private static byte[] replaceBytes(byte[] body, byte[] find, byte[] repl) {
        if (find.length == 0 || body.length < find.length) {
            return body;
        }
        java.util.List<Integer> hits = new java.util.ArrayList<>();
        outer:
        for (int i = 0; i <= body.length - find.length; i++) {
            for (int j = 0; j < find.length; j++) {
                if (body[i + j] != find[j]) {
                    continue outer;
                }
            }
            hits.add(i);
            i += find.length - 1;
        }
        if (hits.isEmpty()) {
            return body;
        }
        int newLen = body.length + hits.size() * (repl.length - find.length);
        byte[] out = new byte[newLen];
        int src = 0;
        int dst = 0;
        for (int hit : hits) {
            int chunk = hit - src;
            System.arraycopy(body, src, out, dst, chunk);
            dst += chunk;
            System.arraycopy(repl, 0, out, dst, repl.length);
            dst += repl.length;
            src = hit + find.length;
        }
        System.arraycopy(body, src, out, dst, body.length - src);
        return out;
    }

    private static String buildSummary(byte[] body, String peer, boolean client) {
        try {
            return TcpStreamFrame.capture(
                    peer != null ? peer : "",
                    client ? TcpStreamFrame.Direction.CLIENT_TO_SERVER
                            : TcpStreamFrame.Direction.SERVER_TO_CLIENT,
                    body, 0, body != null ? body.length : 0, false, "replay").getSummary();
        } catch (Exception e) {
            return "binary " + (body != null ? body.length : 0) + " B";
        }
    }

    public String getPath() {
        return path;
    }

    public String getDirection() {
        return direction;
    }

    public String getPeer() {
        return peer;
    }

    /** TCP stream key from capture (for live relay inject); empty if unknown. */
    public String getStreamKey() {
        return streamKey != null ? streamKey : "";
    }

    public String getSummary() {
        return summary != null ? summary : "";
    }

    /** Restore or override display summary (e.g. project load). */
    public void setSummary(String summary) {
        this.summary = summary != null ? summary : "";
    }

    public int getBodyLength() {
        return rawBody != null ? rawBody.length : 0;
    }

    public boolean isInclude() {
        return include;
    }

    public void setInclude(boolean include) {
        this.include = include;
    }

    public boolean isClientRequest() {
        return direction != null && (direction.contains("CLIENT") || "C2S".equalsIgnoreCase(direction)
                || "C→S".equals(direction));
    }
}
