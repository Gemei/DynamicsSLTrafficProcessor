package com.bdocyber.models;

import java.time.Instant;
import java.util.Arrays;

/**
 * One application chunk / TDS PDU on a TCP connection.
 * Summary is computed lazily so the relay hot path stays cheap.
 */
public class TcpStreamFrame {

    public enum Direction {
        CLIENT_TO_SERVER("C→S", "CLIENT_REQUEST"),
        SERVER_TO_CLIENT("S→C", "SERVER_RESPONSE");

        private final String shortLabel;
        private final String legacyName;

        Direction(String shortLabel, String legacyName) {
            this.shortLabel = shortLabel;
            this.legacyName = legacyName;
        }

        public String shortLabel() {
            return shortLabel;
        }

        public String legacyName() {
            return legacyName;
        }
    }

    private final long seq;
    private final Instant timestamp;
    /** Store key: preferably full connection id (client↔server). */
    private final String streamKey;
    /** Target peer host:port (for replay). */
    private final String peer;
    private final Direction direction;
    private final byte[] body;
    private final boolean matchReplaced;
    private final String source;
    private volatile String summary;
    /** User highlight color name ({@link com.bdocyber.helpers.HighlightColors}), empty = none. */
    private volatile String highlight = "";
    /** Optional user-assigned label/note for findings. */
    private volatile String userName = "";

    public TcpStreamFrame(String peer, Direction direction, byte[] body,
                          boolean matchReplaced, String source) {
        this(peer, peer, direction, body, matchReplaced, source);
    }

    public TcpStreamFrame(String streamKey, String peer, Direction direction, byte[] body,
                          boolean matchReplaced, String source) {
        this(0, Instant.now(), streamKey, peer, direction, body, matchReplaced, source, null);
    }

    public TcpStreamFrame(long seq, Instant timestamp, String peer, Direction direction,
                          byte[] body, boolean matchReplaced, String source) {
        this(seq, timestamp, peer, peer, direction, body, matchReplaced, source, null);
    }

    private TcpStreamFrame(long seq, Instant timestamp, String streamKey, String peer,
                           Direction direction, byte[] body, boolean matchReplaced,
                           String source, String summary) {
        this.seq = seq;
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.streamKey = streamKey != null && !streamKey.isEmpty()
                ? streamKey
                : (peer != null ? peer : "");
        this.peer = peer != null ? peer : "";
        this.direction = direction;
        this.body = body != null ? body : new byte[0];
        this.matchReplaced = matchReplaced;
        this.source = source != null ? source : "";
        this.summary = summary;
    }

    public static TcpStreamFrame capture(String peer, Direction direction, byte[] data, int off, int len,
                                         boolean matchReplaced, String source) {
        return capture(peer, peer, direction, data, off, len, matchReplaced, source);
    }

    public static TcpStreamFrame capture(String streamKey, String peer, Direction direction,
                                         byte[] data, int off, int len,
                                         boolean matchReplaced, String source) {
        byte[] copy = new byte[len];
        if (len > 0) {
            System.arraycopy(data, off, copy, 0, len);
        }
        return new TcpStreamFrame(streamKey, peer, direction, copy, matchReplaced, source);
    }

    public TcpStreamFrame withSeq(long newSeq) {
        TcpStreamFrame f = new TcpStreamFrame(newSeq, timestamp, streamKey, peer, direction, body,
                matchReplaced, source, summary);
        f.highlight = this.highlight;
        f.userName = this.userName;
        return f;
    }

    /** Rebuild a frame from project persistence (preserves seq / timestamp). */
    public static TcpStreamFrame restore(long seq, Instant timestamp, String streamKey, String peer,
                                         Direction direction, byte[] body, boolean matchReplaced,
                                         String source) {
        return new TcpStreamFrame(seq, timestamp, streamKey, peer, direction, body,
                matchReplaced, source, null);
    }

    public String getHighlight() {
        return highlight != null ? highlight : "";
    }

    public void setHighlight(String highlight) {
        this.highlight = highlight != null ? highlight : "";
    }

    public String getUserName() {
        return userName != null ? userName : "";
    }

    public void setUserName(String userName) {
        this.userName = userName != null ? userName.trim() : "";
    }

    /** Summary for tables: custom name if set, else auto TDS summary. */
    public String getDisplaySummary() {
        String name = getUserName();
        if (!name.isEmpty()) {
            return name;
        }
        return getSummary();
    }

    public long getSeq() {
        return seq;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getStreamKey() {
        return streamKey;
    }

    public String getPeer() {
        return peer;
    }

    public Direction getDirection() {
        return direction;
    }

    public byte[] getBody() {
        return Arrays.copyOf(body, body.length);
    }

    public byte[] bodyRef() {
        return body;
    }

    public int getBodyLength() {
        return body.length;
    }

    public boolean isMatchReplaced() {
        return matchReplaced;
    }

    public String getSource() {
        return source;
    }

    public String getSummary() {
        String s = summary;
        if (s == null) {
            s = buildSummary(body);
            summary = s;
        }
        return s;
    }

    /**
     * Cached one-line summary only — does <b>not</b> trigger TDS decode.
     * Prefer this for search/filter hot paths.
     */
    public String getCachedSummary() {
        return summary;
    }

    /**
     * Frame list summary: user name if set, else a richer one-line TDS decode (cached).
     */
    public String getListSummary() {
        String name = getUserName();
        if (!name.isEmpty()) {
            return name;
        }
        return getSummary();
    }

    private static String buildSummary(byte[] data) {
        if (data == null || data.length == 0) {
            return "(empty)";
        }
        try {
            return com.bdocyber.helpers.TdsTextFormatter.oneLineSummary(data, 120);
        } catch (Exception e) {
            return "binary " + data.length + " B";
        }
    }
}
