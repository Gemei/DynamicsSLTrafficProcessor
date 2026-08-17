package com.bdocyber.models;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Ordered frames for one TCP conversation (stream key).
 */
public class TcpStream {

    private final String streamKey;
    private final String peer;
    private final CopyOnWriteArrayList<TcpStreamFrame> frames = new CopyOnWriteArrayList<>();
    private volatile long clientBytes;
    private volatile long serverBytes;
    private volatile int matchReplaceCount;
    /** User highlight color name ({@link com.bdocyber.helpers.HighlightColors}), empty = none. */
    private volatile String highlight = "";
    /** Optional user-assigned name/note for this connection. */
    private volatile String userName = "";

    public TcpStream(String streamKey) {
        this(streamKey, streamKey);
    }

    public TcpStream(String streamKey, String peer) {
        this.streamKey = streamKey != null ? streamKey : "";
        this.peer = peer != null && !peer.isEmpty() ? peer : this.streamKey;
    }

    /** @deprecated use {@link #getStreamKey()} */
    @Deprecated
    public String getPeer() {
        return peer;
    }

    public String getStreamKey() {
        return streamKey;
    }

    /** Short label for UI list (custom name preferred). */
    public String getDisplayLabel() {
        String name = getUserName();
        if (!name.isEmpty()) {
            return name;
        }
        return getConnectionLabel();
    }

    /** Technical connection id (client:port → server:port). */
    public String getConnectionLabel() {
        if (streamKey.equals(peer) || streamKey.isEmpty()) {
            return peer;
        }
        return streamKey;
    }

    public void addFrame(TcpStreamFrame frame) {
        if (frame == null) {
            return;
        }
        frames.add(frame);
        if (frame.getDirection() == TcpStreamFrame.Direction.CLIENT_TO_SERVER) {
            clientBytes += frame.getBodyLength();
        } else {
            serverBytes += frame.getBodyLength();
        }
        if (frame.isMatchReplaced()) {
            matchReplaceCount++;
        }
    }

    /**
     * Live view of frames (CopyOnWriteArrayList). Safe to iterate without holding the store lock;
     * do not mutate the returned list.
     */
    public List<TcpStreamFrame> getFrames() {
        return Collections.unmodifiableList(frames);
    }

    /** Snapshot copy for export / persistence. */
    public List<TcpStreamFrame> copyFrames() {
        return new ArrayList<>(frames);
    }

    public int getFrameCount() {
        return frames.size();
    }

    public long getClientBytes() {
        return clientBytes;
    }

    public long getServerBytes() {
        return serverBytes;
    }

    public int getMatchReplaceCount() {
        return matchReplaceCount;
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

    /** Timestamp of first captured frame (stream start), or null if empty. */
    public Instant getFirstTimestamp() {
        if (frames.isEmpty()) {
            return null;
        }
        return frames.get(0).getTimestamp();
    }

    /** Timestamp of last captured frame, or null if empty. */
    public Instant getLastTimestamp() {
        if (frames.isEmpty()) {
            return null;
        }
        return frames.get(frames.size() - 1).getTimestamp();
    }

    public void clear() {
        frames.clear();
        clientBytes = 0;
        serverBytes = 0;
        matchReplaceCount = 0;
        highlight = "";
        userName = "";
    }
}
