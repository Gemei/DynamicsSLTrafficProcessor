package com.bdocyber.relay;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * One live TCP bridge (app client ↔ SQL server) owned by {@link TcpRelayService}.
 * Stream Replay can inject C→S bytes into the existing session (Burp WebSocket-style)
 * so SSPI/login state is preserved.
 */
public final class ActiveRelaySession {

    private final String streamKey;
    private final String peer;
    private final String clientEndpoint;
    private final Socket clientSocket;
    private final Socket targetSocket;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final AtomicLong injectCount = new AtomicLong(0);
    /** Serializes writes toward the SQL server (pump C→S + inject). */
    private final Object serverWriteLock = new Object();
    /** Serializes writes toward the app client (pump S→C). */
    private final Object clientWriteLock = new Object();

    public ActiveRelaySession(String streamKey, String peer, String clientEndpoint,
                              Socket clientSocket, Socket targetSocket) {
        this.streamKey = Objects.requireNonNull(streamKey);
        this.peer = peer != null ? peer : "";
        this.clientEndpoint = clientEndpoint != null ? clientEndpoint : "";
        this.clientSocket = Objects.requireNonNull(clientSocket);
        this.targetSocket = Objects.requireNonNull(targetSocket);
    }

    public String getStreamKey() {
        return streamKey;
    }

    public String getPeer() {
        return peer;
    }

    public String getClientEndpoint() {
        return clientEndpoint;
    }

    public boolean isOpen() {
        return open.get()
                && !clientSocket.isClosed()
                && !targetSocket.isClosed()
                && clientSocket.isConnected()
                && targetSocket.isConnected();
    }

    public long getInjectCount() {
        return injectCount.get();
    }

    /**
     * Write bytes as if the client sent them (toward SQL Server).
     * Does not go through the app→relay client socket.
     */
    public int injectClientToServer(byte[] data, int off, int len) throws IOException {
        if (!isOpen()) {
            throw new IOException("relay session closed: " + streamKey);
        }
        if (data == null || len <= 0) {
            return 0;
        }
        synchronized (serverWriteLock) {
            if (!isOpen()) {
                throw new IOException("relay session closed: " + streamKey);
            }
            OutputStream out = targetSocket.getOutputStream();
            out.write(data, off, len);
            out.flush();
            injectCount.incrementAndGet();
            return len;
        }
    }

    public int injectClientToServer(byte[] data) throws IOException {
        if (data == null) {
            return 0;
        }
        return injectClientToServer(data, 0, data.length);
    }

    /** Used by C→S pump so inject and live client traffic do not interleave mid-write. */
    public void writeToServer(byte[] data, int off, int len) throws IOException {
        synchronized (serverWriteLock) {
            targetSocket.getOutputStream().write(data, off, len);
        }
    }

    /** Used by S→C pump. */
    public void writeToClient(byte[] data, int off, int len) throws IOException {
        synchronized (clientWriteLock) {
            clientSocket.getOutputStream().write(data, off, len);
        }
    }

    public void markClosed() {
        open.set(false);
    }

    public String label() {
        return streamKey + (isOpen() ? " [live]" : " [closed]");
    }

    @Override
    public String toString() {
        return label();
    }
}
