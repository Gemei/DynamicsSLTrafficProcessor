package com.bdocyber.relay;

import com.bdocyber.helpers.InterceptEngine;
import com.bdocyber.helpers.MatchReplaceEngine;
import com.bdocyber.helpers.TcpStreamStore;
import com.bdocyber.models.TcpStreamFrame;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * High-performance TCP bridge for Dynamics SL TDS.
 * <p>
 * Hot path: read → (optional match/replace) → write. Capture/UI work is async
 * and never blocks the bridge when the capture queue is full.
 */
public class TcpRelayService {

    public interface LogSink {
        void info(String msg);

        void error(String msg);
    }

    private final MatchReplaceEngine matchReplace;
    private final InterceptEngine interceptEngine;
    private final TcpStreamStore streamStore;
    private final LogSink log;

    private volatile String listenHost = "0.0.0.0";
    private volatile int listenPort = 1433;
    private volatile String targetHost = "192.0.2.1";
    private volatile int targetPort = 1433;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile ServerSocket serverSocket;
    private ExecutorService acceptPool;
    private ExecutorService connectionPool;
    private ExecutorService capturePool;
    private final AtomicInteger activeConnections = new AtomicInteger(0);
    private final AtomicLong framesForwarded = new AtomicLong(0);
    private final AtomicLong bytesClientToServer = new AtomicLong(0);
    private final AtomicLong bytesServerToClient = new AtomicLong(0);
    private final AtomicLong lastStatusFireMs = new AtomicLong(0);
    private final CopyOnWriteArrayList<Consumer<TcpRelayService>> statusListeners = new CopyOnWriteArrayList<>();

    /** Async capture so Swing / unpack never stalls the SQL session. */
    private final ArrayBlockingQueue<TcpStreamFrame> captureQueue = new ArrayBlockingQueue<>(8192);

    /** Live bridges for Stream Replay inject (Burp WebSocket-style). */
    private final ConcurrentHashMap<String, ActiveRelaySession> liveSessions = new ConcurrentHashMap<>();

    public TcpRelayService(MatchReplaceEngine matchReplace, InterceptEngine interceptEngine,
                           TcpStreamStore streamStore, LogSink log) {
        this.matchReplace = matchReplace;
        this.interceptEngine = interceptEngine;
        this.streamStore = streamStore;
        this.log = log != null ? wrapLogSink(log) : NOOP_LOG;
    }

    private static final LogSink NOOP_LOG = new LogSink() {
        @Override
        public void info(String msg) {
        }

        @Override
        public void error(String msg) {
        }
    };

    /** Never throw from logging (Burp Logging can be null/tearing down during unload). */
    private static LogSink wrapLogSink(LogSink inner) {
        return new LogSink() {
            @Override
            public void info(String msg) {
                try {
                    inner.info(msg);
                } catch (Throwable ignored) {
                }
            }

            @Override
            public void error(String msg) {
                try {
                    inner.error(msg);
                } catch (Throwable ignored) {
                }
            }
        };
    }

    /** Register a status listener (multiple UI panels may listen). */
    public void addStatusListener(Consumer<TcpRelayService> statusListener) {
        if (statusListener != null) {
            statusListeners.add(statusListener);
        }
    }

    /** Replaces all listeners; prefer {@link #addStatusListener} when multiple panels listen. */
    public void setStatusListener(Consumer<TcpRelayService> statusListener) {
        statusListeners.clear();
        addStatusListener(statusListener);
    }

    public void configure(String listenHost, int listenPort, String targetHost, int targetPort) {
        if (running.get()) {
            throw new IllegalStateException("Stop the relay before changing configuration");
        }
        String lh = listenHost == null || listenHost.isBlank() ? "0.0.0.0" : listenHost.trim();
        if ("*".equals(lh) || "any".equalsIgnoreCase(lh)) {
            lh = "0.0.0.0";
        }
        this.listenHost = lh;
        this.listenPort = listenPort;
        this.targetHost = targetHost == null ? "" : targetHost.trim();
        this.targetPort = targetPort;
    }

    public String getListenHost() {
        return listenHost;
    }

    public int getListenPort() {
        return listenPort;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public boolean isRunning() {
        return running.get();
    }

    public int getActiveConnections() {
        return activeConnections.get();
    }

    /**
     * Snapshot of open relay bridges. Prefer matching {@code streamKey} from a captured frame.
     */
    public List<ActiveRelaySession> listLiveSessions() {
        List<ActiveRelaySession> out = new ArrayList<>();
        for (ActiveRelaySession s : liveSessions.values()) {
            if (s != null && s.isOpen()) {
                out.add(s);
            }
        }
        return out;
    }

    public ActiveRelaySession getLiveSession(String streamKey) {
        if (streamKey == null || streamKey.isEmpty()) {
            return null;
        }
        ActiveRelaySession s = liveSessions.get(streamKey);
        return s != null && s.isOpen() ? s : null;
    }

    /**
     * Pick a live session for replay: exact streamKey, else any session to the same peer,
     * else the sole open session if only one exists.
     */
    public ActiveRelaySession resolveLiveSession(String streamKey, String peer) {
        ActiveRelaySession exact = getLiveSession(streamKey);
        if (exact != null) {
            return exact;
        }
        List<ActiveRelaySession> live = listLiveSessions();
        if (live.isEmpty()) {
            return null;
        }
        if (peer != null && !peer.isEmpty()) {
            for (ActiveRelaySession s : live) {
                if (peerEquals(s.getPeer(), peer)) {
                    return s;
                }
            }
            // peer may be host:port of SQL; stream peer is usually targetHost:targetPort
            for (ActiveRelaySession s : live) {
                if (s.getStreamKey() != null && s.getStreamKey().contains(peer)) {
                    return s;
                }
            }
        }
        if (live.size() == 1) {
            return live.get(0);
        }
        return null;
    }

    private static boolean peerEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.equalsIgnoreCase(b)) {
            return true;
        }
        // normalize host:port
        return a.replace("127.0.0.1", "localhost").equalsIgnoreCase(
                b.replace("127.0.0.1", "localhost"));
    }

    /**
     * Inject C→S payload into a live bridge (as if the Dynamics client sent it).
     * Captures the frame under the session streamKey with source {@code replay-inject}.
     *
     * @return session used
     */
    public ActiveRelaySession injectClientToServer(String streamKey, String peer, byte[] body)
            throws IOException {
        ActiveRelaySession session = resolveLiveSession(streamKey, peer);
        if (session == null) {
            throw new IOException("No live relay session"
                    + (streamKey != null && !streamKey.isEmpty() ? " for " + streamKey : "")
                    + (peer != null && !peer.isEmpty() ? " (peer " + peer + ")" : "")
                    + ". Keep the app connected through the relay, or use New TCP connection mode.");
        }
        if (body == null || body.length == 0) {
            return session;
        }
        session.injectClientToServer(body);
        framesForwarded.incrementAndGet();
        bytesClientToServer.addAndGet(body.length);
        offerCapture(TcpStreamFrame.capture(
                session.getStreamKey(),
                session.getPeer(),
                TcpStreamFrame.Direction.CLIENT_TO_SERVER,
                body, 0, body.length,
                false,
                "replay-inject"));
        fireStatus(false);
        return session;
    }

    public long getFramesForwarded() {
        return framesForwarded.get();
    }

    public long getBytesClientToServer() {
        return bytesClientToServer.get();
    }

    public long getBytesServerToClient() {
        return bytesServerToClient.get();
    }

    public synchronized void start() throws IOException {
        if (running.get()) {
            return;
        }
        if (targetHost.isEmpty() || targetPort <= 0 || targetPort > 65535
                || listenPort <= 0 || listenPort > 65535) {
            throw new IllegalArgumentException("Invalid listen/target host or port");
        }
        if (listenPort == targetPort && isLocalTarget(targetHost)) {
            throw new IllegalArgumentException(
                    "Target cannot be localhost when listen port equals target port ("
                            + listenPort + "). Set Target to the real SQL Server IP/hostname "
                            + "and point the app hostname at this machine (hosts file).");
        }

        InetAddress bindAddr = "0.0.0.0".equals(listenHost)
                ? null
                : InetAddress.getByName(listenHost);

        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(bindAddr, listenPort), 128);
        serverSocket.setSoTimeout(1000);

        acceptPool = Executors.newSingleThreadExecutor(r -> daemon(r, "dsl-tcp-relay-accept"));
        connectionPool = Executors.newCachedThreadPool(r -> daemon(r, "dsl-tcp-relay-conn"));
        capturePool = Executors.newSingleThreadExecutor(r -> daemon(r, "dsl-tcp-relay-capture"));

        running.set(true);
        framesForwarded.set(0);
        bytesClientToServer.set(0);
        bytesServerToClient.set(0);
        captureQueue.clear();
        capturePool.execute(this::captureLoop);
        acceptPool.execute(this::acceptLoop);

        String bindDesc = bindAddr == null ? "0.0.0.0 (all interfaces)" : bindAddr.getHostAddress();
        log.info("[DSL relay] listening on " + bindDesc + ":" + listenPort
                + " → " + targetHost + ":" + targetPort);
        if (listenPort == targetPort) {
            log.info("[DSL relay] Same-port mode: hosts → 127.0.0.1, Target = real IP " + targetHost);
        }
        // Always reassemble TDS PDUs and apply match/replace + intercept at forward time.
        // Path is chosen per packet (not frozen at connection open), so enabling Intercept
        // mid-session still works on every live stream.
        log.info("[DSL relay] forward mode: TDS PDU reassembly (match/replace & intercept applied live on all streams)");
        fireStatus(true);
    }

    public synchronized void stop() {
        running.set(false);
        ServerSocket ss = serverSocket;
        serverSocket = null;
        if (ss != null) {
            try {
                ss.close();
            } catch (IOException ignored) {
            }
        }
        if (acceptPool != null) {
            acceptPool.shutdownNow();
            acceptPool = null;
        }
        if (connectionPool != null) {
            connectionPool.shutdownNow();
            connectionPool = null;
        }
        if (capturePool != null) {
            capturePool.shutdownNow();
            capturePool = null;
        }
        captureQueue.clear();
        for (ActiveRelaySession s : liveSessions.values()) {
            if (s != null) {
                s.markClosed();
            }
        }
        liveSessions.clear();
        activeConnections.set(0);
        log.info("[DSL relay] stopped");
        fireStatus(true);
    }

    private void captureLoop() {
        List<TcpStreamFrame> batch = new ArrayList<>(64);
        while (running.get() || !captureQueue.isEmpty()) {
            try {
                batch.clear();
                TcpStreamFrame first = captureQueue.poll(200, TimeUnit.MILLISECONDS);
                if (first != null) {
                    batch.add(first);
                    captureQueue.drainTo(batch, 255);
                }
                if (!batch.isEmpty() && streamStore != null) {
                    streamStore.addFrames(batch);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                if (running.get()) {
                    log.error("[DSL relay] capture: " + e.getMessage());
                }
            }
        }
    }

    private void offerCapture(TcpStreamFrame frame) {
        if (frame == null || streamStore == null) {
            return;
        }
        // Never block the data path if UI is slow — drop oldest
        if (!captureQueue.offer(frame)) {
            captureQueue.poll();
            captureQueue.offer(frame);
        }
    }

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    private static boolean isLocalTarget(String host) {
        return "127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host) || "::1".equals(host);
    }

    private void acceptLoop() {
        log.info("[DSL relay] accept loop started");
        while (running.get()) {
            ServerSocket ss = serverSocket;
            if (ss == null || ss.isClosed()) {
                break;
            }
            try {
                Socket client = ss.accept();
                log.info("[DSL relay] incoming from " + client.getRemoteSocketAddress());
                ExecutorService pool = connectionPool;
                if (pool != null && !pool.isShutdown()) {
                    pool.execute(() -> handleConnection(client));
                } else {
                    closeQuietly(client);
                }
            } catch (SocketTimeoutException e) {
                // check running flag
            } catch (SocketException e) {
                if (running.get()) {
                    log.error("[DSL relay] accept: " + e.getMessage());
                }
                break;
            } catch (IOException e) {
                if (running.get()) {
                    log.error("[DSL relay] accept: " + e.getMessage());
                }
            }
        }
        log.info("[DSL relay] accept loop ended");
    }

    private void handleConnection(Socket client) {
        activeConnections.incrementAndGet();
        fireStatus(true);
        Socket target = null;
        // Target peer for replay; full streamKey = one TCP conversation (Wireshark-style)
        String peer = targetHost + ":" + targetPort;
        String clientEp = String.valueOf(client.getRemoteSocketAddress());
        // strip leading /
        if (clientEp.startsWith("/")) {
            clientEp = clientEp.substring(1);
        }
        String streamKey = clientEp + " → " + peer;
        ActiveRelaySession session = null;
        try {
            client.setTcpNoDelay(true);
            client.setKeepAlive(true);
            client.setReceiveBufferSize(256 * 1024);
            client.setSendBufferSize(256 * 1024);

            target = new Socket();
            target.setTcpNoDelay(true);
            target.setKeepAlive(true);
            target.setReceiveBufferSize(256 * 1024);
            target.setSendBufferSize(256 * 1024);
            target.connect(new InetSocketAddress(targetHost, targetPort), 10_000);
            log.info("[DSL relay] bridged " + client.getRemoteSocketAddress()
                    + " ↔ " + target.getRemoteSocketAddress() + "  stream=" + streamKey);

            session = new ActiveRelaySession(streamKey, peer, clientEp, client, target);
            liveSessions.put(streamKey, session);
            fireStatus(true);

            final Socket c = client;
            final Socket t = target;
            final String sk = streamKey;
            final String pk = peer;
            final ActiveRelaySession sess = session;
            CountDownLatch done = new CountDownLatch(2);

            // Same pump for every live stream: reassemble PDUs, then apply rules if active.
            // Do not freeze transparent-vs-intercept at connect time (that skipped intercept
            // on streams that opened before Intercept was turned on).
            Thread c2s = new Thread(() -> {
                try {
                    pumpRelay(c, t,
                            TcpStreamFrame.Direction.CLIENT_TO_SERVER,
                            MatchReplaceEngine.Direction.REQUEST,
                            sk, pk, bytesClientToServer, sess, true);
                } finally {
                    shutdownOutput(t);
                    done.countDown();
                }
            }, "dsl-c2s-" + clientEp);
            Thread s2c = new Thread(() -> {
                try {
                    pumpRelay(t, c,
                            TcpStreamFrame.Direction.SERVER_TO_CLIENT,
                            MatchReplaceEngine.Direction.RESPONSE,
                            sk, pk, bytesServerToClient, sess, false);
                } finally {
                    shutdownOutput(c);
                    done.countDown();
                }
            }, "dsl-s2c-" + clientEp);
            c2s.setDaemon(true);
            s2c.setDaemon(true);
            c2s.start();
            s2c.start();
            try {
                done.await(6, TimeUnit.HOURS);
            } catch (InterruptedException ie) {
                // Normal when stop() / extension unload interrupts the connection pool
                Thread.currentThread().interrupt();
            }
        } catch (Exception e) {
            // Ignore noise while stopping; still log real runtime failures while running
            if (running.get()) {
                String msg = e.getMessage();
                log.error("[DSL relay] connection error on " + streamKey + ": "
                        + e.getClass().getSimpleName()
                        + (msg != null && !msg.isEmpty() ? ": " + msg : ""));
            }
        } finally {
            if (session != null) {
                session.markClosed();
                liveSessions.remove(streamKey, session);
            }
            closeQuietly(client);
            closeQuietly(target);
            activeConnections.decrementAndGet();
            if (running.get()) {
                fireStatus(true);
            }
        }
    }

    /**
     * Per-connection pump used for every live stream: reassemble complete TDS PDUs,
     * then forward (with live match/replace + intercept when rules are active).
     */
    private void pumpRelay(Socket from, Socket to,
                           TcpStreamFrame.Direction frameDir,
                           MatchReplaceEngine.Direction mrDir,
                           String streamKey, String peer,
                           AtomicLong byteCounter,
                           ActiveRelaySession session,
                           boolean towardServer) {
        TdsPacketBuffer packetBuffer = new TdsPacketBuffer();
        byte[] buf = new byte[64 * 1024];
        try {
            InputStream in = from.getInputStream();
            int n;
            while (running.get() && !from.isClosed() && !to.isClosed()) {
                n = in.read(buf);
                if (n < 0) {
                    break;
                }
                if (n == 0) {
                    continue;
                }
                packetBuffer.append(buf, 0, n);
                for (byte[] packet : packetBuffer.drainPackets()) {
                    forwardPacket(packet, frameDir, mrDir, streamKey, peer, byteCounter, session, towardServer);
                }
            }
            for (byte[] packet : packetBuffer.flushRemainder()) {
                if (!to.isClosed()) {
                    forwardPacket(packet, frameDir, mrDir, streamKey, peer, byteCounter, session, towardServer);
                }
            }
            try {
                to.getOutputStream().flush();
            } catch (IOException ignored) {
            }
        } catch (SocketException e) {
            // peer closed
        } catch (Exception e) {
            if (running.get() && !(e instanceof InterruptedException)) {
                log.error("[DSL relay] pump " + frameDir.shortLabel() + " " + streamKey + ": "
                        + e.getClass().getSimpleName()
                        + (e.getMessage() != null ? ": " + e.getMessage() : ""));
            } else if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void forwardPacket(byte[] packet,
                               TcpStreamFrame.Direction frameDir,
                               MatchReplaceEngine.Direction mrDir,
                               String streamKey, String peer,
                               AtomicLong byteCounter,
                               ActiveRelaySession session,
                               boolean towardServer) throws IOException {
        boolean replaced = false;
        byte[] wire = packet;
        // Re-check rules on every PDU so enabling Intercept/Match-Replace mid-session applies
        // to all live streams (not only connections opened after enable).
        if (matchReplace != null && matchReplace.isEnabled() && matchReplace.enabledRuleCount() > 0) {
            byte[] modified = matchReplace.apply(packet, mrDir);
            if (modified != null && !Arrays.equals(modified, packet)) {
                wire = modified;
                replaced = true;
            }
        }
        if (interceptEngine != null && interceptEngine.hasActiveRules()) {
            byte[] afterHold = interceptEngine.process(frameDir, peer, wire);
            if (afterHold == null) {
                offerCapture(new TcpStreamFrame(streamKey, peer, frameDir, wire, true, "relay-dropped"));
                fireStatus(false);
                return;
            }
            if (!Arrays.equals(afterHold, wire)) {
                wire = afterHold;
                replaced = true;
            }
        }
        if (session != null && towardServer) {
            session.writeToServer(wire, 0, wire.length);
        } else if (session != null) {
            session.writeToClient(wire, 0, wire.length);
        } else {
            throw new IOException("no session for forward: " + streamKey);
        }
        byteCounter.addAndGet(wire.length);
        framesForwarded.incrementAndGet();
        offerCapture(new TcpStreamFrame(streamKey, peer, frameDir, wire, replaced, "relay"));
        fireStatus(false);
    }

    /** @param force if false, throttle UI status updates */
    private void fireStatus(boolean force) {
        long now = System.currentTimeMillis();
        if (!force && now - lastStatusFireMs.get() < 250) {
            return;
        }
        lastStatusFireMs.set(now);
        for (Consumer<TcpRelayService> l : statusListeners) {
            try {
                l.accept(this);
            } catch (Exception ignored) {
            }
        }
    }

    private static void shutdownOutput(Socket s) {
        if (s == null || s.isClosed()) {
            return;
        }
        try {
            s.shutdownOutput();
        } catch (IOException ignored) {
        }
    }

    private static void closeQuietly(Socket s) {
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
    }
}
