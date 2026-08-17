package com.bdocyber.helpers;

import com.bdocyber.models.TcpStreamFrame;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Holds relay frames when body matches configured rules until the user
 * forwards, edits, or drops them in the Intercept tab.
 */
public class InterceptEngine {

    public enum DecisionType {
        FORWARD,
        DROP
    }

    public static final class PendingIntercept {
        private final long id;
        private final String peer;
        private final TcpStreamFrame.Direction direction;
        private final byte[] originalBody;
        private final InterceptRule matchedRule;
        private final CountDownLatch latch = new CountDownLatch(1);
        private final AtomicReference<byte[]> forwardBody = new AtomicReference<>();
        private final AtomicReference<DecisionType> decision = new AtomicReference<>();
        private final long createdAt = System.currentTimeMillis();

        PendingIntercept(long id, String peer, TcpStreamFrame.Direction direction,
                         byte[] body, InterceptRule rule) {
            this.id = id;
            this.peer = peer;
            this.direction = direction;
            this.originalBody = body != null ? body.clone() : new byte[0];
            this.matchedRule = rule;
            this.forwardBody.set(this.originalBody);
        }

        public long getId() {
            return id;
        }

        public String getPeer() {
            return peer;
        }

        public TcpStreamFrame.Direction getDirection() {
            return direction;
        }

        public byte[] getOriginalBody() {
            return originalBody.clone();
        }

        public byte[] getForwardBody() {
            byte[] b = forwardBody.get();
            return b != null ? b.clone() : new byte[0];
        }

        public void setForwardBody(byte[] body) {
            forwardBody.set(body != null ? body.clone() : new byte[0]);
        }

        public InterceptRule getMatchedRule() {
            return matchedRule;
        }

        public long getCreatedAt() {
            return createdAt;
        }

        public boolean isResolved() {
            return decision.get() != null;
        }

        void resolve(DecisionType type) {
            decision.set(type);
            latch.countDown();
        }

        DecisionType await(long timeout, TimeUnit unit) throws InterruptedException {
            if (!latch.await(timeout, unit)) {
                return null; // timeout
            }
            return decision.get();
        }
    }

    private final CopyOnWriteArrayList<InterceptRule> rules = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<PendingIntercept> pending = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Consumer<PendingIntercept>> listeners = new CopyOnWriteArrayList<>();
    private volatile boolean enabled = false;
    private volatile long nextId = 1;
    /** Auto-forward if user does not act (0 = wait forever). Default 120s. */
    private volatile long timeoutSeconds = 120;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public long getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public void setTimeoutSeconds(long timeoutSeconds) {
        this.timeoutSeconds = Math.max(0, timeoutSeconds);
    }

    public List<InterceptRule> getRules() {
        List<InterceptRule> out = new ArrayList<>();
        for (InterceptRule r : rules) {
            out.add(r.copy());
        }
        return out;
    }

    public void setRules(List<InterceptRule> list) {
        rules.clear();
        if (list != null) {
            for (InterceptRule r : list) {
                if (r != null) {
                    rules.add(r.copy());
                }
            }
        }
    }

    public int activeRuleCount() {
        int n = 0;
        for (InterceptRule r : rules) {
            if (r.isEnabled() && r.getMatch() != null && !r.getMatch().isEmpty()) {
                n++;
            }
        }
        return n;
    }

    public boolean hasActiveRules() {
        return enabled && activeRuleCount() > 0;
    }

    public void addListener(Consumer<PendingIntercept> listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public List<PendingIntercept> getPending() {
        return new ArrayList<>(pending);
    }

    public void forward(long id) {
        PendingIntercept p = find(id);
        if (p != null && !p.isResolved()) {
            p.resolve(DecisionType.FORWARD);
            pending.remove(p);
        }
    }

    public void forwardEdited(long id, byte[] body) {
        PendingIntercept p = find(id);
        if (p != null && !p.isResolved()) {
            p.setForwardBody(body);
            p.resolve(DecisionType.FORWARD);
            pending.remove(p);
        }
    }

    public void drop(long id) {
        PendingIntercept p = find(id);
        if (p != null && !p.isResolved()) {
            p.resolve(DecisionType.DROP);
            pending.remove(p);
        }
    }

    public void forwardAll() {
        for (PendingIntercept p : new ArrayList<>(pending)) {
            if (!p.isResolved()) {
                p.resolve(DecisionType.FORWARD);
            }
            pending.remove(p);
        }
    }

    public void dropAll() {
        for (PendingIntercept p : new ArrayList<>(pending)) {
            if (!p.isResolved()) {
                p.resolve(DecisionType.DROP);
            }
            pending.remove(p);
        }
    }

    private PendingIntercept find(long id) {
        for (PendingIntercept p : pending) {
            if (p.getId() == id) {
                return p;
            }
        }
        return null;
    }

    /**
     * If a rule matches, block until user decision (or timeout → forward original).
     *
     * @return body to send, or {@code null} to drop
     */
    public byte[] process(TcpStreamFrame.Direction direction, String peer, byte[] body) {
        if (!hasActiveRules() || body == null || body.length == 0) {
            return body;
        }
        InterceptRule hit = firstMatch(direction, body);
        if (hit == null) {
            return body;
        }

        PendingIntercept pendingItem;
        synchronized (this) {
            pendingItem = new PendingIntercept(nextId++, peer, direction, body, hit);
            pending.add(pendingItem);
        }
        for (Consumer<PendingIntercept> l : listeners) {
            try {
                l.accept(pendingItem);
            } catch (Exception ignored) {
            }
        }

        try {
            long timeout = timeoutSeconds;
            DecisionType decision;
            if (timeout <= 0) {
                decision = pendingItem.await(365, TimeUnit.DAYS);
            } else {
                decision = pendingItem.await(timeout, TimeUnit.SECONDS);
            }
            pending.remove(pendingItem);
            if (decision == null) {
                // timeout: forward original
                pendingItem.resolve(DecisionType.FORWARD);
                return body;
            }
            if (decision == DecisionType.DROP) {
                return null;
            }
            return pendingItem.getForwardBody();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pending.remove(pendingItem);
            return body;
        }
    }

    private InterceptRule firstMatch(TcpStreamFrame.Direction direction, byte[] body) {
        for (InterceptRule rule : rules) {
            if (!rule.isEnabled() || rule.getMatch() == null || rule.getMatch().isEmpty()) {
                continue;
            }
            boolean dirOk = direction == TcpStreamFrame.Direction.CLIENT_TO_SERVER
                    ? rule.appliesToClientToServer()
                    : rule.appliesToServerToClient();
            if (!dirOk) {
                continue;
            }
            if (bodyMatches(body, rule)) {
                return rule;
            }
        }
        return null;
    }

    private boolean bodyMatches(byte[] body, InterceptRule rule) {
        String enc = rule.getEncoding() == null ? "UTF16LE" : rule.getEncoding().toUpperCase()
                .replace("-", "").replace("_", "");
        if ("RAW".equals(enc) || "LATIN1".equals(enc) || "BOTH".equals(enc) || "ALL".equals(enc)) {
            if (matchInEncoding(body, rule, false)) {
                return true;
            }
        }
        if ("UTF16LE".equals(enc) || "UTF16".equals(enc) || "BOTH".equals(enc) || "ALL".equals(enc)
                || "UNICODE".equals(enc)) {
            if (matchInEncoding(body, rule, true)) {
                return true;
            }
        }
        // default UTF16 if unknown
        if (!"RAW".equals(enc) && !"LATIN1".equals(enc) && !"BOTH".equals(enc) && !"ALL".equals(enc)
                && !"UTF16LE".equals(enc) && !"UTF16".equals(enc)) {
            return matchInEncoding(body, rule, true);
        }
        return false;
    }

    private boolean matchInEncoding(byte[] body, InterceptRule rule, boolean utf16) {
        try {
            if (rule.isRegex()) {
                String text = utf16
                        ? new String(body, 0, body.length - (body.length % 2), StandardCharsets.UTF_16LE)
                        : new String(body, StandardCharsets.ISO_8859_1);
                return Pattern.compile(rule.getMatch(), Pattern.DOTALL | Pattern.CASE_INSENSITIVE)
                        .matcher(text).find();
            }
            byte[] needle = utf16
                    ? rule.getMatch().getBytes(StandardCharsets.UTF_16LE)
                    : rule.getMatch().getBytes(StandardCharsets.ISO_8859_1);
            return indexOf(body, needle) >= 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        if (needle.length == 0 || hay.length < needle.length) {
            return -1;
        }
        outer:
        for (int i = 0; i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
