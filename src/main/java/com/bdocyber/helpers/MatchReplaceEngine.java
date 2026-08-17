package com.bdocyber.helpers;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared match/replace for TCP relay and optional Proxy HTTP traffic.
 * <p>
 * For TDS, replacements are applied to <em>decoded</em> string fields and then
 * re-serialized so packet lengths and NVARCHAR prefixes stay consistent.
 * Raw byte replace is only used as a fallback for non-TDS bodies.
 */
public class MatchReplaceEngine {

    public enum Direction {
        REQUEST,
        RESPONSE
    }

    private final CopyOnWriteArrayList<MatchReplaceRule> rules = new CopyOnWriteArrayList<>();
    private final TdsHelper tdsHelper = new TdsHelper();
    private volatile boolean enabled = true;
    private volatile ApplyListener applyListener;

    public interface ApplyListener {
        void onApplied(MatchReplaceRule rule, Direction direction, int bodyBefore, int bodyAfter, String mode);
    }

    public void setApplyListener(ApplyListener listener) {
        this.applyListener = listener;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<MatchReplaceRule> getRules() {
        return new ArrayList<>(rules);
    }

    public void setRules(List<MatchReplaceRule> newRules) {
        rules.clear();
        if (newRules != null) {
            for (MatchReplaceRule r : newRules) {
                if (r != null) {
                    rules.add(r.copy());
                }
            }
        }
    }

    public void addRule(MatchReplaceRule rule) {
        if (rule != null) {
            rules.add(rule.copy());
        }
    }

    public void clearRules() {
        rules.clear();
    }

    public int enabledRuleCount() {
        int n = 0;
        for (MatchReplaceRule r : rules) {
            if (r.isEnabled() && r.getMatch() != null && !r.getMatch().isEmpty()) {
                n++;
            }
        }
        return n;
    }

    /**
     * Apply enabled rules. Prefer TDS-aware re-pack; fall back to raw bytes only when needed.
     */
    public byte[] apply(byte[] body, Direction direction) {
        if (!enabled || body == null || body.length == 0 || rules.isEmpty()) {
            return body;
        }

        List<MatchReplaceRule> active = activeRules(direction);
        if (active.isEmpty()) {
            return body;
        }

        // 1) TDS structured path (correct for length-changing SQL/userids)
        if (tdsHelper.looksLikeTds(body) || seemsLikeBrokenTds(body)) {
            try {
                byte[] forDecode = normalizeTdsLengthHeader(body);
                byte[] structured = applyTdsStructured(forDecode, active);
                if (structured != null && !Arrays.equals(structured, body)) {
                    for (MatchReplaceRule rule : active) {
                        // one log line summarizing the repack
                        notifyApplied(rule, direction, body.length, structured.length, "TDS-repack");
                        break;
                    }
                    return structured;
                }
                // structured path ran: do NOT fall back to raw TDS byte replace (breaks lengths)
                if (structured != null) {
                    return body;
                }
            } catch (Exception e) {
                // fall through to raw only when structured decode failed entirely
            }
        }

        // 2) Raw byte path (non-TDS, or TDS decode completely failed)
        byte[] current = body;
        for (MatchReplaceRule rule : active) {
            byte[] before = current;
            current = applyRuleRaw(current, rule);
            if (!Arrays.equals(before, current)) {
                notifyApplied(rule, direction, before.length, current.length, "RAW");
            }
        }
        return current;
    }

    private List<MatchReplaceRule> activeRules(Direction direction) {
        List<MatchReplaceRule> active = new ArrayList<>();
        for (MatchReplaceRule rule : rules) {
            if (!rule.isEnabled()) {
                continue;
            }
            if (rule.getMatch() == null || rule.getMatch().isEmpty()) {
                continue;
            }
            if (direction == Direction.REQUEST && !rule.appliesToRequest()) {
                continue;
            }
            if (direction == Direction.RESPONSE && !rule.appliesToResponse()) {
                continue;
            }
            active.add(rule);
        }
        return active;
    }

    private void notifyApplied(MatchReplaceRule rule, Direction direction, int before, int after, String mode) {
        ApplyListener listener = this.applyListener;
        if (listener != null) {
            try {
                listener.onApplied(rule, direction, before, after, mode);
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * True when header looks like TDS but length field disagrees (common after a bad raw replace).
     */
    private boolean seemsLikeBrokenTds(byte[] body) {
        if (body == null || body.length < 8) {
            return false;
        }
        int type = body[0] & 0xFF;
        int length = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
        return (type == 1 || type == 3 || type == 4 || type == 18)
                && length != body.length
                && length >= 8;
    }

    /** Fix TDS header length field to match actual buffer before decode. */
    private static byte[] normalizeTdsLengthHeader(byte[] body) {
        if (body == null || body.length < 8) {
            return body;
        }
        int length = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
        if (length == body.length) {
            return body;
        }
        byte[] copy = Arrays.copyOf(body, body.length);
        copy[2] = (byte) ((body.length >> 8) & 0xFF);
        copy[3] = (byte) (body.length & 0xFF);
        return copy;
    }

    /**
     * Decode → replace strings in JSON → re-pack with correct TDS lengths.
     *
     * @return new body, or {@code body} if no string changed, or {@code null} if not applicable
     */
    private byte[] applyTdsStructured(byte[] body, List<MatchReplaceRule> active) throws Exception {
        JSONArray packets = tdsHelper.unpack(body);
        if (packets.isEmpty()) {
            return null;
        }
        // Reject pure RAW fallback packets (not real decode)
        boolean anyKnown = false;
        for (int i = 0; i < packets.length(); i++) {
            String tn = packets.getJSONObject(i).optString("typeName", "");
            if (!tn.isEmpty() && !"RAW".equals(tn) && !tn.startsWith("UNKNOWN")) {
                anyKnown = true;
                break;
            }
        }
        if (!anyKnown) {
            return null;
        }

        boolean changed = false;
        for (int i = 0; i < packets.length(); i++) {
            JSONObject pkt = packets.getJSONObject(i);
            if (applyRulesToPacket(pkt, active)) {
                changed = true;
            }
        }
        if (!changed) {
            return body;
        }
        return tdsHelper.pack(packets);
    }

    private boolean applyRulesToPacket(JSONObject pkt, List<MatchReplaceRule> active) {
        boolean changed = false;
        String typeName = pkt.optString("typeName", "");

        if (pkt.has("rpc")) {
            JSONObject rpc = pkt.getJSONObject("rpc");
            if (rpc.has("sql") && !rpc.isNull("sql")) {
                String sql = rpc.getString("sql");
                String newSql = applyRulesToString(sql, active);
                if (!sql.equals(newSql)) {
                    rpc.put("sql", newSql);
                    changed = true;
                }
            }
            if (rpc.has("params")) {
                JSONArray params = rpc.getJSONArray("params");
                for (int p = 0; p < params.length(); p++) {
                    JSONObject param = params.getJSONObject(p);
                    if (param.has("value") && !param.isNull("value") && param.get("value") instanceof String) {
                        String v = param.getString("value");
                        String nv = applyRulesToString(v, active);
                        if (!v.equals(nv)) {
                            param.put("value", nv);
                            // keep NVARCHAR maxLen large enough after re-encode
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
            // Keep sql convenience field in sync with NVARCHAR params
            if (changed && rpc.has("sql") && rpc.has("params")) {
                // re-apply sql onto params if only param changed, encodeRpc will use sql if present
            }
        }

        if (pkt.has("sql") && !pkt.isNull("sql") && "SQL_BATCH".equals(typeName)) {
            String sql = pkt.getString("sql");
            String newSql = applyRulesToString(sql, active);
            if (!sql.equals(newSql)) {
                pkt.put("sql", newSql);
                changed = true;
            }
        }

        // Tabular row string cells (when present)
        if (pkt.has("rows")) {
            JSONArray rows = pkt.getJSONArray("rows");
            for (int r = 0; r < rows.length(); r++) {
                JSONObject row = rows.getJSONObject(r);
                if (row.has("values")) {
                    JSONObject values = row.getJSONObject("values");
                    for (String key : values.keySet()) {
                        if (values.isNull(key)) {
                            continue;
                        }
                        Object v = values.get(key);
                        if (v instanceof String) {
                            String nv = applyRulesToString((String) v, active);
                            if (!v.equals(nv)) {
                                values.put(key, nv);
                                changed = true;
                            }
                        }
                    }
                }
            }
            // Row re-pack is not fully supported via pack() for tabular — only RPC/SQL_BATCH rebuild.
            // If only rows changed, fall back is needed; mark by clearing ability...
            // For pack() tabular uses payloadHex, so row edits wouldn't apply. Revert row-only changes
            // to avoid false "changed" without wire effect.
            if (changed && !"RPC".equals(typeName) && !"SQL_BATCH".equals(typeName)) {
                // cannot re-encode tabular rows yet — use raw UTF-16 only if same length
                return false;
            }
        }

        return changed;
    }

    private String applyRulesToString(String text, List<MatchReplaceRule> active) {
        String current = text;
        for (MatchReplaceRule rule : active) {
            String enc = normalizeEncoding(rule.getEncoding());
            // Structured path always works on Java strings (Unicode). RAW encoding still applies
            // as a normal string replace here (characters, not Latin-1 body bytes).
            if ("RAW".equals(enc)) {
                // For TDS structured mode, RAW still means "match the text as typed"
                current = applyOneStringRule(current, rule);
            } else {
                // UTF16LE / BOTH — same for decoded Unicode text
                current = applyOneStringRule(current, rule);
            }
        }
        return current;
    }

    private static String applyOneStringRule(String text, MatchReplaceRule rule) {
        String match = rule.getMatch();
        String repl = rule.getReplace() == null ? "" : rule.getReplace();
        if (match == null || match.isEmpty()) {
            return text;
        }
        if (rule.isRegex()) {
            try {
                return Pattern.compile(match, Pattern.DOTALL).matcher(text).replaceAll(repl);
            } catch (Exception e) {
                return text;
            }
        }
        if (!text.contains(match)) {
            return text;
        }
        return text.replace(match, repl);
    }

    private byte[] applyRuleRaw(byte[] body, MatchReplaceRule rule) {
        String enc = normalizeEncoding(rule.getEncoding());
        if ("UTF16LE".equals(enc)) {
            return applyEncodedRaw(body, rule, true);
        }
        if ("RAW".equals(enc)) {
            return applyEncodedRaw(body, rule, false);
        }
        byte[] utf = applyEncodedRaw(body, rule, true);
        if (!Arrays.equals(utf, body)) {
            return utf;
        }
        return applyEncodedRaw(body, rule, false);
    }

    private static String normalizeEncoding(String encoding) {
        if (encoding == null || encoding.isBlank()) {
            return "UTF16LE";
        }
        String u = encoding.trim().toUpperCase().replace("-", "").replace("_", "");
        if ("UTF16LE".equals(u) || "UTF16".equals(u) || "UNICODE".equals(u)) {
            return "UTF16LE";
        }
        if ("RAW".equals(u) || "LATIN1".equals(u) || "ASCII".equals(u)) {
            return "RAW";
        }
        if ("BOTH".equals(u) || "ALL".equals(u)) {
            return "BOTH";
        }
        return "UTF16LE";
    }

    private byte[] applyEncodedRaw(byte[] body, MatchReplaceRule rule, boolean utf16) {
        try {
            if (rule.isRegex()) {
                return applyRegexRaw(body, rule, utf16);
            }
            byte[] find = encode(rule.getMatch(), utf16);
            byte[] repl = encode(rule.getReplace() == null ? "" : rule.getReplace(), utf16);
            if (find.length == 0) {
                return body;
            }
            // Refuse length-changing raw replace inside TDS-looking bodies (unsafe)
            if (find.length != repl.length && tdsHelper.looksLikeTds(body)) {
                return body;
            }
            return replaceBytes(body, find, repl);
        } catch (Exception e) {
            return body;
        }
    }

    private byte[] applyRegexRaw(byte[] body, MatchReplaceRule rule, boolean utf16) {
        if (utf16) {
            int len = body.length - (body.length % 2);
            if (len < 2) {
                return body;
            }
            String text = new String(body, 0, len, StandardCharsets.UTF_16LE);
            Pattern p = Pattern.compile(rule.getMatch(), Pattern.DOTALL);
            Matcher m = p.matcher(text);
            if (!m.find()) {
                return body;
            }
            String replaced = m.replaceAll(rule.getReplace() == null ? "" : rule.getReplace());
            if (tdsHelper.looksLikeTds(body) && replaced.length() != text.length()) {
                // length-changing regex on TDS via raw path is unsafe
                return body;
            }
            byte[] out = replaced.getBytes(StandardCharsets.UTF_16LE);
            if (body.length % 2 == 1) {
                byte[] withOdd = new byte[out.length + 1];
                System.arraycopy(out, 0, withOdd, 0, out.length);
                withOdd[out.length] = body[body.length - 1];
                return withOdd;
            }
            return out;
        } else {
            String text = new String(body, StandardCharsets.ISO_8859_1);
            Pattern p = Pattern.compile(rule.getMatch(), Pattern.DOTALL);
            Matcher m = p.matcher(text);
            if (!m.find()) {
                return body;
            }
            String replaced = m.replaceAll(rule.getReplace() == null ? "" : rule.getReplace());
            if (tdsHelper.looksLikeTds(body) && replaced.length() != text.length()) {
                return body;
            }
            return replaced.getBytes(StandardCharsets.ISO_8859_1);
        }
    }

    private static byte[] encode(String s, boolean utf16) {
        if (s == null) {
            return new byte[0];
        }
        return utf16 ? s.getBytes(StandardCharsets.UTF_16LE) : s.getBytes(StandardCharsets.ISO_8859_1);
    }

    public static byte[] replaceBytes(byte[] body, byte[] find, byte[] repl) {
        if (find.length == 0 || body.length < find.length) {
            return body;
        }
        List<Integer> hits = new ArrayList<>();
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
}
