package com.bdocyber.helpers;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Compact human-readable TDS dump for Follow Stream / summaries.
 * Server TABULAR_RESULT is a binary token stream — this surfaces tokens/rows, not raw UTF-16 scavenge.
 */
public final class TdsTextFormatter {

    private TdsTextFormatter() {
    }

    public static String formatBody(byte[] body) {
        if (body == null || body.length == 0) {
            return "(no data)\n";
        }
        try {
            TdsHelper helper = new TdsHelper();
            byte[] normalized = normalizeHeaderLength(body);
            if (!helper.looksLikeTds(normalized) && !helper.looksLikeTds(body)) {
                return formatNonTds(body);
            }
            JSONArray packets = helper.unpack(helper.looksLikeTds(normalized) ? normalized : body);
            if (packets.isEmpty()) {
                return formatNonTds(body);
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < packets.length(); i++) {
                if (i > 0) {
                    sb.append('\n');
                }
                formatPacket(packets.getJSONObject(i), sb);
            }
            return sb.toString();
        } catch (Exception e) {
            return "[TDS decode error: " + e.getMessage() + "]\n" + formatNonTds(body);
        }
    }

    /** One-line summary for packet list (TABULAR / RPC / batch). */
    public static String oneLineSummary(byte[] body, int maxLen) {
        if (body == null || body.length == 0) {
            return "(empty)";
        }
        if (maxLen < 16) {
            maxLen = 72;
        }
        try {
            TdsHelper helper = new TdsHelper();
            byte[] normalized = normalizeHeaderLength(body);
            if (!helper.looksLikeTds(normalized) && body.length >= 8) {
                int type = body[0] & 0xFF;
                String quick = typeNameQuick(type);
                if (quick != null) {
                    int hdrLen = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
                    if (hdrLen != body.length && hdrLen >= 8) {
                        return quick + " [incomplete " + body.length + "/" + hdrLen + " B]";
                    }
                    return quick + " (" + body.length + " B)";
                }
            }
            JSONArray packets = helper.unpack(helper.looksLikeTds(normalized) ? normalized : body);
            if (packets.isEmpty()) {
                return "binary " + body.length + " B";
            }
            // Prefer a packet that has row values / columns (merged multi-packet tabular)
            JSONObject best = packets.getJSONObject(0);
            int bestScore = packetSummaryScore(best);
            for (int i = 1; i < packets.length(); i++) {
                JSONObject p = packets.getJSONObject(i);
                int sc = packetSummaryScore(p);
                if (sc > bestScore) {
                    best = p;
                    bestScore = sc;
                }
            }
            String s = oneLinePacket(best, body.length);
            if (s.length() > maxLen) {
                return s.substring(0, maxLen - 1) + "…";
            }
            return s;
        } catch (Exception e) {
            return "binary " + body.length + " B";
        }
    }

    /** Package-visible for FollowStreamBuilder (auth enrichment path). */
    static void formatPacketPublic(JSONObject pkt, StringBuilder sb) {
        formatPacket(pkt, sb);
    }

    static byte[] normalizeHeaderLengthPublic(byte[] body) {
        return normalizeHeaderLength(body);
    }

    private static void formatPacket(JSONObject pkt, StringBuilder sb) {
        String typeName = pkt.optString("typeName", "?");
        sb.append(typeName);
        if (pkt.optBoolean("truncated", false)) {
            sb.append(" [truncated]");
        }
        sb.append('\n');

        if (pkt.has("decodeError")) {
            sb.append("  decodeError: ").append(pkt.get("decodeError")).append('\n');
        }

        if (pkt.has("rpc")) {
            JSONObject rpc = pkt.getJSONObject("rpc");
            sb.append("  ").append(rpc.optString("procName", "RPC"));
            if (rpc.has("procId")) {
                sb.append(" (procId=").append(rpc.get("procId")).append(')');
            }
            sb.append('\n');
            if (rpc.has("sql") && !rpc.isNull("sql")) {
                sb.append("  sql: ").append(TdsHelper.formatSqlForDisplay(rpc.getString("sql"))).append('\n');
            }
            if (rpc.has("params")) {
                JSONArray params = rpc.getJSONArray("params");
                for (int i = 0; i < params.length(); i++) {
                    JSONObject p = params.getJSONObject(i);
                    if (p.has("value") && !p.isNull("value") && p.get("value") instanceof String) {
                        String v = p.getString("value");
                        if (v.length() > 120) {
                            v = v.substring(0, 120) + "…";
                        }
                        String name = p.optString("name", "");
                        sb.append("  param[").append(i).append(']');
                        if (!name.isEmpty()) {
                            sb.append(' ').append(name);
                        }
                        sb.append(" = ").append(v).append('\n');
                    }
                }
            }
            return;
        }

        if (pkt.has("sql") && !pkt.isNull("sql")) {
            sb.append("  sql: ").append(TdsHelper.formatSqlForDisplay(pkt.getString("sql"))).append('\n');
            return;
        }

        if ("TABULAR_RESULT".equals(typeName) || pkt.has("tokens")) {
            formatTabular(pkt, sb);
            return;
        }

        if (pkt.has("prelogin") || "PRELOGIN".equals(typeName)) {
            sb.append("  PRELOGIN options / handshake\n");
            appendUtf16List(pkt, sb);
            return;
        }

        if ("SSPI".equals(typeName) || pkt.has("sspi")) {
            JSONObject sspi = pkt.optJSONObject("sspi");
            if (sspi != null) {
                sb.append("  ").append(sspi.optString("summary", "SSPI")).append('\n');
                if (sspi.has("kind")) {
                    sb.append("  kind: ").append(sspi.get("kind")).append('\n');
                }
                if (sspi.has("ntlm")) {
                    JSONObject ntlm = sspi.getJSONObject("ntlm");
                    sb.append("  NTLM type ").append(ntlm.opt("messageType"))
                            .append(" (").append(ntlm.optString("messageTypeName")).append(")\n");
                    for (String k : new String[]{"domain", "userName", "workstation", "targetName", "serverChallengeHex"}) {
                        if (ntlm.has(k) && !String.valueOf(ntlm.get(k)).isEmpty()) {
                            sb.append("    ").append(k).append(": ").append(ntlm.get(k)).append('\n');
                        }
                    }
                }
                if (sspi.has("kerberos")) {
                    JSONObject krb = sspi.getJSONObject("kerberos");
                    sb.append("  Kerberos ").append(krb.optString("messageType")).append('\n');
                    if (krb.has("spn")) {
                        sb.append("    spn: ").append(krb.get("spn")).append('\n');
                    }
                }
                if (sspi.has("spnego")) {
                    sb.append("  spnego: ").append(sspi.optString("spnegoToken", "")).append('\n');
                }
                sb.append('\n');
                com.bdocyber.helpers.tds.SspiDecoder.appendAuthMaterial(sb, sspi, "  ");
            } else {
                sb.append("  SSPI blob\n");
            }
            return;
        }

        if (pkt.has("note")) {
            sb.append("  ").append(pkt.getString("note")).append('\n');
        }
        appendUtf16List(pkt, sb);
        if (sb.toString().endsWith(typeName + "\n")) {
            sb.append("  (").append(pkt.optInt("length", 0)).append(" B payload; see Hex / Packets detail)\n");
        }
    }

    private static void formatTabular(JSONObject pkt, StringBuilder sb) {
        JSONArray columns = pkt.optJSONArray("columns");
        if (columns != null && columns.length() > 0) {
            sb.append("  columns (").append(columns.length()).append("): ");
            for (int i = 0; i < columns.length(); i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                if (i >= 12) {
                    sb.append("…");
                    break;
                }
                sb.append(columns.getJSONObject(i).optString("name", "col" + i));
            }
            sb.append('\n');
        }

        JSONArray tokens = pkt.optJSONArray("tokens");
        if (tokens != null) {
            int rowN = 0;
            for (int i = 0; i < tokens.length(); i++) {
                JSONObject t = tokens.getJSONObject(i);
                String name = t.optString("name", "TOKEN");
                switch (name) {
                    case "COLMETADATA" -> {
                        /* already listed columns */
                    }
                    case "ROW", "NBCROW" -> {
                        rowN++;
                        if (rowN <= 8) {
                            sb.append("  row[").append(rowN).append("]: ");
                            if (t.has("values")) {
                                sb.append(compactValues(t.getJSONObject("values")));
                            } else if (t.has("strings")) {
                                sb.append(t.get("strings").toString());
                            } else if (t.has("rawHex")) {
                                String hex = t.optString("rawHex", "");
                                sb.append("raw ").append(Math.min(hex.length() / 2, 9999)).append(" B");
                            }
                            sb.append('\n');
                        }
                    }
                    case "ERROR", "INFO" -> {
                        sb.append("  ").append(name);
                        if (t.has("number")) {
                            sb.append(' ').append(t.get("number"));
                        }
                        if (t.has("class")) {
                            sb.append(" (severity ").append(t.get("class")).append(')');
                        }
                        sb.append(": ");
                        if (t.has("message")) {
                            sb.append(t.getString("message"));
                        } else {
                            sb.append("(no message)");
                        }
                        sb.append('\n');
                    }
                    case "RETURNSTATUS" -> sb.append("  returnStatus: ").append(t.opt("value")).append('\n');
                    case "DONE", "DONEPROC", "DONEINPROC" -> {
                        sb.append("  ").append(name)
                                .append(" status=").append(t.opt("status"));
                        boolean countValid = t.optBoolean("countValid",
                                t.has("status") && (t.getInt("status") & 0x10) != 0);
                        if (countValid) {
                            sb.append(" rowCount=").append(t.opt("rowCount"));
                        }
                        sb.append('\n');
                    }
                    case "ENVCHANGE" -> {
                        sb.append("  ENVCHANGE ");
                        if (t.has("envTypeName")) {
                            sb.append(t.getString("envTypeName"));
                        } else {
                            sb.append("type=").append(t.opt("envType"));
                        }
                        if (t.has("oldValue") || t.has("newValue")) {
                            sb.append("  ").append(t.opt("oldValue")).append(" → ").append(t.opt("newValue"));
                        }
                        sb.append('\n');
                    }
                    case "LOGINACK" -> {
                        sb.append("  LOGINACK");
                        if (t.has("progName")) {
                            sb.append(" ").append(t.getString("progName"));
                        }
                        if (t.has("progVersion")) {
                            sb.append(" v").append(t.get("progVersion"));
                        }
                        sb.append('\n');
                    }
                    case "TABNAME" -> {
                        if (t.has("tables")) {
                            sb.append("  TABNAME: ").append(t.get("tables")).append('\n');
                        }
                    }
                    case "RETURNVALUE" -> {
                        sb.append("  RETURNVALUE");
                        if (t.has("name") && t.get("name") instanceof String n && !"RETURNVALUE".equals(n)) {
                            sb.append(' ').append(n);
                        }
                        if (t.has("value")) {
                            sb.append(" = ").append(t.get("value"));
                        }
                        sb.append('\n');
                    }
                    case "UNKNOWN" -> {
                        sb.append("  UNKNOWN token ").append(t.optString("codeHex", ""));
                        JSONArray u = t.optJSONArray("utf16Strings");
                        if (u != null && u.length() > 0) {
                            sb.append(" strings=").append(u);
                        }
                        sb.append('\n');
                    }
                    default -> {
                        if (t.has("decodeError")) {
                            sb.append("  ").append(name).append(" error: ").append(t.get("decodeError")).append('\n');
                        }
                    }
                }
            }
            if (rowN > 8) {
                sb.append("  … ").append(rowN - 8).append(" more row(s)\n");
            }
        }

        JSONArray rows = pkt.optJSONArray("rows");
        if ((tokens == null || tokens.isEmpty()) && rows != null && rows.length() > 0) {
            for (int i = 0; i < Math.min(rows.length(), 8); i++) {
                JSONObject row = rows.getJSONObject(i);
                sb.append("  row[").append(i + 1).append("]: ");
                if (row.has("values")) {
                    sb.append(compactValues(row.getJSONObject("values")));
                } else {
                    sb.append(row.opt("strings"));
                }
                sb.append('\n');
            }
        }

        // Scavenged strings when structure is thin (login/env responses)
        JSONArray utf = pkt.optJSONArray("utf16Strings");
        if (utf != null && utf.length() > 0) {
            boolean thin = !sb.toString().contains("row[") && !sb.toString().contains("columns");
            if (thin || utf.length() <= 12) {
                sb.append("  strings: ");
                for (int i = 0; i < utf.length() && i < 16; i++) {
                    if (i > 0) {
                        sb.append(" | ");
                    }
                    sb.append(utf.getString(i));
                }
                if (utf.length() > 16) {
                    sb.append(" | …");
                }
                sb.append('\n');
            }
        }
    }

    private static String compactValues(JSONObject values) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (String key : values.keySet()) {
            if (n > 0) {
                sb.append(", ");
            }
            if (n >= 10) {
                sb.append("…");
                break;
            }
            Object v = values.get(key);
            String vs = v == null || v == JSONObject.NULL ? "NULL" : String.valueOf(v);
            if (vs.length() > 40) {
                vs = vs.substring(0, 40) + "…";
            }
            sb.append(key).append('=').append(vs);
            n++;
        }
        return sb.toString();
    }

    private static void appendUtf16List(JSONObject pkt, StringBuilder sb) {
        JSONArray utf = pkt.optJSONArray("utf16Strings");
        if (utf != null && utf.length() > 0) {
            sb.append("  strings: ");
            for (int i = 0; i < utf.length() && i < 12; i++) {
                if (i > 0) {
                    sb.append(" | ");
                }
                sb.append(utf.getString(i));
            }
            sb.append('\n');
        }
    }

    /** Higher = better candidate for one-line summary (rows beat bare metadata). */
    private static int packetSummaryScore(JSONObject pkt) {
        if (pkt == null) {
            return 0;
        }
        int score = 0;
        if (pkt.has("columns")) {
            score += 10 + Math.min(pkt.getJSONArray("columns").length(), 50);
        }
        if (pkt.has("rows")) {
            score += 50 + Math.min(pkt.getJSONArray("rows").length() * 5, 100);
        }
        JSONArray tokens = pkt.optJSONArray("tokens");
        if (tokens != null) {
            for (int i = 0; i < tokens.length(); i++) {
                JSONObject t = tokens.getJSONObject(i);
                String name = t.optString("name");
                if ("ROW".equals(name) || "NBCROW".equals(name)) {
                    score += t.has("values") ? 40 : 5;
                }
                if ("ERROR".equals(name)) {
                    score += 80;
                }
            }
        }
        if (pkt.has("rpc") || pkt.has("sql")) {
            score += 30;
        }
        if (pkt.has("sspi")) {
            score += 20;
        }
        return score;
    }

    private static String oneLinePacket(JSONObject pkt, int bodyLen) {
        String typeName = pkt.optString("typeName", "TDS");
        if (pkt.has("rpc")) {
            JSONObject rpc = pkt.getJSONObject("rpc");
            String proc = rpc.optString("procName", "RPC");
            if (rpc.has("sql") && !rpc.isNull("sql")) {
                return proc + ": " + TdsHelper.formatSqlForDisplay(rpc.getString("sql"));
            }
            return proc + " (" + bodyLen + " B)";
        }
        if (pkt.has("sql") && !pkt.isNull("sql")) {
            return "SQL_BATCH: " + TdsHelper.formatSqlForDisplay(pkt.getString("sql"));
        }
        if ("TABULAR_RESULT".equals(typeName) || pkt.has("tokens")) {
            JSONArray tokens = pkt.optJSONArray("tokens");
            if (tokens != null) {
                for (int i = 0; i < tokens.length(); i++) {
                    JSONObject t = tokens.getJSONObject(i);
                    String name = t.optString("name");
                    if ("ERROR".equals(name) || "INFO".equals(name)) {
                        if (t.has("message")) {
                            String m = t.getString("message");
                            if (t.has("number")) {
                                return name + " " + t.get("number") + ": " + m;
                            }
                            return name + ": " + m;
                        }
                    }
                }
            }
            JSONArray cols = pkt.optJSONArray("columns");
            int colN = cols != null ? cols.length() : 0;
            int rowN = 0;
            String firstRow = null;
            if (tokens != null) {
                for (int i = 0; i < tokens.length(); i++) {
                    JSONObject t = tokens.getJSONObject(i);
                    String name = t.optString("name");
                    if ("ROW".equals(name) || "NBCROW".equals(name)) {
                        rowN++;
                        if (firstRow == null && t.has("values")) {
                            firstRow = compactValues(t.getJSONObject("values"));
                        }
                    }
                    if ("DONE".equals(name) || "DONEPROC".equals(name) || "DONEINPROC".equals(name)) {
                        if (t.has("rowCount") && rowN == 0) {
                            // use DONE rowCount as hint
                        }
                    }
                }
            }
            if (pkt.has("rows")) {
                rowN = Math.max(rowN, pkt.getJSONArray("rows").length());
            }
            StringBuilder s = new StringBuilder("TABULAR");
            if (colN > 0) {
                s.append(' ').append(colN).append(" col");
                if (colN != 1) {
                    s.append('s');
                }
                if (cols != null && cols.length() > 0) {
                    s.append(" [");
                    for (int i = 0; i < Math.min(cols.length(), 4); i++) {
                        if (i > 0) {
                            s.append(',');
                        }
                        s.append(cols.getJSONObject(i).optString("name", "?"));
                    }
                    if (cols.length() > 4) {
                        s.append("…");
                    }
                    s.append(']');
                }
            }
            if (rowN > 0) {
                s.append(", ").append(rowN).append(" row");
                if (rowN != 1) {
                    s.append('s');
                }
            }
            if (firstRow != null && !firstRow.isEmpty()) {
                s.append(": ").append(firstRow);
            } else {
                JSONArray utf = pkt.optJSONArray("utf16Strings");
                if (utf != null && utf.length() > 0) {
                    s.append(": ");
                    for (int i = 0; i < Math.min(utf.length(), 4); i++) {
                        if (i > 0) {
                            s.append(" | ");
                        }
                        s.append(utf.getString(i));
                    }
                } else {
                    s.append(" (").append(bodyLen).append(" B)");
                }
            }
            return s.toString();
        }
        if ("PRELOGIN".equals(typeName) || pkt.has("preloginOptions") || pkt.has("prelogin")) {
            StringBuilder s = new StringBuilder("PRELOGIN");
            JSONArray opts = pkt.optJSONArray("preloginOptions");
            if (opts == null && pkt.has("prelogin")) {
                opts = pkt.optJSONObject("prelogin").optJSONArray("options");
            }
            if (opts != null) {
                for (int i = 0; i < opts.length(); i++) {
                    JSONObject o = opts.getJSONObject(i);
                    if (o.has("encryption")) {
                        s.append(" enc=").append(o.get("encryption"));
                    } else if (o.has("version")) {
                        s.append(" v=").append(o.get("version"));
                    } else if (o.has("mars")) {
                        s.append(" mars=").append(o.get("mars"));
                    }
                }
            }
            s.append(" (").append(bodyLen).append(" B)");
            return s.toString();
        }
        if ("SSPI".equals(typeName) || pkt.has("sspi")) {
            JSONObject sspi = pkt.optJSONObject("sspi");
            if (sspi != null && sspi.has("summary")) {
                return "SSPI: " + sspi.getString("summary");
            }
            return "SSPI (" + bodyLen + " B)";
        }
        if ("LOGIN7".equals(typeName) || "TDS7_LOGIN".equals(typeName) || pkt.has("login7")) {
            JSONObject l = pkt.optJSONObject("login7");
            StringBuilder s = new StringBuilder("LOGIN7");
            if (l != null) {
                if (l.has("userName") && !l.optString("userName").isEmpty()) {
                    s.append(' ').append(l.getString("userName"));
                }
                if (l.has("appName") && !l.optString("appName").isEmpty()) {
                    s.append(" app=").append(l.getString("appName"));
                }
                if (l.has("database") && !l.optString("database").isEmpty()) {
                    s.append(" db=").append(l.getString("database"));
                }
                if (l.has("sspi") || (l.optInt("sspiLength", 0) > 0)) {
                    s.append(" +SSPI");
                }
            }
            s.append(" (").append(bodyLen).append(" B)");
            return s.toString();
        }
        // Incomplete / non-matching PDU still label known type when possible
        if (typeName != null && !typeName.isEmpty() && !"RAW".equals(typeName)) {
            return typeName + " (" + bodyLen + " B)";
        }
        return typeName + " (" + bodyLen + " B)";
    }

    private static String formatNonTds(byte[] body) {
        // light UTF-16 scavenge fallback
        StringBuilder run = new StringBuilder();
        StringBuilder out = new StringBuilder();
        out.append("[not TDS / incomplete PDU — printable UTF-16LE]\n");
        boolean any = false;
        for (int i = 0; i + 1 < body.length; i += 2) {
            int lo = body[i] & 0xFF;
            int hi = body[i + 1] & 0xFF;
            if (hi == 0 && lo >= 0x20 && lo < 0x7f) {
                run.append((char) lo);
            } else {
                if (run.length() >= 2) {
                    out.append(run).append('\n');
                    any = true;
                }
                run.setLength(0);
            }
        }
        if (run.length() >= 2) {
            out.append(run).append('\n');
            any = true;
        }
        if (!any) {
            out.append("(").append(body.length).append(" B binary)\n");
        }
        return out.toString();
    }

    private static String typeNameQuick(int type) {
        return switch (type) {
            case 1 -> "SQL_BATCH";
            case 3 -> "RPC";
            case 4 -> "TABULAR";
            case 6 -> "ATTENTION";
            case 14 -> "TXN_MGR";
            case 16 -> "LOGIN7";
            case 17 -> "SSPI";
            case 18 -> "PRELOGIN";
            default -> null;
        };
    }

    /**
     * Only rewrite the first packet length when this looks like a single mis-sized PDU.
     * Multi-packet TABULAR messages must keep their real per-packet lengths.
     */
    static byte[] normalizeHeaderLength(byte[] body) {
        if (body == null || body.length < 8) {
            return body;
        }
        int length = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
        if (length == body.length) {
            return body;
        }
        TdsHelper.PduFraming framing = TdsHelper.analyzePduFraming(body);
        if (framing.completePacketCount >= 1 && framing.isFullyComplete()) {
            return body;
        }
        if (framing.completePacketCount >= 2) {
            return body;
        }
        if (length > body.length || length < 8) {
            byte[] copy = body.clone();
            copy[2] = (byte) ((body.length >> 8) & 0xFF);
            copy[3] = (byte) (body.length & 0xFF);
            return copy;
        }
        return body;
    }
}
