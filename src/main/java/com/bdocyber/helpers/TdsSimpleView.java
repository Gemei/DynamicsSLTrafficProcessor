package com.bdocyber.helpers;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * TDS presentation: simple HTTP-style text by default, full technical JSON optional.
 * <p>
 * Simple view focuses on what is happening (SQL, proc, rows, errors) — no token plumbing,
 * no payloadHex, no instructional hints.
 */
public final class TdsSimpleView {

    public static final String VIEW_SIMPLE = "simple";
    public static final String VIEW_FULL = "full";

    /** Max characters per table cell in Simple/Follow view (display default). 0 = unlimited. */
    private static final ThreadLocal<Integer> MAX_CELL_WIDTH = ThreadLocal.withInitial(() -> 40);

    private TdsSimpleView() {
    }

    /**
     * Temporarily set max cell width for result tables (e.g. unlimited when copying Follow dump).
     * Call {@link #resetMaxCellWidth()} in a finally block.
     *
     * @param maxChars max width, or {@code <= 0} for unlimited
     */
    public static void setMaxCellWidth(int maxChars) {
        MAX_CELL_WIDTH.set(maxChars <= 0 ? Integer.MAX_VALUE : maxChars);
    }

    public static void resetMaxCellWidth() {
        MAX_CELL_WIDTH.remove();
    }

    private static int maxCellWidth() {
        Integer w = MAX_CELL_WIDTH.get();
        return w != null ? w : 40;
    }

    /**
     * @param simple true = human-readable request/response style; false = full JSON unpack
     */
    public static String format(byte[] body, JSONObject meta, boolean simple) {
        try {
            TdsHelper helper = new TdsHelper();
            byte[] norm = normalize(body);
            JSONArray full = helper.looksLikeTds(norm) ? helper.unpack(norm)
                    : (helper.looksLikeTds(body) ? helper.unpack(body) : new JSONArray());
            if (full.isEmpty()) {
                if (simple) {
                    return formatUnknownSimple(body, meta);
                }
                JSONObject raw = new JSONObject();
                copyMeta(meta, raw);
                raw.put("note", "Not recognized as TDS");
                if (body != null) {
                    raw.put("utf16Strings", TdsHelper.extractUtf16Strings(body, 2));
                }
                return raw.toString(2);
            }
            if (simple) {
                return formatHttpStyle(full, meta, body);
            }
            return buildFull(full, meta).toString(2);
        } catch (Exception e) {
            return "Error decoding TDS: " + e.getMessage() + "\n";
        }
    }

    /** HTTP-like plain text for Simple view. */
    public static String formatHttpStyle(JSONArray fullPackets, JSONObject meta, byte[] body) {
        StringBuilder sb = new StringBuilder();
        String direction = meta != null ? meta.optString("direction", "") : "";
        boolean server = direction.contains("SERVER") || direction.contains("S→C")
                || "SERVER_RESPONSE".equals(direction) || "SERVER_TO_CLIENT".equals(direction);
        String peer = meta != null ? meta.optString("peer", "") : "";
        String streamKey = meta != null ? meta.optString("streamKey", "") : "";

        if (server) {
            sb.append("TDS Response");
        } else if (direction.contains("CLIENT") || direction.contains("REQUEST")) {
            sb.append("TDS Request");
        } else {
            sb.append("TDS Message");
        }
        if (!peer.isEmpty()) {
            sb.append(server ? "  from " : "  to ").append(peer);
        } else if (!streamKey.isEmpty()) {
            sb.append("  ").append(streamKey);
        }
        if (meta != null && meta.has("seq")) {
            sb.append("  (#").append(meta.get("seq")).append(')');
        }
        if (body != null) {
            sb.append("  ").append(body.length).append(" bytes");
        }
        sb.append('\n');
        if (meta != null && meta.has("userName") && !meta.optString("userName").isEmpty()) {
            sb.append("Name: ").append(meta.getString("userName")).append('\n');
        }
        if (meta != null && meta.has("assembledBytes")) {
            sb.append("Assembled multi-packet message: ").append(meta.get("assembledBytes"))
                    .append(" bytes\n");
        }
        sb.append('\n');

        for (int i = 0; i < fullPackets.length(); i++) {
            if (i > 0) {
                sb.append('\n');
            }
            appendPacketHttpStyle(fullPackets.getJSONObject(i), sb);
        }
        return sb.toString();
    }

    private static void appendPacketHttpStyle(JSONObject full, StringBuilder sb) {
        if (full.has("rpc")) {
            JSONObject rpc = full.getJSONObject("rpc");
            String proc = rpc.optString("procName", "RPC");
            sb.append(proc);
            if (rpc.has("procId")) {
                sb.append("  (procId=").append(rpc.get("procId")).append(')');
            }
            sb.append('\n');
            if (rpc.has("sql") && !rpc.isNull("sql")) {
                sb.append('\n').append(displaySql(rpc.getString("sql"))).append('\n');
            }
            JSONArray params = rpc.optJSONArray("params");
            if (params != null && params.length() > 0) {
                sb.append('\n').append("Parameters:\n");
                for (int i = 0; i < params.length(); i++) {
                    JSONObject p = params.getJSONObject(i);
                    String name = p.optString("name", "");
                    String type = p.optString("sqlType", "?");
                    sb.append("  [").append(i).append("] ");
                    if (!name.isEmpty()) {
                        sb.append(name).append(" ");
                    }
                    sb.append('(').append(type).append(") = ");
                    if (p.has("value") && !p.isNull("value")) {
                        sb.append(p.get("value"));
                    } else if (p.has("valueHex")) {
                        sb.append("<binary ").append(p.optString("valueHex").length() / 2).append(" B>");
                    } else {
                        sb.append("<empty>");
                    }
                    sb.append('\n');
                }
            }
            return;
        }

        if (full.has("sql") && !full.isNull("sql")
                && ("SQL_BATCH".equals(full.optString("typeName")) || full.has("sql"))) {
            sb.append("SQL Batch\n\n");
            String sql = full.optString("sqlDisplay", null);
            if (sql == null || sql.isEmpty()) {
                sql = displaySql(full.getString("sql"));
            }
            sb.append(sql).append('\n');
            return;
        }

        String typeName = full.optString("typeName", "");
        if ("TABULAR_RESULT".equals(typeName) || full.has("tokens") || full.has("rows")) {
            appendTabularHttpStyle(full, sb);
            return;
        }

        if ("PRELOGIN".equals(typeName)) {
            sb.append("Pre-login handshake\n");
            if (full.has("preloginOptions")) {
                JSONArray opts = full.getJSONArray("preloginOptions");
                for (int i = 0; i < opts.length(); i++) {
                    JSONObject o = opts.getJSONObject(i);
                    sb.append("  ").append(o.optString("optionName", "opt" + o.opt("option")));
                    if (o.has("version")) {
                        sb.append(" = ").append(o.get("version"));
                    } else if (o.has("encryption")) {
                        sb.append(" encryption=").append(o.get("encryption"));
                    } else if (o.has("mars")) {
                        sb.append(" mars=").append(o.get("mars"));
                    }
                    sb.append('\n');
                }
            } else {
                appendStringsLine(full, sb);
            }
            return;
        }

        if (full.has("login7")) {
            JSONObject l = full.getJSONObject("login7");
            sb.append("Login (TDS7)\n");
            for (String k : new String[]{"hostName", "userName", "appName", "serverName", "database", "libraryName"}) {
                if (l.has(k) && !l.optString(k).isEmpty()) {
                    sb.append("  ").append(k).append(": ").append(l.get(k)).append('\n');
                }
            }
            if (l.has("password")) {
                sb.append("  password: ").append(l.get("password")).append('\n');
            }
            JSONObject loginSspi = l.optJSONObject("sspi");
            if (loginSspi == null) {
                loginSspi = full.optJSONObject("sspi");
            }
            if (loginSspi != null) {
                sb.append("  SSPI: ").append(loginSspi.optString("summary", "")).append('\n');
                com.bdocyber.helpers.tds.SspiDecoder.appendAuthMaterial(sb, loginSspi, "  ");
            }
            return;
        }

        if ("SSPI".equals(typeName) || full.has("sspi")) {
            appendSspiSimple(full, sb);
            return;
        }

        if (typeName.contains("LOGIN")) {
            sb.append(typeName.isEmpty() ? "Login / SSPI" : typeName).append('\n');
            appendStringsLine(full, sb);
            if (full.has("note")) {
                sb.append(full.getString("note")).append('\n');
            }
            return;
        }

        sb.append(typeName.isEmpty() ? "Packet" : typeName).append('\n');
        if (full.has("note")) {
            sb.append(full.getString("note")).append('\n');
        }
        appendStringsLine(full, sb);
    }

    private static void appendTabularHttpStyle(JSONObject full, StringBuilder sb) {
        JSONArray tokens = full.optJSONArray("tokens");
        boolean wroteHeader = false;

        // Errors / info first (most important)
        if (tokens != null) {
            for (int i = 0; i < tokens.length(); i++) {
                JSONObject t = tokens.getJSONObject(i);
                String name = t.optString("name");
                if ("ERROR".equals(name) || "INFO".equals(name)) {
                    if (!wroteHeader) {
                        sb.append("Result\n\n");
                        wroteHeader = true;
                    }
                    sb.append(name);
                    if (t.has("number")) {
                        sb.append(' ').append(t.get("number"));
                    }
                    if (t.has("class")) {
                        sb.append("  (severity ").append(t.get("class")).append(')');
                    }
                    if (t.has("serverName")) {
                        sb.append("  server=").append(t.getString("serverName"));
                    }
                    sb.append('\n');
                    if (t.has("message")) {
                        sb.append(t.getString("message")).append('\n');
                    }
                    if (t.has("lineNumber")) {
                        sb.append("Line: ").append(t.get("lineNumber")).append('\n');
                    }
                    sb.append('\n');
                }
            }
        }

        JSONArray cols = full.optJSONArray("columns");
        JSONArray rowValues = collectRows(full);
        JSONArray orderedRows = collectOrderedRows(full);

        if (cols != null && cols.length() > 0 || rowValues.length() > 0) {
            if (!wroteHeader) {
                sb.append("Result set\n\n");
                wroteHeader = true;
            }
            if (cols != null && cols.length() > 0) {
                sb.append("Columns (").append(cols.length()).append("): ");
                for (int i = 0; i < cols.length(); i++) {
                    if (i > 0) {
                        sb.append(", ");
                    }
                    sb.append(cols.getJSONObject(i).optString("name", "col" + i));
                }
                sb.append('\n');
            }
            if (rowValues.length() == 0 && (orderedRows == null || orderedRows.length() == 0)) {
                sb.append("(no rows)\n");
            } else {
                int n = Math.max(rowValues.length(),
                        orderedRows != null ? orderedRows.length() : 0);
                sb.append("Rows (").append(n).append("):\n\n");
                appendResultTable(sb, cols, orderedRows, rowValues);
            }
            sb.append('\n');
        }

        if (tokens != null) {
            for (int i = 0; i < tokens.length(); i++) {
                JSONObject t = tokens.getJSONObject(i);
                String name = t.optString("name");
                if ("RETURNSTATUS".equals(name)) {
                    sb.append("Return status: ").append(t.opt("value")).append('\n');
                } else if ("DONE".equals(name) || "DONEPROC".equals(name) || "DONEINPROC".equals(name)) {
                    sb.append(name);
                    // DoneRowCount is only meaningful when DONE_COUNT (0x10) is set ([MS-TDS] 2.2.7.6)
                    boolean countValid = t.optBoolean("countValid",
                            t.has("status") && (t.getInt("status") & 0x10) != 0);
                    if (countValid && t.has("rowCount")) {
                        long rc = t.getLong("rowCount");
                        // Guard against mis-parsed huge counts (e.g. 0x5D5D5D5D from stream desync)
                        if (rc >= 0 && rc < 1_000_000_000L) {
                            sb.append("  rows affected: ").append(rc);
                        } else {
                            sb.append("  rows affected: ").append(rc)
                                    .append(" (suspicious — check Full view)");
                        }
                    }
                    sb.append('\n');
                } else if ("ENVCHANGE".equals(name)) {
                    sb.append("Env change");
                    if (t.has("envTypeName")) {
                        sb.append(": ").append(t.getString("envTypeName"));
                    } else if (t.has("envType")) {
                        sb.append(" type=").append(t.get("envType"));
                    }
                    if (t.has("newValue") || t.has("oldValue")) {
                        sb.append("  ");
                        if (t.has("oldValue")) {
                            sb.append(t.get("oldValue")).append(" → ");
                        }
                        sb.append(t.opt("newValue"));
                    } else if (t.has("newValueHex")) {
                        sb.append("  (binary ").append(t.optString("newValueHex").length() / 2).append(" B)");
                    }
                    sb.append('\n');
                } else if ("LOGINACK".equals(name)) {
                    sb.append("Login OK");
                    if (t.has("progName")) {
                        sb.append("  server=").append(t.getString("progName"));
                    }
                    if (t.has("progVersion")) {
                        sb.append("  version=").append(t.get("progVersion"));
                    }
                    if (t.has("tdsVersionHex")) {
                        sb.append("  tds=").append(t.get("tdsVersionHex"));
                    }
                    sb.append('\n');
                } else if ("TABNAME".equals(name) && t.has("tables")) {
                    sb.append("Table: ").append(t.get("tables")).append('\n');
                }
            }
        }

        // Only show scavenged strings if we had almost nothing useful
        if (!wroteHeader && rowValues.length() == 0) {
            JSONArray utf = full.optJSONArray("utf16Strings");
            if (utf != null && utf.length() > 0) {
                sb.append("Text:\n");
                for (int i = 0; i < utf.length(); i++) {
                    String s = utf.optString(i, "");
                    if (isMostlyPrintableAscii(s)) {
                        sb.append("  ").append(s).append('\n');
                    }
                }
            }
        }
    }

    private static JSONArray collectRows(JSONObject full) {
        JSONArray out = new JSONArray();
        JSONArray tokens = full.optJSONArray("tokens");
        if (tokens != null) {
            for (int i = 0; i < tokens.length(); i++) {
                JSONObject t = tokens.getJSONObject(i);
                String name = t.optString("name");
                if ("ROW".equals(name) || "NBCROW".equals(name)) {
                    if (t.has("values")) {
                        out.put(t.getJSONObject("values"));
                    } else if (t.has("strings")) {
                        // ROW without COLMETADATA context — show scavenged strings
                        out.put(stringsToValues(t.getJSONArray("strings")));
                    }
                }
            }
        }
        if (out.length() == 0 && full.has("rows")) {
            JSONArray rows = full.getJSONArray("rows");
            for (int i = 0; i < rows.length(); i++) {
                JSONObject r = rows.getJSONObject(i);
                if (r.has("values")) {
                    out.put(r.getJSONObject("values"));
                } else if (r.has("ordered")) {
                    JSONObject mapped = new JSONObject();
                    JSONArray cols = full.optJSONArray("columns");
                    JSONArray ordered = r.getJSONArray("ordered");
                    for (int c = 0; c < ordered.length(); c++) {
                        String cname = cols != null && c < cols.length()
                                ? cols.getJSONObject(c).optString("name", "col" + c)
                                : "col" + c;
                        mapped.put(cname, ordered.get(c));
                    }
                    out.put(mapped);
                }
            }
        }
        return out;
    }

    /** Prefer column-order arrays for table layout. */
    private static JSONArray collectOrderedRows(JSONObject full) {
        JSONArray out = new JSONArray();
        if (full.has("rows")) {
            JSONArray rows = full.getJSONArray("rows");
            for (int i = 0; i < rows.length(); i++) {
                JSONObject r = rows.getJSONObject(i);
                if (r.has("ordered")) {
                    out.put(r.getJSONArray("ordered"));
                }
            }
        }
        if (out.length() > 0) {
            return out;
        }
        JSONArray tokens = full.optJSONArray("tokens");
        if (tokens != null) {
            for (int i = 0; i < tokens.length(); i++) {
                JSONObject t = tokens.getJSONObject(i);
                String name = t.optString("name");
                if (("ROW".equals(name) || "NBCROW".equals(name)) && t.has("values")) {
                    // Build ordered from columns if present
                    JSONArray cols = full.optJSONArray("columns");
                    JSONObject values = t.getJSONObject("values");
                    if (cols != null && cols.length() > 0) {
                        JSONArray ord = new JSONArray();
                        for (int c = 0; c < cols.length(); c++) {
                            String cname = cols.getJSONObject(c).optString("name", "col" + c);
                            ord.put(values.has(cname) ? values.get(cname) : JSONObject.NULL);
                        }
                        out.put(ord);
                    }
                }
            }
        }
        return out;
    }

    private static JSONObject stringsToValues(JSONArray strings) {
        JSONObject values = new JSONObject();
        if (strings == null) {
            return values;
        }
        for (int i = 0; i < strings.length(); i++) {
            values.put("str" + i, strings.optString(i, ""));
        }
        return values;
    }

    /**
     * ASCII table for result sets (column headers + rows). Wide tables wrap by printing
     * a vertical key=value block after a compact header when many columns.
     */
    private static void appendResultTable(StringBuilder sb, JSONArray cols,
                                          JSONArray orderedRows, JSONArray rowValues) {
        int colCount = cols != null ? cols.length() : 0;
        int rowCount = orderedRows != null && orderedRows.length() > 0
                ? orderedRows.length() : rowValues.length();
        if (rowCount == 0) {
            return;
        }

        // Many columns (typical Dynamics SL UserRec): vertical layout is more readable
        if (colCount > 12) {
            for (int r = 0; r < rowCount; r++) {
                sb.append("── Row ").append(r + 1).append(" ──\n");
                if (cols != null && orderedRows != null && r < orderedRows.length()) {
                    JSONArray ord = orderedRows.getJSONArray(r);
                    for (int c = 0; c < cols.length(); c++) {
                        String cname = cols.getJSONObject(c).optString("name", "col" + c);
                        Object v = c < ord.length() ? ord.get(c) : JSONObject.NULL;
                        sb.append(String.format("  %-24s  %s%n", cname, cellText(v)));
                    }
                } else if (r < rowValues.length() && rowValues.get(r) instanceof JSONObject jo) {
                    for (String key : jo.keySet()) {
                        sb.append(String.format("  %-24s  %s%n", key, cellText(jo.get(key))));
                    }
                }
                sb.append('\n');
            }
            return;
        }

        // Compact grid for narrower result sets
        String[] headers;
        if (cols != null && cols.length() > 0) {
            headers = new String[cols.length()];
            for (int i = 0; i < cols.length(); i++) {
                headers[i] = cols.getJSONObject(i).optString("name", "col" + i);
            }
        } else if (rowValues.length() > 0 && rowValues.get(0) instanceof JSONObject jo) {
            List<String> keys = new ArrayList<>();
            for (String k : jo.keySet()) {
                keys.add(k);
            }
            headers = keys.toArray(new String[0]);
        } else {
            headers = new String[]{"value"};
        }

        final int maxW = maxCellWidth();
        final boolean unlimited = maxW == Integer.MAX_VALUE;
        int[] widths = new int[headers.length];
        for (int i = 0; i < headers.length; i++) {
            int hlen = headers[i].length();
            widths[i] = unlimited ? Math.max(3, hlen) : Math.min(maxW, Math.max(3, hlen));
        }
        String[][] cells = new String[rowCount][headers.length];
        for (int r = 0; r < rowCount; r++) {
            for (int c = 0; c < headers.length; c++) {
                String text;
                if (orderedRows != null && r < orderedRows.length()) {
                    JSONArray ord = orderedRows.getJSONArray(r);
                    text = cellText(c < ord.length() ? ord.get(c) : JSONObject.NULL);
                } else if (r < rowValues.length() && rowValues.get(r) instanceof JSONObject jo) {
                    text = cellText(jo.opt(headers[c]));
                } else {
                    text = "";
                }
                if (!unlimited && text.length() > maxW) {
                    text = text.substring(0, Math.max(0, maxW - 1)) + "…";
                }
                cells[r][c] = text;
                if (unlimited) {
                    widths[c] = Math.max(widths[c], text.length());
                } else {
                    widths[c] = Math.min(maxW, Math.max(widths[c], text.length()));
                }
            }
        }

        // header
        sb.append("| ");
        for (int c = 0; c < headers.length; c++) {
            if (c > 0) {
                sb.append(" | ");
            }
            sb.append(pad(headers[c], widths[c]));
        }
        sb.append(" |\n| ");
        for (int c = 0; c < headers.length; c++) {
            if (c > 0) {
                sb.append(" | ");
            }
            sb.append("-".repeat(widths[c]));
        }
        sb.append(" |\n");
        for (int r = 0; r < rowCount; r++) {
            sb.append("| ");
            for (int c = 0; c < headers.length; c++) {
                if (c > 0) {
                    sb.append(" | ");
                }
                sb.append(pad(cells[r][c], widths[c]));
            }
            sb.append(" |\n");
        }
    }

    private static String cellText(Object v) {
        if (v == null || v == JSONObject.NULL) {
            return "NULL";
        }
        String s = String.valueOf(v);
        return s.replace('\n', ' ').replace('\r', ' ');
    }

    /** Prefer sanitized SQL for Simple/Follow views. */
    private static String displaySql(String sql) {
        return com.bdocyber.helpers.TdsHelper.formatSqlForDisplay(sql);
    }

    private static String pad(String s, int w) {
        if (s == null) {
            s = "";
        }
        if (s.length() >= w) {
            return s.substring(0, w);
        }
        return s + " ".repeat(w - s.length());
    }

    private static void appendSspiSimple(JSONObject full, StringBuilder sb) {
        JSONObject sspi = full.optJSONObject("sspi");
        if (sspi == null) {
            sb.append("SSPI\n");
            if (full.has("note")) {
                sb.append(full.getString("note")).append('\n');
            }
            appendStringsLine(full, sb);
            return;
        }
        sb.append("SSPI authentication\n");
        sb.append("  ").append(sspi.optString("summary", "SSPI")).append('\n');
        String kind = sspi.optString("kind", "");
        if (!kind.isEmpty()) {
            sb.append("  kind: ").append(kind);
            if (sspi.has("mechanism")) {
                sb.append("  (").append(sspi.get("mechanism")).append(')');
            }
            if (sspi.has("thisMechName")) {
                sb.append("  gss=").append(sspi.get("thisMechName"));
            }
            sb.append('\n');
        }
        if (sspi.has("spnegoToken")) {
            sb.append("  SPNEGO: ").append(sspi.get("spnegoToken"));
            JSONObject sp = sspi.optJSONObject("spnego");
            if (sp != null) {
                if (sp.has("negStateName")) {
                    sb.append("  state=").append(sp.get("negStateName"));
                }
                if (sp.has("supportedMechName")) {
                    sb.append("  supported=").append(sp.get("supportedMechName"));
                }
                if (sp.has("mechTypeNames")) {
                    sb.append("  mechs=").append(sp.getJSONArray("mechTypeNames"));
                }
            }
            sb.append('\n');
        }
        JSONObject ntlm = sspi.optJSONObject("ntlm");
        if (ntlm == null && sspi.optJSONObject("spnego") != null) {
            ntlm = sspi.getJSONObject("spnego").optJSONObject("ntlm");
        }
        if (ntlm != null) {
            sb.append("  NTLM ").append(ntlm.optString("messageTypeName", ""));
            sb.append(" (type ").append(ntlm.opt("messageType")).append(")\n");
            for (String k : new String[]{"domain", "userName", "workstation", "targetName"}) {
                if (ntlm.has(k) && !ntlm.optString(k).isEmpty()) {
                    sb.append("    ").append(k).append(": ").append(ntlm.get(k)).append('\n');
                }
            }
            if (ntlm.has("serverChallengeHex")) {
                sb.append("    serverChallenge: ").append(ntlm.get("serverChallengeHex")).append('\n');
            }
            if (ntlm.has("flagsHex")) {
                sb.append("    flags: ").append(ntlm.get("flagsHex"));
                if (ntlm.has("flagNames")) {
                    sb.append("  ").append(ntlm.getJSONArray("flagNames"));
                }
                sb.append('\n');
            }
            JSONObject ti = ntlm.optJSONObject("targetInfo");
            if (ti != null) {
                sb.append("    targetInfo:\n");
                for (String k : new String[]{"nbComputerName", "nbDomainName", "dnsComputerName",
                        "dnsDomainName", "dnsTreeName", "targetName"}) {
                    if (ti.has(k) && !ti.optString(k).isEmpty()) {
                        sb.append("      ").append(k).append(": ").append(ti.get(k)).append('\n');
                    }
                }
            }
            if (ntlm.has("version")) {
                JSONObject v = ntlm.getJSONObject("version");
                sb.append("    version: ").append(v.optString("product", "")).append('\n');
            }
        }
        JSONObject krb = sspi.optJSONObject("kerberos");
        if (krb == null && sspi.optJSONObject("spnego") != null) {
            krb = sspi.getJSONObject("spnego").optJSONObject("kerberos");
        }
        if (krb != null) {
            sb.append("  Kerberos ").append(krb.optString("messageType", "")).append('\n');
            if (krb.has("spn")) {
                sb.append("    spn: ").append(krb.get("spn")).append('\n');
            }
            JSONArray strings = krb.optJSONArray("strings");
            if (strings != null && strings.length() > 0) {
                sb.append("    principals: ");
                for (int i = 0; i < strings.length() && i < 8; i++) {
                    if (i > 0) {
                        sb.append(" | ");
                    }
                    sb.append(strings.getString(i));
                }
                sb.append('\n');
            }
        }
        // NetNTLM hashes + Kerberos tickets (promoted credentials)
        sb.append('\n');
        com.bdocyber.helpers.tds.SspiDecoder.appendAuthMaterial(sb, sspi, "  ");

        if (sspi.has("decodeError")) {
            sb.append("  decodeError: ").append(sspi.get("decodeError")).append('\n');
        }
    }

    private static void appendStringsLine(JSONObject full, StringBuilder sb) {
        JSONArray utf = full.optJSONArray("utf16Strings");
        if (utf == null || utf.length() == 0) {
            return;
        }
        sb.append("Strings: ");
        boolean any = false;
        for (int i = 0; i < utf.length(); i++) {
            String s = utf.optString(i, "");
            if (!isMostlyPrintableAscii(s)) {
                continue;
            }
            if (any) {
                sb.append(" | ");
            }
            sb.append(s);
            any = true;
        }
        if (any) {
            sb.append('\n');
        }
    }

    private static boolean isMostlyPrintableAscii(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        int ok = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t') {
                ok++;
            }
        }
        return ok * 10 >= s.length() * 8; // >= 80% printable ASCII
    }

    private static String formatUnknownSimple(byte[] body, JSONObject meta) {
        StringBuilder sb = new StringBuilder();
        sb.append("Binary message");
        if (meta != null && meta.has("direction")) {
            sb.append("  ").append(meta.get("direction"));
        }
        if (body != null) {
            sb.append("  ").append(body.length).append(" bytes\n\n");
            JSONArray utf = TdsHelper.extractUtf16Strings(body, 2);
            for (int i = 0; i < utf.length(); i++) {
                String s = utf.optString(i, "");
                if (isMostlyPrintableAscii(s)) {
                    sb.append(s).append('\n');
                }
            }
        } else {
            sb.append("\n(no data)\n");
        }
        return sb.toString();
    }

    public static JSONObject buildFull(JSONArray fullPackets, JSONObject meta) {
        JSONObject env = new JSONObject();
        copyMeta(meta, env);
        // Deep-ish copy packets without payloadHex noise
        JSONArray cleaned = new JSONArray();
        for (int i = 0; i < fullPackets.length(); i++) {
            cleaned.put(stripPayloadHex(fullPackets.getJSONObject(i)));
        }
        env.put("packets", cleaned);
        return env;
    }

    private static JSONObject stripPayloadHex(JSONObject o) {
        JSONObject c = new JSONObject(o.toString());
        c.remove("payloadHex");
        c.remove("rawHex");
        if (c.has("rpc")) {
            JSONObject rpc = c.getJSONObject("rpc");
            rpc.remove("allHeadersHex");
            if (rpc.has("params")) {
                JSONArray params = rpc.getJSONArray("params");
                for (int i = 0; i < params.length(); i++) {
                    params.getJSONObject(i).remove("rawHex");
                    params.getJSONObject(i).remove("collationHex");
                }
            }
        }
        if (c.has("tokens")) {
            JSONArray tokens = c.getJSONArray("tokens");
            for (int i = 0; i < tokens.length(); i++) {
                JSONObject t = tokens.getJSONObject(i);
                t.remove("rawHex");
                t.remove("offset");
            }
        }
        return c;
    }

    /**
     * Pack editor text back to TDS bytes.
     * Supports full JSON, simple JSON, and human Simple view (SQL Batch / RPC SQL).
     */
    public static byte[] packEditor(String text, byte[] originalBody, TdsHelper helper) throws Exception {
        if (text == null || text.isBlank()) {
            return originalBody != null ? originalBody : new byte[0];
        }
        String trimmed = text.trim();
        if (trimmed.startsWith("[")) {
            return helper.pack(new JSONArray(trimmed));
        }
        if (!trimmed.startsWith("{")) {
            String hex = trimmed.replaceAll("\\s+", "");
            if (hex.matches("(?i)[0-9a-f]+") && hex.length() % 2 == 0 && hex.length() >= 16) {
                return TdsHelper.fromHex(hex);
            }
            // Human Simple view (SQL Batch / RPC) — re-pack SQL edits onto original body
            return packFromSimplePlainText(trimmed, originalBody, helper);
        }
        JSONObject obj = new JSONObject(trimmed);
        boolean simple = VIEW_SIMPLE.equalsIgnoreCase(obj.optString("view"))
                || looksLikeSimplePackets(obj.optJSONArray("packets"));

        if (!simple && obj.has("packets")) {
            JSONArray pkts = obj.getJSONArray("packets");
            if (looksLikeSimplePackets(pkts) && !hasFullShape(pkts)) {
                simple = true;
            }
        }

        if (simple) {
            byte[] base = originalBody;
            if (base == null || base.length == 0) {
                throw new IllegalArgumentException("Need original body to re-pack simple edits");
            }
            JSONArray full = helper.unpack(normalize(base));
            applySimpleEdits(full, obj);
            return helper.pack(full);
        }

        if (obj.has("packets")) {
            return helper.pack(obj.getJSONArray("packets"));
        }
        return helper.pack(new JSONArray().put(obj));
    }

    /**
     * Re-pack Simple (HTTP-style) editor text by applying extracted SQL to the original TDS body.
     */
    static byte[] packFromSimplePlainText(String text, byte[] originalBody, TdsHelper helper)
            throws Exception {
        if (originalBody == null || originalBody.length == 0) {
            throw new IllegalArgumentException(
                    "Simple view needs the original packet body to re-pack; re-send the frame to Replay.");
        }
        if (!helper.looksLikeTds(normalize(originalBody)) && !helper.looksLikeTds(originalBody)) {
            throw new IllegalArgumentException(
                    "Original body is not TDS — switch to Full / hex to edit.");
        }
        String sql = extractSqlFromSimpleText(text);
        if (sql == null) {
            throw new IllegalArgumentException(
                    "Could not find SQL to apply in Simple view.\n"
                            + "Edit the SQL under “SQL Batch” or after the procedure name, "
                            + "or switch to Full and edit JSON.");
        }
        // Normalize line endings; trim only trailing blank lines (keep intentional leading spaces)
        sql = sql.replace("\r\n", "\n").replace('\r', '\n');
        while (sql.endsWith("\n")) {
            sql = sql.substring(0, sql.length() - 1);
        }
        if (sql.isEmpty()) {
            throw new IllegalArgumentException("SQL text is empty after edit.");
        }

        byte[] base = helper.looksLikeTds(normalize(originalBody)) ? normalize(originalBody) : originalBody;
        JSONArray full = helper.unpack(base);
        if (full.isEmpty()) {
            throw new IllegalArgumentException("Could not unpack original TDS packet.");
        }
        // Compare to original SQL — if unchanged, still pack (round-trip) so user gets feedback
        applySqlToPacket(full.getJSONObject(0), sql);
        // Multi-packet bodies: only first packet holds client SQL typically
        return helper.pack(full);
    }

    /**
     * Pull editable SQL out of Simple view text.
     * Formats:
     * <pre>
     * SQL Batch
     *
     * SELECT ...
     * </pre>
     * or RPC:
     * <pre>
     * Sp_CursorOpen  (procId=2)
     *
     * Select * from ...
     *
     * Parameters:
     * </pre>
     */
    static String extractSqlFromSimpleText(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String t = text.replace("\r\n", "\n").replace('\r', '\n');

        // --- SQL Batch block ---
        int batchIdx = indexOfIgnoreCase(t, "SQL Batch");
        if (batchIdx >= 0) {
            int after = batchIdx + "SQL Batch".length();
            // skip whitespace / blank lines after header
            while (after < t.length() && (t.charAt(after) == ' ' || t.charAt(after) == '\t')) {
                after++;
            }
            if (after < t.length() && t.charAt(after) == '\n') {
                after++;
            }
            while (after < t.length() && t.charAt(after) == '\n') {
                after++;
            }
            String sql = t.substring(after);
            // stop at common trailing sections if any
            int stop = indexOfSection(sql, new String[]{"Parameters:", "Result", "Result set", "SSPI "});
            if (stop >= 0) {
                sql = sql.substring(0, stop);
            }
            sql = stripTrailingBlankLines(sql);
            if (!sql.isBlank()) {
                return sql;
            }
        }

        // --- RPC with SQL between proc line and Parameters ---
        int paramsIdx = indexOfIgnoreCase(t, "\nParameters:");
        if (paramsIdx < 0) {
            paramsIdx = indexOfIgnoreCase(t, "\nParameters\n");
        }
        // Find first blank line after header (TDS Request / proc name)
        String body = t;
        // Drop leading meta lines (TDS Request/Response, empty)
        String[] lines = body.split("\n", -1);
        int start = 0;
        while (start < lines.length) {
            String line = lines[start].trim();
            if (line.isEmpty()
                    || line.startsWith("TDS Request")
                    || line.startsWith("TDS Response")
                    || line.startsWith("TDS Message")
                    || line.startsWith("Name:")
                    || line.matches(".*\\(\\d+\\s*B\\).*")
                    || line.matches(".*procId=\\d+.*")
                    || (line.contains("procId=") && line.contains("("))) {
                start++;
                continue;
            }
            // proc name only line e.g. "Sp_CursorOpen  (procId=2)" already handled above
            if (line.matches("(?i)sp_[a-z0-9_]+.*") || line.matches("(?i)[a-z_][a-z0-9_]*\\s*\\(.*procId.*")) {
                start++;
                // skip following blank lines
                while (start < lines.length && lines[start].trim().isEmpty()) {
                    start++;
                }
                break;
            }
            break;
        }
        StringBuilder sqlSb = new StringBuilder();
        for (int i = start; i < lines.length; i++) {
            String line = lines[i];
            if (line.trim().equalsIgnoreCase("Parameters:")
                    || line.trim().equalsIgnoreCase("Parameters")
                    || line.startsWith("  [") && line.contains(") = ")) {
                break;
            }
            if (sqlSb.length() > 0) {
                sqlSb.append('\n');
            }
            sqlSb.append(line);
        }
        String sql = stripTrailingBlankLines(sqlSb.toString());
        if (!sql.isBlank() && looksLikeSql(sql)) {
            return sql;
        }

        // Free-text: whole editor is just SQL (user deleted headers)
        String whole = stripTrailingBlankLines(t);
        // remove TDS meta first line if present
        if (whole.startsWith("TDS Request") || whole.startsWith("TDS Response") || whole.startsWith("TDS Message")) {
            int nl = whole.indexOf('\n');
            whole = nl >= 0 ? whole.substring(nl + 1).stripLeading() : "";
        }
        if (looksLikeSql(whole)) {
            return whole;
        }
        return null;
    }

    private static boolean looksLikeSql(String s) {
        if (s == null || s.isBlank()) {
            return false;
        }
        String low = s.toLowerCase();
        return low.contains("select") || low.contains("insert") || low.contains("update")
                || low.contains("delete") || low.contains("exec") || low.contains("create")
                || low.contains("alter") || low.contains("declare") || low.contains("from ")
                || low.contains("where ");
    }

    private static String stripTrailingBlankLines(String s) {
        if (s == null) {
            return "";
        }
        int end = s.length();
        while (end > 0 && (s.charAt(end - 1) == '\n' || s.charAt(end - 1) == '\r'
                || s.charAt(end - 1) == ' ' || s.charAt(end - 1) == '\t')) {
            end--;
        }
        return s.substring(0, end);
    }

    private static int indexOfIgnoreCase(String hay, String needle) {
        return hay.toLowerCase().indexOf(needle.toLowerCase());
    }

    private static int indexOfSection(String sql, String[] markers) {
        int best = -1;
        for (String m : markers) {
            int i = indexOfIgnoreCase(sql, "\n" + m);
            if (i >= 0 && (best < 0 || i < best)) {
                best = i;
            }
        }
        return best;
    }

    public static boolean isSimpleView(String text) {
        if (text == null || text.isBlank()) {
            return true;
        }
        String t = text.trim();
        if (!t.startsWith("{") && !t.startsWith("[")) {
            return true; // HTTP-style text
        }
        try {
            JSONObject o = new JSONObject(t);
            if (VIEW_FULL.equalsIgnoreCase(o.optString("view"))) {
                return false;
            }
            return true;
        } catch (Exception e) {
            return true;
        }
    }

    private static boolean looksLikeSimplePackets(JSONArray packets) {
        if (packets == null || packets.length() == 0) {
            return false;
        }
        JSONObject p0 = packets.optJSONObject(0);
        return p0 != null && p0.has("kind") && !p0.has("typeName");
    }

    private static boolean hasFullShape(JSONArray packets) {
        if (packets == null || packets.length() == 0) {
            return false;
        }
        JSONObject p0 = packets.optJSONObject(0);
        return p0 != null && (p0.has("typeName") || p0.has("type"));
    }

    public static void applySimpleEdits(JSONArray fullPackets, JSONObject simpleEnv) {
        String topSql = simpleEnv.has("sql") && !simpleEnv.isNull("sql")
                ? simpleEnv.getString("sql") : null;
        JSONArray simplePkts = simpleEnv.optJSONArray("packets");
        if (simplePkts == null) {
            if (topSql != null && fullPackets.length() > 0) {
                applySqlToPacket(fullPackets.getJSONObject(0), topSql);
            }
            return;
        }
        for (int i = 0; i < simplePkts.length() && i < fullPackets.length(); i++) {
            JSONObject sp = simplePkts.getJSONObject(i);
            JSONObject fp = fullPackets.getJSONObject(i);
            String sql = sp.has("sql") && !sp.isNull("sql") ? sp.getString("sql") : null;
            if (sql == null && i == 0 && topSql != null) {
                sql = topSql;
            }
            if (sql != null) {
                applySqlToPacket(fp, sql);
            }
            if (sp.has("params") && fp.has("rpc")) {
                JSONArray spParams = sp.getJSONArray("params");
                JSONArray fpParams = fp.getJSONObject("rpc").optJSONArray("params");
                if (fpParams != null) {
                    for (int p = 0; p < spParams.length() && p < fpParams.length(); p++) {
                        JSONObject spP = spParams.getJSONObject(p);
                        JSONObject fpP = fpParams.getJSONObject(p);
                        if (spP.has("value") && !spP.isNull("value")) {
                            fpP.put("value", spP.get("value"));
                            if (spP.get("value") instanceof String v) {
                                int need = v.getBytes(java.nio.charset.StandardCharsets.UTF_16LE).length;
                                if (fpP.optInt("maxLen", 0) < need) {
                                    fpP.put("maxLen", need);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static void applySqlToPacket(JSONObject fp, String sql) {
        if (fp.has("rpc")) {
            JSONObject rpc = fp.getJSONObject("rpc");
            rpc.put("sql", sql);
            JSONArray params = rpc.optJSONArray("params");
            if (params != null) {
                int firstNv = findFirstNVarchar(params);
                for (int i = 0; i < params.length(); i++) {
                    JSONObject p = params.getJSONObject(i);
                    if ("NVARCHAR".equals(p.optString("sqlType")) || p.optInt("type") == 0xE7) {
                        Object old = p.opt("value");
                        boolean looksSql = old instanceof String os
                                && os.toLowerCase().matches("(?s).*(select|insert|update|delete|exec|create|alter).*");
                        if (looksSql || i == firstNv) {
                            p.put("value", sql);
                            int need = sql.getBytes(java.nio.charset.StandardCharsets.UTF_16LE).length;
                            if (p.optInt("maxLen", 0) < need) {
                                p.put("maxLen", need);
                            }
                            break;
                        }
                    }
                }
            }
        } else if (fp.has("sql") || "SQL_BATCH".equals(fp.optString("typeName"))) {
            fp.put("sql", sql);
        }
    }

    private static int findFirstNVarchar(JSONArray params) {
        for (int i = 0; i < params.length(); i++) {
            JSONObject p = params.getJSONObject(i);
            if ("NVARCHAR".equals(p.optString("sqlType")) || p.optInt("type") == 0xE7) {
                return i;
            }
        }
        return 0;
    }

    private static void copyMeta(JSONObject meta, JSONObject env) {
        if (meta == null) {
            return;
        }
        for (String k : new String[]{
                "seq", "streamKey", "peer", "direction", "matchReplaced", "highlight",
                "userName", "source", "id", "matchedRule", "step", "mode", "summary"
        }) {
            if (meta.has(k)) {
                env.put(k, meta.get(k));
            }
        }
    }

    /**
     * Fix a single incomplete TDS packet whose length field was rewritten to the buffer size
     * (common in some capture paths). Do <b>not</b> rewrite multi-packet messages — that
     * destroys framing and breaks COLMETADATA+ROW spanning PDUs.
     */
    private static byte[] normalize(byte[] body) {
        if (body == null || body.length < 8) {
            return body;
        }
        int length = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
        if (length == body.length) {
            return body;
        }
        // Multiple complete PDUs already in buffer — leave alone
        TdsHelper.PduFraming framing = TdsHelper.analyzePduFraming(body);
        if (framing.completePacketCount >= 1 && framing.isFullyComplete()) {
            return body;
        }
        if (framing.completePacketCount >= 2) {
            return body;
        }
        // Single truncated / mis-sized packet: rewrite length to match buffer
        if (length > body.length || length < 8) {
            byte[] copy = body.clone();
            copy[2] = (byte) ((body.length >> 8) & 0xFF);
            copy[3] = (byte) (body.length & 0xFF);
            return copy;
        }
        // Declared first packet ends before buffer end but framing incomplete — leave raw
        return body;
    }
}
