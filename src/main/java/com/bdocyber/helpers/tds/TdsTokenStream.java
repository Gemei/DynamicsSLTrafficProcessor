package com.bdocyber.helpers.tds;

import com.bdocyber.helpers.ArraySliceHelper;
import com.bdocyber.helpers.TdsHelper;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Decode MS-TDS Type=4 tabular token stream ([MS-TDS] 2.2.7).
 */
public final class TdsTokenStream {

    private TdsTokenStream() {
    }

    public static void decode(byte[] payload, JSONObject pkt) {
        JSONArray tokens = new JSONArray();
        JSONArray rows = new JSONArray();
        JSONArray columns = new JSONArray();
        TdsCursor c = new TdsCursor(payload);

        while (c.remaining() > 0) {
            // skip padding zeros between tokens
            if (c.peekU8() == 0x00) {
                c.u8();
                continue;
            }
            int tokenStart = c.pos();
            int token = c.u8();
            JSONObject t = new JSONObject();
            t.put("code", token);
            t.put("codeHex", String.format("0x%02X", token));
            t.put("name", TdsSpec.tokenName(token));
            try {
                switch (token) {
                    case TdsSpec.TOK_COLMETADATA -> columns = decodeColMetadata(c, t);
                    case TdsSpec.TOK_ALTMETADATA -> decodeAltMetadata(c, t);
                    case TdsSpec.TOK_TABNAME -> decodeTabName(c, t);
                    case TdsSpec.TOK_COLINFO -> decodeLengthPrefixed(c, t, true);
                    case TdsSpec.TOK_ORDER -> decodeLengthPrefixed(c, t, true);
                    case TdsSpec.TOK_OFFSET -> decodeOffset(c, t);
                    case TdsSpec.TOK_ENVCHANGE -> decodeEnvChange(c, t);
                    case TdsSpec.TOK_ROW -> decodeRow(c, t, columns, rows, false);
                    case TdsSpec.TOK_NBCROW -> decodeNbcRow(c, t, columns, rows);
                    case TdsSpec.TOK_ALTROW -> decodeAltRow(c, t);
                    case TdsSpec.TOK_RETURNSTATUS -> {
                        t.put("value", c.u32());
                    }
                    case TdsSpec.TOK_DONE, TdsSpec.TOK_DONEPROC, TdsSpec.TOK_DONEINPROC -> decodeDone(c, t);
                    case TdsSpec.TOK_ERROR, TdsSpec.TOK_INFO -> decodeErrorInfo(c, t);
                    case TdsSpec.TOK_RETURNVALUE -> decodeReturnValue(c, t);
                    case TdsSpec.TOK_LOGINACK -> decodeLoginAck(c, t);
                    case TdsSpec.TOK_FEATUREEXTACK -> decodeFeatureExtAck(c, t);
                    case TdsSpec.TOK_SESSIONSTATE -> decodeSessionState(c, t);
                    case TdsSpec.TOK_SSPI -> decodeSspiToken(c, t);
                    case TdsSpec.TOK_FEDAUTHINFO -> decodeFedAuthInfo(c, t);
                    default -> {
                        // length-prefixed skip if possible
                        if (c.has(2)) {
                            int len = c.u16();
                            if (len >= 0 && c.has(len) && len < c.remaining() + len) {
                                t.put("rawHex", c.hex(len));
                                t.put("utf16Strings", TdsHelper.extractUtf16Strings(
                                        ArraySliceHelper.getArraySlice(payload, c.pos() - len, c.pos()), 2));
                                tokens.put(t);
                                continue;
                            }
                            c.setPos(c.pos() - 2);
                        }
                        t.put("rawHex", TdsHelper.toHex(ArraySliceHelper.getArraySlice(
                                payload, c.pos(), payload.length)));
                        t.put("utf16Strings", TdsHelper.extractUtf16Strings(
                                ArraySliceHelper.getArraySlice(payload, c.pos(), payload.length), 3));
                        tokens.put(t);
                        c.setPos(payload.length);
                    }
                }
                tokens.put(t);
            } catch (Exception e) {
                t.put("decodeError", e.getMessage());
                t.put("rawHex", TdsHelper.toHex(ArraySliceHelper.getArraySlice(
                        payload, tokenStart, payload.length)));
                tokens.put(t);
                break;
            }
        }

        pkt.put("tokens", tokens);
        if (!columns.isEmpty()) {
            pkt.put("columns", columns);
        }
        if (!rows.isEmpty()) {
            pkt.put("rows", rows);
        }
        pkt.put("utf16Strings", TdsHelper.extractUtf16Strings(payload, 3));
    }

    /**
     * COLMETADATA ([MS-TDS] 2.2.7.4).
     * UserType is ULONG (TDS 7.2+) or USHORT (7.1-); we auto-detect.
     * TEXT/NTEXT/IMAGE include TableName; encrypted columns include CryptoMetaData.
     */
    private static JSONArray decodeColMetadata(TdsCursor c, JSONObject t) {
        int count = c.u16();
        t.put("count", count == 0xFFFF ? 0 : count);
        t.put("noMetaData", count == 0xFFFF);
        JSONArray columns = new JSONArray();
        if (count == 0xFFFF) {
            t.put("columns", columns);
            return columns;
        }
        if (count < 0 || count > 4096) {
            t.put("decodeError", "COLMETADATA count out of range: " + count);
            t.put("columns", columns);
            return columns;
        }

        int start = c.pos();
        // Optional CekTable (column encryption) — only when present; try parse with/without
        ColMetaResult best = null;
        for (boolean withCek : new boolean[]{false, true}) {
            for (int utBytes : new int[]{4, 2}) {
                TdsCursor trial = new TdsCursor(c.data(), start);
                try {
                    if (withCek) {
                        if (!skipCekTable(trial)) {
                            continue;
                        }
                    }
                    ColMetaResult r = parseColDataList(trial, count, utBytes);
                    if (best == null || r.score > best.score) {
                        best = r;
                        best.userTypeBytes = utBytes;
                        best.hadCekTable = withCek;
                    }
                    // Perfect score: stop early
                    if (r.score >= count * 10 && r.badNames == 0 && r.unknownTypes == 0) {
                        break;
                    }
                } catch (Exception ignored) {
                    // try next strategy
                }
            }
            if (best != null && best.score >= count * 10 && best.badNames == 0) {
                break;
            }
        }

        if (best == null || best.columns.isEmpty()) {
            // Fall back to 4-byte UserType without CEK (most common modern SQL Server)
            try {
                ColMetaResult r = parseColDataList(new TdsCursor(c.data(), start), count, 4);
                best = r;
                best.userTypeBytes = 4;
            } catch (Exception e) {
                t.put("decodeError", "COLMETADATA parse failed: " + e.getMessage());
                t.put("columns", columns);
                return columns;
            }
        }

        c.setPos(best.endPos);
        t.put("columns", best.columns);
        t.put("userTypeBytes", best.userTypeBytes);
        if (best.hadCekTable) {
            t.put("cekTable", true);
        }
        if (best.unknownTypes > 0 || best.badNames > best.columns.length() / 2) {
            t.put("decodeWarning",
                    "COLMETADATA may be misaligned (" + best.unknownTypes + " unknown types, "
                            + best.badNames + " bad names). score=" + best.score);
        }
        return best.columns;
    }

    private static final class ColMetaResult {
        JSONArray columns = new JSONArray();
        int endPos;
        int score;
        int unknownTypes;
        int badNames;
        int userTypeBytes = 4;
        boolean hadCekTable;
    }

    private static ColMetaResult parseColDataList(TdsCursor c, int count, int userTypeBytes) {
        ColMetaResult r = new ColMetaResult();
        for (int i = 0; i < count; i++) {
            if (c.remaining() < 4) {
                throw new IllegalStateException("truncated at column " + i);
            }
            JSONObject col = new JSONObject();
            long userType = userTypeBytes == 4 ? c.u32u() : (c.u16() & 0xFFFFL);
            int flags = c.u16();
            int colType = c.u8();
            col.put("userType", userType);
            col.put("flags", flags);
            col.put("flagNames", colFlagNames(flags));
            c.setPos(TdsTypeReader.parseTypeInfo(c.data(), c.pos(), colType, col));

            // TableName after TYPE_INFO for TEXT/NTEXT/IMAGE
            if (TdsTypeReader.needsTableName(colType)) {
                col.put("tableName", readPartName(c));
            }
            // CryptoMetaData when fEncrypted (0x0400)
            if ((flags & 0x0400) != 0) {
                skipCryptoMetaData(c, col);
            }

            String name = safeBVarchar(c);
            col.put("name", name);
            if (!TdsTypeReader.isKnownSqlType(colType)) {
                r.unknownTypes++;
                r.score -= 5;
            } else {
                r.score += 10;
            }
            if (!isSaneColumnName(name)) {
                r.badNames++;
                r.score -= 8;
                col.put("nameCorrupt", true);
                // Prefer synthetic name for rows map so JSON stays readable
                if (name == null || name.isEmpty() || !isSaneColumnName(name)) {
                    col.put("nameRaw", name);
                    col.put("name", "col" + i);
                }
            } else {
                r.score += 3;
            }
            r.columns.put(col);
        }
        r.endPos = c.pos();
        return r;
    }

    private static JSONArray colFlagNames(int flags) {
        JSONArray a = new JSONArray();
        if ((flags & 0x0001) != 0) {
            a.put("Nullable");
        }
        if ((flags & 0x0010) != 0) {
            a.put("Identity");
        }
        if ((flags & 0x0020) != 0) {
            a.put("Computed");
        }
        if ((flags & 0x0200) != 0) {
            a.put("SparseColumnSet");
        }
        if ((flags & 0x0400) != 0) {
            a.put("Encrypted");
        }
        if ((flags & 0x1000) != 0) {
            a.put("Hidden");
        }
        if ((flags & 0x2000) != 0) {
            a.put("Key");
        }
        return a;
    }

    private static boolean skipCekTable(TdsCursor c) {
        if (!c.has(2)) {
            return false;
        }
        int ekCount = c.u16();
        // Sanity: encryption key count is small
        if (ekCount < 0 || ekCount > 64) {
            return false;
        }
        for (int i = 0; i < ekCount; i++) {
            if (!c.has(4 + 4 + 4 + 8 + 1)) {
                return false;
            }
            c.skip(4); // DatabaseId
            c.skip(4); // CekId
            c.skip(4); // CekVersion
            c.skip(8); // CekMdVersion
            int valCount = c.u8();
            if (valCount < 0 || valCount > 32) {
                return false;
            }
            for (int v = 0; v < valCount; v++) {
                if (!c.has(2)) {
                    return false;
                }
                int encLen = c.u16();
                if (encLen < 0 || !c.has(encLen)) {
                    return false;
                }
                c.skip(encLen);
                // KeyStoreName USHORT len + chars, KeyPath USHORT + chars, AsymmetricKey USHORT + chars
                for (int s = 0; s < 3; s++) {
                    if (!c.has(2)) {
                        return false;
                    }
                    int n = c.u16();
                    if (n < 0 || n > 2048 || !c.has(n * 2)) {
                        return false;
                    }
                    c.skip(n * 2);
                }
            }
        }
        return true;
    }

    private static void skipCryptoMetaData(TdsCursor c, JSONObject col) {
        if (!c.has(2 + 4 + 1)) {
            return;
        }
        int ordinal = c.u16();
        long ut = c.u32u();
        int algo = c.u8();
        col.put("cryptoOrdinal", ordinal);
        col.put("cryptoUserType", ut);
        col.put("cryptoAlgo", algo);
        if (algo == 0 && c.has(1)) {
            // AlgoName B_VARCHAR
            col.put("cryptoAlgoName", safeBVarchar(c));
        }
        if (c.has(2)) {
            col.put("cryptoEncryptionType", c.u8());
            col.put("cryptoNormVersion", c.u8());
        }
    }

    private static JSONArray readPartName(TdsCursor c) {
        JSONArray parts = new JSONArray();
        if (!c.has(1)) {
            return parts;
        }
        int num = c.u8();
        if (num < 0 || num > 16) {
            // desync — do not consume further
            c.setPos(c.pos() - 1);
            return parts;
        }
        for (int i = 0; i < num; i++) {
            if (!c.has(2)) {
                break;
            }
            parts.put(c.usVarchar());
        }
        return parts;
    }

    private static String safeBVarchar(TdsCursor c) {
        if (!c.has(1)) {
            return "";
        }
        int n = c.u8();
        if (n < 0 || n > 128 || !c.has(n * 2)) {
            // Rewind length byte so a later strategy can re-parse
            c.setPos(c.pos() - 1);
            throw new IllegalStateException("invalid B_VARCHAR length " + n);
        }
        return c.utf16(n);
    }

    private static boolean isSaneColumnName(String name) {
        if (name == null || name.isEmpty()) {
            return true; // empty allowed
        }
        if (name.length() > 128) {
            return false;
        }
        int bad = 0;
        int nul = 0;
        for (int i = 0; i < name.length(); i++) {
            char ch = name.charAt(i);
            if (ch == 0) {
                nul++;
            }
            // printable BMP / common identifier chars
            if (ch < 0x20 && ch != 0) {
                bad++;
            } else if (Character.isISOControl(ch)) {
                bad++;
            } else if (ch >= 0x80 && !Character.isLetterOrDigit(ch) && ch != '_'
                    && Character.UnicodeScript.of(ch) == Character.UnicodeScript.UNKNOWN) {
                bad++;
            }
            // private-use / lots of CJK in a Dynamics DB is rare for col names mixed with NULs
        }
        if (nul > 0) {
            return false;
        }
        // mostly CJK garbage often appears when binary is read as UTF-16
        int nonAscii = 0;
        for (int i = 0; i < name.length(); i++) {
            if (name.charAt(i) > 0x7F) {
                nonAscii++;
            }
        }
        if (name.length() >= 4 && nonAscii * 2 >= name.length() * 1 && bad + nul > 0) {
            return false;
        }
        // pure high-bit garbage without letters
        if (name.length() >= 3 && nonAscii == name.length()) {
            boolean anyLetter = false;
            for (int i = 0; i < name.length(); i++) {
                if (Character.isLetter(name.charAt(i))) {
                    anyLetter = true;
                    break;
                }
            }
            // allow pure non-ASCII letters (international names)
            if (!anyLetter) {
                return false;
            }
        }
        return bad * 4 < name.length() + 1;
    }

    private static void decodeAltMetadata(TdsCursor c, JSONObject t) {
        // Similar to COLMETADATA with extra ByCols
        int count = c.u16();
        t.put("count", count);
        if (c.has(2)) {
            t.put("id", c.u16());
        }
        if (c.has(1)) {
            int byCols = c.u8();
            t.put("byCols", byCols);
            if (byCols > 0 && c.has(byCols * 2)) {
                JSONArray bc = new JSONArray();
                for (int i = 0; i < byCols; i++) {
                    bc.put(c.u16());
                }
                t.put("byColIds", bc);
            }
        }
        int start = c.pos();
        ColMetaResult best = null;
        for (int utBytes : new int[]{4, 2}) {
            try {
                ColMetaResult r = parseColDataList(new TdsCursor(c.data(), start), count, utBytes);
                if (best == null || r.score > best.score) {
                    best = r;
                    best.userTypeBytes = utBytes;
                }
            } catch (Exception ignored) {
            }
        }
        if (best != null) {
            c.setPos(best.endPos);
            t.put("columns", best.columns);
            t.put("userTypeBytes", best.userTypeBytes);
        } else {
            t.put("columns", new JSONArray());
        }
    }

    private static void decodeTabName(TdsCursor c, JSONObject t) {
        // [MS-TDS] 2.2.7.23: Length USHORT; each table = NumParts BYTE + PartName US_VARCHAR*
        int length = c.u16();
        if (length < 0 || !c.has(length)) {
            t.put("decodeError", "TABNAME length out of range: " + length);
            return;
        }
        byte[] data = c.bytes(length);
        JSONArray tables = new JSONArray();
        TdsCursor tc = new TdsCursor(data);
        while (tc.remaining() > 0) {
            int parts = tc.u8();
            JSONArray partNames = new JSONArray();
            for (int i = 0; i < parts && tc.remaining() > 0; i++) {
                // PartName = US_VARCHAR (USHORT char count + UTF-16LE)
                if (!tc.has(2)) {
                    break;
                }
                partNames.put(tc.usVarchar());
            }
            tables.put(partNames);
            if (parts == 0) {
                break;
            }
        }
        t.put("tables", tables);
    }

    private static void decodeLengthPrefixed(TdsCursor c, JSONObject t, boolean ushortLen) {
        int length = ushortLen ? c.u16() : c.u8();
        t.put("rawHex", c.hex(length));
    }

    private static void decodeOffset(TdsCursor c, JSONObject t) {
        // OFFSET: USHORT identifier, USHORT offset length, then data
        if (c.has(4)) {
            t.put("id", c.u16());
            int len = c.u16();
            t.put("rawHex", c.hex(Math.min(len, c.remaining())));
        }
    }

    private static void decodeEnvChange(TdsCursor c, JSONObject t) {
        int length = c.u16();
        byte[] data = c.bytes(length);
        if (data.length == 0) {
            return;
        }
        int envType = data[0] & 0xFF;
        t.put("envType", envType);
        t.put("envTypeName", TdsSpec.envChangeName(envType));
        TdsCursor ec = new TdsCursor(data, 1);
        boolean bVarchar = envType == 1 || envType == 2 || envType == 3 || envType == 4
                || envType == 5 || envType == 6 || envType == 13 || envType == 19;
        boolean bVarbyte = envType == 7 || envType == 8 || envType == 9 || envType == 10
                || envType == 11 || envType == 12 || envType == 15 || envType == 16 || envType == 17;
        if (bVarchar) {
            if (ec.remaining() > 0) {
                t.put("newValue", ec.bVarchar());
            }
            if (ec.remaining() > 0) {
                t.put("oldValue", ec.bVarchar());
            }
        } else if (bVarbyte) {
            if (ec.remaining() > 0) {
                int n = ec.u8();
                if (n > 0 && ec.has(n)) {
                    t.put("newValueHex", ec.hex(n));
                }
            }
            if (ec.remaining() > 0) {
                int n = ec.u8();
                if (n > 0 && ec.has(n)) {
                    t.put("oldValueHex", ec.hex(n));
                }
            }
        } else if (envType == 20 || envType == 21) {
            // Routing NEWVALUE structure
            if (ec.has(2)) {
                int rlen = ec.u16();
                if (ec.has(rlen)) {
                    TdsCursor rc = new TdsCursor(ec.bytes(rlen));
                    if (rc.has(1 + 2)) {
                        t.put("routeProtocol", rc.u8());
                        t.put("routePort", rc.u16());
                        if (rc.remaining() > 0) {
                            t.put("routeServer", rc.usVarchar());
                        }
                        if (envType == 21 && rc.remaining() > 0) {
                            t.put("routeDatabase", rc.usVarchar());
                        }
                    }
                }
            }
            if (ec.remaining() >= 2) {
                // OLDVALUE often 0x00 0x00
                t.put("oldValueHex", ec.hex(Math.min(2, ec.remaining())));
            }
        } else {
            t.put("utf16Strings", TdsHelper.extractUtf16Strings(data, 2));
        }
    }

    private static void decodeRow(TdsCursor c, JSONObject t, JSONArray columns, JSONArray rows, boolean nbc) {
        JSONObject row = new JSONObject();
        if (!columns.isEmpty()) {
            JSONObject values = new JSONObject();
            JSONArray ordered = new JSONArray();
            int errors = 0;
            for (int i = 0; i < columns.length(); i++) {
                JSONObject col = columns.getJSONObject(i);
                String cname = col.optString("name", "col" + i);
                try {
                    Object[] vr = TdsTypeReader.readValue(c.data(), c.pos(), col);
                    c.setPos((Integer) vr[0]);
                    Object val = vr[1];
                    if (val == null) {
                        values.put(cname, JSONObject.NULL);
                        ordered.put(JSONObject.NULL);
                    } else {
                        values.put(cname, val);
                        ordered.put(val);
                    }
                } catch (Exception ex) {
                    errors++;
                    values.put(cname, JSONObject.NULL);
                    ordered.put(JSONObject.NULL);
                    // Desync risk: skip to next known token so following rows/DONE can still parse
                    if (errors == 1) {
                        t.put("rowDecodeWarning", "column " + cname + ": " + ex.getMessage());
                    }
                    int next = findNextToken(c.data(), c.pos());
                    // Only jump if remaining columns would likely be wrong
                    if (i < columns.length() - 1 && next > c.pos()) {
                        // leave partial values; stop reading further columns in this row
                        t.put("rowPartial", true);
                        break;
                    }
                }
            }
            row.put("values", values);
            row.put("ordered", ordered);
            t.put("values", values);
            if (errors > 0) {
                t.put("rowColumnErrors", errors);
            }
        } else {
            int next = findNextToken(c.data(), c.pos());
            byte[] raw = ArraySliceHelper.getArraySlice(c.data(), c.pos(), next);
            t.put("rawHex", TdsHelper.toHex(raw));
            t.put("strings", TdsHelper.extractUtf16Strings(raw, 1));
            // Best-effort: expose scavenged strings so Simple view is not empty
            JSONArray strs = TdsHelper.extractUtf16Strings(raw, 1);
            if (strs != null && strs.length() > 0) {
                JSONObject values = new JSONObject();
                for (int i = 0; i < strs.length(); i++) {
                    values.put("str" + i, strs.getString(i));
                }
                t.put("values", values);
                row.put("values", values);
            }
            c.setPos(next);
        }
        rows.put(row);
    }

    private static void decodeNbcRow(TdsCursor c, JSONObject t, JSONArray columns, JSONArray rows) {
        JSONObject row = new JSONObject();
        if (columns.isEmpty()) {
            int next = findNextToken(c.data(), c.pos());
            byte[] raw = ArraySliceHelper.getArraySlice(c.data(), c.pos(), next);
            t.put("rawHex", TdsHelper.toHex(raw));
            JSONArray strs = TdsHelper.extractUtf16Strings(raw, 1);
            if (strs != null && strs.length() > 0) {
                JSONObject values = new JSONObject();
                for (int i = 0; i < strs.length(); i++) {
                    values.put("str" + i, strs.getString(i));
                }
                t.put("values", values);
                row.put("values", values);
            }
            c.setPos(next);
            rows.put(row);
            return;
        }
        int colCount = columns.length();
        int bitmapBytes = (colCount + 7) / 8;
        byte[] bitmap = c.bytes(bitmapBytes);
        t.put("nullBitmapHex", TdsHelper.toHex(bitmap));
        JSONObject values = new JSONObject();
        JSONArray ordered = new JSONArray();
        int errors = 0;
        for (int i = 0; i < colCount; i++) {
            JSONObject col = columns.getJSONObject(i);
            String cname = col.optString("name", "col" + i);
            boolean isNull = ((bitmap[i / 8] >> (i % 8)) & 1) == 1;
            if (isNull) {
                values.put(cname, JSONObject.NULL);
                ordered.put(JSONObject.NULL);
            } else {
                try {
                    Object[] vr = TdsTypeReader.readValue(c.data(), c.pos(), col);
                    c.setPos((Integer) vr[0]);
                    Object val = vr[1];
                    if (val == null) {
                        values.put(cname, JSONObject.NULL);
                        ordered.put(JSONObject.NULL);
                    } else {
                        values.put(cname, val);
                        ordered.put(val);
                    }
                } catch (Exception ex) {
                    errors++;
                    values.put(cname, JSONObject.NULL);
                    ordered.put(JSONObject.NULL);
                    if (errors == 1) {
                        t.put("rowDecodeWarning", "column " + cname + ": " + ex.getMessage());
                    }
                    t.put("rowPartial", true);
                    break;
                }
            }
        }
        row.put("values", values);
        row.put("ordered", ordered);
        t.put("values", values);
        if (errors > 0) {
            t.put("rowColumnErrors", errors);
        }
        rows.put(row);
    }

    private static void decodeAltRow(TdsCursor c, JSONObject t) {
        if (c.has(2)) {
            t.put("id", c.u16());
        }
        int next = findNextToken(c.data(), c.pos());
        t.put("rawHex", TdsHelper.toHex(ArraySliceHelper.getArraySlice(c.data(), c.pos(), next)));
        c.setPos(next);
    }

    /**
     * DONE / DONEPROC / DONEINPROC ([MS-TDS] 2.2.7.6).
     * DoneRowCount is ULONG (4) pre-TDS 7.2 and ULONGLONG (8) for TDS 7.2+.
     * Modern SQL Server / Dynamics always use 8-byte counts when 8+ bytes remain.
     * RowCount is only meaningful when DONE_COUNT (0x10) is set.
     */
    private static void decodeDone(TdsCursor c, JSONObject t) {
        int status = c.u16();
        t.put("status", status);
        t.put("curcmd", c.u16());
        int rem = c.remaining();
        long rowCount;
        int width;
        // Prefer 8-byte DoneRowCount whenever possible (TDS 7.2+). Using 4-byte when 8 remain
        // mis-aligns the stream and yields nonsense counts like 0x5D5D5D5D ("]]]]").
        if (rem >= 8) {
            rowCount = c.i64();
            width = 8;
        } else if (rem >= 4) {
            rowCount = c.u32u();
            width = 4;
        } else {
            rowCount = 0;
            width = 0;
        }
        // Store as unsigned-ish long; UI should only show when COUNT flag is set
        t.put("rowCount", rowCount);
        t.put("rowCountWidth", width);
        t.put("countValid", (status & TdsSpec.DONE_COUNT) != 0);
        JSONArray flags = new JSONArray();
        if ((status & TdsSpec.DONE_MORE) != 0) {
            flags.put("MORE");
        }
        if ((status & TdsSpec.DONE_ERROR) != 0) {
            flags.put("ERROR");
        }
        if ((status & TdsSpec.DONE_INXACT) != 0) {
            flags.put("INXACT");
        }
        if ((status & TdsSpec.DONE_COUNT) != 0) {
            flags.put("COUNT");
        }
        if ((status & TdsSpec.DONE_ATTN) != 0) {
            flags.put("ATTN");
        }
        if ((status & TdsSpec.DONE_SRVERROR) != 0) {
            flags.put("SRVERROR");
        }
        if (!flags.isEmpty()) {
            t.put("statusFlags", flags);
        }
    }

    private static void decodeErrorInfo(TdsCursor c, JSONObject t) {
        int length = c.u16();
        byte[] data = c.bytes(length);
        TdsCursor e = new TdsCursor(data);
        if (!e.has(6)) {
            return;
        }
        t.put("number", e.u32());
        t.put("state", e.u8());
        t.put("class", e.u8());
        if (e.has(2)) {
            t.put("message", e.usVarchar());
        }
        if (e.remaining() > 0) {
            t.put("serverName", e.bVarchar());
        }
        if (e.remaining() > 0) {
            t.put("procName", e.bVarchar());
        }
        if (e.has(4)) {
            t.put("lineNumber", e.u32());
        } else if (e.has(2)) {
            t.put("lineNumber", e.u16());
        }
    }

    private static void decodeReturnValue(TdsCursor c, JSONObject t) {
        t.put("paramName", c.bVarchar());
        t.put("status", c.u8());
        t.put("userType", c.u32u());
        t.put("flags", c.u16());
        int type = c.u8();
        JSONObject typeMeta = new JSONObject();
        c.setPos(TdsTypeReader.parseTypeInfo(c.data(), c.pos(), type, typeMeta));
        t.put("sqlType", typeMeta.optString("sqlType"));
        t.put("typeMeta", typeMeta);
        Object[] vr = TdsTypeReader.readValue(c.data(), c.pos(), typeMeta);
        c.setPos((Integer) vr[0]);
        if (vr[1] == null) {
            t.put("value", JSONObject.NULL);
        } else {
            t.put("value", vr[1]);
        }
    }

    private static void decodeLoginAck(TdsCursor c, JSONObject t) {
        int length = c.u16();
        byte[] data = c.bytes(length);
        TdsCursor a = new TdsCursor(data);
        if (!a.has(5)) {
            return;
        }
        int iface = a.u8();
        t.put("interface", iface);
        t.put("interfaceName", iface == 0 ? "SQL_DFLT" : (iface == 1 ? "SQL_TSQL" : "unknown"));
        t.put("tdsVersionHex", a.hex(4));
        t.put("progName", a.bVarchar());
        if (a.has(4)) {
            t.put("progVersion", String.format("%d.%d.%d.%d",
                    a.u8(), a.u8(), a.u8(), a.u8()));
        }
    }

    private static void decodeFeatureExtAck(TdsCursor c, JSONObject t) {
        JSONArray features = new JSONArray();
        while (c.remaining() > 0) {
            int featureId = c.u8();
            if (featureId == 0xFF) {
                break;
            }
            JSONObject f = new JSONObject();
            f.put("featureId", featureId);
            int dlen = c.u32();
            if (dlen > 0 && c.has(dlen)) {
                f.put("dataHex", c.hex(dlen));
            }
            features.put(f);
        }
        t.put("features", features);
    }

    private static void decodeSessionState(TdsCursor c, JSONObject t) {
        int length = c.u32();
        long seq = c.has(4) ? c.u32u() : 0;
        t.put("seqNo", seq);
        if (c.has(1)) {
            t.put("status", c.u8());
        }
        int take = Math.min(length, c.remaining());
        // length is total state data; we've consumed seq+status already in some versions
        t.put("rawHex", c.hex(Math.min(take, c.remaining())));
    }

    private static void decodeSspiToken(TdsCursor c, JSONObject t) {
        int length = c.u16();
        byte[] blob = c.bytes(length);
        t.put("sspiLength", length);
        JSONObject sspi = SspiDecoder.decode(blob);
        t.put("sspi", sspi);
        t.put("note", sspi.optString("summary", "SSPI blob (authentication)"));
        // keep short hex for full view / round-trip inspection (cap large tokens)
        if (blob.length <= 256) {
            t.put("sspiHex", TdsHelper.toHex(blob));
        } else {
            t.put("sspiHexPreview", TdsHelper.toHex(blob, 0, 64) + "…");
        }
    }

    private static void decodeFedAuthInfo(TdsCursor c, JSONObject t) {
        int length = c.u32();
        int count = c.has(4) ? c.u32() : 0;
        t.put("count", count);
        JSONArray opts = new JSONArray();
        // simplified: remainder as hex + utf16 scavenge
        int rem = Math.min(length, c.remaining());
        byte[] data = c.bytes(rem);
        t.put("rawHex", TdsHelper.toHex(data));
        t.put("utf16Strings", TdsHelper.extractUtf16Strings(data, 2));
        t.put("options", opts);
    }

    private static int findNextToken(byte[] payload, int from) {
        for (int i = from; i < payload.length; i++) {
            int b = payload[i] & 0xFF;
            if (b == TdsSpec.TOK_ROW || b == TdsSpec.TOK_NBCROW || b == TdsSpec.TOK_ALTROW
                    || b == TdsSpec.TOK_DONE || b == TdsSpec.TOK_DONEPROC || b == TdsSpec.TOK_DONEINPROC
                    || b == TdsSpec.TOK_RETURNSTATUS || b == TdsSpec.TOK_RETURNVALUE
                    || b == TdsSpec.TOK_ERROR || b == TdsSpec.TOK_INFO || b == TdsSpec.TOK_COLMETADATA
                    || b == TdsSpec.TOK_TABNAME || b == TdsSpec.TOK_COLINFO || b == TdsSpec.TOK_ORDER
                    || b == TdsSpec.TOK_ENVCHANGE || b == TdsSpec.TOK_LOGINACK
                    || b == TdsSpec.TOK_FEATUREEXTACK || b == TdsSpec.TOK_SSPI
                    || b == TdsSpec.TOK_FEDAUTHINFO || b == TdsSpec.TOK_SESSIONSTATE
                    || b == TdsSpec.TOK_OFFSET || b == TdsSpec.TOK_ALTMETADATA) {
                return i;
            }
        }
        return payload.length;
    }
}
