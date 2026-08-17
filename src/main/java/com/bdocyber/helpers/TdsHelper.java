package com.bdocyber.helpers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.bdocyber.helpers.tds.SspiDecoder;
import com.bdocyber.helpers.tds.TdsSpec;
import com.bdocyber.helpers.tds.TdsTokenStream;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;

/**
 * Serialize / deserialize Microsoft TDS packets ([MS-TDS] v20260330).
 * Packet framing, RPC/SQL_BATCH, full tabular token stream, LOGIN7/PRELOGIN, types.
 */
public class TdsHelper {

    private final Logging logging;

    public TdsHelper(MontoyaApi api) {
        this.logging = api != null ? api.logging() : null;
    }

    public TdsHelper(Logging logging) {
        this.logging = logging;
    }

    /** Test / offline use without Burp API. */
    public TdsHelper() {
        this.logging = null;
    }

    private void logError(String msg) {
        if (this.logging != null) {
            this.logging.logToError(msg);
        }
    }

    public boolean looksLikeTds(byte[] body) {
        if (body == null || body.length < DSLConstants.TDS_HEADER_LEN) {
            return false;
        }
        int type = body[0] & 0xFF;
        int length = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
        if (!isKnownType(type)) {
            return false;
        }
        // Length is total packet size including 8-byte header (big-endian)
        return length >= DSLConstants.TDS_HEADER_LEN && length <= body.length;
    }

    /**
     * Framing analysis for capture/replay: how many complete TDS PDUs are present
     * and whether the buffer is truncated mid-packet.
     */
    public static final class PduFraming {
        public final boolean startsLikeTds;
        /** Bytes forming one or more complete packets from offset 0 (0 if first PDU incomplete). */
        public final int completeBytes;
        public final int completePacketCount;
        /** Declared length of the incomplete trailing/first packet, or 0. */
        public final int incompleteDeclaredLength;
        public final int trailingIncompleteBytes;
        public final String warning;

        public PduFraming(boolean startsLikeTds, int completeBytes, int completePacketCount,
                          int incompleteDeclaredLength, int trailingIncompleteBytes, String warning) {
            this.startsLikeTds = startsLikeTds;
            this.completeBytes = completeBytes;
            this.completePacketCount = completePacketCount;
            this.incompleteDeclaredLength = incompleteDeclaredLength;
            this.trailingIncompleteBytes = trailingIncompleteBytes;
            this.warning = warning;
        }

        public boolean isFullyComplete() {
            return startsLikeTds && completePacketCount > 0 && trailingIncompleteBytes == 0
                    && completeBytes > 0 && warning == null;
        }

        public boolean hasWarning() {
            return warning != null && !warning.isEmpty();
        }
    }

    /**
     * Walk TDS length-prefixed headers. Non-TDS buffers return startsLikeTds=false and no warning.
     */
    public static PduFraming analyzePduFraming(byte[] body) {
        if (body == null || body.length == 0) {
            return new PduFraming(false, 0, 0, 0, 0, null);
        }
        if (body.length < DSLConstants.TDS_HEADER_LEN) {
            int type = body.length > 0 ? (body[0] & 0xFF) : 0;
            if (TdsSpec.isKnownPacketType(type)) {
                return new PduFraming(true, 0, 0, 0, body.length,
                        "Incomplete TDS header (" + body.length + " B < 8)");
            }
            return new PduFraming(false, 0, 0, 0, 0, null);
        }
        int type0 = body[0] & 0xFF;
        if (!TdsSpec.isKnownPacketType(type0)) {
            return new PduFraming(false, 0, 0, 0, 0, null);
        }
        int off = 0;
        int packets = 0;
        while (off + DSLConstants.TDS_HEADER_LEN <= body.length) {
            int type = body[off] & 0xFF;
            int length = ((body[off + 2] & 0xFF) << 8) | (body[off + 3] & 0xFF);
            if (!TdsSpec.isKnownPacketType(type)
                    || length < DSLConstants.TDS_HEADER_LEN
                    || length > 4 * 1024 * 1024) {
                if (packets == 0) {
                    return new PduFraming(false, 0, 0, 0, 0, null);
                }
                int trail = body.length - off;
                return new PduFraming(true, off, packets, 0, trail,
                        "Trailing non-TDS after " + packets + " complete PDU(s) (" + trail + " B)");
            }
            if (off + length > body.length) {
                int have = body.length - off;
                String warn = packets == 0
                        ? "Incomplete TDS PDU: have " + have + " B, header length=" + length
                        : "Trailing incomplete TDS PDU after " + packets + " complete: have "
                        + have + " B, header length=" + length;
                return new PduFraming(true, off, packets, length, have, warn);
            }
            off += length;
            packets++;
        }
        if (off < body.length) {
            int trail = body.length - off;
            return new PduFraming(true, off, packets, 0, trail,
                    "Trailing incomplete TDS header after " + packets + " complete PDU(s) (" + trail + " B)");
        }
        return new PduFraming(true, off, packets, 0, 0, null);
    }

    /**
     * Prefer complete TDS PDUs for Stream Replay: drop trailing incomplete bytes when
     * at least one full packet is present. Returns original body if not TDS or fully complete
     * or only incomplete (nothing safe to prefer).
     */
    public static byte[] preferCompletePdus(byte[] body) {
        PduFraming f = analyzePduFraming(body);
        if (f.startsLikeTds && f.completeBytes > 0 && f.completeBytes < body.length) {
            byte[] out = new byte[f.completeBytes];
            System.arraycopy(body, 0, out, 0, f.completeBytes);
            return out;
        }
        return body;
    }

    /**
     * True when the body looks like TDS and deep-decodes without errors into a known packet type.
     * Used for Proxy highlighting so undecodable / non-TDS traffic is left alone.
     */
    public boolean isSuccessfullyDecoded(byte[] body) {
        if (!looksLikeTds(body)) {
            return false;
        }
        try {
            JSONArray packets = unpack(body);
            if (packets == null || packets.isEmpty()) {
                return false;
            }
            boolean anyKnown = false;
            for (int i = 0; i < packets.length(); i++) {
                JSONObject pkt = packets.getJSONObject(i);
                if (pkt.has("decodeError") && !pkt.optString("decodeError").isEmpty()) {
                    return false;
                }
                if (pkt.optBoolean("truncated", false)) {
                    return false;
                }
                String typeName = pkt.optString("typeName", "");
                if (typeName.isEmpty() || "RAW".equals(typeName) || typeName.startsWith("UNKNOWN")) {
                    continue;
                }
                anyKnown = true;
            }
            return anyKnown;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isKnownType(int type) {
        return TdsSpec.isKnownPacketType(type);
    }

    public int getBodyOffset(byte[] requestOrResponse) {
        Matcher m = DSLConstants.BODY_OFFSET.matcher(new String(requestOrResponse, StandardCharsets.ISO_8859_1));
        if (m.find()) {
            return m.end();
        }
        return -1;
    }

    /**
     * Decode one or more TDS packets in a body to a JSON array.
     * <p>
     * Tabular / bulk server messages often span multiple TDS packets (EOM only on the last).
     * Those payloads are concatenated and decoded as one token stream so COLMETADATA from
     * the first packet applies to ROW tokens in later packets.
     */
    public JSONArray unpack(byte[] body) {
        JSONArray packets = new JSONArray();
        int offset = 0;
        while (offset + DSLConstants.TDS_HEADER_LEN <= body.length) {
            int type = body[offset] & 0xFF;
            int status = body[offset + 1] & 0xFF;
            int length = ((body[offset + 2] & 0xFF) << 8) | (body[offset + 3] & 0xFF);
            int spid = ((body[offset + 4] & 0xFF) << 8) | (body[offset + 5] & 0xFF);
            int packetId = body[offset + 6] & 0xFF;
            int window = body[offset + 7] & 0xFF;

            JSONObject pkt = new JSONObject();
            pkt.put("offset", offset);
            pkt.put("type", type);
            pkt.put("typeName", typeName(type));
            pkt.put("status", status);
            pkt.put("length", length);
            pkt.put("spid", spid);
            pkt.put("packetId", packetId);
            pkt.put("window", window);

            int payloadEnd;
            boolean truncated = false;
            if (length < DSLConstants.TDS_HEADER_LEN) {
                payloadEnd = body.length;
                truncated = true;
            } else if (offset + length > body.length) {
                payloadEnd = body.length;
                truncated = true;
            } else {
                payloadEnd = offset + length;
            }
            pkt.put("truncated", truncated);

            byte[] payload = ArraySliceHelper.getArraySlice(body, offset + DSLConstants.TDS_HEADER_LEN, payloadEnd);
            int nextOffset;

            // Multi-packet TABULAR/BULK message: merge payloads until EOM (or type change / trunc)
            if (!truncated
                    && (type == TdsSpec.PKT_TABULAR || type == TdsSpec.PKT_BULK)
                    && length >= DSLConstants.TDS_HEADER_LEN) {
                MessageMerge merge = mergeTabularMessage(body, offset, type);
                payload = merge.mergedPayload;
                nextOffset = merge.endOffset;
                truncated = merge.truncated;
                pkt.put("truncated", truncated);
                pkt.put("status", merge.lastStatus);
                pkt.put("length", merge.totalWireLength);
                pkt.put("mergedPackets", merge.packetCount);
                if (merge.packetCount > 1) {
                    pkt.put("messageWireHex", toHex(ArraySliceHelper.getArraySlice(
                            body, offset, merge.endOffset)));
                    pkt.put("note", "Multi-packet tabular message (" + merge.packetCount
                            + " PDUs); token stream decoded on concatenated payloads.");
                }
            } else {
                nextOffset = (length < DSLConstants.TDS_HEADER_LEN || offset + length > body.length)
                        ? body.length
                        : offset + length;
            }

            pkt.put("payloadHex", toHex(payload));

            try {
                switch (type) {
                    case TdsSpec.PKT_RPC -> decodeRpc(payload, pkt);
                    case TdsSpec.PKT_SQL_BATCH -> decodeSqlBatch(payload, pkt);
                    case TdsSpec.PKT_TABULAR, TdsSpec.PKT_BULK -> TdsTokenStream.decode(payload, pkt);
                    case TdsSpec.PKT_PRELOGIN -> decodePrelogin(payload, pkt);
                    case TdsSpec.PKT_LOGIN7, TdsSpec.PKT_PRE_TDS7_LOGIN -> decodeLogin7(payload, pkt);
                    case TdsSpec.PKT_SSPI -> {
                        JSONObject sspi = SspiDecoder.decode(payload);
                        pkt.put("sspi", sspi);
                        pkt.put("sspiLength", payload.length);
                        pkt.put("note", sspi.optString("summary",
                                "SSPI authentication blob (Negotiate/NTLM/Kerberos)."));
                        if (sspi.has("utf16Strings")) {
                            pkt.put("utf16Strings", sspi.get("utf16Strings"));
                        } else {
                            pkt.put("utf16Strings", extractUtf16Strings(payload, 4));
                        }
                    }
                    case TdsSpec.PKT_FEDAUTH -> {
                        pkt.put("note", "Federated authentication token.");
                        pkt.put("utf16Strings", extractUtf16Strings(payload, 4));
                    }
                    case TdsSpec.PKT_TXN_MGR -> {
                        pkt.put("note", "Transaction manager request.");
                        if (payload.length >= 2) {
                            pkt.put("requestType", ((payload[0] & 0xFF) | ((payload[1] & 0xFF) << 8)));
                        }
                        pkt.put("utf16Strings", extractUtf16Strings(payload, 3));
                    }
                    case TdsSpec.PKT_ATTENTION -> pkt.put("note", "Attention / cancel signal (no payload fields).");
                    default -> {
                        pkt.put("note", "Unknown packet type; payloadHex preserved for round-trip.");
                        pkt.put("utf16Strings", extractUtf16Strings(payload, 4));
                    }
                }
            } catch (Exception e) {
                pkt.put("decodeError", e.getMessage());
                pkt.put("utf16Strings", extractUtf16Strings(payload, 4));
            }

            packets.put(pkt);

            if (nextOffset <= offset) {
                break;
            }
            offset = nextOffset;
            if (offset >= body.length) {
                break;
            }
        }

        if (packets.isEmpty() && body.length > 0) {
            JSONObject fallback = new JSONObject();
            fallback.put("typeName", "RAW");
            fallback.put("payloadHex", toHex(body));
            fallback.put("utf16Strings", extractUtf16Strings(body, 4));
            packets.put(fallback);
        }
        return packets;
    }

    /**
     * Concatenate payloads of consecutive same-type TABULAR/BULK packets until EOM.
     * Required so COLMETADATA in packet 1 applies to ROW tokens in later packets.
     */
    private static MessageMerge mergeTabularMessage(byte[] body, int startOffset, int expectedType) {
        ByteArrayOutputStream merged = new ByteArrayOutputStream();
        int off = startOffset;
        int packetCount = 0;
        int lastStatus = 0;
        boolean truncated = false;
        int wireStart = startOffset;

        while (off + DSLConstants.TDS_HEADER_LEN <= body.length) {
            int type = body[off] & 0xFF;
            int status = body[off + 1] & 0xFF;
            int length = ((body[off + 2] & 0xFF) << 8) | (body[off + 3] & 0xFF);
            if (packetCount > 0 && type != expectedType) {
                break;
            }
            if (type != expectedType) {
                break;
            }
            if (length < DSLConstants.TDS_HEADER_LEN) {
                truncated = true;
                break;
            }
            int end = off + length;
            if (end > body.length) {
                // include partial payload
                byte[] partial = ArraySliceHelper.getArraySlice(
                        body, off + DSLConstants.TDS_HEADER_LEN, body.length);
                try {
                    merged.write(partial);
                } catch (Exception ignored) {
                }
                packetCount++;
                lastStatus = status;
                truncated = true;
                off = body.length;
                break;
            }
            byte[] part = ArraySliceHelper.getArraySlice(
                    body, off + DSLConstants.TDS_HEADER_LEN, end);
            try {
                merged.write(part);
            } catch (Exception ignored) {
            }
            packetCount++;
            lastStatus = status;
            off = end;
            // EOM ends the TDS message
            if ((status & TdsSpec.STATUS_EOM) != 0) {
                break;
            }
            // Safety: avoid infinite loop on malformed streams
            if (packetCount > 10_000) {
                truncated = true;
                break;
            }
        }

        MessageMerge m = new MessageMerge();
        m.mergedPayload = merged.toByteArray();
        m.endOffset = off;
        m.packetCount = Math.max(1, packetCount);
        m.lastStatus = lastStatus;
        m.truncated = truncated;
        m.totalWireLength = Math.max(0, off - wireStart);
        return m;
    }

    private static final class MessageMerge {
        byte[] mergedPayload = new byte[0];
        int endOffset;
        int packetCount;
        int lastStatus;
        boolean truncated;
        int totalWireLength;
    }

    /**
     * Re-encode JSON packets to TDS binary body.
     * Prefer structured rebuild for RPC/SQL_BATCH when fields are present;
     * otherwise use payloadHex.
     */
    public byte[] pack(JSONArray packets) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < packets.length(); i++) {
            JSONObject pkt = packets.getJSONObject(i);
            byte[] rawPacket = packSingle(pkt);
            out.write(rawPacket);
        }
        return out.toByteArray();
    }

    private byte[] packSingle(JSONObject pkt) throws Exception {
        String typeName = pkt.optString("typeName", "");
        int type = pkt.has("type") ? pkt.getInt("type") : typeFromName(typeName);

        // Multi-packet tabular messages: prefer original wire framing for exact round-trip
        String wireHex = pkt.optString("messageWireHex", "");
        if (!wireHex.isEmpty()) {
            return fromHex(wireHex);
        }

        if (type == DSLConstants.TDS_RPC && pkt.has("rpc")) {
            byte[] payload = encodeRpc(pkt.getJSONObject("rpc"), pkt.optString("payloadHex", null));
            return wrapPacket(type, pkt, payload);
        }
        if (type == DSLConstants.TDS_SQL_BATCH && pkt.has("sql")) {
            byte[] payload = encodeSqlBatch(pkt);
            return wrapPacket(type, pkt, payload);
        }

        // Fall back to original payload hex (safe round-trip)
        String hex = pkt.optString("payloadHex", "");
        if (hex.isEmpty() && pkt.has("rawHex")) {
            hex = pkt.getString("rawHex");
        }
        if (hex.isEmpty()) {
            throw new IllegalArgumentException("Packet missing payloadHex and structured fields for type " + typeName);
        }
        byte[] payload = fromHex(hex);
        // Merged multi-packet payload may exceed one TDS packet; split into EOM-framed chunks
        if (payload.length + DSLConstants.TDS_HEADER_LEN > 0xFFFF
                && (type == DSLConstants.TDS_TABULAR || type == DSLConstants.TDS_BULK)) {
            return wrapPacketSplit(type, pkt, payload);
        }
        return wrapPacket(type, pkt, payload);
    }

    /** Split oversized tabular payload into multiple TDS packets (last has EOM). */
    private byte[] wrapPacketSplit(int type, JSONObject pkt, byte[] payload) {
        int spid = pkt.optInt("spid", 0);
        int window = pkt.optInt("window", 0);
        int maxPayload = 0xFFFF - DSLConstants.TDS_HEADER_LEN;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int off = 0;
        int packetId = Math.max(1, pkt.optInt("packetId", 1));
        while (off < payload.length) {
            int n = Math.min(maxPayload, payload.length - off);
            boolean last = off + n >= payload.length;
            byte[] chunk = ArraySliceHelper.getArraySlice(payload, off, off + n);
            JSONObject hdr = new JSONObject();
            hdr.put("status", last ? TdsSpec.STATUS_EOM : 0);
            hdr.put("spid", spid);
            hdr.put("packetId", packetId++);
            hdr.put("window", window);
            try {
                out.write(wrapPacket(type, hdr, chunk));
            } catch (Exception e) {
                throw new IllegalArgumentException("Failed to split tabular packet: " + e.getMessage());
            }
            off += n;
        }
        return out.toByteArray();
    }

    private byte[] wrapPacket(int type, JSONObject pkt, byte[] payload) {
        int status = pkt.optInt("status", 1);
        int spid = pkt.optInt("spid", 0);
        int packetId = pkt.optInt("packetId", 1);
        int window = pkt.optInt("window", 0);
        int length = DSLConstants.TDS_HEADER_LEN + payload.length;
        if (length > 0xFFFF) {
            throw new IllegalArgumentException("TDS packet too large: " + length);
        }
        byte[] packet = new byte[length];
        packet[0] = (byte) type;
        packet[1] = (byte) status;
        packet[2] = (byte) ((length >> 8) & 0xFF);
        packet[3] = (byte) (length & 0xFF);
        packet[4] = (byte) ((spid >> 8) & 0xFF);
        packet[5] = (byte) (spid & 0xFF);
        packet[6] = (byte) packetId;
        packet[7] = (byte) window;
        System.arraycopy(payload, 0, packet, DSLConstants.TDS_HEADER_LEN, payload.length);
        return packet;
    }

    private void decodeRpc(byte[] payload, JSONObject pkt) {
        JSONObject rpc = new JSONObject();
        int pos = 0;
        int headersLen = peekAllHeadersLength(payload);
        if (headersLen > 0) {
            rpc.put("allHeadersLen", headersLen);
            rpc.put("allHeadersHex", toHex(ArraySliceHelper.getArraySlice(payload, 0, headersLen)));
            pos = headersLen;
        } else {
            rpc.put("allHeadersLen", 0);
            rpc.put("allHeadersHex", "");
        }

        if (pos + 2 > payload.length) {
            pkt.put("rpc", rpc);
            return;
        }
        int nameLen = readU16LE(payload, pos);
        pos += 2;
        if (nameLen == DSLConstants.NAME_BY_PROCDID) {
            int procId = readU16LE(payload, pos);
            pos += 2;
            rpc.put("procId", procId);
            rpc.put("procName", DSLConstants.PROC_IDS.getOrDefault(procId, "Unknown(" + procId + ")"));
        } else {
            String name = readUtf16(payload, pos, nameLen);
            pos += nameLen * 2;
            rpc.put("procName", name);
        }

        if (pos + 2 <= payload.length) {
            rpc.put("optionFlags", readU16LE(payload, pos));
            pos += 2;
        }

        JSONArray params = new JSONArray();
        while (pos < payload.length) {
            JSONObject param = new JSONObject();
            int start = pos;
            if (pos + 1 > payload.length) {
                break;
            }
            int nlen = payload[pos] & 0xFF;
            pos += 1;
            String pname = "";
            if (nlen > 0) {
                if (pos + nlen * 2 > payload.length) {
                    break;
                }
                pname = readUtf16(payload, pos, nlen);
                pos += nlen * 2;
            }
            param.put("name", pname);
            if (pos + 2 > payload.length) {
                break;
            }
            int status = payload[pos] & 0xFF;
            pos += 1;
            int type = payload[pos] & 0xFF;
            pos += 1;
            param.put("status", status);
            param.put("type", type);
            param.put("typeHex", String.format("0x%02X", type));

            try {
                pos = decodeTypeInfoAndValue(payload, pos, type, param);
            } catch (Exception e) {
                param.put("decodeError", e.getMessage());
                param.put("rawHex", toHex(ArraySliceHelper.getArraySlice(payload, start, payload.length)));
                params.put(param);
                break;
            }
            param.put("rawHex", toHex(ArraySliceHelper.getArraySlice(payload, start, pos)));
            params.put(param);
        }
        rpc.put("params", params);

        // Convenience: first NVARCHAR-looking value as sql if Sp_CursorOpen / Sp_ExecuteSql
        String sql = findSqlParam(params);
        if (sql != null) {
            rpc.put("sql", sql);
        }
        pkt.put("rpc", rpc);
    }

    private String findSqlParam(JSONArray params) {
        for (int i = 0; i < params.length(); i++) {
            JSONObject p = params.getJSONObject(i);
            if ("NVARCHAR".equals(p.optString("sqlType")) || "BIGVARCHAR".equals(p.optString("sqlType"))) {
                String v = p.optString("value", null);
                if (v != null && v.length() >= 6) {
                    String lower = v.toLowerCase();
                    if (lower.startsWith("select") || lower.startsWith("insert") || lower.startsWith("update")
                            || lower.startsWith("delete") || lower.startsWith("exec") || lower.contains(" from ")) {
                        return v;
                    }
                }
            }
        }
        // fallback: longest nvarchar
        String best = null;
        for (int i = 0; i < params.length(); i++) {
            JSONObject p = params.getJSONObject(i);
            if (p.has("value") && p.get("value") instanceof String) {
                String v = p.getString("value");
                if (best == null || v.length() > best.length()) {
                    best = v;
                }
            }
        }
        return best;
    }

    private int decodeTypeInfoAndValue(byte[] payload, int pos, int type, JSONObject param) {
        // Fixed-length types (no TYPE_INFO length prefix beyond the type byte already consumed)
        if (isFixedLenType(type)) {
            int size = fixedTypeSize(type);
            param.put("sqlType", fixedTypeName(type));
            param.put("fixedSize", size);
            if (pos + size > payload.length) {
                throw new IllegalStateException("Truncated fixed type 0x" + Integer.toHexString(type));
            }
            putFixedValue(param, type, payload, pos, size);
            return pos + size;
        }

        switch (type) {
            case 0x26 -> { // INTN
                int maxLen = payload[pos] & 0xFF;
                pos += 1;
                int actual = payload[pos] & 0xFF;
                pos += 1;
                param.put("sqlType", "INTN");
                param.put("maxLen", maxLen);
                if (actual == 0) {
                    param.put("value", JSONObject.NULL);
                } else {
                    param.put("value", readSignedLe(payload, pos, actual));
                    pos += actual;
                }
            }
            case 0x68 -> { // BITN
                int maxLen = payload[pos] & 0xFF;
                pos += 1;
                int actual = payload[pos] & 0xFF;
                pos += 1;
                param.put("sqlType", "BITN");
                param.put("maxLen", maxLen);
                if (actual == 0) {
                    param.put("value", JSONObject.NULL);
                } else {
                    param.put("value", payload[pos] & 0xFF);
                    pos += actual;
                }
            }
            case 0xE7, 0xEF -> { // NVARCHAR / NCHAR
                int maxLen = readU16LE(payload, pos);
                pos += 2;
                byte[] collation = ArraySliceHelper.getArraySlice(payload, pos, pos + 5);
                pos += 5;
                param.put("sqlType", type == 0xE7 ? "NVARCHAR" : "NCHAR");
                param.put("maxLen", maxLen);
                param.put("collationHex", toHex(collation));
                int byteLen = readU16LE(payload, pos);
                pos += 2;
                if (byteLen == 0xFFFF) {
                    param.put("value", JSONObject.NULL);
                } else {
                    param.put("value", new String(payload, pos, byteLen, StandardCharsets.UTF_16LE));
                    pos += byteLen;
                }
            }
            case 0xA7, 0xAF -> { // BIGVARCHAR / BIGCHAR
                int maxLen = readU16LE(payload, pos);
                pos += 2;
                byte[] collation = ArraySliceHelper.getArraySlice(payload, pos, pos + 5);
                pos += 5;
                param.put("sqlType", type == 0xA7 ? "BIGVARCHAR" : "BIGCHAR");
                param.put("maxLen", maxLen);
                param.put("collationHex", toHex(collation));
                int byteLen = readU16LE(payload, pos);
                pos += 2;
                if (byteLen == 0xFFFF) {
                    param.put("value", JSONObject.NULL);
                } else {
                    param.put("value", new String(payload, pos, byteLen, StandardCharsets.ISO_8859_1));
                    pos += byteLen;
                }
            }
            case 0xA5, 0xAD -> { // BIGVARBIN / BIGBINARY
                int maxLen = readU16LE(payload, pos);
                pos += 2;
                param.put("sqlType", type == 0xA5 ? "BIGVARBIN" : "BIGBINARY");
                param.put("maxLen", maxLen);
                int byteLen = readU16LE(payload, pos);
                pos += 2;
                if (byteLen == 0xFFFF) {
                    param.put("value", JSONObject.NULL);
                } else {
                    param.put("valueHex", toHex(ArraySliceHelper.getArraySlice(payload, pos, pos + byteLen)));
                    pos += byteLen;
                }
            }
            case 0x24 -> { // GUID
                int maxLen = payload[pos] & 0xFF;
                pos += 1;
                int actual = payload[pos] & 0xFF;
                pos += 1;
                param.put("sqlType", "GUID");
                param.put("maxLen", maxLen);
                if (actual == 0) {
                    param.put("value", JSONObject.NULL);
                } else {
                    param.put("valueHex", toHex(ArraySliceHelper.getArraySlice(payload, pos, pos + actual)));
                    pos += actual;
                }
            }
            case 0x6F, 0x6D, 0x6C, 0x6A, 0x6E -> { // DATETIMN / FLTN / MONEYN / DECIMALN / NUMERICN
                int maxLen = payload[pos] & 0xFF;
                pos += 1;
                param.put("sqlType", switch (type) {
                    case 0x6F -> "DATETIMN";
                    case 0x6D -> "FLTN";
                    case 0x6C -> "MONEYN";
                    case 0x6A -> "DECIMALN";
                    default -> "NUMERICN";
                });
                if (type == 0x6A || type == 0x6E) {
                    param.put("precision", payload[pos] & 0xFF);
                    param.put("scale", payload[pos + 1] & 0xFF);
                    pos += 2;
                }
                int actual = payload[pos] & 0xFF;
                pos += 1;
                param.put("maxLen", maxLen);
                if (actual == 0) {
                    param.put("value", JSONObject.NULL);
                } else {
                    param.put("valueHex", toHex(ArraySliceHelper.getArraySlice(payload, pos, pos + actual)));
                    pos += actual;
                }
            }
            default -> {
                param.put("sqlType", "UNKNOWN");
                param.put("note", "Unparsed TDS type; keep rawHex for round-trip");
                throw new IllegalStateException("Unparsed type 0x" + Integer.toHexString(type));
            }
        }
        return pos;
    }

    /**
     * Encode RPC payload. If rpc.sql is set, update the first NVARCHAR param value.
     * Rebuilds from structured params when present; otherwise uses original payload with SQL patch.
     */
    private byte[] encodeRpc(JSONObject rpc, String originalPayloadHex) throws Exception {
        // If params array present, rebuild fully
        if (rpc.has("params")) {
            ByteArrayOutputStream payload = new ByteArrayOutputStream();
            String headersHex = rpc.optString("allHeadersHex", "");
            if (!headersHex.isEmpty()) {
                payload.write(fromHex(headersHex));
            }

            if (rpc.has("procId")) {
                writeU16LE(payload, DSLConstants.NAME_BY_PROCDID);
                writeU16LE(payload, rpc.getInt("procId"));
            } else {
                String name = rpc.optString("procName", "");
                writeU16LE(payload, name.length());
                payload.write(name.getBytes(StandardCharsets.UTF_16LE));
            }
            writeU16LE(payload, rpc.optInt("optionFlags", 0));

            JSONArray params = rpc.getJSONArray("params");
            // Apply convenience sql field onto first matching nvarchar
            if (rpc.has("sql")) {
                applySqlToParams(params, rpc.getString("sql"));
            }

            for (int i = 0; i < params.length(); i++) {
                JSONObject p = params.getJSONObject(i);
                payload.write(encodeParam(p));
            }
            return payload.toByteArray();
        }

        // Patch SQL inside original payload hex
        if (originalPayloadHex != null && !originalPayloadHex.isEmpty() && rpc.has("sql")) {
            byte[] original = fromHex(originalPayloadHex);
            return patchSqlInRpcPayload(original, rpc.getString("sql"));
        }

        if (originalPayloadHex != null) {
            return fromHex(originalPayloadHex);
        }
        throw new IllegalArgumentException("RPC encode requires params or payloadHex");
    }

    private void applySqlToParams(JSONArray params, String sql) {
        for (int i = 0; i < params.length(); i++) {
            JSONObject p = params.getJSONObject(i);
            if ("NVARCHAR".equals(p.optString("sqlType")) || p.optInt("type") == 0xE7) {
                String v = p.optString("value", "");
                String lower = v.toLowerCase();
                if (v.isEmpty() || lower.startsWith("select") || lower.startsWith("insert")
                        || lower.startsWith("update") || lower.startsWith("delete")
                        || lower.startsWith("exec") || lower.contains(" from ") || i == 1) {
                    p.put("value", sql);
                    // maxLen is in characters for NVARCHAR type meta in some paths; we store byte-oriented maxLen from wire
                    int neededChars = sql.length();
                    int neededBytes = neededChars * 2;
                    int maxLen = p.optInt("maxLen", neededBytes);
                    // wire maxLen for NVARCHAR is max byte length often; samples used 104 for 52 chars
                    if (maxLen < neededBytes) {
                        p.put("maxLen", neededBytes);
                    }
                    return;
                }
            }
        }
    }

    private byte[] encodeParam(JSONObject p) throws Exception {
        int type = p.has("type") ? p.getInt("type") : typeFromSqlType(p.optString("sqlType"));
        String sqlType = p.optString("sqlType", "");

        boolean canRebuild = isFixedLenType(type)
                || "INTN".equals(sqlType) || type == 0x26
                || "BITN".equals(sqlType) || type == 0x68
                || "NVARCHAR".equals(sqlType) || type == 0xE7
                || "NCHAR".equals(sqlType) || type == 0xEF
                || "BIGVARCHAR".equals(sqlType) || type == 0xA7
                || "BIGCHAR".equals(sqlType) || type == 0xAF
                || "BIGVARBIN".equals(sqlType) || type == 0xA5
                || "BIGBINARY".equals(sqlType) || type == 0xAD
                || "GUID".equals(sqlType) || type == 0x24;

        if (!canRebuild && p.has("rawHex")) {
            return fromHex(p.getString("rawHex"));
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String name = p.optString("name", "");
        out.write(name.length());
        if (!name.isEmpty()) {
            out.write(name.getBytes(StandardCharsets.UTF_16LE));
        }
        out.write(p.optInt("status", 0));
        out.write(type);

        if (isFixedLenType(type)) {
            writeFixedValue(out, type, p);
        } else if ("INTN".equals(sqlType) || type == 0x26) {
            int maxLen = p.optInt("maxLen", 4);
            out.write(maxLen);
            if (p.isNull("value")) {
                out.write(0);
            } else {
                long val = p.getLong("value");
                int actual = maxLen >= 4 ? 4 : Math.max(1, maxLen);
                if (maxLen >= 8) {
                    actual = 8;
                } else if (maxLen >= 4) {
                    actual = 4;
                } else if (maxLen >= 2) {
                    actual = 2;
                } else {
                    actual = 1;
                }
                out.write(actual);
                for (int i = 0; i < actual; i++) {
                    out.write((int) ((val >> (8 * i)) & 0xFF));
                }
            }
        } else if ("BITN".equals(sqlType) || type == 0x68) {
            out.write(p.optInt("maxLen", 1));
            if (p.isNull("value")) {
                out.write(0);
            } else {
                out.write(1);
                out.write(p.getInt("value") & 0xFF);
            }
        } else if ("NVARCHAR".equals(sqlType) || type == 0xE7 || "NCHAR".equals(sqlType) || type == 0xEF) {
            writeCharParam(out, p, true);
        } else if ("BIGVARCHAR".equals(sqlType) || type == 0xA7 || "BIGCHAR".equals(sqlType) || type == 0xAF) {
            writeCharParam(out, p, false);
        } else if ("BIGVARBIN".equals(sqlType) || type == 0xA5 || "BIGBINARY".equals(sqlType) || type == 0xAD) {
            int maxLen = p.optInt("maxLen", 0);
            writeU16LE(out, maxLen);
            if (p.isNull("value") && !p.has("valueHex")) {
                writeU16LE(out, 0xFFFF);
            } else {
                byte[] data = p.has("valueHex")
                        ? fromHex(p.getString("valueHex"))
                        : p.optString("value", "").getBytes(StandardCharsets.ISO_8859_1);
                writeU16LE(out, data.length);
                out.write(data);
            }
        } else if ("GUID".equals(sqlType) || type == 0x24) {
            out.write(p.optInt("maxLen", 16));
            if (p.isNull("value") && !p.has("valueHex")) {
                out.write(0);
            } else {
                byte[] data = p.has("valueHex") ? fromHex(p.getString("valueHex")) : new byte[16];
                out.write(data.length);
                out.write(data);
            }
        } else if (p.has("rawHex")) {
            return fromHex(p.getString("rawHex"));
        } else {
            throw new IllegalArgumentException("Cannot encode param type " + sqlType + " / 0x" + Integer.toHexString(type));
        }
        return out.toByteArray();
    }

    private void writeCharParam(ByteArrayOutputStream out, JSONObject p, boolean utf16) throws Exception {
        byte[] coll = p.has("collationHex") ? fromHex(p.getString("collationHex"))
                : new byte[]{0x09, 0x04, (byte) 0xD0, 0x00, 0x34};
        if (p.isNull("value")) {
            writeU16LE(out, p.optInt("maxLen", 0));
            out.write(coll);
            writeU16LE(out, 0xFFFF);
            return;
        }
        String value = p.optString("value", "");
        byte[] bytes = utf16
                ? value.getBytes(StandardCharsets.UTF_16LE)
                : value.getBytes(StandardCharsets.ISO_8859_1);
        int maxLen = Math.max(p.optInt("maxLen", bytes.length), bytes.length);
        writeU16LE(out, maxLen);
        out.write(coll);
        writeU16LE(out, bytes.length);
        out.write(bytes);
    }

    private byte[] patchSqlInRpcPayload(byte[] payload, String newSql) {
        // Find NVARCHAR (0xE7) with longest string and replace
        int i = 0;
        int bestStart = -1;
        int bestValStart = -1;
        int bestValLen = -1;
        int bestMaxLenPos = -1;
        while (i < payload.length - 8) {
            if ((payload[i] & 0xFF) == 0xE7) {
                int maxLenPos = i + 1;
                // collation is 5 bytes at i+3; value length USHORT at i+8
                int lenPos = i + 8;
                if (lenPos + 2 <= payload.length) {
                    int byteLen = readU16LE(payload, lenPos);
                    int valStart = lenPos + 2;
                    if (byteLen != 0xFFFF && valStart + byteLen <= payload.length && byteLen > bestValLen) {
                        bestStart = i;
                        bestValStart = valStart;
                        bestValLen = byteLen;
                        bestMaxLenPos = maxLenPos;
                    }
                }
            }
            i++;
        }
        if (bestStart < 0) {
            logError("[!] patchSqlInRpcPayload: no NVARCHAR found; returning original");
            return payload;
        }
        byte[] newVal = newSql.getBytes(StandardCharsets.UTF_16LE);
        int oldMax = readU16LE(payload, bestMaxLenPos);
        int newMax = Math.max(oldMax, newVal.length);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(payload, 0, bestMaxLenPos);
        // maxLen
        out.write(newMax & 0xFF);
        out.write((newMax >> 8) & 0xFF);
        // collation
        out.write(payload, bestMaxLenPos + 2, 5);
        // byte length
        out.write(newVal.length & 0xFF);
        out.write((newVal.length >> 8) & 0xFF);
        try {
            out.write(newVal);
            int after = bestValStart + bestValLen;
            if (after < payload.length) {
                out.write(payload, after, payload.length - after);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return out.toByteArray();
    }

    private void decodeSqlBatch(byte[] payload, JSONObject pkt) {
        int headersLen = peekAllHeadersLength(payload);
        if (headersLen > 0) {
            pkt.put("allHeadersLen", headersLen);
            pkt.put("allHeadersHex", toHex(ArraySliceHelper.getArraySlice(payload, 0, headersLen)));
        }
        int sqlOff = headersLen;
        int sqlLen = payload.length - sqlOff;
        if (sqlLen < 0) {
            sqlLen = 0;
            sqlOff = 0;
        }
        // SQL Batch text is UCS-2/UTF-16LE. Odd trailing byte is ignored for the string decode.
        if ((sqlLen & 1) != 0) {
            pkt.put("sqlOddTrailingByte", true);
            sqlLen--;
        }
        String sql = sqlLen > 0
                ? new String(payload, sqlOff, sqlLen, StandardCharsets.UTF_16LE)
                : "";
        // Strip UTF-16 BOM / NUL padding sometimes left at end of batch
        if (!sql.isEmpty() && sql.charAt(0) == '\uFEFF') {
            sql = sql.substring(1);
        }
        while (sql.endsWith("\0")) {
            sql = sql.substring(0, sql.length() - 1);
        }
        pkt.put("sql", sql);
        pkt.put("sqlDisplay", formatSqlForDisplay(sql));
    }

    /**
     * Human-readable SQL: keep printable text, replace binary/control runs so Dynamics
     * concurrency blobs (version/tstamp/zcount) do not render as mojibake.
     */
    public static String formatSqlForDisplay(String sql) {
        if (sql == null || sql.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder(sql.length() + 32);
        int i = 0;
        while (i < sql.length()) {
            char c = sql.charAt(i);
            if (isSqlPrintable(c)) {
                out.append(c);
                i++;
                continue;
            }
            int start = i;
            while (i < sql.length() && !isSqlPrintable(sql.charAt(i))) {
                i++;
            }
            String run = sql.substring(start, i);
            byte[] raw = run.getBytes(StandardCharsets.UTF_16LE);
            out.append("<bin ").append(raw.length).append(" B");
            if (raw.length > 0) {
                out.append(": 0x");
                int show = Math.min(raw.length, 16);
                for (int b = 0; b < show; b++) {
                    out.append(String.format("%02x", raw[b] & 0xFF));
                }
                if (raw.length > show) {
                    out.append("…");
                }
            }
            out.append('>');
        }
        return out.toString();
    }

    private static boolean isSqlPrintable(char c) {
        // Normal SQL / identifiers / operators; allow common whitespace
        if (c == '\n' || c == '\r' || c == '\t') {
            return true;
        }
        // Printable ASCII
        if (c >= 0x20 && c < 0x7F) {
            return true;
        }
        // Allow common Unicode letters used in identifiers (keep simple)
        return Character.isLetterOrDigit(c);
    }

    private byte[] encodeSqlBatch(JSONObject pkt) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            String headersHex = pkt.optString("allHeadersHex", "");
            if (!headersHex.isEmpty()) {
                out.write(fromHex(headersHex));
            }
            String sql = pkt.getString("sql");
            out.write(sql.getBytes(StandardCharsets.UTF_16LE));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return out.toByteArray();
    }

    /**
     * LOGIN7 (type 16) - structured fields per [MS-TDS] 2.2.6.4 (common assessment fields).
     */
    private void decodeLogin7(byte[] payload, JSONObject pkt) {
        JSONObject login = new JSONObject();
        if (payload.length < 36) {
            login.put("note", "LOGIN7 payload too short");
            pkt.put("login7", login);
            pkt.put("utf16Strings", extractUtf16Strings(payload, 2));
            return;
        }
        login.put("length", readU32LE(payload, 0));
        login.put("tdsVersionHex", toHex(ArraySliceHelper.getArraySlice(payload, 4, 8)));
        login.put("packetSize", readU32LE(payload, 8));
        login.put("clientProgVerHex", toHex(ArraySliceHelper.getArraySlice(payload, 12, 16)));
        login.put("clientPid", readU32LE(payload, 16));
        login.put("connectionId", readU32LE(payload, 20));
        login.put("optionFlags1", payload[24] & 0xFF);
        login.put("optionFlags2", payload[25] & 0xFF);
        login.put("typeFlags", payload[26] & 0xFF);
        login.put("optionFlags3", payload[27] & 0xFF);
        login.put("clientTimeZone", readI32LE(payload, 28));
        login.put("clientLcid", readU32LE(payload, 32));
        String[] fields = {
                "hostName", "userName", "password", "appName", "serverName",
                "unused", "libraryName", "locale", "database"
        };
        int base = 36;
        for (int i = 0; i < fields.length && base + 4 <= payload.length; i++) {
            int off = readU16LE(payload, base);
            int len = readU16LE(payload, base + 2);
            base += 4;
            if ("password".equals(fields[i])) {
                login.put("password", len > 0 ? "<" + len + " chars encrypted>" : "");
                continue;
            }
            if (off > 0 && len > 0 && off + len * 2 <= payload.length) {
                login.put(fields[i], readUtf16(payload, off, len));
            } else {
                login.put(fields[i], "");
            }
        }
        // ClientID (6 bytes) then ibSSPI / cbSSPI ([MS-TDS] 2.2.6.4) — cbSSPI is length in bytes
        if (base + 10 <= payload.length) {
            login.put("clientIdHex", toHex(payload, base, 6));
            base += 6;
            int sspiOff = readU16LE(payload, base);
            int sspiLen = readU16LE(payload, base + 2);
            login.put("sspiOffset", sspiOff);
            login.put("sspiLength", sspiLen);
            if (sspiOff > 0 && sspiLen > 0 && sspiOff + sspiLen <= payload.length) {
                byte[] sspiBlob = ArraySliceHelper.getArraySlice(payload, sspiOff, sspiOff + sspiLen);
                JSONObject sspi = SspiDecoder.decode(sspiBlob);
                login.put("sspi", sspi);
                pkt.put("sspi", sspi);
            }
        }
        pkt.put("login7", login);
        pkt.put("utf16Strings", extractUtf16Strings(payload, 3));
    }

    private void decodePrelogin(byte[] payload, JSONObject pkt) {
        JSONArray options = new JSONArray();
        int pos = 0;
        // Option headers are only the 5-byte entries until 0xFF — do not walk into option DATA.
        // Known option tokens are small integers (0–7 typical); stop if we leave that range.
        while (pos + 5 <= payload.length) {
            int opt = payload[pos] & 0xFF;
            if (opt == 0xFF) {
                pos += 1;
                break;
            }
            // Sanity: PRELOGIN option ids are 0x00–0x07 (+ extensions); garbage means we left the table
            if (opt > 0x20) {
                break;
            }
            int off = ((payload[pos + 1] & 0xFF) << 8) | (payload[pos + 2] & 0xFF);
            int len = ((payload[pos + 3] & 0xFF) << 8) | (payload[pos + 4] & 0xFF);
            if (len < 0 || off < 0 || off > payload.length || (len > 0 && off + len > payload.length)) {
                break;
            }
            JSONObject o = new JSONObject();
            o.put("option", opt);
            o.put("optionName", TdsSpec.preloginOptionName(opt));
            o.put("offset", off);
            o.put("length", len);
            if (len > 0 && off + len <= payload.length) {
                byte[] data = ArraySliceHelper.getArraySlice(payload, off, off + len);
                o.put("dataHex", toHex(data));
                if (opt == 0 && len >= 6) { // VERSION
                    o.put("version", String.format("%d.%d.%d.%d",
                            data[0] & 0xFF, data[1] & 0xFF,
                            ((data[2] & 0xFF) << 8) | (data[3] & 0xFF),
                            ((data[4] & 0xFF) << 8) | (data[5] & 0xFF)));
                } else if (opt == 1 && len >= 1) {
                    int enc = data[0] & 0xFF;
                    o.put("encryption", enc);
                    o.put("encryptionName", encryptionName(enc));
                } else if (opt == 4 && len >= 1) {
                    o.put("mars", data[0] & 0xFF);
                }
            }
            options.put(o);
            pos += 5;
            // safety cap
            if (options.length() > 32) {
                break;
            }
        }
        pkt.put("preloginOptions", options);
    }

    private static boolean isFixedLenType(int type) {
        return type == 0x30 || type == 0x32 || type == 0x34 || type == 0x38
                || type == 0x3A || type == 0x3B || type == 0x3C || type == 0x3D
                || type == 0x3E || type == 0x7A || type == 0x7F || type == 0x28;
    }

    private static int fixedTypeSize(int type) {
        return switch (type) {
            case 0x30 -> 1; // INT1
            case 0x32 -> 1; // BIT
            case 0x34 -> 2; // INT2
            case 0x38 -> 4; // INT4
            case 0x7F -> 8; // INT8
            case 0x3A -> 4; // DATETIM4
            case 0x3B -> 4; // FLT4
            case 0x3C -> 8; // MONEY
            case 0x3D -> 8; // DATETIME
            case 0x3E -> 8; // FLT8
            case 0x7A -> 4; // MONEY4
            case 0x28 -> 3; // DATE
            default -> 0;
        };
    }

    private static String fixedTypeName(int type) {
        return switch (type) {
            case 0x30 -> "INT1";
            case 0x32 -> "BIT";
            case 0x34 -> "INT2";
            case 0x38 -> "INT4";
            case 0x7F -> "INT8";
            case 0x3A -> "DATETIM4";
            case 0x3B -> "FLT4";
            case 0x3C -> "MONEY";
            case 0x3D -> "DATETIME";
            case 0x3E -> "FLT8";
            case 0x7A -> "MONEY4";
            case 0x28 -> "DATE";
            default -> "FIXED_0x" + Integer.toHexString(type);
        };
    }

    private static void putFixedValue(JSONObject param, int type, byte[] payload, int pos, int size) {
        param.put("value", decodeFixedValue(type, payload, pos, size));
        if (type == 0x3A || type == 0x3D || type == 0x3C || type == 0x7A || type == 0x28) {
            param.put("valueHex", toHex(ArraySliceHelper.getArraySlice(payload, pos, pos + size)));
        }
    }

    private static Object decodeFixedValue(int type, byte[] payload, int pos, int size) {
        return switch (type) {
            case 0x30, 0x32 -> payload[pos] & 0xFF;
            case 0x34 -> (short) ((payload[pos] & 0xFF) | ((payload[pos + 1] & 0xFF) << 8));
            case 0x38 -> readI32Static(payload, pos);
            case 0x7F -> {
                long v = 0;
                for (int i = 0; i < 8; i++) {
                    v |= ((long) (payload[pos + i] & 0xFF)) << (8 * i);
                }
                yield v;
            }
            case 0x3B -> Float.intBitsToFloat(readI32Static(payload, pos));
            case 0x3E -> Double.longBitsToDouble(
                    (payload[pos] & 0xFFL)
                            | ((payload[pos + 1] & 0xFFL) << 8)
                            | ((payload[pos + 2] & 0xFFL) << 16)
                            | ((payload[pos + 3] & 0xFFL) << 24)
                            | ((payload[pos + 4] & 0xFFL) << 32)
                            | ((payload[pos + 5] & 0xFFL) << 40)
                            | ((payload[pos + 6] & 0xFFL) << 48)
                            | ((payload[pos + 7] & 0xFFL) << 56));
            default -> toHex(ArraySliceHelper.getArraySlice(payload, pos, pos + size));
        };
    }

    private static void writeFixedValue(ByteArrayOutputStream out, int type, JSONObject p) throws Exception {
        int size = fixedTypeSize(type);
        if (p.has("valueHex")) {
            byte[] data = fromHex(p.getString("valueHex"));
            out.write(data, 0, Math.min(size, data.length));
            for (int i = data.length; i < size; i++) {
                out.write(0);
            }
            return;
        }
        if (type == 0x30 || type == 0x32) {
            out.write(p.optInt("value", 0) & 0xFF);
        } else if (type == 0x34) {
            int v = p.optInt("value", 0);
            out.write(v & 0xFF);
            out.write((v >> 8) & 0xFF);
        } else if (type == 0x38) {
            int v = p.optInt("value", 0);
            for (int i = 0; i < 4; i++) {
                out.write((v >> (8 * i)) & 0xFF);
            }
        } else if (type == 0x7F) {
            long v = p.optLong("value", 0L);
            for (int i = 0; i < 8; i++) {
                out.write((int) ((v >> (8 * i)) & 0xFF));
            }
        } else {
            for (int i = 0; i < size; i++) {
                out.write(0);
            }
        }
    }

    private static Object readSignedLe(byte[] payload, int pos, int actual) {
        long val = 0;
        for (int i = 0; i < actual; i++) {
            val |= ((long) (payload[pos + i] & 0xFF)) << (8 * i);
        }
        if (actual == 1) {
            return (byte) val;
        }
        if (actual == 2) {
            return (short) val;
        }
        if (actual == 4) {
            return (int) val;
        }
        return val;
    }

    private static int readI32Static(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }

    private int peekAllHeadersLength(byte[] payload) {
        if (payload.length < 4) {
            return 0;
        }
        int total = readU32LE(payload, 0);
        if (total < 4 || total > payload.length) {
            return 0;
        }
        // Validate stream of headers
        int pos = 4;
        while (pos + 4 <= total) {
            int hlen = readU32LE(payload, pos);
            if (hlen < 4 || pos + hlen > total) {
                return 0;
            }
            pos += hlen;
        }
        return pos == total ? total : 0;
    }

    public String toPrettyJson(JSONArray packets) {
        return packets.toString(2);
    }

    public static String typeName(int type) {
        return TdsSpec.packetTypeName(type);
    }

    /** PRELOGIN ENCRYPTION option labels (MS-TDS). */
    public static String encryptionName(int enc) {
        return switch (enc) {
            case 0 -> "OFF";
            case 1 -> "ON";
            case 2 -> "NOT_SUPPORTED";
            case 3 -> "REQUIRED";
            default -> "unknown(" + enc + ")";
        };
    }

    private int typeFromName(String name) {
        if (name == null) {
            return 0;
        }
        return switch (name) {
            case "SQL_BATCH" -> 1;
            case "RPC" -> 3;
            case "TABULAR_RESULT" -> 4;
            case "ATTENTION" -> 6;
            case "BULK_LOAD" -> 7;
            case "TXN_MANAGER" -> 14;
            case "TDS7_LOGIN" -> 16;
            case "SSPI" -> 17;
            case "PRELOGIN" -> 18;
            default -> 0;
        };
    }

    private int typeFromSqlType(String sqlType) {
        return switch (sqlType) {
            case "INTN" -> 0x26;
            case "BITN" -> 0x68;
            case "NVARCHAR" -> 0xE7;
            case "NCHAR" -> 0xEF;
            case "BIGVARCHAR" -> 0xA7;
            case "BIGCHAR" -> 0xAF;
            case "BIGVARBIN" -> 0xA5;
            case "BIGBINARY" -> 0xAD;
            case "GUID" -> 0x24;
            case "INT1" -> 0x30;
            case "INT2" -> 0x34;
            case "INT4" -> 0x38;
            case "INT8" -> 0x7F;
            case "BIT" -> 0x32;
            default -> 0;
        };
    }

    private static int readU16LE(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static int readU32LE(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }

    private static int readI32LE(byte[] b, int off) {
        return readU32LE(b, off);
    }

    private static void writeU16LE(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
        out.write((v >> 8) & 0xFF);
    }

    /**
     * Parse ERROR (0xAA) / INFO (0xAB) token body per MS-TDS.
     * MsgText is US_VARCHAR (2-byte character count), not a single length byte.
     */

    private static String readUtf16(byte[] b, int off, int charCount) {
        if (b == null || charCount <= 0 || off < 0 || off + charCount * 2 > b.length) {
            return "";
        }
        return new String(b, off, charCount * 2, StandardCharsets.UTF_16LE);
    }

    public static String toHex(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        return toHex(data, 0, data.length);
    }

    public static String toHex(byte[] data, int off, int len) {
        if (data == null || len <= 0 || off < 0 || off >= data.length) {
            return "";
        }
        int n = Math.min(len, data.length - off);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            sb.append(String.format("%02x", data[off + i] & 0xFF));
        }
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        String clean = hex.replaceAll("\\s+", "");
        if (clean.length() % 2 != 0) {
            throw new IllegalArgumentException("Odd hex length");
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static JSONArray extractUtf16Strings(byte[] data, int minLen) {
        JSONArray arr = new JSONArray();
        int i = 0;
        while (i < data.length - 3) {
            if (data[i] >= 0x20 && data[i] < 0x7f && data[i + 1] == 0) {
                StringBuilder sb = new StringBuilder();
                int j = i;
                while (j < data.length - 1 && data[j + 1] == 0
                        && ((data[j] >= 0x20 && data[j] < 0x7f) || data[j] == 0x09 || data[j] == 0x0a || data[j] == 0x0d)) {
                    sb.append((char) (data[j] & 0xFF));
                    j += 2;
                }
                if (sb.length() >= minLen) {
                    arr.put(sb.toString());
                }
                i = Math.max(i + 2, j);
            } else {
                i++;
            }
        }
        return arr;
    }

    /**
     * Best-effort host:port extraction from a URL/path (legacy helpers / HTTP context menus).
     */
    public static String extractPeer(String pathOrUrl) {
        if (pathOrUrl == null || pathOrUrl.isEmpty()) {
            return "";
        }
        // host:port at end of path
        int colon = pathOrUrl.lastIndexOf(':');
        if (colon > 0 && colon < pathOrUrl.length() - 1) {
            int start = pathOrUrl.lastIndexOf('/', colon);
            String hostPort = pathOrUrl.substring(start + 1);
            if (hostPort.matches("^[\\w.\\-]+:\\d+$")) {
                return hostPort;
            }
        }
        return "";
    }
}
