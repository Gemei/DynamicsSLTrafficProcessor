package com.bdocyber.helpers;

import com.bdocyber.helpers.tds.SspiDecoder;
import com.bdocyber.models.TcpStreamFrame;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Builds a Wireshark-style Follow TCP Stream dump from ordered frames.
 */
public final class FollowStreamBuilder {

    public enum ViewMode {
        /** Structured TDS unpack (best for server TABULAR_RESULT). */
        TDS_DECODE,
        HEX,
        UTF16_TEXT,
        RAW_ASCII
    }

    private FollowStreamBuilder() {
    }

    public static String build(List<TcpStreamFrame> frames, ViewMode mode, boolean bothDirections) {
        if (frames == null || frames.isEmpty()) {
            return "(empty stream)";
        }
        StringBuilder sb = new StringBuilder(Math.min(frames.size() * 64, 1_000_000));
        sb.append("# Follow TCP Stream (reconstructed from captured frames)\n");
        sb.append("# C→S = client to server, S→C = server to client\n");
        sb.append("# TDS multi-packet messages are merged (COLMETADATA+ROW) before decode.\n");
        if (mode == ViewMode.UTF16_TEXT) {
            sb.append("# UTF-16 mode only shows printable strings — server replies are mostly binary tokens;\n");
            sb.append("# use View: TDS decode for structured S→C (columns, rows, DONE, errors).\n");
        } else if (mode == ViewMode.TDS_DECODE) {
            sb.append("# TDS decode: unpacks MS-TDS (RPC/SQL_BATCH/TABULAR tokens).\n");
            sb.append("# SSPI: NetNTLM hashes are completed using Type2 challenges seen earlier in this stream.\n");
            sb.append("# Kerberos tickets (AP-REQ) are shown as base64/hex when present.\n");
        }
        sb.append('\n');

        // Track last NTLM Type2 challenge so Type3 frames get complete NetNTLM hashes
        String lastNtlmChallenge = null;
        StringBuilder authIndex = new StringBuilder();

        // Merge multi-PDU messages so server tabular results show rows, not column names only
        List<TdsMessageAssembler.AssembledMessage> messages = TdsMessageAssembler.assembleAll(frames);

        for (TdsMessageAssembler.AssembledMessage msg : messages) {
            boolean c2s = msg.direction == TcpStreamFrame.Direction.CLIENT_TO_SERVER;
            if (!bothDirections && !c2s) {
                continue;
            }
            String tag = c2s ? "C→S" : "S→C";
            sb.append("----- ").append(tag);
            if (msg.multiPacket) {
                sb.append("  seq=").append(msg.firstSeq()).append("–").append(msg.lastSeq())
                        .append("  (").append(msg.frames.size()).append(" PDUs, ")
                        .append(msg.totalBytes()).append(" B)");
            } else {
                sb.append("  seq=").append(msg.firstSeq())
                        .append("  ").append(msg.totalBytes()).append(" B");
            }
            TcpStreamFrame head = msg.frames.get(0);
            if (head.isMatchReplaced()) {
                sb.append("  [MOD]");
            }
            if (head.getUserName() != null && !head.getUserName().isEmpty()) {
                sb.append("  \"").append(head.getUserName()).append('"');
            }
            sb.append(" -----\n");
            byte[] body = msg.wire;
            switch (mode) {
                case TDS_DECODE -> {
                    DecodeResult dr = formatTdsWithAuth(body, lastNtlmChallenge);
                    if (dr.challenge != null) {
                        lastNtlmChallenge = dr.challenge;
                    }
                    sb.append(dr.text);
                    if (dr.authSummary != null && !dr.authSummary.isEmpty()) {
                        authIndex.append("# seq=").append(msg.firstSeq()).append(' ')
                                .append(tag).append(" — ").append(dr.authSummary).append('\n');
                    }
                }
                case HEX -> appendHex(sb, body);
                case UTF16_TEXT -> appendUtf16(sb, body);
                case RAW_ASCII -> appendAscii(sb, body);
            }
            if (mode != ViewMode.TDS_DECODE) {
                sb.append('\n');
            } else if (sb.length() == 0 || sb.charAt(sb.length() - 1) != '\n') {
                sb.append('\n');
            }
            sb.append('\n');
        }

        if (mode == ViewMode.TDS_DECODE && authIndex.length() > 0) {
            sb.append("===== Authentication material index =====\n");
            sb.append(authIndex);
            sb.append('\n');
        }
        return sb.toString();
    }

    private static final class DecodeResult {
        final String text;
        final String challenge;
        final String authSummary;

        DecodeResult(String text, String challenge, String authSummary) {
            this.text = text;
            this.challenge = challenge;
            this.authSummary = authSummary;
        }
    }

    /**
     * Unpack TDS and complete NTLM hashes using the stream's last Type2 challenge.
     */
    private static DecodeResult formatTdsWithAuth(byte[] body, String lastChallenge) {
        if (body == null || body.length == 0) {
            return new DecodeResult("(no data)\n", null, null);
        }
        try {
            TdsHelper helper = new TdsHelper();
            byte[] normalized = TdsTextFormatter.normalizeHeaderLengthPublic(body);
            byte[] use = helper.looksLikeTds(normalized) ? normalized
                    : (helper.looksLikeTds(body) ? body : null);
            if (use == null) {
                return new DecodeResult(TdsTextFormatter.formatBody(body), null, null);
            }
            JSONArray packets = helper.unpack(use);
            if (packets.isEmpty()) {
                return new DecodeResult(TdsTextFormatter.formatBody(body), null, null);
            }
            StringBuilder sb = new StringBuilder();
            String challengeOut = null;
            String authSummary = null;
            for (int i = 0; i < packets.length(); i++) {
                if (i > 0) {
                    sb.append('\n');
                }
                JSONObject pkt = packets.getJSONObject(i);
                // Complete SSPI Type3 with prior Type2 challenge
                if (pkt.has("sspi")) {
                    JSONObject sspi = pkt.getJSONObject("sspi");
                    String ch = SspiDecoder.extractServerChallenge(sspi);
                    if (ch != null) {
                        challengeOut = ch;
                    }
                    if (lastChallenge != null) {
                        SspiDecoder.applyServerChallenge(sspi, lastChallenge);
                    }
                    SspiDecoder.promoteAuthMaterial(sspi);
                    StringBuilder one = new StringBuilder();
                    SspiDecoder.appendAuthMaterial(one, sspi, "");
                    if (one.length() > 0) {
                        String sum = sspi.optString("ntlmHash", "");
                        if (sum.isEmpty() && sspi.has("kerberosTicketBase64")) {
                            sum = "Kerberos ticket " + sspi.optInt("kerberosTicketLength", 0) + " B";
                        } else if (!sum.isEmpty() && sum.length() > 80) {
                            sum = sum.substring(0, 80) + "…";
                        }
                        if (!sum.isEmpty()) {
                            authSummary = sum;
                        }
                    }
                }
                // Also SSPI tokens inside tabular results
                JSONArray tokens = pkt.optJSONArray("tokens");
                if (tokens != null) {
                    for (int t = 0; t < tokens.length(); t++) {
                        JSONObject tok = tokens.getJSONObject(t);
                        if (tok.has("sspi")) {
                            JSONObject sspi = tok.getJSONObject("sspi");
                            String ch = SspiDecoder.extractServerChallenge(sspi);
                            if (ch != null) {
                                challengeOut = ch;
                            }
                            if (lastChallenge != null) {
                                SspiDecoder.applyServerChallenge(sspi, lastChallenge);
                            }
                            SspiDecoder.promoteAuthMaterial(sspi);
                        }
                    }
                }
                if (pkt.has("login7") && pkt.getJSONObject("login7").has("sspi")) {
                    JSONObject sspi = pkt.getJSONObject("login7").getJSONObject("sspi");
                    if (lastChallenge != null) {
                        SspiDecoder.applyServerChallenge(sspi, lastChallenge);
                    }
                    SspiDecoder.promoteAuthMaterial(sspi);
                    pkt.put("sspi", sspi);
                }
                // Tabular results: human Simple view (tables/rows); others: technical packet dump
                if (pkt.has("columns") || pkt.has("rows")
                        || "TABULAR_RESULT".equals(pkt.optString("typeName"))) {
                    JSONObject meta = new JSONObject();
                    meta.put("direction", "SERVER_RESPONSE");
                    if (pkt.optInt("mergedPackets", 1) > 1) {
                        meta.put("assembledBytes", body.length);
                    }
                    sb.append(TdsSimpleView.formatHttpStyle(new JSONArray().put(pkt), meta, body));
                } else {
                    TdsTextFormatter.formatPacketPublic(pkt, sb);
                }
            }
            return new DecodeResult(sb.toString(), challengeOut, authSummary);
        } catch (Exception e) {
            return new DecodeResult(TdsTextFormatter.formatBody(body), null, null);
        }
    }

    private static void appendHex(StringBuilder sb, byte[] body) {
        if (body == null || body.length == 0) {
            sb.append("(no data)\n");
            return;
        }
        for (int i = 0; i < body.length; i += 16) {
            sb.append(String.format("%08x  ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < body.length) {
                    sb.append(String.format("%02x ", body[i + j] & 0xFF));
                } else {
                    sb.append("   ");
                }
                if (j == 7) {
                    sb.append(' ');
                }
            }
            sb.append(' ');
            for (int j = 0; j < 16 && i + j < body.length; j++) {
                int b = body[i + j] & 0xFF;
                sb.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
            }
            sb.append('\n');
        }
    }

    /** Min printable UTF-16LE run length to emit (filters single-byte noise; keeps short tokens like "AB"). */
    private static final int MIN_UTF16_RUN = 2;

    private static void appendUtf16(StringBuilder sb, byte[] body) {
        if (body == null || body.length == 0) {
            sb.append("(no data)\n");
            return;
        }
        StringBuilder run = new StringBuilder();
        boolean any = false;
        for (int i = 0; i + 1 < body.length; i += 2) {
            int lo = body[i] & 0xFF;
            int hi = body[i + 1] & 0xFF;
            if (hi == 0 && lo >= 0x20 && lo < 0x7f) {
                run.append((char) lo);
            } else {
                if (run.length() >= MIN_UTF16_RUN) {
                    sb.append(run).append('\n');
                    any = true;
                }
                run.setLength(0);
            }
        }
        if (run.length() >= MIN_UTF16_RUN) {
            sb.append(run).append('\n');
            any = true;
        }
        if (!any) {
            sb.append("[little printable UTF-16LE text in this frame]\n");
        }
    }

    private static void appendAscii(StringBuilder sb, byte[] body) {
        if (body == null || body.length == 0) {
            sb.append("(no data)\n");
            return;
        }
        for (byte value : body) {
            int b = value & 0xFF;
            if (b == '\n' || b == '\r' || b == '\t') {
                sb.append((char) b);
            } else if (b >= 0x20 && b < 0x7f) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        sb.append('\n');
    }

    /** Concatenate only C→S (or all) raw bytes for export/replay. */
    public static byte[] concatenate(List<TcpStreamFrame> frames, boolean clientToServerOnly) {
        int total = 0;
        for (TcpStreamFrame f : frames) {
            if (clientToServerOnly && f.getDirection() != TcpStreamFrame.Direction.CLIENT_TO_SERVER) {
                continue;
            }
            total += f.getBodyLength();
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (TcpStreamFrame f : frames) {
            if (clientToServerOnly && f.getDirection() != TcpStreamFrame.Direction.CLIENT_TO_SERVER) {
                continue;
            }
            byte[] b = f.bodyRef();
            System.arraycopy(b, 0, out, pos, b.length);
            pos += b.length;
        }
        return out;
    }
}
