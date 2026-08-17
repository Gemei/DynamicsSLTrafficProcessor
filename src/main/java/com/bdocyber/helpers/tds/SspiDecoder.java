package com.bdocyber.helpers.tds;

import com.bdocyber.helpers.TdsHelper;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Decode SSPI / GSS-API tokens used by TDS integrated authentication:
 * raw NTLMSSP, SPNEGO (NegTokenInit / NegTokenResp), and Kerberos (AP-REQ/AP-REP).
 * <p>
 * References: [MS-NLMP], RFC 4178 (SPNEGO), RFC 4120/4121 (Kerberos), RFC 2743 (GSS-API).
 */
public final class SspiDecoder {

    private static final byte[] NTLM_MAGIC = {
            'N', 'T', 'L', 'M', 'S', 'S', 'P', 0
    };

    // Well-known mechanism OIDs
    private static final String OID_SPNEGO = "1.3.6.1.5.5.2";
    private static final String OID_KERBEROS5 = "1.2.840.113554.1.2.2";
    private static final String OID_KERBEROS5_USER2USER = "1.2.840.113554.1.2.2.3";
    private static final String OID_MS_KRB5 = "1.2.840.48018.1.2.2";
    private static final String OID_NTLMSSP = "1.3.6.1.4.1.311.2.2.10";

    private SspiDecoder() {
    }

    /**
     * Decode an SSPI blob into a structured JSON object (never null).
     */
    public static JSONObject decode(byte[] data) {
        return decode(data, null);
    }

    /**
     * @param serverChallengeHex optional 16-char hex from prior NTLM Type2 (pairs Type3 → NetNTLM hash)
     */
    public static JSONObject decode(byte[] data, String serverChallengeHex) {
        JSONObject out = new JSONObject();
        if (data == null || data.length == 0) {
            out.put("kind", "empty");
            out.put("summary", "empty SSPI");
            return out;
        }
        out.put("length", data.length);
        try {
            if (startsWithNtlm(data, 0)) {
                JSONObject ntlm = decodeNtlm(data, 0, serverChallengeHex);
                out.put("kind", "NTLM");
                out.put("mechanism", "NTLMSSP");
                out.put("ntlm", ntlm);
                out.put("summary", ntlm.optString("summary", "NTLM"));
                promoteAuthMaterial(out);
                return out;
            }
            if ((data[0] & 0xFF) == 0x60) {
                // GSS-API InitialContextToken [APPLICATION 0] IMPLICIT SEQUENCE
                JSONObject gss = decodeGssInitial(data, out, serverChallengeHex);
                promoteAuthMaterial(gss);
                return gss;
            }
            if ((data[0] & 0xFF) == 0xA0) {
                // SPNEGO NegTokenInit as naked context-specific [0]
                JSONObject spnego = decodeSpnegoNegTokenInit(data, 0, serverChallengeHex);
                out.put("kind", "SPNEGO");
                out.put("spnegoToken", "NegTokenInit");
                out.put("spnego", spnego);
                out.put("summary", spnegoSummary("NegTokenInit", spnego));
                mergeInner(out, spnego);
                promoteAuthMaterial(out);
                return out;
            }
            if ((data[0] & 0xFF) == 0xA1) {
                JSONObject spnego = decodeSpnegoNegTokenResp(data, 0, serverChallengeHex);
                out.put("kind", "SPNEGO");
                out.put("spnegoToken", "NegTokenResp");
                out.put("spnego", spnego);
                out.put("summary", spnegoSummary("NegTokenResp", spnego));
                mergeInner(out, spnego);
                promoteAuthMaterial(out);
                return out;
            }
            // Kerberos raw APPLICATION tags (without GSS wrapper) — uncommon on TDS but possible
            int tag = data[0] & 0xFF;
            if (tag == 0x6E || tag == 0x6F || tag == 0x61) {
                JSONObject krb = decodeKerberosApp(data, 0);
                out.put("kind", "Kerberos");
                out.put("mechanism", "Kerberos");
                out.put("kerberos", krb);
                out.put("summary", krb.optString("summary", "Kerberos"));
                promoteAuthMaterial(out);
                return out;
            }
            out.put("kind", "unknown");
            out.put("summary", "unknown SSPI (" + data.length + " B, first=0x"
                    + Integer.toHexString(data[0] & 0xFF) + ")");
            out.put("utf16Strings", TdsHelper.extractUtf16Strings(data, 3));
            out.put("hexPreview", TdsHelper.toHex(data, 0, Math.min(32, data.length)));
        } catch (Exception e) {
            out.put("kind", "error");
            out.put("decodeError", e.getMessage() != null ? e.getMessage() : e.toString());
            out.put("summary", "SSPI decode error");
            out.put("utf16Strings", TdsHelper.extractUtf16Strings(data, 3));
        }
        promoteAuthMaterial(out);
        return out;
    }

    public static String oneLineSummary(byte[] data) {
        JSONObject d = decode(data);
        return d.optString("summary", "SSPI");
    }

    /**
     * Pair a previously decoded SSPI object with an NTLM Type2 server challenge so NetNTLM hashes complete.
     */
    public static void applyServerChallenge(JSONObject sspi, String serverChallengeHex) {
        if (sspi == null || serverChallengeHex == null || serverChallengeHex.isBlank()) {
            return;
        }
        String ch = normalizeChallengeHex(serverChallengeHex);
        if (ch == null) {
            return;
        }
        JSONObject ntlm = sspi.optJSONObject("ntlm");
        if (ntlm == null && sspi.optJSONObject("spnego") != null) {
            ntlm = sspi.getJSONObject("spnego").optJSONObject("ntlm");
        }
        if (ntlm != null && ntlm.optInt("messageType", 0) == 3) {
            buildNtlmHashes(ntlm, ch);
            promoteAuthMaterial(sspi);
        }
    }

    /** Server challenge from Type2 (16 hex chars), or null. */
    public static String extractServerChallenge(JSONObject sspi) {
        if (sspi == null) {
            return null;
        }
        JSONObject ntlm = sspi.optJSONObject("ntlm");
        if (ntlm == null && sspi.optJSONObject("spnego") != null) {
            ntlm = sspi.getJSONObject("spnego").optJSONObject("ntlm");
        }
        if (ntlm != null && ntlm.optInt("messageType", 0) == 2) {
            String ch = ntlm.optString("serverChallengeHex", "");
            return normalizeChallengeHex(ch);
        }
        if (sspi.has("serverChallengeHex")) {
            return normalizeChallengeHex(sspi.optString("serverChallengeHex"));
        }
        return null;
    }

    /**
     * Human-readable credentials block (hashes / tickets) for Simple, Full text, Follow Stream.
     */
    public static void appendAuthMaterial(StringBuilder sb, JSONObject sspi, String indent) {
        if (sspi == null || sb == null) {
            return;
        }
        String ind = indent != null ? indent : "";
        JSONObject cred = sspi.optJSONObject("credentials");
        if (cred == null) {
            // fall back to top-level / nested
            cred = sspi;
        }
        boolean any = false;
        if (cred.has("ntlmHash") && !cred.optString("ntlmHash").isEmpty()) {
            any = true;
            String type = cred.optString("ntlmHashType", "NetNTLM");
            boolean complete = cred.optBoolean("ntlmHashComplete", false);
            sb.append(ind).append("NTLM hash (").append(type);
            if (!complete) {
                sb.append(", needs Type2 challenge");
            } else {
                sb.append(hashcatHint(type));
            }
            sb.append("):\n");
            sb.append(ind).append("  ").append(cred.getString("ntlmHash")).append('\n');
        }
        if (cred.has("lmResponseHex") && !cred.optString("lmResponseHex").isEmpty()) {
            any = true;
            sb.append(ind).append("NTLM LM response:  ").append(cred.getString("lmResponseHex")).append('\n');
        }
        if (cred.has("ntResponseHex") && !cred.optString("ntResponseHex").isEmpty()) {
            any = true;
            sb.append(ind).append("NTLM NT response:  ").append(cred.getString("ntResponseHex")).append('\n');
        }
        if (cred.has("serverChallengeHex") && !cred.optString("serverChallengeHex").isEmpty()) {
            any = true;
            sb.append(ind).append("NTLM server challenge: ").append(cred.getString("serverChallengeHex")).append('\n');
        }
        if (cred.has("ntProofStrHex") && !cred.optString("ntProofStrHex").isEmpty()) {
            any = true;
            sb.append(ind).append("NTLM v2 NTProofStr: ").append(cred.getString("ntProofStrHex")).append('\n');
        }
        if (cred.has("kerberosTicketBase64") && !cred.optString("kerberosTicketBase64").isEmpty()) {
            any = true;
            sb.append(ind).append("Kerberos ticket (")
                    .append(cred.optInt("kerberosTicketLength", 0)).append(" B, base64):\n");
            appendWrapped(sb, ind + "  ", cred.getString("kerberosTicketBase64"), 76);
            if (cred.has("kerberosTicketHex")) {
                sb.append(ind).append("Kerberos ticket (hex):\n");
                appendWrapped(sb, ind + "  ", cred.getString("kerberosTicketHex"), 64);
            }
        }
        if (cred.has("kerberosApReqBase64") && !cred.optString("kerberosApReqBase64").isEmpty()) {
            any = true;
            sb.append(ind).append("Kerberos AP-REQ (")
                    .append(cred.optInt("kerberosApReqLength", 0)).append(" B, base64):\n");
            appendWrapped(sb, ind + "  ", cred.getString("kerberosApReqBase64"), 76);
        }
        if (cred.has("kerberosAuthenticatorBase64")
                && !cred.optString("kerberosAuthenticatorBase64").isEmpty()) {
            any = true;
            sb.append(ind).append("Kerberos authenticator (encrypted, base64):\n");
            appendWrapped(sb, ind + "  ", cred.getString("kerberosAuthenticatorBase64"), 76);
        }
        if (!any && sspi.has("ntlm")) {
            JSONObject ntlm = sspi.getJSONObject("ntlm");
            if (ntlm.optInt("messageType", 0) == 2 && ntlm.has("serverChallengeHex")) {
                sb.append(ind).append("NTLM server challenge: ")
                        .append(ntlm.getString("serverChallengeHex")).append('\n');
            }
        }
    }

    private static String hashcatHint(String type) {
        if (type == null) {
            return "";
        }
        if (type.contains("v2")) {
            return ", hashcat -m 5600 / john netntlmv2";
        }
        if (type.contains("v1")) {
            return ", hashcat -m 5500 / john netntlm";
        }
        return "";
    }

    private static void appendWrapped(StringBuilder sb, String indent, String text, int width) {
        if (text == null) {
            return;
        }
        for (int i = 0; i < text.length(); i += width) {
            sb.append(indent).append(text, i, Math.min(i + width, text.length())).append('\n');
        }
    }

    /**
     * Lift hash/ticket fields to {@code credentials} + top-level for Full JSON and UI.
     */
    public static void promoteAuthMaterial(JSONObject sspi) {
        if (sspi == null) {
            return;
        }
        JSONObject cred = new JSONObject();
        JSONObject ntlm = sspi.optJSONObject("ntlm");
        if (ntlm == null && sspi.optJSONObject("spnego") != null) {
            ntlm = sspi.getJSONObject("spnego").optJSONObject("ntlm");
        }
        if (ntlm != null) {
            if (ntlm.has("serverChallengeHex")) {
                cred.put("serverChallengeHex", ntlm.getString("serverChallengeHex"));
                sspi.put("serverChallengeHex", ntlm.getString("serverChallengeHex"));
            }
            if (ntlm.has("ntlmHash")) {
                cred.put("ntlmHash", ntlm.getString("ntlmHash"));
                cred.put("ntlmHashType", ntlm.optString("ntlmHashType", ""));
                cred.put("ntlmHashComplete", ntlm.optBoolean("ntlmHashComplete", false));
                sspi.put("ntlmHash", ntlm.getString("ntlmHash"));
                sspi.put("ntlmHashType", ntlm.optString("ntlmHashType", ""));
                sspi.put("ntlmHashComplete", ntlm.optBoolean("ntlmHashComplete", false));
            }
            if (ntlm.has("lmResponseHex")) {
                cred.put("lmResponseHex", ntlm.getString("lmResponseHex"));
                sspi.put("lmResponseHex", ntlm.getString("lmResponseHex"));
            }
            if (ntlm.has("ntResponseHex")) {
                cred.put("ntResponseHex", ntlm.getString("ntResponseHex"));
                sspi.put("ntResponseHex", ntlm.getString("ntResponseHex"));
            }
            if (ntlm.has("ntProofStrHex")) {
                cred.put("ntProofStrHex", ntlm.getString("ntProofStrHex"));
                sspi.put("ntProofStrHex", ntlm.getString("ntProofStrHex"));
            }
            if (ntlm.has("ntlmResponseVersion")) {
                cred.put("ntlmResponseVersion", ntlm.get("ntlmResponseVersion"));
            }
        }
        JSONObject krb = sspi.optJSONObject("kerberos");
        if (krb == null && sspi.optJSONObject("spnego") != null) {
            krb = sspi.getJSONObject("spnego").optJSONObject("kerberos");
        }
        if (krb != null) {
            for (String k : new String[]{
                    "ticketHex", "ticketBase64", "ticketLength",
                    "apReqHex", "apReqBase64", "apReqLength",
                    "authenticatorHex", "authenticatorBase64", "authenticatorLength",
                    "spn"
            }) {
                if (krb.has(k)) {
                    String ck = switch (k) {
                        case "ticketHex" -> "kerberosTicketHex";
                        case "ticketBase64" -> "kerberosTicketBase64";
                        case "ticketLength" -> "kerberosTicketLength";
                        case "apReqHex" -> "kerberosApReqHex";
                        case "apReqBase64" -> "kerberosApReqBase64";
                        case "apReqLength" -> "kerberosApReqLength";
                        case "authenticatorHex" -> "kerberosAuthenticatorHex";
                        case "authenticatorBase64" -> "kerberosAuthenticatorBase64";
                        case "authenticatorLength" -> "kerberosAuthenticatorLength";
                        default -> "kerberos" + Character.toUpperCase(k.charAt(0)) + k.substring(1);
                    };
                    if ("spn".equals(k)) {
                        cred.put("spn", krb.get(k));
                        sspi.put("spn", krb.get(k));
                    } else {
                        cred.put(ck, krb.get(k));
                        sspi.put(ck, krb.get(k));
                    }
                }
            }
        }
        if (!cred.isEmpty()) {
            sspi.put("credentials", cred);
        }
    }

    // -------------------------------------------------------------------------
    // GSS-API InitialContextToken
    // -------------------------------------------------------------------------

    private static JSONObject decodeGssInitial(byte[] data, JSONObject out, String serverChallengeHex) {
        DerReader r = new DerReader(data, 0);
        DerValue app = r.readValue();
        if (app.tag != 0x60) {
            throw new IllegalArgumentException("expected APPLICATION 0, got 0x" + Integer.toHexString(app.tag));
        }
        DerReader inner = app.contentReader();
        DerValue oidVal = inner.readValue();
        if (oidVal.tag != 0x06) {
            throw new IllegalArgumentException("expected OID in GSS token");
        }
        String oid = decodeOid(oidVal.content);
        out.put("gssWrapper", true);
        out.put("thisMech", oid);
        out.put("thisMechName", oidName(oid));

        byte[] rest = inner.remainingBytes();
        if (OID_SPNEGO.equals(oid)) {
            out.put("kind", "SPNEGO");
            out.put("mechanism", "SPNEGO (Negotiate)");
            if (rest.length > 0) {
                JSONObject spnego;
                int t = rest[0] & 0xFF;
                if (t == 0xA0) {
                    spnego = decodeSpnegoNegTokenInit(rest, 0, serverChallengeHex);
                    out.put("spnegoToken", "NegTokenInit");
                } else if (t == 0xA1) {
                    spnego = decodeSpnegoNegTokenResp(rest, 0, serverChallengeHex);
                    out.put("spnegoToken", "NegTokenResp");
                } else {
                    spnego = new JSONObject();
                    spnego.put("note", "unexpected SPNEGO content tag 0x" + Integer.toHexString(t));
                    spnego.put("hexPreview", TdsHelper.toHex(rest, 0, Math.min(32, rest.length)));
                }
                out.put("spnego", spnego);
                out.put("summary", spnegoSummary(out.optString("spnegoToken", "SPNEGO"), spnego));
                mergeInner(out, spnego);
            } else {
                out.put("summary", "SPNEGO (empty)");
            }
            return out;
        }
        if (isKerberosOid(oid)) {
            out.put("kind", "Kerberos");
            out.put("mechanism", oidName(oid));
            if (rest.length > 0) {
                JSONObject krb = decodeKerberosApp(rest, 0);
                // Full GSS token (mech + AP-REQ) for export
                out.put("gssTokenBase64", Base64.getEncoder().encodeToString(data));
                out.put("gssTokenHex", TdsHelper.toHex(data));
                out.put("kerberos", krb);
                out.put("summary", "Kerberos " + krb.optString("messageType", "")
                        + " via " + oidName(oid));
            } else {
                out.put("summary", "Kerberos (" + oidName(oid) + ")");
            }
            return out;
        }
        if (OID_NTLMSSP.equals(oid)) {
            out.put("kind", "NTLM");
            out.put("mechanism", "NTLMSSP (OID)");
            if (startsWithNtlm(rest, 0)) {
                JSONObject ntlm = decodeNtlm(rest, 0, serverChallengeHex);
                out.put("ntlm", ntlm);
                out.put("summary", ntlm.optString("summary", "NTLM"));
            } else {
                out.put("summary", "NTLMSSP OID (no NTLMSSP magic in token)");
            }
            return out;
        }
        out.put("kind", "GSS");
        out.put("mechanism", oidName(oid));
        out.put("summary", "GSS " + oidName(oid));
        if (rest.length > 0 && startsWithNtlm(rest, 0)) {
            JSONObject ntlm = decodeNtlm(rest, 0, serverChallengeHex);
            out.put("ntlm", ntlm);
            out.put("summary", ntlm.optString("summary", "NTLM"));
        } else if (rest.length > 0) {
            out.put("innerHexPreview", TdsHelper.toHex(rest, 0, Math.min(48, rest.length)));
            out.put("utf16Strings", TdsHelper.extractUtf16Strings(rest, 3));
        }
        return out;
    }

    private static void mergeInner(JSONObject out, JSONObject spnego) {
        if (spnego.has("ntlm")) {
            out.put("ntlm", spnego.get("ntlm"));
            if (!out.has("kind") || "SPNEGO".equals(out.optString("kind"))) {
                // keep kind SPNEGO but expose ntlm at top for simple view
            }
        }
        if (spnego.has("kerberos")) {
            out.put("kerberos", spnego.get("kerberos"));
        }
        if (spnego.has("innerKind")) {
            out.put("innerKind", spnego.get("innerKind"));
        }
    }

    // -------------------------------------------------------------------------
    // SPNEGO
    // -------------------------------------------------------------------------

    private static JSONObject decodeSpnegoNegTokenInit(byte[] data, int offset, String serverChallengeHex) {
        JSONObject o = new JSONObject();
        DerReader r = new DerReader(data, offset);
        DerValue outer = r.readValue();
        DerReader seq = unwrapSequence(outer);
        while (seq.hasMore()) {
            DerValue f = seq.readValue();
            int ctx = f.tag & 0x1F;
            switch (ctx) {
                case 0 -> { // mechTypes
                    JSONArray mechs = new JSONArray();
                    JSONArray names = new JSONArray();
                    DerReader list = unwrapSequence(f);
                    while (list.hasMore()) {
                        DerValue oidV = list.readValue();
                        if (oidV.tag == 0x06) {
                            String oid = decodeOid(oidV.content);
                            mechs.put(oid);
                            names.put(oidName(oid));
                        }
                    }
                    o.put("mechTypes", mechs);
                    o.put("mechTypeNames", names);
                }
                case 1 -> o.put("reqFlagsHex", TdsHelper.toHex(f.content));
                case 2 -> { // mechToken
                    byte[] tok = unwrapOctetContent(f.content);
                    o.put("mechTokenLength", tok.length);
                    decodeInnerMechToken(tok, o, serverChallengeHex);
                }
                case 3 -> {
                    o.put("mechListMICLength", f.content.length);
                    o.put("mechListMICHex", TdsHelper.toHex(f.content, 0, Math.min(16, f.content.length)));
                }
                default -> o.put("unknownField_" + ctx, TdsHelper.toHex(f.content, 0, Math.min(16, f.content.length)));
            }
        }
        return o;
    }

    private static JSONObject decodeSpnegoNegTokenResp(byte[] data, int offset, String serverChallengeHex) {
        JSONObject o = new JSONObject();
        DerReader r = new DerReader(data, offset);
        DerValue outer = r.readValue();
        DerReader seq = unwrapSequence(outer);
        while (seq.hasMore()) {
            DerValue f = seq.readValue();
            int ctx = f.tag & 0x1F;
            switch (ctx) {
                case 0 -> { // negState ENUMERATED
                    int st = f.content.length > 0 ? (f.content[0] & 0xFF) : -1;
                    if (f.content.length >= 3 && (f.content[0] & 0xFF) == 0x0A) {
                        st = f.content[f.content.length - 1] & 0xFF;
                    } else if ((f.tag & 0x20) != 0) {
                        try {
                            DerValue en = new DerReader(f.content, 0).readValue();
                            if (en.content.length > 0) {
                                st = en.content[0] & 0xFF;
                            }
                        } catch (Exception ignored) {
                        }
                    }
                    o.put("negState", st);
                    o.put("negStateName", negStateName(st));
                }
                case 1 -> { // supportedMech OID
                    byte[] c = f.content;
                    if (c.length > 2 && (c[0] & 0xFF) == 0x06) {
                        DerValue oidV = new DerReader(c, 0).readValue();
                        String oid = decodeOid(oidV.content);
                        o.put("supportedMech", oid);
                        o.put("supportedMechName", oidName(oid));
                    } else if (c.length > 0) {
                        try {
                            if ((c[0] & 0xFF) == 0x06) {
                                String oid = decodeOid(new DerReader(c, 0).readValue().content);
                                o.put("supportedMech", oid);
                                o.put("supportedMechName", oidName(oid));
                            } else {
                                String oid = decodeOid(c);
                                o.put("supportedMech", oid);
                                o.put("supportedMechName", oidName(oid));
                            }
                        } catch (Exception e) {
                            o.put("supportedMechHex", TdsHelper.toHex(c));
                        }
                    }
                }
                case 2 -> {
                    byte[] tok = unwrapOctetContent(f.content);
                    o.put("responseTokenLength", tok.length);
                    decodeInnerMechToken(tok, o, serverChallengeHex);
                }
                case 3 -> {
                    o.put("mechListMICLength", f.content.length);
                    o.put("mechListMICHex", TdsHelper.toHex(f.content, 0, Math.min(16, f.content.length)));
                }
                default -> o.put("unknownField_" + ctx, TdsHelper.toHex(f.content, 0, Math.min(16, f.content.length)));
            }
        }
        return o;
    }

    private static byte[] unwrapOctetContent(byte[] tok) {
        if (tok != null && tok.length > 2 && (tok[0] & 0xFF) == 0x04) {
            try {
                DerValue oct = new DerReader(tok, 0).readValue();
                if (oct.tag == 0x04) {
                    return oct.content;
                }
            } catch (Exception ignored) {
            }
        }
        return tok != null ? tok : new byte[0];
    }

    private static void decodeInnerMechToken(byte[] tok, JSONObject o, String serverChallengeHex) {
        if (tok == null || tok.length == 0) {
            return;
        }
        if (startsWithNtlm(tok, 0)) {
            JSONObject ntlm = decodeNtlm(tok, 0, serverChallengeHex);
            o.put("innerKind", "NTLM");
            o.put("ntlm", ntlm);
            return;
        }
        if ((tok[0] & 0xFF) == 0x60) {
            JSONObject nested = decode(tok, serverChallengeHex);
            o.put("innerKind", nested.optString("kind", "GSS"));
            o.put("innerToken", nested);
            if (nested.has("kerberos")) {
                o.put("kerberos", nested.get("kerberos"));
            }
            if (nested.has("ntlm")) {
                o.put("ntlm", nested.get("ntlm"));
            }
            return;
        }
        int t = tok[0] & 0xFF;
        if (t == 0x6E || t == 0x6F || t == 0x6C || t == 0x7E || t == 0x61) {
            JSONObject krb = decodeKerberosApp(tok, 0);
            o.put("innerKind", "Kerberos");
            o.put("kerberos", krb);
            return;
        }
        o.put("innerKind", "opaque");
        o.put("mechTokenHexPreview", TdsHelper.toHex(tok, 0, Math.min(48, tok.length)));
        o.put("utf16Strings", TdsHelper.extractUtf16Strings(tok, 3));
    }

    private static String spnegoSummary(String tokenName, JSONObject spnego) {
        StringBuilder sb = new StringBuilder("SPNEGO ").append(tokenName);
        if (spnego.has("negStateName")) {
            sb.append(' ').append(spnego.getString("negStateName"));
        }
        if (spnego.has("supportedMechName")) {
            sb.append(" mech=").append(spnego.getString("supportedMechName"));
        } else if (spnego.has("mechTypeNames")) {
            JSONArray names = spnego.getJSONArray("mechTypeNames");
            if (names.length() > 0) {
                sb.append(" mechs=[");
                for (int i = 0; i < names.length(); i++) {
                    if (i > 0) {
                        sb.append(',');
                    }
                    sb.append(names.getString(i));
                }
                sb.append(']');
            }
        }
        if (spnego.has("ntlm")) {
            sb.append(" → ").append(spnego.getJSONObject("ntlm").optString("summary", "NTLM"));
        } else if (spnego.has("kerberos")) {
            sb.append(" → ").append(spnego.getJSONObject("kerberos").optString("summary", "Kerberos"));
        } else if (spnego.has("innerKind")) {
            sb.append(" → ").append(spnego.getString("innerKind"));
        }
        return sb.toString();
    }

    private static String negStateName(int st) {
        return switch (st) {
            case 0 -> "accept-completed";
            case 1 -> "accept-incomplete";
            case 2 -> "reject";
            case 3 -> "request-mic";
            default -> "unknown(" + st + ")";
        };
    }

    // -------------------------------------------------------------------------
    // NTLM
    // -------------------------------------------------------------------------

    private static boolean startsWithNtlm(byte[] data, int off) {
        if (data == null || off + 8 > data.length) {
            return false;
        }
        for (int i = 0; i < 8; i++) {
            if (data[off + i] != NTLM_MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    private static JSONObject decodeNtlm(byte[] data, int off, String serverChallengeHex) {
        JSONObject n = new JSONObject();
        if (!startsWithNtlm(data, off)) {
            n.put("summary", "not NTLM");
            return n;
        }
        int type = readU32LE(data, off + 8);
        n.put("signature", "NTLMSSP");
        n.put("messageType", type);
        n.put("messageTypeName", ntlmTypeName(type));
        switch (type) {
            case 1 -> decodeNtlmType1(data, off, n);
            case 2 -> decodeNtlmType2(data, off, n);
            case 3 -> decodeNtlmType3(data, off, n, serverChallengeHex);
            default -> {
                n.put("summary", "NTLM type " + type);
                n.put("utf16Strings", TdsHelper.extractUtf16Strings(data, 3));
            }
        }
        return n;
    }

    private static void decodeNtlmType1(byte[] data, int off, JSONObject n) {
        // Negotiate: Signature(8) Type(4) Flags(4) DomainFields(8) WorkstationFields(8) [Version(8)]
        if (off + 32 > data.length) {
            n.put("summary", "NTLM Type1 (truncated)");
            return;
        }
        long flags = readU32LE(data, off + 12) & 0xFFFFFFFFL;
        n.put("flags", flags);
        n.put("flagsHex", String.format("0x%08X", flags));
        n.put("flagNames", ntlmFlagNames(flags));
        putNtlmSecurityBuffer(data, off, off + 16, n, "domain", flags);
        putNtlmSecurityBuffer(data, off, off + 24, n, "workstation", flags);
        if ((flags & 0x02000000L) != 0 && off + 40 <= data.length) {
            n.put("version", decodeNtlmVersion(data, off + 32));
        }
        String dom = n.optString("domain", "");
        String ws = n.optString("workstation", "");
        StringBuilder sum = new StringBuilder("NTLM Type1 Negotiate");
        if (!ws.isEmpty()) {
            sum.append(" workstation=").append(ws);
        }
        if (!dom.isEmpty()) {
            sum.append(" domain=").append(dom);
        }
        n.put("summary", sum.toString());
    }

    private static void decodeNtlmType2(byte[] data, int off, JSONObject n) {
        // Challenge: Sig(8) Type(4) TargetNameFields(8) Flags(4) ServerChallenge(8) Reserved(8) TargetInfoFields(8) [Version]
        if (off + 32 > data.length) {
            n.put("summary", "NTLM Type2 (truncated)");
            return;
        }
        putNtlmSecurityBuffer(data, off, off + 12, n, "targetName", 0);
        long flags = readU32LE(data, off + 20) & 0xFFFFFFFFL;
        n.put("flags", flags);
        n.put("flagsHex", String.format("0x%08X", flags));
        n.put("flagNames", ntlmFlagNames(flags));
        n.put("serverChallengeHex", TdsHelper.toHex(data, off + 24, 8));
        if (off + 48 <= data.length) {
            putNtlmSecurityBuffer(data, off, off + 40, n, "targetInfoRaw", flags);
            // TargetInfo is AV_PAIR list, not a string — replace if we parsed buffer as bytes
            SecurityBuf ti = readSecurityBuf(data, off, off + 40);
            if (ti != null && ti.length > 0 && ti.offset + ti.length <= data.length) {
                byte[] av = copy(data, ti.offset, ti.length);
                n.put("targetInfo", decodeAvPairs(av));
                n.remove("targetInfoRaw");
            }
        }
        if ((flags & 0x02000000L) != 0 && off + 56 <= data.length) {
            n.put("version", decodeNtlmVersion(data, off + 48));
        }
        String target = n.optString("targetName", "");
        StringBuilder sum = new StringBuilder("NTLM Type2 Challenge");
        if (!target.isEmpty()) {
            sum.append(" target=").append(target);
        }
        if (n.has("targetInfo")) {
            JSONObject ti = n.getJSONObject("targetInfo");
            if (ti.has("nbComputerName")) {
                sum.append(" server=").append(ti.getString("nbComputerName"));
            }
            if (ti.has("dnsDomainName")) {
                sum.append(" dns=").append(ti.getString("dnsDomainName"));
            }
        }
        n.put("summary", sum.toString());
    }

    private static void decodeNtlmType3(byte[] data, int off, JSONObject n, String serverChallengeHex) {
        // Authenticate: Sig(8) Type(4) LmResp(8) NtResp(8) Domain(8) User(8) Workstation(8)
        //               [SessionKey(8)] Flags(4) [Version(8)] [MIC(16)]
        if (off + 52 > data.length) {
            n.put("summary", "NTLM Type3 (truncated)");
            return;
        }
        SecurityBuf lm = readSecurityBuf(data, off, off + 12);
        SecurityBuf nt = readSecurityBuf(data, off, off + 20);
        if (lm != null) {
            n.put("lmResponseLength", lm.length);
            if (lm.length > 0 && lm.offset + lm.length <= data.length) {
                n.put("lmResponseHex", TdsHelper.toHex(data, lm.offset, lm.length));
            } else {
                n.put("lmResponseHex", "");
            }
        }
        if (nt != null) {
            n.put("ntResponseLength", nt.length);
            if (nt.length > 0 && nt.offset + nt.length <= data.length) {
                n.put("ntResponseHex", TdsHelper.toHex(data, nt.offset, nt.length));
                // NTLMv2: 16-byte NTProofStr + client challenge blob
                if (nt.length > 24) {
                    n.put("ntlmResponseVersion", "v2");
                    n.put("ntProofStrHex", TdsHelper.toHex(data, nt.offset, 16));
                    n.put("ntlmv2BlobHex", TdsHelper.toHex(data, nt.offset + 16, nt.length - 16));
                } else if (nt.length == 24) {
                    n.put("ntlmResponseVersion", "v1");
                } else if (nt.length >= 16) {
                    n.put("ntlmResponseVersion", "unknown");
                    n.put("ntProofStrHex", TdsHelper.toHex(data, nt.offset, 16));
                }
            } else {
                n.put("ntResponseHex", "");
            }
        }
        putNtlmSecurityBuffer(data, off, off + 28, n, "domain", 0);
        putNtlmSecurityBuffer(data, off, off + 36, n, "userName", 0);
        putNtlmSecurityBuffer(data, off, off + 44, n, "workstation", 0);
        if (off + 60 <= data.length) {
            putNtlmSecurityBuffer(data, off, off + 52, n, "sessionKey", 0);
            if (n.has("sessionKey") && n.optString("sessionKey").isEmpty()) {
                SecurityBuf sk = readSecurityBuf(data, off, off + 52);
                if (sk != null && sk.length > 0 && sk.offset + sk.length <= data.length) {
                    n.put("sessionKeyHex", TdsHelper.toHex(data, sk.offset, sk.length));
                    n.remove("sessionKey");
                }
            }
        }
        if (off + 64 <= data.length) {
            long flags = readU32LE(data, off + 60) & 0xFFFFFFFFL;
            if (flags != 0 && (flags & 0xFF000000L) != 0xFF000000L) {
                n.put("flags", flags);
                n.put("flagsHex", String.format("0x%08X", flags));
                n.put("flagNames", ntlmFlagNames(flags));
            }
        }
        String user = n.optString("userName", "");
        String dom = n.optString("domain", "");
        String ws = n.optString("workstation", "");
        StringBuilder sum = new StringBuilder("NTLM Type3 Authenticate");
        if (!user.isEmpty()) {
            sum.append(' ').append(dom.isEmpty() ? user : dom + "\\" + user);
        }
        if (!ws.isEmpty()) {
            sum.append(" from ").append(ws);
        }
        n.put("summary", sum.toString());
        buildNtlmHashes(n, serverChallengeHex);
    }

    /**
     * Build crackable NetNTLM hash lines (hashcat/john formats).
     * NetNTLMv2: user::domain:challenge:ntproof:blob
     * NetNTLMv1: user::domain:lmresp:ntresp:challenge
     */
    private static void buildNtlmHashes(JSONObject n, String serverChallengeHex) {
        if (n == null || n.optInt("messageType", 0) != 3) {
            return;
        }
        String user = n.optString("userName", "");
        String domain = n.optString("domain", "");
        String lm = n.optString("lmResponseHex", "");
        String nt = n.optString("ntResponseHex", "");
        String ch = normalizeChallengeHex(serverChallengeHex);
        boolean complete = ch != null;
        if (!complete) {
            ch = "0000000000000000";
        }
        n.put("serverChallengeHex", complete ? ch : "");
        n.put("ntlmHashComplete", complete);

        String ver = n.optString("ntlmResponseVersion", "");
        if ("v2".equals(ver) || (nt.length() > 48)) {
            // nt is hex: 32 chars proof + rest blob
            String proof;
            String blob;
            if (n.has("ntProofStrHex") && n.has("ntlmv2BlobHex")) {
                proof = n.getString("ntProofStrHex");
                blob = n.getString("ntlmv2BlobHex");
            } else if (nt.length() >= 32) {
                proof = nt.substring(0, 32);
                blob = nt.substring(32);
            } else {
                proof = nt;
                blob = "";
            }
            // Hashcat 5600 / JtR netntlmv2
            String hash = user + "::" + domain + ":" + ch + ":" + proof + ":" + blob;
            n.put("ntlmHashType", "NetNTLMv2");
            n.put("ntlmHash", hash);
            n.put("ntlmHashHashcatMode", 5600);
        } else if ("v1".equals(ver) || nt.length() == 48) {
            // Hashcat 5500 / JtR netntlm: user::domain:lm:nt:challenge
            if (lm.isEmpty()) {
                lm = "000000000000000000000000000000000000000000000000";
            }
            String hash = user + "::" + domain + ":" + lm + ":" + nt + ":" + ch;
            n.put("ntlmHashType", "NetNTLMv1");
            n.put("ntlmHash", hash);
            n.put("ntlmHashHashcatMode", 5500);
        } else if (!nt.isEmpty()) {
            n.put("ntlmHashType", "NetNTLM-unknown");
            n.put("ntlmHash", user + "::" + domain + ":" + ch + ":" + nt);
            n.put("ntlmHashHashcatMode", -1);
        }
        if (!complete && n.has("ntlmHash")) {
            n.put("ntlmHashNote",
                    "Server challenge unknown — pair with Type2 challenge from this stream for a crackable hash.");
        }
    }

    private static String normalizeChallengeHex(String hex) {
        if (hex == null) {
            return null;
        }
        String clean = hex.replaceAll("\\s+", "").toLowerCase();
        if (clean.length() != 16) {
            return null;
        }
        for (int i = 0; i < 16; i++) {
            char c = clean.charAt(i);
            if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
                return null;
            }
        }
        return clean;
    }

    private static void putNtlmSecurityBuffer(byte[] data, int msgOff, int fieldOff, JSONObject n,
                                              String name, long flags) {
        SecurityBuf b = readSecurityBuf(data, msgOff, fieldOff);
        if (b == null || b.length == 0) {
            n.put(name, "");
            return;
        }
        if (b.offset + b.length > data.length) {
            n.put(name, "");
            n.put(name + "Truncated", true);
            return;
        }
        // Domain/user/workstation are Unicode if NEGOTIATE_UNICODE (0x1), else OEM
        boolean unicode = (flags & 0x1L) != 0 || flags == 0;
        // For type2/3 we often don't pass flags for string fields — detect UTF-16
        if ("targetInfoRaw".equals(name) || "sessionKey".equals(name)) {
            n.put(name, TdsHelper.toHex(data, b.offset, b.length));
            return;
        }
        String s;
        if (unicode || looksLikeUtf16Le(data, b.offset, b.length)) {
            s = new String(data, b.offset, b.length, StandardCharsets.UTF_16LE);
        } else {
            s = new String(data, b.offset, b.length, StandardCharsets.ISO_8859_1);
        }
        // strip NULs
        s = s.replace("\u0000", "").trim();
        n.put(name, s);
    }

    private static boolean looksLikeUtf16Le(byte[] data, int off, int len) {
        if (len < 2 || (len & 1) != 0) {
            return false;
        }
        int asciiZeros = 0;
        for (int i = 1; i < len; i += 2) {
            if (data[off + i] == 0) {
                asciiZeros++;
            }
        }
        return asciiZeros >= len / 4;
    }

    private static SecurityBuf readSecurityBuf(byte[] data, int msgOff, int fieldOff) {
        if (fieldOff + 8 > data.length) {
            return null;
        }
        int len = readU16LE(data, fieldOff);
        // maxLength at fieldOff+2 is part of the NTLM security buffer; unused for decode
        int offset = readU32LE(data, fieldOff + 4);
        // offsets are from start of NTLM message
        int abs = msgOff + offset;
        // sometimes offset is absolute from buffer start if msgOff==0
        if (offset >= 0 && abs + len <= data.length) {
            return new SecurityBuf(len, abs);
        }
        if (offset + len <= data.length) {
            return new SecurityBuf(len, offset);
        }
        return new SecurityBuf(len, abs);
    }

    private static JSONObject decodeAvPairs(byte[] av) {
        JSONObject info = new JSONObject();
        JSONArray pairs = new JSONArray();
        int pos = 0;
        while (pos + 4 <= av.length) {
            int id = readU16LE(av, pos);
            int len = readU16LE(av, pos + 2);
            pos += 4;
            if (id == 0) { // MsvAvEOL
                JSONObject p = new JSONObject();
                p.put("id", 0);
                p.put("name", "EOL");
                pairs.put(p);
                break;
            }
            if (pos + len > av.length) {
                break;
            }
            JSONObject p = new JSONObject();
            p.put("id", id);
            p.put("name", avPairName(id));
            String value;
            if (id == 7 || id == 8) { // timestamp / flags — binary
                value = TdsHelper.toHex(av, pos, len);
                if (id == 7 && len == 8) {
                    long filetime = readU64LE(av, pos);
                    p.put("filetime", filetime);
                }
                if (id == 6 && len == 4) { // flags
                    p.put("flags", readU32LE(av, pos));
                }
            } else if (id == 10) { // channel bindings
                value = TdsHelper.toHex(av, pos, len);
            } else {
                value = new String(av, pos, len, StandardCharsets.UTF_16LE).replace("\u0000", "");
            }
            p.put("value", value);
            pairs.put(p);
            switch (id) {
                case 1 -> info.put("nbComputerName", value);
                case 2 -> info.put("nbDomainName", value);
                case 3 -> info.put("dnsComputerName", value);
                case 4 -> info.put("dnsDomainName", value);
                case 5 -> info.put("dnsTreeName", value);
                case 9 -> info.put("targetName", value);
                default -> {
                }
            }
            pos += len;
        }
        info.put("pairs", pairs);
        return info;
    }

    private static String avPairName(int id) {
        return switch (id) {
            case 0 -> "EOL";
            case 1 -> "NbComputerName";
            case 2 -> "NbDomainName";
            case 3 -> "DnsComputerName";
            case 4 -> "DnsDomainName";
            case 5 -> "DnsTreeName";
            case 6 -> "Flags";
            case 7 -> "Timestamp";
            case 8 -> "SingleHost";
            case 9 -> "TargetName";
            case 10 -> "ChannelBindings";
            default -> "AvId_" + id;
        };
    }

    private static JSONObject decodeNtlmVersion(byte[] data, int off) {
        JSONObject v = new JSONObject();
        if (off + 8 > data.length) {
            return v;
        }
        v.put("major", data[off] & 0xFF);
        v.put("minor", data[off + 1] & 0xFF);
        v.put("build", readU16LE(data, off + 2));
        v.put("revision", data[off + 7] & 0xFF);
        v.put("product", (data[off] & 0xFF) + "." + (data[off + 1] & 0xFF)
                + "." + readU16LE(data, off + 2));
        return v;
    }

    private static String ntlmTypeName(int type) {
        return switch (type) {
            case 1 -> "NEGOTIATE";
            case 2 -> "CHALLENGE";
            case 3 -> "AUTHENTICATE";
            default -> "TYPE_" + type;
        };
    }

    private static JSONArray ntlmFlagNames(long flags) {
        // Common [MS-NLMP] Negotiate flags
        Map<Long, String> map = new LinkedHashMap<>();
        map.put(0x00000001L, "UNICODE");
        map.put(0x00000002L, "OEM");
        map.put(0x00000004L, "REQUEST_TARGET");
        map.put(0x00000010L, "SIGN");
        map.put(0x00000020L, "SEAL");
        map.put(0x00000040L, "DATAGRAM");
        map.put(0x00000080L, "LM_KEY");
        map.put(0x00000200L, "NTLM");
        map.put(0x00001000L, "DOMAIN_SUPPLIED");
        map.put(0x00002000L, "WORKSTATION_SUPPLIED");
        map.put(0x00008000L, "ALWAYS_SIGN");
        map.put(0x00010000L, "TARGET_TYPE_DOMAIN");
        map.put(0x00020000L, "TARGET_TYPE_SERVER");
        map.put(0x00080000L, "EXTENDED_SESSIONSECURITY");
        map.put(0x00100000L, "IDENTIFY");
        map.put(0x00200000L, "NON_NT_SESSION_KEY");
        map.put(0x00800000L, "TARGET_INFO");
        map.put(0x02000000L, "VERSION");
        map.put(0x20000000L, "128");
        map.put(0x40000000L, "KEY_EXCH");
        map.put(0x80000000L, "56");
        JSONArray names = new JSONArray();
        for (Map.Entry<Long, String> e : map.entrySet()) {
            if ((flags & e.getKey()) != 0) {
                names.put(e.getValue());
            }
        }
        return names;
    }

    // -------------------------------------------------------------------------
    // Kerberos (lightweight: message type + principal strings)
    // -------------------------------------------------------------------------

    private static JSONObject decodeKerberosApp(byte[] data, int offset) {
        JSONObject k = new JSONObject();
        // Full message TLV from offset (includes APPLICATION tag) for export
        DerReader r = new DerReader(data, offset);
        DerValue app = r.readValue();
        int appTag = app.tag & 0x1F;
        byte[] fullMsg = copy(data, app.start, app.end - app.start);
        String msg = switch (app.tag) {
            case 0x6E -> "AP-REQ";
            case 0x6F -> "AP-REP";
            case 0x6C -> "TGS-REQ";
            case 0x7E -> "KRB-ERROR";
            case 0x61 -> "Ticket";
            case 0x6B -> "AS-REQ";
            case 0x6D -> "TGS-REP";
            default -> "APPLICATION_" + appTag + "/0x" + Integer.toHexString(app.tag);
        };
        k.put("messageType", msg);
        k.put("applicationTag", app.tag);
        k.put("messageLength", fullMsg.length);
        k.put("messageHex", TdsHelper.toHex(fullMsg));
        k.put("messageBase64", Base64.getEncoder().encodeToString(fullMsg));

        if (app.tag == 0x6E) {
            // AP-REQ: export full AP-REQ + extract Ticket (APPLICATION 1 / context [3])
            k.put("apReqLength", fullMsg.length);
            k.put("apReqHex", TdsHelper.toHex(fullMsg));
            k.put("apReqBase64", Base64.getEncoder().encodeToString(fullMsg));
            extractApReqParts(app.content, k);
        } else if (app.tag == 0x61) {
            k.put("ticketLength", fullMsg.length);
            k.put("ticketHex", TdsHelper.toHex(fullMsg));
            k.put("ticketBase64", Base64.getEncoder().encodeToString(fullMsg));
        } else if (app.tag == 0x6F) {
            k.put("apRepLength", fullMsg.length);
            k.put("apRepHex", TdsHelper.toHex(fullMsg));
            k.put("apRepBase64", Base64.getEncoder().encodeToString(fullMsg));
        }

        // Also search entire message for nested Ticket (0x61)
        if (!k.has("ticketBase64")) {
            byte[] ticket = findApplicationTicket(data, offset);
            if (ticket != null) {
                k.put("ticketLength", ticket.length);
                k.put("ticketHex", TdsHelper.toHex(ticket));
                k.put("ticketBase64", Base64.getEncoder().encodeToString(ticket));
            }
        }

        List<String> strings = new ArrayList<>();
        scavengeKerberosStrings(app.content, strings);
        JSONArray arr = new JSONArray();
        for (String s : strings) {
            if (s.length() >= 2 && s.length() < 256) {
                arr.put(s);
            }
        }
        k.put("strings", arr);
        for (int i = 0; i < arr.length(); i++) {
            String s = arr.getString(i);
            if (s.startsWith("MSSQLSvc/") || s.contains("MSSQLSvc/")) {
                k.put("spn", s.contains("MSSQLSvc/") ? s.substring(s.indexOf("MSSQLSvc/")) : s);
                break;
            }
        }
        StringBuilder sum = new StringBuilder("Kerberos ").append(msg);
        if (k.has("spn")) {
            sum.append(' ').append(k.getString("spn"));
        } else if (arr.length() > 0) {
            sum.append(' ').append(arr.getString(0));
            if (arr.length() > 1) {
                sum.append('@').append(arr.getString(Math.min(1, arr.length() - 1)));
            }
        }
        if (k.has("ticketLength")) {
            sum.append(" ticket=").append(k.getInt("ticketLength")).append('B');
        }
        k.put("summary", sum.toString());
        return k;
    }

    /**
     * AP-REQ SEQUENCE fields: pvno[0], msg-type[1], ap-options[2], ticket[3], authenticator[4].
     */
    private static void extractApReqParts(byte[] apReqContent, JSONObject k) {
        try {
            DerReader seq = new DerReader(apReqContent, 0);
            // content may start with SEQUENCE
            if (apReqContent.length > 0 && (apReqContent[0] & 0xFF) == 0x30) {
                DerValue s = seq.readValue();
                seq = s.contentReader();
            }
            while (seq.hasMore()) {
                DerValue f = seq.readValue();
                int ctx = f.tag & 0x1F;
                if (ctx == 3) {
                    // ticket — may be naked Ticket APPLICATION 1 or wrapped
                    byte[] ticket = findTicketBytes(f);
                    if (ticket != null) {
                        k.put("ticketLength", ticket.length);
                        k.put("ticketHex", TdsHelper.toHex(ticket));
                        k.put("ticketBase64", Base64.getEncoder().encodeToString(ticket));
                    }
                } else if (ctx == 4) {
                    byte[] auth = f.content;
                    // often EncryptedData SEQUENCE inside
                    if (auth.length > 0 && (auth[0] & 0xFF) == 0x30) {
                        // keep full field including context wrapper for fidelity
                        auth = copy(f.content, 0, f.content.length);
                    }
                    // Prefer full TLV of authenticator field
                    try {
                        // rebuild not available — use content; if nested APPLICATION use find
                        k.put("authenticatorLength", auth.length);
                        k.put("authenticatorHex", TdsHelper.toHex(auth));
                        k.put("authenticatorBase64", Base64.getEncoder().encodeToString(auth));
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static byte[] findTicketBytes(DerValue field) {
        if (field == null) {
            return null;
        }
        // Explicit Ticket APPLICATION 1 inside content
        if (field.content.length > 0 && (field.content[0] & 0xFF) == 0x61) {
            try {
                DerValue t = new DerReader(field.content, 0).readValue();
                return copy(field.content, t.start, t.end - t.start);
            } catch (Exception e) {
                return field.content;
            }
        }
        // field itself might be APPLICATION 1 (rare)
        if (field.tag == 0x61) {
            // We don't have outer bytes; return content wrapped is incomplete — use content only
            return field.content;
        }
        // Search nested
        return findApplicationTicket(field.content, 0);
    }

    /** Find first Kerberos Ticket (APPLICATION 1, tag 0x61) TLV in buffer. */
    private static byte[] findApplicationTicket(byte[] data, int from) {
        if (data == null) {
            return null;
        }
        for (int i = from; i < data.length; i++) {
            if ((data[i] & 0xFF) != 0x61) {
                continue;
            }
            try {
                DerValue v = new DerReader(data, i).readValue();
                if (v.tag == 0x61 && v.content.length > 8) {
                    return copy(data, v.start, v.end - v.start);
                }
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private static void scavengeKerberosStrings(byte[] data, List<String> out) {
        if (data == null || data.length == 0) {
            return;
        }
        try {
            DerReader r = new DerReader(data, 0);
            while (r.hasMore()) {
                DerValue v = r.readValue();
                scavengeDerValue(v, out, 0);
            }
        } catch (Exception e) {
            // fall through to raw GeneralString scan
        }
        // Raw scan for printable ASCII runs (realms, hostnames)
        StringBuilder cur = new StringBuilder();
        for (byte b : data) {
            int c = b & 0xFF;
            if (c >= 0x20 && c < 0x7F && c != '\\') {
                cur.append((char) c);
            } else {
                if (cur.length() >= 3) {
                    String s = cur.toString();
                    if (looksLikePrincipal(s) && !out.contains(s)) {
                        out.add(s);
                    }
                }
                cur.setLength(0);
            }
        }
        if (cur.length() >= 3) {
            String s = cur.toString();
            if (looksLikePrincipal(s) && !out.contains(s)) {
                out.add(s);
            }
        }
    }

    private static void scavengeDerValue(DerValue v, List<String> out, int depth) {
        if (depth > 32) {
            return;
        }
        // string types: UTF8 0x0C, Printable 0x13, IA5 0x16, General 0x1B, BMP 0x1E, Universal 0x1C
        int tag = v.tag & 0x1F;
        boolean isString = v.tag == 0x0C || v.tag == 0x13 || v.tag == 0x16 || v.tag == 0x1B
                || v.tag == 0x1E || tag == 0x0C || tag == 0x13 || tag == 0x16 || tag == 0x1B;
        if (isString && (v.tag & 0x20) == 0) {
            String s;
            if (v.tag == 0x1E) {
                s = new String(v.content, StandardCharsets.UTF_16BE).trim();
            } else {
                s = new String(v.content, StandardCharsets.UTF_8).trim();
            }
            if (s.length() >= 2 && looksLikePrincipal(s) && !out.contains(s)) {
                out.add(s);
            }
            return;
        }
        if ((v.tag & 0x20) != 0 && v.content.length > 0) {
            try {
                DerReader r = new DerReader(v.content, 0);
                while (r.hasMore()) {
                    scavengeDerValue(r.readValue(), out, depth + 1);
                }
            } catch (Exception ignored) {
            }
        }
    }

    private static boolean looksLikePrincipal(String s) {
        if (s == null || s.length() < 2) {
            return false;
        }
        // filter binary garbage
        int good = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '.' || c == '-' || c == '_' || c == '/' || c == '@' || c == ':') {
                good++;
            }
        }
        return good >= s.length() * 0.85;
    }

    // -------------------------------------------------------------------------
    // OID / helpers
    // -------------------------------------------------------------------------

    private static boolean isKerberosOid(String oid) {
        return OID_KERBEROS5.equals(oid) || OID_MS_KRB5.equals(oid) || OID_KERBEROS5_USER2USER.equals(oid);
    }

    private static String oidName(String oid) {
        if (oid == null) {
            return "unknown";
        }
        return switch (oid) {
            case OID_SPNEGO -> "SPNEGO";
            case OID_KERBEROS5 -> "Kerberos5";
            case OID_KERBEROS5_USER2USER -> "Kerberos5-U2U";
            case OID_MS_KRB5 -> "MS-KRB5";
            case OID_NTLMSSP -> "NTLMSSP";
            default -> oid;
        };
    }

    private static String decodeOid(byte[] content) {
        if (content == null || content.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int first = content[0] & 0xFF;
        sb.append(first / 40).append('.').append(first % 40);
        long val = 0;
        for (int i = 1; i < content.length; i++) {
            int b = content[i] & 0xFF;
            val = (val << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                sb.append('.').append(val);
                val = 0;
            }
        }
        return sb.toString();
    }

    private static DerReader unwrapSequence(DerValue v) {
        // Context-specific constructed wraps a SEQUENCE
        if (v.content.length > 0 && (v.content[0] & 0xFF) == 0x30) {
            DerValue seq = new DerReader(v.content, 0).readValue();
            return seq.contentReader();
        }
        return v.contentReader();
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

    private static long readU64LE(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= (long) (b[off + i] & 0xFF) << (8 * i);
        }
        return v;
    }

    private static byte[] copy(byte[] src, int off, int len) {
        byte[] d = new byte[len];
        System.arraycopy(src, off, d, 0, len);
        return d;
    }

    private static final class SecurityBuf {
        final int length;
        final int offset;

        SecurityBuf(int length, int offset) {
            this.length = length;
            this.offset = offset;
        }
    }

    // -------------------------------------------------------------------------
    // Minimal DER reader
    // -------------------------------------------------------------------------

    static final class DerValue {
        final int tag;
        final byte[] content;
        final int start;
        final int end;

        DerValue(int tag, byte[] content, int start, int end) {
            this.tag = tag;
            this.content = content;
            this.start = start;
            this.end = end;
        }

        DerReader contentReader() {
            return new DerReader(content, 0);
        }
    }

    static final class DerReader {
        private final byte[] data;
        private int pos;
        private final int end;

        DerReader(byte[] data, int pos) {
            this.data = data != null ? data : new byte[0];
            this.pos = Math.max(0, pos);
            this.end = this.data.length;
        }

        boolean hasMore() {
            return pos < end;
        }

        byte[] remainingBytes() {
            if (pos >= end) {
                return new byte[0];
            }
            return copy(data, pos, end - pos);
        }

        DerValue readValue() {
            if (pos >= end) {
                throw new IllegalArgumentException("DER truncated at start");
            }
            int start = pos;
            int tag = data[pos++] & 0xFF;
            // multi-byte tags not fully supported beyond low tags
            if ((tag & 0x1F) == 0x1F) {
                while (pos < end && (data[pos] & 0x80) != 0) {
                    pos++;
                }
                if (pos < end) {
                    pos++;
                }
            }
            if (pos >= end) {
                throw new IllegalArgumentException("DER truncated in tag");
            }
            int lenByte = data[pos++] & 0xFF;
            int length;
            if ((lenByte & 0x80) == 0) {
                length = lenByte;
            } else {
                int n = lenByte & 0x7F;
                if (n == 0 || n > 4 || pos + n > end) {
                    throw new IllegalArgumentException("DER bad length");
                }
                length = 0;
                for (int i = 0; i < n; i++) {
                    length = (length << 8) | (data[pos++] & 0xFF);
                }
            }
            if (length < 0 || pos + length > end) {
                throw new IllegalArgumentException("DER content past end (len=" + length + ")");
            }
            byte[] content = copy(data, pos, length);
            pos += length;
            return new DerValue(tag, content, start, pos);
        }
    }
}
