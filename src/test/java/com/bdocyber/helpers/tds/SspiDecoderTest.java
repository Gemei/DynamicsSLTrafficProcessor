package com.bdocyber.helpers.tds;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class SspiDecoderTest {

    @Test
    public void decodeRawNtlmType1() {
        // NTLMSSP\0 + type1 + flags UNICODE|REQUEST_TARGET|NTLM|ALWAYS_SIGN|VERSION
        // + empty domain + workstation "PC1" unicode
        byte[] msg = buildNtlmType1("CORP", "PC1");
        JSONObject d = SspiDecoder.decode(msg);
        assertEquals("NTLM", d.getString("kind"));
        JSONObject ntlm = d.getJSONObject("ntlm");
        assertEquals(1, ntlm.getInt("messageType"));
        assertEquals("NEGOTIATE", ntlm.getString("messageTypeName"));
        assertEquals("CORP", ntlm.getString("domain"));
        assertEquals("PC1", ntlm.getString("workstation"));
        assertTrue(d.getString("summary").contains("Type1"));
    }

    @Test
    public void decodeRawNtlmType2WithTargetInfo() {
        byte[] msg = buildNtlmType2("SERVER", "DOMAIN");
        JSONObject d = SspiDecoder.decode(msg);
        assertEquals("NTLM", d.getString("kind"));
        JSONObject ntlm = d.getJSONObject("ntlm");
        assertEquals(2, ntlm.getInt("messageType"));
        assertEquals("SERVER", ntlm.getString("targetName"));
        assertTrue(ntlm.has("serverChallengeHex"));
        assertEquals(16, ntlm.getString("serverChallengeHex").length()); // 8 bytes hex
        JSONObject ti = ntlm.getJSONObject("targetInfo");
        assertEquals("SERVER", ti.getString("nbComputerName"));
        assertEquals("DOMAIN", ti.getString("nbDomainName"));
    }

    @Test
    public void decodeRawNtlmType3() {
        byte[] msg = buildNtlmType3("CORP", "alice", "WS01");
        JSONObject d = SspiDecoder.decode(msg);
        JSONObject ntlm = d.getJSONObject("ntlm");
        assertEquals(3, ntlm.getInt("messageType"));
        assertEquals("alice", ntlm.getString("userName"));
        assertEquals("CORP", ntlm.getString("domain"));
        assertEquals("WS01", ntlm.getString("workstation"));
        assertTrue(d.getString("summary").contains("alice"));
    }

    @Test
    public void decodeSpnegoNegTokenInitWithNtlm() {
        byte[] ntlm = buildNtlmType1("CORP", "PC1");
        byte[] spnego = wrapSpnegoNegTokenInitWithNtlm(ntlm);
        JSONObject d = SspiDecoder.decode(spnego);
        assertEquals("SPNEGO", d.getString("kind"));
        assertEquals("NegTokenInit", d.getString("spnegoToken"));
        assertTrue(d.has("ntlm") || d.getJSONObject("spnego").has("ntlm"));
        JSONObject ntlmObj = d.has("ntlm") ? d.getJSONObject("ntlm") : d.getJSONObject("spnego").getJSONObject("ntlm");
        assertEquals(1, ntlmObj.getInt("messageType"));
        assertTrue(d.getString("summary").toLowerCase().contains("spnego")
                || d.getString("summary").contains("NTLM"));
    }

    @Test
    public void decodeSpnegoNegTokenRespAcceptIncomplete() {
        byte[] ntlm = buildNtlmType2("SQL01", "CORP");
        byte[] resp = wrapSpnegoNegTokenResp(1, ntlm); // accept-incomplete
        JSONObject d = SspiDecoder.decode(resp);
        assertEquals("SPNEGO", d.getString("kind"));
        assertEquals("NegTokenResp", d.getString("spnegoToken"));
        JSONObject sp = d.getJSONObject("spnego");
        assertEquals("accept-incomplete", sp.getString("negStateName"));
        assertTrue(sp.has("ntlm") || d.has("ntlm"));
    }

    @Test
    public void oneLineSummaryNonEmpty() {
        String s = SspiDecoder.oneLineSummary(buildNtlmType1("A", "B"));
        assertNotNull(s);
        assertFalse(s.isBlank());
    }

    @Test
    public void ntlmType3ProducesNetNtlmHashWithChallenge() {
        byte[] type3 = buildNtlmType3("CORP", "alice", "WS01");
        // Type3 with 24-byte NT response → NetNTLMv1
        JSONObject d = SspiDecoder.decode(type3, "a0a1a2a3a4a5a6a7");
        assertTrue(d.has("ntlmHash") || d.getJSONObject("ntlm").has("ntlmHash"));
        String hash = d.has("ntlmHash") ? d.getString("ntlmHash") : d.getJSONObject("ntlm").getString("ntlmHash");
        assertTrue(hash.contains("alice"));
        assertTrue(hash.contains("CORP"));
        assertTrue(hash.toLowerCase().contains("a0a1a2a3a4a5a6a7"));
        assertTrue(d.optBoolean("ntlmHashComplete", d.getJSONObject("ntlm").optBoolean("ntlmHashComplete", false)));
        assertTrue(d.has("credentials"));
        assertTrue(d.getJSONObject("credentials").has("ntlmHash"));
    }

    @Test
    public void ntlmType3V2HashFormat() {
        byte[] type3 = buildNtlmType3V2("CORP", "bob", "PC1");
        JSONObject d = SspiDecoder.decode(type3, "1122334455667788");
        JSONObject ntlm = d.getJSONObject("ntlm");
        assertEquals("v2", ntlm.getString("ntlmResponseVersion"));
        assertEquals("NetNTLMv2", ntlm.getString("ntlmHashType"));
        String hash = ntlm.getString("ntlmHash");
        // user::domain:challenge:proof:blob
        String[] parts = hash.split(":");
        assertTrue(parts.length >= 5);
        assertEquals("bob", parts[0]);
        assertEquals("", parts[1]);
        assertEquals("CORP", parts[2]);
        assertEquals("1122334455667788", parts[3]);
        assertEquals(32, parts[4].length()); // proof hex
    }

    @Test
    public void applyServerChallengeCompletesHash() {
        byte[] type3 = buildNtlmType3("CORP", "alice", "WS01");
        JSONObject d = SspiDecoder.decode(type3);
        assertFalse(d.getJSONObject("ntlm").optBoolean("ntlmHashComplete", true));
        SspiDecoder.applyServerChallenge(d, "deadbeefcafebabe");
        assertTrue(d.getJSONObject("ntlm").getBoolean("ntlmHashComplete"));
        assertTrue(d.getString("ntlmHash").contains("deadbeefcafebabe"));
    }

    @Test
    public void appendAuthMaterialIncludesHash() {
        byte[] type3 = buildNtlmType3("CORP", "alice", "WS01");
        JSONObject d = SspiDecoder.decode(type3, "0102030405060708");
        StringBuilder sb = new StringBuilder();
        SspiDecoder.appendAuthMaterial(sb, d, "  ");
        String text = sb.toString();
        assertTrue(text.contains("NTLM hash"));
        assertTrue(text.contains("alice"));
        assertTrue(text.contains("NT response") || text.contains("NTLM NT response"));
    }

    private static byte[] buildNtlmType3V2(String domain, String user, String workstation) {
        // NT response: 16-byte proof + blob (respType=1, hi=1, reserved, time, client chal, ...)
        byte[] lm = new byte[24];
        byte[] nt = new byte[16 + 28];
        for (int i = 0; i < 16; i++) {
            nt[i] = (byte) (0xB0 + i);
        }
        nt[16] = 0x01; // resp type
        nt[17] = 0x01; // hi
        // rest zeros ok for structure
        byte[] dom = domain.getBytes(StandardCharsets.UTF_16LE);
        byte[] usr = user.getBytes(StandardCharsets.UTF_16LE);
        byte[] ws = workstation.getBytes(StandardCharsets.UTF_16LE);
        int off = 72;
        int total = off + lm.length + nt.length + dom.length + usr.length + ws.length;
        byte[] m = new byte[total];
        writeNtlmMagic(m, 0);
        writeU32(m, 8, 3);
        int cur = off;
        writeSecBuf(m, 12, lm.length, cur);
        System.arraycopy(lm, 0, m, cur, lm.length);
        cur += lm.length;
        writeSecBuf(m, 20, nt.length, cur);
        System.arraycopy(nt, 0, m, cur, nt.length);
        cur += nt.length;
        writeSecBuf(m, 28, dom.length, cur);
        System.arraycopy(dom, 0, m, cur, dom.length);
        cur += dom.length;
        writeSecBuf(m, 36, usr.length, cur);
        System.arraycopy(usr, 0, m, cur, usr.length);
        cur += usr.length;
        writeSecBuf(m, 44, ws.length, cur);
        System.arraycopy(ws, 0, m, cur, ws.length);
        writeSecBuf(m, 52, 0, cur);
        writeU32(m, 60, (int) (0x00000001L | 0x00000200L | 0x00080000L | 0x02000000L));
        return m;
    }

    // --- builders ---

    private static byte[] buildNtlmType1(String domain, String workstation) {
        byte[] dom = domain.getBytes(StandardCharsets.UTF_16LE);
        byte[] ws = workstation.getBytes(StandardCharsets.UTF_16LE);
        int payloadOff = 40; // after version
        int total = payloadOff + dom.length + ws.length;
        byte[] m = new byte[total];
        writeNtlmMagic(m, 0);
        writeU32(m, 8, 1);
        long flags = 0x00000001L | 0x00000200L | 0x00008000L | 0x00001000L | 0x00002000L | 0x02000000L;
        writeU32(m, 12, (int) flags);
        // domain fields at 16
        writeU16(m, 16, dom.length);
        writeU16(m, 18, dom.length);
        writeU32(m, 20, payloadOff);
        // workstation at 24
        writeU16(m, 24, ws.length);
        writeU16(m, 26, ws.length);
        writeU32(m, 28, payloadOff + dom.length);
        // version at 32
        m[32] = 10;
        m[33] = 0;
        writeU16(m, 34, 19041);
        m[39] = 0x0F;
        System.arraycopy(dom, 0, m, payloadOff, dom.length);
        System.arraycopy(ws, 0, m, payloadOff + dom.length, ws.length);
        return m;
    }

    private static byte[] buildNtlmType2(String computer, String domain) {
        byte[] target = computer.getBytes(StandardCharsets.UTF_16LE);
        // AV pairs: NbComputerName, NbDomainName, EOL
        byte[] avComp = computer.getBytes(StandardCharsets.UTF_16LE);
        byte[] avDom = domain.getBytes(StandardCharsets.UTF_16LE);
        byte[] av = new byte[4 + avComp.length + 4 + avDom.length + 4];
        int p = 0;
        writeU16(av, p, 1);
        writeU16(av, p + 2, avComp.length);
        System.arraycopy(avComp, 0, av, p + 4, avComp.length);
        p += 4 + avComp.length;
        writeU16(av, p, 2);
        writeU16(av, p + 2, avDom.length);
        System.arraycopy(avDom, 0, av, p + 4, avDom.length);
        p += 4 + avDom.length;
        writeU16(av, p, 0);
        writeU16(av, p + 2, 0);

        int header = 56;
        int total = header + target.length + av.length;
        byte[] m = new byte[total];
        writeNtlmMagic(m, 0);
        writeU32(m, 8, 2);
        writeU16(m, 12, target.length);
        writeU16(m, 14, target.length);
        writeU32(m, 16, header);
        long flags = 0x00000001L | 0x00000200L | 0x00008000L | 0x00800000L | 0x00020000L | 0x02000000L;
        writeU32(m, 20, (int) flags);
        // challenge
        for (int i = 0; i < 8; i++) {
            m[24 + i] = (byte) (0xA0 + i);
        }
        // reserved 32-39
        writeU16(m, 40, av.length);
        writeU16(m, 42, av.length);
        writeU32(m, 44, header + target.length);
        // version 48
        m[48] = 10;
        m[55] = 0x0F;
        System.arraycopy(target, 0, m, header, target.length);
        System.arraycopy(av, 0, m, header + target.length, av.length);
        return m;
    }

    private static byte[] buildNtlmType3(String domain, String user, String workstation) {
        byte[] lm = new byte[24];
        byte[] nt = new byte[24];
        for (int i = 0; i < 24; i++) {
            lm[i] = (byte) i;
            nt[i] = (byte) (0x10 + i);
        }
        byte[] dom = domain.getBytes(StandardCharsets.UTF_16LE);
        byte[] usr = user.getBytes(StandardCharsets.UTF_16LE);
        byte[] ws = workstation.getBytes(StandardCharsets.UTF_16LE);
        int off = 72; // conservative header with flags+version
        int total = off + lm.length + nt.length + dom.length + usr.length + ws.length;
        byte[] m = new byte[total];
        writeNtlmMagic(m, 0);
        writeU32(m, 8, 3);
        int cur = off;
        writeSecBuf(m, 12, lm.length, cur);
        System.arraycopy(lm, 0, m, cur, lm.length);
        cur += lm.length;
        writeSecBuf(m, 20, nt.length, cur);
        System.arraycopy(nt, 0, m, cur, nt.length);
        cur += nt.length;
        writeSecBuf(m, 28, dom.length, cur);
        System.arraycopy(dom, 0, m, cur, dom.length);
        cur += dom.length;
        writeSecBuf(m, 36, usr.length, cur);
        System.arraycopy(usr, 0, m, cur, usr.length);
        cur += usr.length;
        writeSecBuf(m, 44, ws.length, cur);
        System.arraycopy(ws, 0, m, cur, ws.length);
        // session key empty at 52
        writeSecBuf(m, 52, 0, cur);
        writeU32(m, 60, (int) (0x00000001L | 0x00000200L | 0x02000000L));
        return m;
    }

    /** GSS-API APPLICATION 0 + SPNEGO OID + NegTokenInit [0] with mechToken = NTLM. */
    private static byte[] wrapSpnegoNegTokenInitWithNtlm(byte[] ntlm) {
        // mechTypes [0] SEQUENCE OF OID = NTLMSSP 1.3.6.1.4.1.311.2.2.10
        byte[] ntlmOid = oidBytes(new int[]{1, 3, 6, 1, 4, 1, 311, 2, 2, 10});
        byte[] mechTypesSeq = seq(oidTag(ntlmOid));
        byte[] mechTypesField = context(0, mechTypesSeq);
        // SPNEGO often uses explicit OCTET STRING inside context
        byte[] mechTokenExplicit = context(2, octetString(ntlm));
        byte[] negInitSeq = seq(concat(mechTypesField, mechTokenExplicit));
        byte[] negInit = context(0, negInitSeq);

        byte[] spnegoOid = oidBytes(new int[]{1, 3, 6, 1, 5, 5, 2});
        byte[] gssInner = concat(oidTag(spnegoOid), negInit);
        return app0(gssInner);
    }

    private static byte[] wrapSpnegoNegTokenResp(int negState, byte[] ntlm) {
        // [0] ENUMERATED negState
        byte[] en = new byte[]{0x0A, 0x01, (byte) negState};
        byte[] stateField = context(0, en);
        byte[] tokField = context(2, octetString(ntlm));
        byte[] seqBody = seq(concat(stateField, tokField));
        return context(1, seqBody); // NegTokenResp is [1]
    }

    private static void writeNtlmMagic(byte[] m, int off) {
        byte[] magic = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
        System.arraycopy(magic, 0, m, off, 8);
    }

    private static void writeSecBuf(byte[] m, int fieldOff, int len, int offset) {
        writeU16(m, fieldOff, len);
        writeU16(m, fieldOff + 2, len);
        writeU32(m, fieldOff + 4, offset);
    }

    private static void writeU16(byte[] b, int off, int v) {
        b[off] = (byte) (v & 0xFF);
        b[off + 1] = (byte) ((v >> 8) & 0xFF);
    }

    private static void writeU32(byte[] b, int off, int v) {
        b[off] = (byte) (v & 0xFF);
        b[off + 1] = (byte) ((v >> 8) & 0xFF);
        b[off + 2] = (byte) ((v >> 16) & 0xFF);
        b[off + 3] = (byte) ((v >> 24) & 0xFF);
    }

    private static byte[] oidBytes(int[] arcs) {
        // first byte = 40*arc0+arc1
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        bos.write(40 * arcs[0] + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            int v = arcs[i];
            if (v < 0x80) {
                bos.write(v);
            } else {
                // multi-byte base128
                int n = v;
                byte[] tmp = new byte[5];
                int ti = 0;
                tmp[ti++] = (byte) (n & 0x7F);
                n >>= 7;
                while (n > 0) {
                    tmp[ti++] = (byte) ((n & 0x7F) | 0x80);
                    n >>= 7;
                }
                for (int j = ti - 1; j >= 0; j--) {
                    bos.write(tmp[j] & 0xFF);
                }
            }
        }
        return bos.toByteArray();
    }

    private static byte[] oidTag(byte[] content) {
        return tlv(0x06, content);
    }

    private static byte[] octetString(byte[] content) {
        return tlv(0x04, content);
    }

    private static byte[] seq(byte[] content) {
        return tlv(0x30, content);
    }

    private static byte[] context(int n, byte[] content) {
        return tlv(0xA0 | n, content);
    }

    private static byte[] app0(byte[] content) {
        return tlv(0x60, content);
    }

    private static byte[] tlv(int tag, byte[] content) {
        int len = content.length;
        byte[] out;
        if (len < 0x80) {
            out = new byte[2 + len];
            out[0] = (byte) tag;
            out[1] = (byte) len;
            System.arraycopy(content, 0, out, 2, len);
        } else if (len <= 0xFF) {
            out = new byte[3 + len];
            out[0] = (byte) tag;
            out[1] = (byte) 0x81;
            out[2] = (byte) len;
            System.arraycopy(content, 0, out, 3, len);
        } else {
            out = new byte[4 + len];
            out[0] = (byte) tag;
            out[1] = (byte) 0x82;
            out[2] = (byte) ((len >> 8) & 0xFF);
            out[3] = (byte) (len & 0xFF);
            System.arraycopy(content, 0, out, 4, len);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
