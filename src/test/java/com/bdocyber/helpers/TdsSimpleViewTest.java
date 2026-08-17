package com.bdocyber.helpers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class TdsSimpleViewTest {

    @Test
    public void simpleTabularIsHttpStyleWithoutHexNoise() throws Exception {
        Path bin = Path.of("samples/server_response_1_request_body.bin");
        if (!Files.exists(bin)) {
            return;
        }
        byte[] body = Files.readAllBytes(bin);
        String simple = TdsSimpleView.format(body, null, true);
        assertFalse(simple.contains("payloadHex"), "simple must not show payloadHex");
        assertFalse(simple.contains("_hint"), "simple must not show _hint");
        assertTrue(simple.contains("Result") || simple.contains("Columns") || simple.contains("Rows")
                        || simple.contains("TDS"),
                () -> "expected readable simple view, got:\n" + simple.substring(0, Math.min(400, simple.length())));

        String full = TdsSimpleView.format(body, null, false);
        assertFalse(full.contains("_hint"));
        assertFalse(full.contains("\"payloadHex\""), "full envelope should not include payloadHex");
        assertTrue(full.contains("tokens") || full.contains("typeName") || full.contains("COLMETADATA"));
    }

    @Test
    public void errorMessageUsesUtf16UsVarchar() {
        // Synthetic ERROR token body: number=15161, state=1, class=16, msg="Invalid object"
        // LONG 15161 LE, state 1, class 16, USHORT 15, UTF-16LE "Invalid object"
        String msg = "Invalid object";
        byte[] msgUtf16 = msg.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        // number
        bos.write(15161 & 0xFF);
        bos.write((15161 >> 8) & 0xFF);
        bos.write((15161 >> 16) & 0xFF);
        bos.write((15161 >> 24) & 0xFF);
        bos.write(1); // state
        bos.write(16); // class
        bos.write(msg.length() & 0xFF);
        bos.write((msg.length() >> 8) & 0xFF);
        bos.writeBytes(msgUtf16);
        bos.write(0); // server name empty
        bos.write(0); // proc empty
        bos.write(0);
        bos.write(0); // line
        byte[] errBody = bos.toByteArray();
        // wrap as TDS TABULAR packet: header + token 0xAA + USHORT len + body
        int tokenLen = errBody.length;
        int packetLen = 8 + 1 + 2 + tokenLen;
        byte[] pkt = new byte[packetLen];
        pkt[0] = 4; // TABULAR
        pkt[1] = 1;
        pkt[2] = (byte) ((packetLen >> 8) & 0xFF);
        pkt[3] = (byte) (packetLen & 0xFF);
        pkt[8] = (byte) 0xAA;
        pkt[9] = (byte) (tokenLen & 0xFF);
        pkt[10] = (byte) ((tokenLen >> 8) & 0xFF);
        System.arraycopy(errBody, 0, pkt, 11, errBody.length);

        String simple = TdsSimpleView.format(pkt, null, true);
        assertTrue(simple.contains("Invalid object"), () -> "got:\n" + simple);
        assertFalse(simple.contains("\\u"), "should not be mojibake escapes of wrong decode");
    }

    @Test
    public void fullJsonSqlEditRepacks() throws Exception {
        Path bin = Path.of("samples/Select_request_1_request_body.bin");
        if (!Files.exists(bin)) {
            return;
        }
        byte[] body = Files.readAllBytes(bin);
        TdsHelper helper = new TdsHelper();
        String full = TdsSimpleView.format(body, null, false);
        JSONObject env = new JSONObject(full);
        String newSql = "Select * from userrec where userid = 'ADMIN'";
        env.getJSONArray("packets").getJSONObject(0).getJSONObject("rpc").put("sql", newSql);
        env.getJSONArray("packets").getJSONObject(0).getJSONObject("rpc")
                .getJSONArray("params").getJSONObject(1).put("value", newSql);
        byte[] packed = TdsSimpleView.packEditor(env.toString(2), body, helper);
        assertTrue(helper.looksLikeTds(packed));
        JSONArray again = helper.unpack(packed);
        assertEquals(newSql, again.getJSONObject(0).getJSONObject("rpc").getString("sql"));
    }

    @Test
    public void simpleViewShowsReadableSql() throws Exception {
        Path bin = Path.of("samples/Select_request_1_request_body.bin");
        if (!Files.exists(bin)) {
            return;
        }
        byte[] body = Files.readAllBytes(bin);
        String simple = TdsSimpleView.format(body, null, true);
        assertTrue(simple.contains("Select") || simple.contains("select") || simple.contains("Sp_Cursor"),
                () -> simple.substring(0, Math.min(300, simple.length())));
        assertFalse(simple.contains("payloadHex"));
    }

    @Test
    public void simplePlainTextSqlEditIsAppliedNotDiscarded() throws Exception {
        Path bin = Path.of("samples/Select_request_1_request_body.bin");
        if (!Files.exists(bin)) {
            return;
        }
        byte[] body = Files.readAllBytes(bin);
        TdsHelper helper = new TdsHelper();
        String simple = TdsSimpleView.format(body, null, true);
        String newSql = "Select * from userrec where userid = 'ADMIN'";
        // Replace the original SQL fragment in simple text with new SQL
        String originalSql = helper.unpack(body).getJSONObject(0).getJSONObject("rpc").getString("sql");
        String edited = simple.replace(originalSql, newSql);
        assertNotEquals(simple, edited, "test setup: simple text should contain original SQL");

        byte[] packed = TdsSimpleView.packEditor(edited, body, helper);
        assertFalse(java.util.Arrays.equals(body, packed), "edit must change body bytes");
        assertEquals(newSql, helper.unpack(packed).getJSONObject(0).getJSONObject("rpc").getString("sql"));
    }

    @Test
    public void extractSqlFromSqlBatchSimpleText() {
        String text = "TDS Request  to 10.0.0.1:1433  100 bytes\n\nSQL Batch\n\nSELECT COUNT(*) FROM foo\nWHERE x = 1\n";
        assertEquals("SELECT COUNT(*) FROM foo\nWHERE x = 1",
                TdsSimpleView.extractSqlFromSimpleText(text));
    }
}
