package com.bdocyber.helpers;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class MatchReplaceEngineTest {

    @Test
    public void tdsRepackAllowsShorterUseridWithoutBreakingHeader() throws Exception {
        Path bin = Path.of("samples/Select_request_1_request_body.bin");
        if (!Files.exists(bin)) {
            bin = Path.of("C:\\Home\\My_Software\\DynamicsSLTrafficProcessor\\samples\\Select_request_1_request_body.bin");
        }
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.exists(bin));
        byte[] body = Files.readAllBytes(bin);
        assertEquals(188, body.length);
        assertEquals(188, ((body[2] & 0xFF) << 8) | (body[3] & 0xFF));

        MatchReplaceEngine engine = new MatchReplaceEngine();
        engine.setEnabled(true);
        // 13 → 11 chars (same failure mode as APPAPMANAGER1 → APPAPADMIN1)
        engine.setRules(List.of(new MatchReplaceRule(
                true, "REQUEST", "APPAPMANAGER1", "APPAPADMIN1",
                false, "UTF16LE", "test")));

        byte[] out = engine.apply(body, MatchReplaceEngine.Direction.REQUEST);
        assertNotEquals(body.length, out.length, "body length should change");
        int lenField = ((out[2] & 0xFF) << 8) | (out[3] & 0xFF);
        assertEquals(out.length, lenField, "TDS length field must match actual body");

        TdsHelper tds = new TdsHelper();
        assertTrue(tds.isSuccessfullyDecoded(out));
        String sql = tds.unpack(out).getJSONObject(0).getJSONObject("rpc").getString("sql");
        assertEquals("Select * from userrec where userid = 'APPAPADMIN1'", sql);
        assertFalse(sql.contains("APPAPMANAGER1"));
    }

    @Test
    public void tdsRepackSameLengthStillWorks() throws Exception {
        Path bin = Path.of("samples/Select_request_1_request_body.bin");
        if (!Files.exists(bin)) {
            bin = Path.of("C:\\Home\\My_Software\\DynamicsSLTrafficProcessor\\samples\\Select_request_1_request_body.bin");
        }
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.exists(bin));
        byte[] body = Files.readAllBytes(bin);

        MatchReplaceEngine engine = new MatchReplaceEngine();
        engine.setRules(List.of(new MatchReplaceRule(
                true, "REQUEST", "APPAPMANAGER1", "HACKEDUSERXX1",
                false, "UTF16LE", "test")));

        byte[] out = engine.apply(body, MatchReplaceEngine.Direction.REQUEST);
        assertEquals(body.length, out.length);
        assertEquals(out.length, ((out[2] & 0xFF) << 8) | (out[3] & 0xFF));
        TdsHelper tds = new TdsHelper();
        assertTrue(tds.unpack(out).getJSONObject(0).getJSONObject("rpc").getString("sql")
                .contains("HACKEDUSERXX1"));
    }

    @Test
    public void responseTargetSkipsClientRequestDirection() {
        MatchReplaceEngine engine = new MatchReplaceEngine();
        engine.setRules(List.of(new MatchReplaceRule(
                true, "RESPONSE", "ABC", "XYZ", false, "RAW", "")));

        byte[] body = "xxABCyy".getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = engine.apply(body, MatchReplaceEngine.Direction.REQUEST);
        assertArrayEquals(body, out);

        out = engine.apply(body, MatchReplaceEngine.Direction.RESPONSE);
        assertEquals("xxXYZyy", new String(out, StandardCharsets.ISO_8859_1));
    }

    @Test
    public void rawNonTdsStillWorks() {
        MatchReplaceEngine engine = new MatchReplaceEngine();
        engine.setRules(List.of(new MatchReplaceRule(
                true, "BOTH", "foo", "bar", false, "RAW", "")));
        byte[] body = "xxfooyy".getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = engine.apply(body, MatchReplaceEngine.Direction.REQUEST);
        assertEquals("xxbaryy", new String(out, StandardCharsets.ISO_8859_1));
    }
}
