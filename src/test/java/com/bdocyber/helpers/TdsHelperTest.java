package com.bdocyber.helpers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class TdsHelperTest {

    private static final Path LOCAL_SAMPLES = Path.of("samples");

    @Test
    public void decodeSpCursorOpenSelect() throws Exception {
        byte[] body = loadBody("Select_request_1_request_body.bin");
        TdsHelper helper = new TdsHelper();
        assertTrue(helper.looksLikeTds(body));

        JSONArray packets = helper.unpack(body);
        assertEquals(1, packets.length());
        JSONObject pkt = packets.getJSONObject(0);
        assertEquals("RPC", pkt.getString("typeName"));
        assertEquals(3, pkt.getInt("type"));

        JSONObject rpc = pkt.getJSONObject("rpc");
        assertEquals(2, rpc.getInt("procId"));
        assertEquals("Sp_CursorOpen", rpc.getString("procName"));
        assertEquals("Select * from userrec where userid = 'APPAPMANAGER1'", rpc.getString("sql"));

        JSONArray params = rpc.getJSONArray("params");
        assertEquals(5, params.length());
        assertEquals("NVARCHAR", params.getJSONObject(1).getString("sqlType"));
    }

    @Test
    public void roundTripSelectUnchanged() throws Exception {
        byte[] body = loadBody("Select_request_1_request_body.bin");
        TdsHelper helper = new TdsHelper();
        JSONArray packets = helper.unpack(body);
        byte[] rebuilt = helper.pack(packets);
        assertArrayEquals(body, rebuilt);
    }

    @Test
    public void editSqlAndRepack() throws Exception {
        byte[] body = loadBody("Select_request_1_request_body.bin");
        TdsHelper helper = new TdsHelper();
        JSONArray packets = helper.unpack(body);
        JSONObject rpc = packets.getJSONObject(0).getJSONObject("rpc");
        String newSql = "Select * from userrec where userid = 'ADMIN'";
        rpc.put("sql", newSql);
        rpc.getJSONArray("params").getJSONObject(1).put("value", newSql);

        byte[] rebuilt = helper.pack(packets);
        assertTrue(helper.looksLikeTds(rebuilt));
        int len = ((rebuilt[2] & 0xFF) << 8) | (rebuilt[3] & 0xFF);
        assertEquals(rebuilt.length, len);

        JSONArray again = helper.unpack(rebuilt);
        assertEquals(newSql, again.getJSONObject(0).getJSONObject("rpc").getString("sql"));
    }

    @Test
    public void decodeCursorOption() throws Exception {
        byte[] body = loadBody("other_client_requests_1_request_body.bin");
        TdsHelper helper = new TdsHelper();
        JSONObject rpc = helper.unpack(body).getJSONObject(0).getJSONObject("rpc");
        assertEquals("Sp_CursorOption", rpc.getString("procName"));
        assertEquals(8, rpc.getInt("procId"));
        assertEquals("UserRec", rpc.getJSONArray("params").getJSONObject(2).getString("value"));
    }

    @Test
    public void decodeDoneProcResponse() throws Exception {
        byte[] body = loadBody("other_server_responses_1_request_body.bin");
        TdsHelper helper = new TdsHelper();
        JSONObject pkt = helper.unpack(body).getJSONObject(0);
        assertEquals("TABULAR_RESULT", pkt.getString("typeName"));
        JSONArray tokens = pkt.getJSONArray("tokens");
        assertTrue(tokens.length() >= 2);
        assertEquals("RETURNSTATUS", tokens.getJSONObject(0).getString("name"));
        assertEquals("DONEPROC", tokens.getJSONObject(1).getString("name"));
    }

    @Test
    public void decodeServerColMetadata() throws Exception {
        Path bin = LOCAL_SAMPLES.resolve("server_response_1_request_body.bin");
        assumeTrue(Files.exists(bin), "sample body missing");
        byte[] body = Files.readAllBytes(bin);
        TdsHelper helper = new TdsHelper();
        JSONObject pkt = helper.unpack(body).getJSONObject(0);
        assertEquals("TABULAR_RESULT", pkt.getString("typeName"));
        assertTrue(pkt.has("columns"));
        JSONArray cols = pkt.getJSONArray("columns");
        assertEquals(56, cols.length());
        assertEquals("AlignFormGrid", cols.getJSONObject(0).getString("name"));
        JSONArray tokens = pkt.getJSONArray("tokens");
        boolean sawTab = false;
        boolean sawDone = false;
        for (int i = 0; i < tokens.length(); i++) {
            String name = tokens.getJSONObject(i).optString("name");
            if ("TABNAME".equals(name)) {
                sawTab = true;
            }
            if ("DONEINPROC".equals(name) || "DONEPROC".equals(name) || "DONE".equals(name)) {
                sawDone = true;
            }
        }
        assertTrue(sawTab, "expected TABNAME token");
        assertTrue(sawDone, "expected DONE* token");
    }

    @Test
    public void roundTripCursorOption() throws Exception {
        byte[] body = loadBody("other_client_requests_1_request_body.bin");
        TdsHelper helper = new TdsHelper();
        byte[] rebuilt = helper.pack(helper.unpack(body));
        assertArrayEquals(body, rebuilt);
    }

    @Test
    public void formatSqlForDisplayHidesBinaryRuns() {
        // Printable SQL with a binary concurrency blob in the middle (as Dynamics often embeds)
        String raw = "update t set v=v where b='" + "\u0001\u0002\u0003\u0004" + "' and x=1";
        String shown = TdsHelper.formatSqlForDisplay(raw);
        assertTrue(shown.startsWith("update t set v=v where b='"), shown);
        assertTrue(shown.contains("<bin "), shown);
        assertTrue(shown.contains("0x"), shown);
        assertTrue(shown.endsWith("' and x=1") || shown.contains("and x=1"), shown);
        assertFalse(shown.contains("\u0001"), shown);
    }

    @Test
    public void decodeDoneWith8ByteRowCount() {
        // TABULAR (type 4): DONE token FD, status=0x10 COUNT, curcmd=0xC1, rowCount=5 as ULONGLONG
        byte[] body = new byte[]{
                0x04, 0x01, 0x00, 0x15, 0x00, 0x00, 0x01, 0x00, // header length=21
                (byte) 0xFD, // DONE
                0x10, 0x00, // status COUNT
                (byte) 0xC1, 0x00, // curcmd
                0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // rowCount=5 (8 bytes)
        };
        TdsHelper helper = new TdsHelper();
        JSONObject pkt = helper.unpack(body).getJSONObject(0);
        JSONArray tokens = pkt.getJSONArray("tokens");
        assertEquals(1, tokens.length());
        JSONObject done = tokens.getJSONObject(0);
        assertEquals("DONE", done.getString("name"));
        assertEquals(5L, done.getLong("rowCount"));
        assertEquals(8, done.getInt("rowCountWidth"));
    }

    /**
     * Multi-packet TABULAR: COLMETADATA in PDU1 (no EOM), ROW+DONE in PDU2 (EOM).
     * Must merge payloads so the row is decoded with column metadata.
     */
    @Test
    public void multiPacketTabularMergesColMetadataWithRow() {
        // COLMETADATA: 1 column, UserType ULONG=0, flags=0, INT4 (0x38), name "id" (B_VARCHAR)
        // name: len=2, 'i'=0x69 0x00, 'd'=0x64 0x00
        byte[] colMeta = new byte[]{
                (byte) 0x81, // COLMETADATA
                0x01, 0x00, // count=1
                0x00, 0x00, 0x00, 0x00, // userType
                0x00, 0x00, // flags
                0x38, // INT4
                0x02, // name length 2 chars
                0x69, 0x00, 0x64, 0x00 // "id"
        };
        byte[] rowAndDone = new byte[]{
                (byte) 0xD1, // ROW
                0x2A, 0x00, 0x00, 0x00, // value 42
                (byte) 0xFD, // DONE
                0x10, 0x00, // COUNT
                0x00, 0x00, // curcmd
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // rowCount=1
        };
        byte[] p1 = tdsPacket((byte) 0x04, (byte) 0x00, colMeta, 1); // no EOM
        byte[] p2 = tdsPacket((byte) 0x04, (byte) 0x01, rowAndDone, 2); // EOM
        byte[] body = new byte[p1.length + p2.length];
        System.arraycopy(p1, 0, body, 0, p1.length);
        System.arraycopy(p2, 0, body, p1.length, p2.length);

        TdsHelper helper = new TdsHelper();
        JSONArray packets = helper.unpack(body);
        assertEquals(1, packets.length(), "multi-packet message should unpack as one logical packet");
        JSONObject pkt = packets.getJSONObject(0);
        assertEquals(2, pkt.getInt("mergedPackets"));
        assertTrue(pkt.has("columns"));
        assertEquals(1, pkt.getJSONArray("columns").length());
        assertEquals("id", pkt.getJSONArray("columns").getJSONObject(0).getString("name"));
        assertTrue(pkt.has("rows"));
        assertEquals(1, pkt.getJSONArray("rows").length());
        JSONObject values = pkt.getJSONArray("rows").getJSONObject(0).getJSONObject("values");
        assertEquals(42, values.getInt("id"));

        // Simple view must show the row, not "(no rows)"
        org.json.JSONObject meta = new org.json.JSONObject();
        meta.put("direction", "SERVER_RESPONSE");
        String simple = TdsSimpleView.format(body, meta, true);
        assertFalse(simple.contains("(no rows)"), simple);
        assertTrue(simple.contains("id") || simple.contains("42"), simple);
    }

    private static byte[] tdsPacket(byte type, byte status, byte[] payload, int packetId) {
        int len = 8 + payload.length;
        byte[] p = new byte[len];
        p[0] = type;
        p[1] = status;
        p[2] = (byte) ((len >> 8) & 0xFF);
        p[3] = (byte) (len & 0xFF);
        p[4] = 0;
        p[5] = 0;
        p[6] = (byte) packetId;
        p[7] = 0;
        System.arraycopy(payload, 0, p, 8, payload.length);
        return p;
    }

    @Test
    public void decodeDoneWith4ByteRowCountWhenOnlyFourRemain() {
        byte[] body = new byte[]{
                0x04, 0x01, 0x00, 0x11, 0x00, 0x00, 0x01, 0x00, // length=17
                (byte) 0xFD,
                0x10, 0x00,
                (byte) 0xC1, 0x00,
                0x03, 0x00, 0x00, 0x00 // rowCount=3 (4 bytes only)
        };
        TdsHelper helper = new TdsHelper();
        JSONObject done = helper.unpack(body).getJSONObject(0).getJSONArray("tokens").getJSONObject(0);
        assertEquals(3L, done.getLong("rowCount"));
        assertEquals(4, done.getInt("rowCountWidth"));
    }

    @Test
    public void analyzePduFramingDetectsIncompleteAndPreferComplete() {
        byte[] full = new byte[]{
                0x03, 0x01, 0x00, 0x0A, 0, 0, 1, 0, 0x01, 0x02
        };
        TdsHelper.PduFraming ok = TdsHelper.analyzePduFraming(full);
        assertTrue(ok.isFullyComplete());
        assertEquals(1, ok.completePacketCount);
        assertFalse(ok.hasWarning());

        byte[] incomplete = new byte[6];
        System.arraycopy(full, 0, incomplete, 0, 6);
        // fix length field to claim 10 bytes
        incomplete[2] = 0x00;
        incomplete[3] = 0x0A;
        TdsHelper.PduFraming bad = TdsHelper.analyzePduFraming(incomplete);
        assertTrue(bad.startsLikeTds);
        assertTrue(bad.hasWarning());
        assertEquals(0, bad.completePacketCount);

        byte[] twoAndPartial = new byte[full.length + 4];
        System.arraycopy(full, 0, twoAndPartial, 0, full.length);
        twoAndPartial[full.length] = 0x03;
        twoAndPartial[full.length + 1] = 0x01;
        twoAndPartial[full.length + 2] = 0x00;
        twoAndPartial[full.length + 3] = 0x0C; // claims 12, only 4 bytes present
        TdsHelper.PduFraming partial = TdsHelper.analyzePduFraming(twoAndPartial);
        assertEquals(1, partial.completePacketCount);
        assertEquals(full.length, partial.completeBytes);
        assertTrue(partial.hasWarning());
        byte[] preferred = TdsHelper.preferCompletePdus(twoAndPartial);
        assertArrayEquals(full, preferred);
    }

    private static void assumeTrue(boolean cond, String msg) {
        org.junit.jupiter.api.Assumptions.assumeTrue(cond, msg);
    }

    /** Load sanitized fixture from local samples/*.bin only. */
    private static byte[] loadBody(String localBinName) throws Exception {
        Path bin = LOCAL_SAMPLES.resolve(localBinName);
        assumeTrue(Files.exists(bin), "missing sample: " + bin);
        return Files.readAllBytes(bin);
    }
}
