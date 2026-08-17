package com.bdocyber.helpers;

import com.bdocyber.models.TcpStreamFrame;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class TdsMessageAssemblerTest {

    @Test
    public void assemblesMultiPduTabularForRowDecode() {
        // COLMETADATA in PDU1 (no EOM), ROW+DONE in PDU2 (EOM) — same as TdsHelperTest
        byte[] colMeta = new byte[]{
                (byte) 0x81, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
                0x38,
                0x02, 0x69, 0x00, 0x64, 0x00
        };
        byte[] rowAndDone = new byte[]{
                (byte) 0xD1, 0x2A, 0x00, 0x00, 0x00,
                (byte) 0xFD, 0x10, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        byte[] p1 = tdsPacket((byte) 0x04, (byte) 0x00, colMeta, 1);
        byte[] p2 = tdsPacket((byte) 0x04, (byte) 0x01, rowAndDone, 2);

        TcpStreamFrame f1 = TcpStreamFrame.restore(1, java.time.Instant.EPOCH, "c→s", "10.0.0.1:1433",
                TcpStreamFrame.Direction.SERVER_TO_CLIENT, p1, false, "test");
        TcpStreamFrame f2 = TcpStreamFrame.restore(2, java.time.Instant.EPOCH, "c→s", "10.0.0.1:1433",
                TcpStreamFrame.Direction.SERVER_TO_CLIENT, p2, false, "test");

        List<TcpStreamFrame> stream = List.of(f1, f2);

        byte[] merged = TdsMessageAssembler.assembleMessageContaining(stream, f2);
        assertEquals(p1.length + p2.length, merged.length);

        String simple = TdsSimpleView.format(merged, meta(), true);
        assertFalse(simple.contains("(no rows)"), simple);
        assertTrue(simple.contains("42"), simple);
        assertTrue(simple.contains("id"), simple);
        // table / vertical row formatting
        assertTrue(simple.contains("Row") || simple.contains("|"), simple);
    }

    @Test
    public void assembleAllGroupsMultiPduMessage() {
        byte[] colMeta = new byte[]{(byte) 0x81, (byte) 0xFF, (byte) 0xFF};
        byte[] done = new byte[]{
                (byte) 0xFD, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        byte[] p1 = tdsPacket((byte) 0x04, (byte) 0x00, colMeta, 1);
        byte[] p2 = tdsPacket((byte) 0x04, (byte) 0x01, done, 2);
        TcpStreamFrame f1 = TcpStreamFrame.restore(1, java.time.Instant.EPOCH, "k", "p",
                TcpStreamFrame.Direction.SERVER_TO_CLIENT, p1, false, "t");
        TcpStreamFrame f2 = TcpStreamFrame.restore(2, java.time.Instant.EPOCH, "k", "p",
                TcpStreamFrame.Direction.SERVER_TO_CLIENT, p2, false, "t");

        List<TdsMessageAssembler.AssembledMessage> msgs =
                TdsMessageAssembler.assembleAll(List.of(f1, f2));
        assertEquals(1, msgs.size());
        assertTrue(msgs.get(0).multiPacket);
        assertEquals(2, msgs.get(0).frames.size());
    }

    private static JSONObject meta() {
        JSONObject m = new JSONObject();
        m.put("direction", "SERVER_RESPONSE");
        return m;
    }

    private static byte[] tdsPacket(byte type, byte status, byte[] payload, int packetId) {
        int len = 8 + payload.length;
        byte[] p = new byte[len];
        p[0] = type;
        p[1] = status;
        p[2] = (byte) ((len >> 8) & 0xFF);
        p[3] = (byte) (len & 0xFF);
        p[6] = (byte) packetId;
        System.arraycopy(payload, 0, p, 8, payload.length);
        return p;
    }
}
