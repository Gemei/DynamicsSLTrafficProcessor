package com.bdocyber.relay;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class TdsPacketBufferTest {

    @Test
    public void reassemblesSplitTdsPacket() {
        // type=3 status=1 length=12 (8 header + 4 payload)
        byte[] packet = new byte[]{
                0x03, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x00,
                0x11, 0x22, 0x33, 0x44
        };
        TdsPacketBuffer buf = new TdsPacketBuffer();
        buf.append(packet, 0, 5);
        assertTrue(buf.drainPackets().isEmpty());
        buf.append(packet, 5, packet.length - 5);
        List<byte[]> out = buf.drainPackets();
        assertEquals(1, out.size());
        assertArrayEquals(packet, out.get(0));
    }

    @Test
    public void drainsTwoPackets() {
        byte[] p1 = new byte[]{0x03, 0x01, 0x00, 0x0A, 0, 0, 1, 0, 0x01, 0x02};
        byte[] p2 = new byte[]{0x04, 0x01, 0x00, 0x09, 0, 0, 1, 0, 0x03};
        TdsPacketBuffer buf = new TdsPacketBuffer();
        byte[] both = new byte[p1.length + p2.length];
        System.arraycopy(p1, 0, both, 0, p1.length);
        System.arraycopy(p2, 0, both, p1.length, p2.length);
        buf.append(both);
        List<byte[]> out = buf.drainPackets();
        assertEquals(2, out.size());
        assertArrayEquals(p1, out.get(0));
        assertArrayEquals(p2, out.get(1));
    }
}
