package com.bdocyber.helpers;

import com.bdocyber.models.TcpStreamFrame;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DslProjectPersistenceCompressTest {

    @Test
    void compressForStorage_roundTripsUtf8() {
        String plain = "{\"hello\":\"world\",\"n\":42}";
        String stored = DslProjectPersistence.compressForStorage(plain);
        assertTrue(stored.startsWith(DslProjectPersistence.STORAGE_GZIP_PREFIX));
        assertEquals(plain, DslProjectPersistence.decompressFromStorage(stored));
    }

    @Test
    void decompressFromStorage_acceptsLegacyPlainJson() {
        String legacy = "{\"frames\":[]}";
        assertEquals(legacy, DslProjectPersistence.decompressFromStorage(legacy));
    }

    @Test
    void encodeStreams_usesCompressedEnvelopeAndBodiesGzip() {
        DslProjectPersistence.Snapshot snap = new DslProjectPersistence.Snapshot();
        byte[] sqlish = ("SELECT * FROM employees WHERE id = 1 -- "
                + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").repeat(20)
                .getBytes(StandardCharsets.UTF_16LE);
        snap.streamFrames.add(TcpStreamFrame.restore(
                10L, Instant.ofEpochMilli(1_700_000_000_000L),
                "10.0.0.1:50000↔10.0.0.2:1433", "10.0.0.2:1433",
                TcpStreamFrame.Direction.CLIENT_TO_SERVER, sqlish, false, "relay"));
        snap.streamFrames.add(TcpStreamFrame.restore(
                11L, Instant.ofEpochMilli(1_700_000_000_100L),
                "10.0.0.1:50000↔10.0.0.2:1433", "10.0.0.2:1433",
                TcpStreamFrame.Direction.SERVER_TO_CLIENT,
                "OK".repeat(200).getBytes(StandardCharsets.UTF_8), false, "relay"));
        snap.streamNames.put("10.0.0.1:50000↔10.0.0.2:1433", "finding-1");

        String stored = DslProjectPersistence.encodeStreams(snap);
        assertTrue(stored.startsWith(DslProjectPersistence.STORAGE_GZIP_PREFIX));
        assertFalse(stored.contains("\"frames\""), "outer envelope should hide plain JSON");

        DslProjectPersistence.Snapshot loaded = new DslProjectPersistence.Snapshot();
        DslProjectPersistence.decodeStreams(stored, loaded);
        assertEquals(2, loaded.streamFrames.size());
        assertEquals(10L, loaded.streamFrames.get(0).getSeq());
        assertEquals(11L, loaded.streamFrames.get(1).getSeq());
        assertArrayEquals(sqlish, loaded.streamFrames.get(0).bodyRef());
        assertArrayEquals(snap.streamFrames.get(1).bodyRef(), loaded.streamFrames.get(1).bodyRef());
        assertEquals("finding-1", loaded.streamNames.get("10.0.0.1:50000↔10.0.0.2:1433"));
        assertEquals(TcpStreamFrame.Direction.SERVER_TO_CLIENT, loaded.streamFrames.get(1).getDirection());
    }

    @Test
    void decodeStreams_readsLegacyPerFrameBase64() {
        String legacy = """
                {"frames":[{"seq":1,"ts":1000,"streamKey":"k","peer":"p","dir":"C2S","mod":false,"src":"t","b64":"aGVsbG8="}],"count":1}
                """;
        DslProjectPersistence.Snapshot snap = new DslProjectPersistence.Snapshot();
        DslProjectPersistence.decodeStreams(legacy, snap);
        assertEquals(1, snap.streamFrames.size());
        assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8), snap.streamFrames.get(0).bodyRef());
        assertEquals("k", snap.streamFrames.get(0).getStreamKey());
    }

    @Test
    void compressedPayload_isSmallerThanLegacyStyleBase64Json() {
        DslProjectPersistence.Snapshot snap = new DslProjectPersistence.Snapshot();
        byte[] body = ("TDS SQL batch payload with lots of repeated structure. ").repeat(80)
                .getBytes(StandardCharsets.UTF_16LE);
        for (int i = 0; i < 40; i++) {
            snap.streamFrames.add(TcpStreamFrame.restore(
                    i + 1L, Instant.ofEpochMilli(1_000L + i),
                    "client:1↔server:1433", "server:1433",
                    i % 2 == 0 ? TcpStreamFrame.Direction.CLIENT_TO_SERVER
                            : TcpStreamFrame.Direction.SERVER_TO_CLIENT,
                    body, false, "relay"));
        }
        String compressed = DslProjectPersistence.encodeStreams(snap);
        // Rough legacy size: JSON overhead + base64(body) per frame
        int legacyApprox = 0;
        for (TcpStreamFrame f : snap.streamFrames) {
            legacyApprox += 120 + ((f.getBodyLength() + 2) / 3) * 4;
        }
        assertTrue(compressed.length() < legacyApprox,
                "compressed=" + compressed.length() + " legacyApprox=" + legacyApprox);
        assertTrue(compressed.length() < legacyApprox / 2,
                "expected >2x savings on repetitive TDS-like capture; compressed="
                        + compressed.length() + " legacyApprox=" + legacyApprox);
    }

    @Test
    void unpackBodiesBlob_roundTrips() throws Exception {
        byte[] a = new byte[]{1, 2, 3};
        byte[] b = new byte[0];
        byte[] c = "xyz".getBytes(StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream dos = new java.io.DataOutputStream(bos);
        dos.writeInt(a.length);
        dos.write(a);
        dos.writeInt(b.length);
        dos.writeInt(c.length);
        dos.write(c);
        List<byte[]> out = DslProjectPersistence.unpackBodiesBlob(bos.toByteArray(), 3);
        assertEquals(3, out.size());
        assertArrayEquals(a, out.get(0));
        assertArrayEquals(b, out.get(1));
        assertArrayEquals(c, out.get(2));
    }
}
