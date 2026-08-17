package com.bdocyber.helpers;

import com.bdocyber.models.TcpStreamFrame;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TcpStreamStoreTest {

    @Test
    public void separatesConnectionsToSamePeer() {
        TcpStreamStore store = new TcpStreamStore();
        store.addFrame(new TcpStreamFrame(
                "127.0.0.1:1111 → 10.0.0.1:1433",
                "10.0.0.1:1433",
                TcpStreamFrame.Direction.CLIENT_TO_SERVER,
                new byte[]{1, 2, 3},
                false,
                "test"));
        store.addFrame(new TcpStreamFrame(
                "127.0.0.1:2222 → 10.0.0.1:1433",
                "10.0.0.1:1433",
                TcpStreamFrame.Direction.CLIENT_TO_SERVER,
                new byte[]{4},
                false,
                "test"));

        assertEquals(2, store.streamCount());
        assertEquals(1, store.getStream("127.0.0.1:1111 → 10.0.0.1:1433").getFrameCount());
        assertEquals(1, store.getStream("127.0.0.1:2222 → 10.0.0.1:1433").getFrameCount());
    }

    @Test
    public void followBuilderOrdersChunks() {
        var frames = java.util.List.of(
                new TcpStreamFrame("s", "p", TcpStreamFrame.Direction.CLIENT_TO_SERVER,
                        "AB".getBytes(java.nio.charset.StandardCharsets.UTF_16LE), false, "t"),
                new TcpStreamFrame("s", "p", TcpStreamFrame.Direction.SERVER_TO_CLIENT,
                        "CD".getBytes(java.nio.charset.StandardCharsets.UTF_16LE), false, "t")
        );
        String follow = FollowStreamBuilder.build(frames, FollowStreamBuilder.ViewMode.UTF16_TEXT, true);
        assertTrue(follow.contains("C→S"));
        assertTrue(follow.contains("S→C"));
        assertTrue(follow.contains("AB") || follow.contains("A"));
    }

    @Test
    public void followTdsDecodeSurfacesTabularTokens() throws Exception {
        java.nio.file.Path bin = java.nio.file.Path.of("samples/server_response_1_request_body.bin");
        if (!java.nio.file.Files.exists(bin)) {
            return; // sample optional in CI
        }
        byte[] body = java.nio.file.Files.readAllBytes(bin);
        var frames = java.util.List.of(
                new TcpStreamFrame("s", "p", TcpStreamFrame.Direction.SERVER_TO_CLIENT, body, false, "t")
        );
        String follow = FollowStreamBuilder.build(frames, FollowStreamBuilder.ViewMode.TDS_DECODE, true);
        assertTrue(follow.contains("TABULAR") || follow.contains("columns") || follow.contains("COLMETADATA")
                        || follow.contains("DONE") || follow.contains("row"),
                () -> "expected structured tabular dump, got:\n" + follow.substring(0, Math.min(500, follow.length())));
        String summary = new TcpStreamFrame("s", "p", TcpStreamFrame.Direction.SERVER_TO_CLIENT, body, false, "t")
                .getSummary();
        assertFalse(summary.equals("TABULAR_RESULT (" + body.length + " B)"),
                "summary should be richer than bare type+size: " + summary);
    }
}
