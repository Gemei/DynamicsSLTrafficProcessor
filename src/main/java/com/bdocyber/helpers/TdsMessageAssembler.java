package com.bdocyber.helpers;

import com.bdocyber.helpers.tds.TdsSpec;
import com.bdocyber.models.TcpStreamFrame;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Reassembles multi-packet TDS <em>messages</em> from per-PDU capture frames.
 * <p>
 * SQL Server splits large tabular results across several Type=4 packets; only the last
 * has the EOM status bit. Capture stores each PDU as its own {@link TcpStreamFrame}.
 * Decoding a single non-EOM (or EOM-only tail) frame alone loses COLMETADATA ↔ ROW linkage.
 * This helper concatenates the wire bytes of every PDU in the same message.
 */
public final class TdsMessageAssembler {

    private TdsMessageAssembler() {
    }

    /**
     * Build the full TDS message wire buffer that contains {@code target}
     * (same direction, consecutive same-type PDUs until EOM).
     * Returns {@code target}'s body if assembly is not applicable.
     */
    public static byte[] assembleMessageContaining(List<TcpStreamFrame> streamFrames,
                                                   TcpStreamFrame target) {
        if (target == null) {
            return new byte[0];
        }
        byte[] targetBody = target.bodyRef();
        if (streamFrames == null || streamFrames.isEmpty() || targetBody == null
                || targetBody.length < DSLConstants.TDS_HEADER_LEN) {
            return target.getBody();
        }
        if (!isAssemblableTds(targetBody)) {
            return target.getBody();
        }

        int idx = indexOfFrame(streamFrames, target);
        if (idx < 0) {
            // not in list — still try single-body unpack
            return target.getBody();
        }

        int type = targetBody[0] & 0xFF;
        TcpStreamFrame.Direction dir = target.getDirection();

        // Walk backward: previous same-type PDUs without EOM are earlier parts of this message
        int start = idx;
        while (start > 0) {
            TcpStreamFrame prev = streamFrames.get(start - 1);
            if (prev.getDirection() != dir) {
                break;
            }
            byte[] pb = prev.bodyRef();
            if (!isAssemblableTds(pb) || (pb[0] & 0xFF) != type) {
                break;
            }
            // If the previous PDU has EOM, it closed the prior message
            if ((pb[1] & TdsSpec.STATUS_EOM) != 0) {
                break;
            }
            start--;
        }

        // Walk forward through non-EOM continuation packets
        int end = start;
        while (end < streamFrames.size()) {
            TcpStreamFrame f = streamFrames.get(end);
            if (f.getDirection() != dir) {
                break;
            }
            byte[] b = f.bodyRef();
            if (!isAssemblableTds(b) || (b[0] & 0xFF) != type) {
                break;
            }
            end++;
            if ((b[1] & TdsSpec.STATUS_EOM) != 0) {
                break;
            }
        }
        // Ensure target is included even if status bits are wrong
        if (end <= idx) {
            end = idx + 1;
        }
        if (start == idx && end == idx + 1) {
            return target.getBody();
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int i = start; i < end; i++) {
            byte[] b = streamFrames.get(i).getBody();
            if (b != null && b.length > 0) {
                try {
                    bos.write(b);
                } catch (Exception ignored) {
                }
            }
        }
        byte[] merged = bos.toByteArray();
        return merged.length > 0 ? merged : target.getBody();
    }

    /**
     * Group frames into message-sized wire buffers (for Follow Stream).
     * Each entry is one or more consecutive same-direction PDUs forming one TDS message
     * (or a non-TDS single frame).
     */
    public static List<AssembledMessage> assembleAll(List<TcpStreamFrame> frames) {
        List<AssembledMessage> out = new ArrayList<>();
        if (frames == null || frames.isEmpty()) {
            return out;
        }
        int i = 0;
        while (i < frames.size()) {
            TcpStreamFrame f = frames.get(i);
            byte[] body = f.bodyRef();
            if (!isAssemblableTds(body)) {
                out.add(new AssembledMessage(List.of(f), f.getBody(), f.getDirection(), false));
                i++;
                continue;
            }
            int type = body[0] & 0xFF;
            TcpStreamFrame.Direction dir = f.getDirection();
            int start = i;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            List<TcpStreamFrame> group = new ArrayList<>();
            while (i < frames.size()) {
                TcpStreamFrame cur = frames.get(i);
                if (cur.getDirection() != dir) {
                    break;
                }
                byte[] b = cur.bodyRef();
                if (!isAssemblableTds(b) || (b[0] & 0xFF) != type) {
                    break;
                }
                group.add(cur);
                try {
                    bos.write(cur.getBody());
                } catch (Exception ignored) {
                }
                i++;
                if ((b[1] & TdsSpec.STATUS_EOM) != 0) {
                    break;
                }
            }
            boolean multi = group.size() > 1;
            out.add(new AssembledMessage(group, bos.toByteArray(), dir, multi));
            if (i == start) {
                i++; // safety
            }
        }
        return out;
    }

    public static boolean isAssemblableTds(byte[] body) {
        if (body == null || body.length < DSLConstants.TDS_HEADER_LEN) {
            return false;
        }
        int type = body[0] & 0xFF;
        int length = ((body[2] & 0xFF) << 8) | (body[3] & 0xFF);
        if (length < DSLConstants.TDS_HEADER_LEN || length > body.length) {
            // allow truncated single buffer for best-effort
            if (length < DSLConstants.TDS_HEADER_LEN) {
                return false;
            }
        }
        // Messages that commonly span multiple PDUs
        return type == TdsSpec.PKT_TABULAR || type == TdsSpec.PKT_BULK
                || type == TdsSpec.PKT_RPC || type == TdsSpec.PKT_SQL_BATCH
                || type == TdsSpec.PKT_LOGIN7 || type == TdsSpec.PKT_SSPI;
    }

    private static int indexOfFrame(List<TcpStreamFrame> frames, TcpStreamFrame target) {
        for (int i = 0; i < frames.size(); i++) {
            TcpStreamFrame f = frames.get(i);
            if (f == target) {
                return i;
            }
            if (f.getSeq() == target.getSeq()
                    && f.getStreamKey() != null
                    && f.getStreamKey().equals(target.getStreamKey())) {
                return i;
            }
        }
        return -1;
    }

    public static final class AssembledMessage {
        public final List<TcpStreamFrame> frames;
        public final byte[] wire;
        public final TcpStreamFrame.Direction direction;
        public final boolean multiPacket;

        public AssembledMessage(List<TcpStreamFrame> frames, byte[] wire,
                                TcpStreamFrame.Direction direction, boolean multiPacket) {
            this.frames = frames;
            this.wire = wire != null ? wire : new byte[0];
            this.direction = direction;
            this.multiPacket = multiPacket;
        }

        public long firstSeq() {
            return frames.isEmpty() ? 0 : frames.get(0).getSeq();
        }

        public long lastSeq() {
            return frames.isEmpty() ? 0 : frames.get(frames.size() - 1).getSeq();
        }

        public int totalBytes() {
            return wire.length;
        }
    }
}
