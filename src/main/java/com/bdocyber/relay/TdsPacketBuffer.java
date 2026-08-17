package com.bdocyber.relay;

import com.bdocyber.helpers.DSLConstants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Accumulates TCP bytes and emits complete TDS packets when framing is clear.
 * Unknown/non-TDS data is forwarded immediately (no multi-KB hold).
 */
public class TdsPacketBuffer {

    private static final int MAX_BUFFER = 16 * 1024 * 1024;
    private static final int MAX_TDS_PACKET = 4 * 1024 * 1024;

    private byte[] buf = new byte[64 * 1024];
    private int size;

    public synchronized void append(byte[] data, int off, int len) {
        if (data == null || len <= 0) {
            return;
        }
        ensureCapacity(size + len);
        System.arraycopy(data, off, buf, size, len);
        size += len;
        if (size > MAX_BUFFER) {
            throw new IllegalStateException("TDS buffer exceeded " + MAX_BUFFER + " bytes");
        }
    }

    public synchronized void append(byte[] data) {
        if (data != null) {
            append(data, 0, data.length);
        }
    }

    /**
     * Drain complete TDS packets and/or raw chunks that should be forwarded now.
     */
    public synchronized List<byte[]> drainPackets() {
        List<byte[]> out = new ArrayList<>();
        int pos = 0;

        while (pos < size) {
            int remaining = size - pos;
            if (remaining < DSLConstants.TDS_HEADER_LEN) {
                break;
            }

            int type = buf[pos] & 0xFF;
            int length = ((buf[pos + 2] & 0xFF) << 8) | (buf[pos + 3] & 0xFF);

            if (isPlausibleTds(type, length)) {
                if (remaining < length) {
                    // wait for rest of packet
                    break;
                }
                out.add(copy(buf, pos, length));
                pos += length;
                continue;
            }

            // Not valid TDS at this offset: forward everything we have immediately
            // (partial garbage, etc.) — never stall the app waiting for 4KB.
            out.add(copy(buf, pos, remaining));
            pos = size;
            break;
        }

        if (pos > 0) {
            int left = size - pos;
            if (left > 0) {
                System.arraycopy(buf, pos, buf, 0, left);
            }
            size = left;
        }
        return out;
    }

    public synchronized List<byte[]> flushRemainder() {
        List<byte[]> out = drainPackets();
        if (size > 0) {
            out.add(copy(buf, 0, size));
            size = 0;
        }
        return out;
    }

    public synchronized int size() {
        return size;
    }

    private void ensureCapacity(int need) {
        if (need <= buf.length) {
            return;
        }
        int n = buf.length;
        while (n < need) {
            n *= 2;
        }
        buf = Arrays.copyOf(buf, n);
    }

    private static boolean isPlausibleTds(int type, int length) {
        if (length < DSLConstants.TDS_HEADER_LEN || length > MAX_TDS_PACKET) {
            return false;
        }
        // Common TDS packet types (incl. prelogin/login/sspi)
        return type == 1 || type == 2 || type == 3 || type == 4 || type == 6
                || type == 7 || type == 14 || type == 16 || type == 17 || type == 18;
    }

    private static byte[] copy(byte[] src, int off, int len) {
        byte[] b = new byte[len];
        System.arraycopy(src, off, b, 0, len);
        return b;
    }
}
