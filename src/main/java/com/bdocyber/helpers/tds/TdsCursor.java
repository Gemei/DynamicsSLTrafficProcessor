package com.bdocyber.helpers.tds;

import com.bdocyber.helpers.ArraySliceHelper;
import com.bdocyber.helpers.TdsHelper;

import java.nio.charset.StandardCharsets;

/** Little-endian cursor over a TDS payload. */
public final class TdsCursor {
    private final byte[] data;
    private int pos;

    public TdsCursor(byte[] data) {
        this(data, 0);
    }

    public TdsCursor(byte[] data, int pos) {
        this.data = data != null ? data : new byte[0];
        this.pos = Math.max(0, pos);
    }

    public int pos() {
        return pos;
    }

    public void setPos(int p) {
        this.pos = p;
    }

    public int remaining() {
        return data.length - pos;
    }

    public boolean has(int n) {
        return pos + n <= data.length;
    }

    public int length() {
        return data.length;
    }

    public byte[] data() {
        return data;
    }

    public int u8() {
        return data[pos++] & 0xFF;
    }

    public int u16() {
        int v = (data[pos] & 0xFF) | ((data[pos + 1] & 0xFF) << 8);
        pos += 2;
        return v;
    }

    public int u32() {
        int v = (data[pos] & 0xFF)
                | ((data[pos + 1] & 0xFF) << 8)
                | ((data[pos + 2] & 0xFF) << 16)
                | ((data[pos + 3] & 0xFF) << 24);
        pos += 4;
        return v;
    }

    public long u32u() {
        return u32() & 0xFFFFFFFFL;
    }

    public long i64() {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v |= (long) (data[pos + i] & 0xFF) << (8 * i);
        }
        pos += 8;
        return v;
    }

    public byte[] bytes(int n) {
        byte[] b = ArraySliceHelper.getArraySlice(data, pos, pos + n);
        pos += n;
        return b;
    }

    public String utf16(int chars) {
        if (chars <= 0) {
            return "";
        }
        String s = new String(data, pos, chars * 2, StandardCharsets.UTF_16LE);
        pos += chars * 2;
        return s;
    }

    public String bVarchar() {
        int n = u8();
        return utf16(n);
    }

    public String usVarchar() {
        int n = u16();
        return utf16(n);
    }

    public String hex(int n) {
        return TdsHelper.toHex(bytes(n));
    }

    public void skip(int n) {
        pos += n;
    }

    public int peekU8() {
        return data[pos] & 0xFF;
    }
}
