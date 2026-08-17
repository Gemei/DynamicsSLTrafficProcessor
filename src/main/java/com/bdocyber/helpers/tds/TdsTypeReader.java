package com.bdocyber.helpers.tds;

import com.bdocyber.helpers.TdsHelper;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/**
 * TYPE_INFO + value decoding for MS-TDS (COLMETADATA, ROW, RPC params, RETURNVALUE).
 * Covers fixed, variable, PLP (partially length-prefixed), temporal, numeric types.
 */
public final class TdsTypeReader {

    private TdsTypeReader() {
    }

    public static boolean isFixed(int type) {
        return type == 0x30 || type == 0x32 || type == 0x34 || type == 0x38
                || type == 0x3A || type == 0x3B || type == 0x3C || type == 0x3D
                || type == 0x3E || type == 0x7A || type == 0x7F || type == 0x28;
    }

    /** True if this is a recognized TYPE_INFO type byte (not a desync artifact). */
    public static boolean isKnownSqlType(int type) {
        if (isFixed(type)) {
            return true;
        }
        return type == 0x22 || type == 0x23 || type == 0x24 || type == 0x25 || type == 0x26
                || type == 0x27 || type == 0x29 || type == 0x2A || type == 0x2B || type == 0x2D
                || type == 0x2E || type == 0x2F || type == 0x63 || type == 0x68 || type == 0x6A
                || type == 0x6C || type == 0x6D || type == 0x6E || type == 0x6F || type == 0xA5
                || type == 0xA7 || type == 0xAD || type == 0xAF || type == 0xE1 || type == 0xE7
                || type == 0xEF || type == 0xF0 || type == 0xF1;
    }

    /** TEXT / NTEXT / IMAGE require TableName after TYPE_INFO in COLMETADATA. */
    public static boolean needsTableName(int type) {
        return type == 0x22 || type == 0x23 || type == 0x63;
    }

    public static int fixedSize(int type) {
        return switch (type) {
            case 0x30, 0x32 -> 1;
            case 0x34 -> 2;
            case 0x38, 0x3A, 0x3B, 0x7A -> 4;
            case 0x28 -> 3; // DATE
            case 0x3C, 0x3D, 0x3E, 0x7F -> 8;
            default -> 0;
        };
    }

    public static String typeName(int type) {
        if (isFixed(type)) {
            return switch (type) {
                case 0x30 -> "INT1";
                case 0x32 -> "BIT";
                case 0x34 -> "INT2";
                case 0x38 -> "INT4";
                case 0x7F -> "INT8";
                case 0x3A -> "DATETIM4";
                case 0x3B -> "FLT4";
                case 0x3C -> "MONEY";
                case 0x3D -> "DATETIME";
                case 0x3E -> "FLT8";
                case 0x7A -> "MONEY4";
                case 0x28 -> "DATE";
                default -> "FIXED_0x" + Integer.toHexString(type);
            };
        }
        return switch (type) {
            case 0x22 -> "IMAGE";
            case 0x23 -> "TEXT";
            case 0x24 -> "GUID";
            case 0x25 -> "VARBINARY";
            case 0x26 -> "INTN";
            case 0x27 -> "VARCHAR";
            case 0x2D -> "BINARY";
            case 0x2F -> "CHAR";
            case 0x63 -> "NTEXT";
            case 0x68 -> "BITN";
            case 0x6A -> "DECIMALN";
            case 0x6C -> "MONEYN";
            case 0x6D -> "FLTN";
            case 0x6E -> "NUMERICN";
            case 0x6F -> "DATETIMN";
            case 0xA5 -> "BIGVARBIN";
            case 0xA7 -> "BIGVARCHAR";
            case 0xAD -> "BIGBINARY";
            case 0xAF -> "BIGCHAR";
            case 0xE1 -> "XML";
            case 0xE7 -> "NVARCHAR";
            case 0xEF -> "NCHAR";
            case 0xF0 -> "UDT";
            case 0xF1 -> "SSVARIANT";
            case 0x29 -> "TIME";
            case 0x2A -> "DATETIME2";
            case 0x2B -> "DATETIMEOFFSET";
            case 0x2E -> "TIMEN"; // legacy
            default -> "TYPE_0x" + Integer.toHexString(type);
        };
    }

    /** Parse TYPE_INFO after the type byte has already been consumed; updates meta and returns new pos. */
    public static int parseTypeInfo(byte[] payload, int pos, int type, JSONObject meta) {
        TdsCursor c = new TdsCursor(payload, pos);
        meta.put("type", type);
        meta.put("typeHex", String.format("0x%02X", type));
        meta.put("sqlType", typeName(type));
        if (isFixed(type)) {
            meta.put("fixedSize", fixedSize(type));
            return c.pos();
        }
        switch (type) {
            case 0xE7, 0xEF, 0xA7, 0xAF -> { // big char types
                int maxLen = c.u16();
                meta.put("maxLen", maxLen);
                if (maxLen == 0xFFFF) {
                    meta.put("plp", true); // LOB / max
                }
                meta.put("collationHex", c.hex(5));
            }
            case 0xA5, 0xAD -> {
                int maxLen = c.u16();
                meta.put("maxLen", maxLen);
                if (maxLen == 0xFFFF) {
                    meta.put("plp", true);
                }
            }
            case 0xE1 -> { // XML — schema present flag + optional schema
                int schema = c.u8();
                meta.put("xmlSchemaPresent", schema);
                if (schema == 1) {
                    // DbName B_VARCHAR, OwningSchema B_VARCHAR, XmlSchemaCollection US_VARCHAR
                    meta.put("xmlDb", c.bVarchar());
                    meta.put("xmlSchema", c.bVarchar());
                    meta.put("xmlCollection", c.usVarchar());
                }
                meta.put("plp", true);
            }
            case 0xF0 -> { // UDT
                // USHORT maxLen, then DB name, schema, type name (B_VARCHAR each)
                meta.put("maxLen", c.u16());
                meta.put("udtDb", c.bVarchar());
                meta.put("udtSchema", c.bVarchar());
                meta.put("udtType", c.bVarchar());
                meta.put("plp", true);
            }
            case 0x26, 0x68, 0x6D, 0x6F, 0x6C, 0x24 -> meta.put("maxLen", c.u8());
            case 0x6A, 0x6E -> {
                meta.put("maxLen", c.u8());
                meta.put("precision", c.u8());
                meta.put("scale", c.u8());
            }
            case 0x29, 0x2A, 0x2B -> meta.put("scale", c.u8());
            case 0x23, 0x63, 0x22 -> { // TEXT / NTEXT / IMAGE
                meta.put("maxLen", c.u32u());
                if (type != 0x22) {
                    meta.put("collationHex", c.hex(5));
                }
                // TableName (NumParts + US_VARCHAR*) is after TYPE_INFO in ColMetaData — see TdsTokenStream
            }
            case 0xF1 -> { // SSVARIANT — max 8009
                meta.put("maxLen", c.u32());
            }
            case 0x25, 0x27, 0x2D, 0x2F -> { // legacy small types
                meta.put("maxLen", c.u8());
                if (type == 0x27 || type == 0x2F) {
                    meta.put("collationHex", c.hex(5));
                }
            }
            default -> {
                // best effort: leave remaining for value reader
                meta.put("typeInfoNote", "minimal TYPE_INFO for 0x" + Integer.toHexString(type));
            }
        }
        return c.pos();
    }

    /**
     * Read value for ROW / RETURNVALUE after TYPE_INFO is in col.
     * @return Object[]{newPos, value} value may be null for NULL
     */
    public static Object[] readValue(byte[] payload, int pos, JSONObject col) {
        int type = col.getInt("type");
        TdsCursor c = new TdsCursor(payload, pos);
        try {
            if (isFixed(type)) {
                int size = fixedSize(type);
                if (!c.has(size)) {
                    return new Object[]{c.pos(), null};
                }
                Object v = decodeFixed(type, c);
                return new Object[]{c.pos(), v};
            }
            if (col.optBoolean("plp", false) || type == 0xE1 || type == 0xF0
                    || (col.optInt("maxLen") == 0xFFFF && (type == 0xE7 || type == 0xA7 || type == 0xA5))) {
                return readPlp(c, type);
            }
            switch (type) {
                case 0xE7, 0xEF -> {
                    int byteLen = c.u16();
                    if (byteLen == 0xFFFF) {
                        return new Object[]{c.pos(), null};
                    }
                    String s = new String(payload, c.pos(), byteLen, StandardCharsets.UTF_16LE);
                    c.skip(byteLen);
                    return new Object[]{c.pos(), s};
                }
                case 0xA7, 0xAF, 0x27, 0x2F -> {
                    int byteLen = type == 0x27 || type == 0x2F ? c.u8() : c.u16();
                    if (byteLen == 0xFF || byteLen == 0xFFFF) {
                        return new Object[]{c.pos(), null};
                    }
                    String s = new String(payload, c.pos(), byteLen, StandardCharsets.ISO_8859_1);
                    c.skip(byteLen);
                    return new Object[]{c.pos(), s};
                }
                case 0xA5, 0xAD, 0x25, 0x2D -> {
                    int byteLen = (type == 0x25 || type == 0x2D) ? c.u8() : c.u16();
                    if (byteLen == 0xFF || byteLen == 0xFFFF) {
                        return new Object[]{c.pos(), null};
                    }
                    return new Object[]{c.pos() + byteLen, c.hex(byteLen)};
                }
                case 0x26, 0x68, 0x24, 0x6D, 0x6F, 0x6C, 0x6A, 0x6E -> {
                    int actual = c.u8();
                    if (actual == 0) {
                        return new Object[]{c.pos(), null};
                    }
                    if (type == 0x26) {
                        return new Object[]{c.pos() + actual, readSignedLe(payload, c.pos(), actual)};
                    }
                    if (type == 0x68) {
                        int b = c.u8();
                        return new Object[]{c.pos(), b};
                    }
                    if (type == 0x24 && actual == 16) {
                        return new Object[]{c.pos() + 16, formatGuid(c.bytes(16))};
                    }
                    return new Object[]{c.pos() + actual, c.hex(actual)};
                }
                case 0x29, 0x2A, 0x2B, 0x28 -> {
                    // scale-dependent size
                    int scale = col.optInt("scale", 0);
                    int size = temporalSize(type, scale);
                    if (!c.has(size)) {
                        return new Object[]{c.pos(), null};
                    }
                    return new Object[]{c.pos() + size, c.hex(size)};
                }
                case 0x23, 0x63, 0x22 -> {
                    // TEXT/NTEXT/IMAGE often: textptr 16 + timestamp 8 + data len + data
                    if (c.remaining() >= 24) {
                        int tplen = c.u8();
                        if (tplen == 0) {
                            return new Object[]{c.pos(), null};
                        }
                        c.skip(tplen); // textptr
                        c.skip(8); // timestamp
                        int dlen = c.u32();
                        if (type == 0x63) {
                            String s = new String(payload, c.pos(), dlen, StandardCharsets.UTF_16LE);
                            c.skip(dlen);
                            return new Object[]{c.pos(), s};
                        }
                        if (type == 0x23) {
                            String s = new String(payload, c.pos(), dlen, StandardCharsets.ISO_8859_1);
                            c.skip(dlen);
                            return new Object[]{c.pos(), s};
                        }
                        return new Object[]{c.pos() + dlen, c.hex(dlen)};
                    }
                    return new Object[]{c.pos(), null};
                }
                default -> {
                    // unknown: try USHORT length-prefixed
                    if (c.has(2)) {
                        int n = c.u16();
                        if (n == 0xFFFF) {
                            return new Object[]{c.pos(), null};
                        }
                        if (c.has(n)) {
                            return new Object[]{c.pos() + n, c.hex(n)};
                        }
                    }
                    throw new IllegalStateException("ROW value unparsed type 0x" + Integer.toHexString(type));
                }
            }
        } catch (Exception e) {
            throw e instanceof RuntimeException re ? re : new IllegalStateException(e);
        }
    }

    /** Partially Length-Prefixed (PLP) streams for MAX / XML / UDT. */
    private static Object[] readPlp(TdsCursor c, int type) {
        if (!c.has(8)) {
            return new Object[]{c.pos(), null};
        }
        long total = c.i64();
        // PLP_NULL
        if (total == -1L || total == 0xFFFFFFFFFFFFFFFFL) {
            return new Object[]{c.pos(), null};
        }
        // chunks until ULONG 0
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        while (c.has(4)) {
            long chunkLen = c.u32u();
            if (chunkLen == 0) {
                break;
            }
            if (!c.has((int) chunkLen)) {
                break;
            }
            try {
                bos.write(c.bytes((int) chunkLen));
            } catch (Exception ignored) {
                break;
            }
        }
        byte[] all = bos.toByteArray();
        if (type == 0xE7 || type == 0xEF || type == 0xE1 || type == 0x63) {
            return new Object[]{c.pos(), new String(all, StandardCharsets.UTF_16LE)};
        }
        if (type == 0xA7 || type == 0xAF || type == 0x23) {
            return new Object[]{c.pos(), new String(all, StandardCharsets.ISO_8859_1)};
        }
        return new Object[]{c.pos(), TdsHelper.toHex(all)};
    }

    private static int temporalSize(int type, int scale) {
        // rough sizes per MS-TDS
        int scaleBytes = scale <= 2 ? 3 : (scale <= 4 ? 4 : 5);
        return switch (type) {
            case 0x28 -> 3; // DATE
            case 0x29 -> scaleBytes; // TIME
            case 0x2A -> scaleBytes + 3; // DATETIME2
            case 0x2B -> scaleBytes + 5; // DATETIMEOFFSET
            default -> scaleBytes;
        };
    }

    private static Object decodeFixed(int type, TdsCursor c) {
        return switch (type) {
            case 0x30 -> c.u8();
            case 0x32 -> c.u8() != 0;
            case 0x34 -> (short) c.u16();
            case 0x38 -> c.u32();
            case 0x7F -> c.i64();
            case 0x3B -> Float.intBitsToFloat(c.u32());
            case 0x3E -> Double.longBitsToDouble(c.i64());
            default -> c.hex(fixedSize(type));
        };
    }

    private static Object readSignedLe(byte[] b, int off, int len) {
        long v = 0;
        for (int i = 0; i < len; i++) {
            v |= (long) (b[off + i] & 0xFF) << (8 * i);
        }
        // sign extend
        int shift = (8 - len) * 8;
        if (len < 8) {
            v = (v << shift) >> shift;
        }
        if (len <= 4) {
            return (int) v;
        }
        return v;
    }

    private static String formatGuid(byte[] g) {
        if (g.length < 16) {
            return TdsHelper.toHex(g);
        }
        // SQL Server GUID wire order
        return String.format("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
                g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
    }
}
