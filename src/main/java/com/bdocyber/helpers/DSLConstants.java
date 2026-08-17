package com.bdocyber.helpers;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Constants for Dynamics SL / TDS traffic processor (built-in TCP relay).
 */
public final class DSLConstants {
    public static final String EXTENSION_NAME = "DynamicsSLTrafficProcessor";
    public static final String CAPTION = "DSL";
    public static final String SEND_TO_DSL_CAPTION = "Send body to DSL tab";
    public static final String SEND_TO_STREAM_CAPTION = "Send to DSL Stream Replay";
    public static final String LOADED_LOG_MSG = "[+] DynamicsSLTrafficProcessor loaded (built-in TCP relay + TDS).";
    public static final String UNLOADED_LOG_MSG = "[*] DynamicsSLTrafficProcessor unloaded.";

    public static final Pattern BODY_OFFSET = Pattern.compile("(\r\n\r\n)");

    // TDS packet header Type values — [MS-TDS] 2.2.3.1.1 (v20260330)
    public static final int TDS_SQL_BATCH = 1;
    public static final int TDS_RPC = 3;
    public static final int TDS_TABULAR = 4;          // all server result token streams
    public static final int TDS_ATTENTION = 6;
    public static final int TDS_BULK = 7;
    public static final int TDS_FEDAUTH_TOKEN = 8;
    public static final int TDS_TXN_MANAGER = 14;
    public static final int TDS_LOGIN7 = 16;
    public static final int TDS_SSPI = 17;
    public static final int TDS_PRELOGIN = 18;

    // Common token types inside Type=4 Tabular result — [MS-TDS] 2.2.7
    public static final int TOKEN_COLMETADATA = 0x81;
    public static final int TOKEN_ERROR = 0xAA;
    public static final int TOKEN_INFO = 0xAB;
    public static final int TOKEN_LOGINACK = 0xAD;
    public static final int TOKEN_ROW = 0xD1;
    public static final int TOKEN_NBCROW = 0xD2;
    public static final int TOKEN_ENVCHANGE = 0xE3;
    public static final int TOKEN_DONE = 0xFD;
    public static final int TOKEN_DONEPROC = 0xFE;
    public static final int TOKEN_DONEINPROC = 0xFF;

    public static final int TDS_HEADER_LEN = 8;
    public static final int NAME_BY_PROCDID = 0xFFFF;

    // Well-known RPC proc IDs
    public static final Map<Integer, String> PROC_IDS;

    static {
        Map<Integer, String> m = new HashMap<>();
        m.put(1, "Sp_Cursor");
        m.put(2, "Sp_CursorOpen");
        m.put(3, "Sp_CursorPrepare");
        m.put(4, "Sp_CursorExecute");
        m.put(5, "Sp_CursorPrepExec");
        m.put(6, "Sp_CursorUnprepare");
        m.put(7, "Sp_CursorFetch");
        m.put(8, "Sp_CursorOption");
        m.put(9, "Sp_CursorClose");
        m.put(10, "Sp_ExecuteSql");
        m.put(11, "Sp_Prepare");
        m.put(12, "Sp_Execute");
        m.put(13, "Sp_PrepExec");
        m.put(14, "Sp_Unprepare");
        PROC_IDS = Collections.unmodifiableMap(m);
    }

    private DSLConstants() {
    }
}
