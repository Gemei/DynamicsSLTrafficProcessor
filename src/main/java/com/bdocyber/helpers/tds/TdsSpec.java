package com.bdocyber.helpers.tds;

/**
 * MS-TDS constants from [MS-TDS] v20260330 (packet types, tokens, data types).
 * Full protocol reference: Microsoft Tabular Data Stream Protocol.
 */
public final class TdsSpec {

    private TdsSpec() {
    }

    // --- Packet header Type (2.2.3.1.1) ---
    public static final int PKT_SQL_BATCH = 0x01;
    public static final int PKT_PRE_TDS7_LOGIN = 0x02;
    public static final int PKT_RPC = 0x03;
    public static final int PKT_TABULAR = 0x04;
    public static final int PKT_ATTENTION = 0x06;
    public static final int PKT_BULK = 0x07;
    public static final int PKT_FEDAUTH = 0x08;
    public static final int PKT_TXN_MGR = 0x0E;
    public static final int PKT_LOGIN7 = 0x10;
    public static final int PKT_SSPI = 0x11;
    public static final int PKT_PRELOGIN = 0x12;

    // Status flags (2.2.3.1.2)
    public static final int STATUS_EOM = 0x01;
    public static final int STATUS_IGNORE = 0x02;
    public static final int STATUS_RESETCONNECTION = 0x08;
    public static final int STATUS_RESETCONNECTIONSKIPTRAN = 0x10;

    // --- Token types inside Type=4 Tabular result (2.2.7) ---
    public static final int TOK_OFFSET = 0x78;
    public static final int TOK_RETURNSTATUS = 0x79;
    public static final int TOK_COLMETADATA = 0x81;
    public static final int TOK_ALTMETADATA = 0x88;
    public static final int TOK_TABNAME = 0xA4;
    public static final int TOK_COLINFO = 0xA5;
    public static final int TOK_ORDER = 0xA9;
    public static final int TOK_ERROR = 0xAA;
    public static final int TOK_INFO = 0xAB;
    public static final int TOK_RETURNVALUE = 0xAC;
    public static final int TOK_LOGINACK = 0xAD;
    public static final int TOK_FEATUREEXTACK = 0xAE;
    public static final int TOK_ROW = 0xD1;
    public static final int TOK_NBCROW = 0xD2;
    public static final int TOK_ALTROW = 0xD3;
    public static final int TOK_ENVCHANGE = 0xE3;
    public static final int TOK_SESSIONSTATE = 0xE4;
    public static final int TOK_SSPI = 0xED;
    public static final int TOK_FEDAUTHINFO = 0xEE;
    public static final int TOK_DONE = 0xFD;
    public static final int TOK_DONEPROC = 0xFE;
    public static final int TOK_DONEINPROC = 0xFF;

    // DONE status bits
    public static final int DONE_FINAL = 0x00;
    public static final int DONE_MORE = 0x01;
    public static final int DONE_ERROR = 0x02;
    public static final int DONE_INXACT = 0x04;
    public static final int DONE_COUNT = 0x10;
    public static final int DONE_ATTN = 0x20;
    public static final int DONE_SRVERROR = 0x100;

    public static String packetTypeName(int type) {
        return switch (type) {
            case PKT_SQL_BATCH -> "SQL_BATCH";
            case PKT_PRE_TDS7_LOGIN -> "PRE_TDS7_LOGIN";
            case PKT_RPC -> "RPC";
            case PKT_TABULAR -> "TABULAR_RESULT";
            case PKT_ATTENTION -> "ATTENTION";
            case PKT_BULK -> "BULK_LOAD";
            case PKT_FEDAUTH -> "FEDAUTH_TOKEN";
            case PKT_TXN_MGR -> "TRANSACTION_MANAGER";
            case PKT_LOGIN7 -> "TDS7_LOGIN";
            case PKT_SSPI -> "SSPI";
            case PKT_PRELOGIN -> "PRELOGIN";
            default -> "UNKNOWN_0x" + Integer.toHexString(type);
        };
    }

    public static String tokenName(int token) {
        return switch (token) {
            case TOK_OFFSET -> "OFFSET";
            case TOK_RETURNSTATUS -> "RETURNSTATUS";
            case TOK_COLMETADATA -> "COLMETADATA";
            case TOK_ALTMETADATA -> "ALTMETADATA";
            case TOK_TABNAME -> "TABNAME";
            case TOK_COLINFO -> "COLINFO";
            case TOK_ORDER -> "ORDER";
            case TOK_ERROR -> "ERROR";
            case TOK_INFO -> "INFO";
            case TOK_RETURNVALUE -> "RETURNVALUE";
            case TOK_LOGINACK -> "LOGINACK";
            case TOK_FEATUREEXTACK -> "FEATUREEXTACK";
            case TOK_ROW -> "ROW";
            case TOK_NBCROW -> "NBCROW";
            case TOK_ALTROW -> "ALTROW";
            case TOK_ENVCHANGE -> "ENVCHANGE";
            case TOK_SESSIONSTATE -> "SESSIONSTATE";
            case TOK_SSPI -> "SSPI";
            case TOK_FEDAUTHINFO -> "FEDAUTHINFO";
            case TOK_DONE -> "DONE";
            case TOK_DONEPROC -> "DONEPROC";
            case TOK_DONEINPROC -> "DONEINPROC";
            default -> "UNKNOWN_0x" + Integer.toHexString(token);
        };
    }

    public static boolean isKnownPacketType(int type) {
        return type == PKT_SQL_BATCH || type == PKT_PRE_TDS7_LOGIN || type == PKT_RPC
                || type == PKT_TABULAR || type == PKT_ATTENTION || type == PKT_BULK
                || type == PKT_FEDAUTH || type == PKT_TXN_MGR || type == PKT_LOGIN7
                || type == PKT_SSPI || type == PKT_PRELOGIN;
    }

    public static String envChangeName(int type) {
        return switch (type) {
            case 1 -> "Database";
            case 2 -> "Language";
            case 3 -> "Character set";
            case 4 -> "Packet size";
            case 5 -> "Unicode sorting LCID";
            case 6 -> "Unicode sorting flags";
            case 7 -> "SQL Collation";
            case 8 -> "Begin Transaction";
            case 9 -> "Commit Transaction";
            case 10 -> "Rollback Transaction";
            case 11 -> "Enlist DTC";
            case 12 -> "Defect Transaction";
            case 13 -> "Database Mirroring";
            case 15 -> "Promote Transaction";
            case 16 -> "TM Address";
            case 17 -> "Transaction ended";
            case 18 -> "ResetConnection ack";
            case 19 -> "User instance";
            case 20 -> "Routing";
            case 21 -> "Enhanced Routing";
            default -> "Type " + type;
        };
    }

    public static String preloginOptionName(int opt) {
        return switch (opt) {
            case 0 -> "VERSION";
            case 1 -> "ENCRYPTION";
            case 2 -> "INSTOPT";
            case 3 -> "THREADID";
            case 4 -> "MARS";
            case 5 -> "TRACEID";
            case 6 -> "FEDAUTHREQUIRED";
            case 7 -> "NONCEOPT";
            case 0xFF -> "TERMINATOR";
            default -> "OPTION_" + opt;
        };
    }
}
