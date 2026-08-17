# DynamicsSLTrafficProcessor (DSL)

Burp Suite extension for **Microsoft Dynamics SL** client ↔ SQL Server **TDS** traffic.

Dynamics SL’s `swimapi` / Solomon kernel `Sql*` APIs use the **TDS (Tabular Data Stream)** wire protocol (typically TCP **1433**). This extension **listens and relays TCP itself**, groups traffic into **TCP Streams** and **Frames**, deserializes TDS to JSON, and supports **TDS-aware match/replace**, intercept, and **Stream Replay**.

**Capture path:** built-in **TCP relay only** (no external scripts such as mitm_relay). There is no dependency on pseudo-HTTP capture tools.

**Project persistence:** match/replace rules, intercept rules, relay host/port settings, captured **TCP Streams** / **Frames**, and **Stream Replay tabs** (numbered sessions with steps) are saved in the **Burp project file** (`Persistence.extensionData()`). Reopen the same project after a Burp restart to restore them. Temporary/unsaved projects lose extension data when discarded.

## Capture setup (built-in relay)

Desktop apps almost always use a **fixed port** (SQL Server **1433**). Use the **same port on both sides** of the relay:

```text
Listen  0.0.0.0:1433  →  Target  <real-sql-ip>:1433
```

1. Build and load the extension JAR in Burp (Extender → Extensions → Add).
2. Open **DSL → Relay**.
3. **Update the hosts file** (required for desktop apps) so the SQL hostname resolves to localhost:

   ```text
   # C:\Windows\System32\drivers\etc\hosts  (run editor as Administrator)
   127.0.0.1    your-sql-hostname
   ```

   Use the hostname from the app connection string — **not** the real SQL IP. That routes the client to your machine while still using port 1433.

4. Set **Listen** to `0.0.0.0` / `1433` and **Target** to the **real** SQL Server IP / `1433`.
5. Stop any local service already bound to 1433 (local SQL Server, etc.).
6. Click **Start relay**.
7. Open **DSL → TCP Streams** to watch traffic.

**Do not** set Target to `127.0.0.1` when Listen port equals Target port — that loops onto the relay itself. Target must be the real server address.

Match/replace and intercept rules apply on the relay path automatically.

### Performance notes

The relay **reassembles complete TDS PDUs on every live stream**, then forwards (with optional match/replace and intercept). Rules are checked **per PDU at forward time**, so turning Intercept on applies to **all open streams**, not only connections opened after enable. Capture is batched asynchronously; the TCP Streams UI coalesces refresh work.

This environment’s Dynamics SL ↔ SQL path is typically **cleartext TDS** (PRELOGIN ENCRYPTION off). Authentication is often **Windows integrated (SSPI / Negotiate)**, not SQL passwords in LOGIN7 — see [Windows integrated authentication (SSPI)](#windows-integrated-authentication-sspi).

## Features

| Tab (left → right) | What it does |
|-----|----------------|
| **Relay** | Start/stop TCP listener; hosts-file guidance for desktop apps |
| **Intercept** | Pause the relay when body text matches; Forward / Drop / edit |
| **TCP Streams** | Capture table of **TCP Streams** + **Frames** + **Follow Stream**; live tint; rename/highlight/send via **right-click** |
| **Stream Replay** | **Burp Repeater-style tabs** (numbered, rename, highlight); step edit; live-session inject or new TCP |
| **Match / Replace** | Live rules (master **On** + per-rule **On**); **TDS unpack → edit → re-pack** (no Apply button) |
| **Convert** | Ad-hoc TDS ↔ JSON offline |

**Views (Simple / Full):** frame / step detail defaults to a human **Simple** view (SQL, params, rows, errors, SSPI auth material). **Full** is the technical JSON from `unpack` (tokens, columns, credentials, etc.). Simple SQL edits can be **Apply**’d back to the wire body for RPC/SQL_BATCH.

### Naming

Throughout the UI we use:

| Term | Meaning |
|------|---------|
| **TCP Stream** | One captured client↔server TCP connection |
| **Frame** | One captured TDS PDU (or remainder chunk) on that stream |
| **Stream Replay tab** | One numbered replay session (like Burp Repeater) |

### TCP Streams

Streams are keyed **per TCP connection**, not only by remote host:

```text
127.0.0.1:56800 → 192.0.2.1:1433
```

Two clients (or reconnects) to the same SQL server appear as separate streams.

#### Stream list columns

| Column | Content |
|--------|---------|
| **#** | Sequential ID in the current list (1…n) |
| **Name** | Optional user label (right-click → **Rename TCP Stream**); blank until set |
| **Frames** | Frame count |
| **Time (UTC)** | First-frame timestamp (`yyyy-MM-dd hh:mm:ss AM/PM UTC`) |

Hover a row for the full connection endpoint (`client → server`) as a tooltip.

**Row tints** (not a column): the stream that **most recently received frames** gets a soft **amber** tint so you can spot the last update; **open relay sessions** use a soft **green** tint. When a session ends, the green tint is removed. **User highlight colors always win** over both auto-tints.

**Auto-scroll** (checked by default on both lists): keeps the **TCP Streams** list at the latest stream, and the **Frames** list at the latest frame. Scroll **up** to pause (checkbox clears); scroll back to the **bottom** to resume (checkbox re-checks).

**Search:** top bar searches stream **names / endpoints** and frame content (UTF-16LE / RAW). With **All streams** checked (default), the TCP Streams list is filtered to matching streams; Frames in the selected stream are filtered the same way.

#### Frames sub-tab

| Column | Content |
|--------|---------|
| **#** | Frame number **within this TCP Stream** (starts at 1 per stream) |
| **Dir** | C→S / S→C |
| **Date** | `yyyy-MM-dd` **UTC** |
| **Time (UTC)** | 12-hour `h:mm:ss.SSS AM/PM` **UTC** |
| **Bytes / Mod / HL / Summary** | Size, match/replace star, user highlight, one-line TDS summary |

Frame **Summary** uses a richer one-line decode (RPC/SQL, TABULAR cols, SSPI summary, PRELOGIN options, incomplete PDU notes)—not type+size only.

#### Follow Stream sub-tab

Continuous dump of the selected TCP Stream (`C→S` / `S→C`). Modes: **TDS decode** (default), **UTF-16 text**, **hex**, **raw ASCII**.

- **Follow Stream** always auto-updates for the selected TCP Stream (full conversation; search only highlights hits).  
- **TDS decode** surfaces **NetNTLM hashes** and **Kerberos tickets**, pairs NTLM Type2 challenges with later Type3 in-stream, and can append an auth material index.  

#### Actions (toolbar vs right-click)

| Toolbar | Right-click TCP Stream | Right-click Frame(s) |
|---------|------------------------|----------------------|
| Refresh | Rename / clear name | Rename Frame / clear name |
| Clear stream *(confirm)* | Highlight stream | Highlight selected Frames |
| Clear all *(confirm)* | Send TCP Stream to Replay | Send selected Frames / whole stream to Replay |
| | Clear this TCP Stream | Send Frame body to Convert |

### Stream Replay (Repeater-style tabs)

Each tab is an independent step list + editor + log, like **Burp Repeater**:

| Feature | Behavior |
|---------|----------|
| **Numbered tabs** | Sequential **1**, **2**, **3**, … (`+ New` allocates the next number) |
| **Rename** | Double-click tab or right-click → Rename (title becomes `2: my note`) |
| **Highlight** | Right-click tab → color palette (tab strip tinted) |
| **Close** | Tab × or right-click Close / Close others / Close all (always keeps one tab) |
| **Send from TCP Streams** | Opens a **new tab** (optional peer as title) with those frames as steps |

#### Replay transport & UI

Compact per-tab toolbar:

| Control | Role |
|---------|------|
| **Live session / New TCP** | Live inject into open relay bridge vs fresh socket |
| **Session** + ↻ | Auto (match stream/peer) or pick a live bridge by **TCP Stream #** (and name if set); tooltip shows the connection endpoint |
| **C→S only** | Skip S→C steps when replaying |
| **Replay / Replay Selected / Stop** | Run included steps, selected only, or abort |

- **Live session** keeps SSPI/login state; **New TCP** does not (SSPI replay usually fails).  
- After each C→S send, waits up to **5s** for a server reply (live: poll new S→C frames; new TCP: read socket).  
- Incomplete TDS PDUs are warned; complete PDUs preferred when trailing junk is present.  
- Step table **right-click**: move up/down, remove, clear all (confirm), replay selected.  
- Thin **Find / Replace** row for bulk string edits (UTF-16LE / RAW).  
- **Step editor**: Simple / Full, Apply, Reload. **Ctrl+Z** where undo is wired.  

### Match / Replace

Rules apply on the **TCP relay** (primary). Application is **TDS-aware**:

1. Unpack TDS packets when possible.  
2. Apply match/replace on decoded SQL/params and/or raw UTF-16LE / RAW.  
3. **Re-pack** packets with corrected TDS header lengths.  

**No Apply button** — toggle master **On** or a rule’s **On** column; table edits sync live. Target: **REQUEST** (C→S), **RESPONSE** (S→C), **BOTH**.

Optional: if a Proxy HTTP body looks like TDS, rules/highlights may also apply there; that is secondary to the relay.

| Mechanism | Best for |
|-----------|----------|
| Match / Replace (live) | Automatic swaps (userids, tokens, constants) on the wire |
| DSL editor pack/unpack | **Simple** view / JSON (sql/params/rows); Full for tokens |
| Stream Replay | Multi-tab sessions; multi-step C→S with live inject or new TCP |

## Quick usage

1. Start the **Relay** (hosts file + listen/target as above).
2. Use the app so traffic appears under **TCP Streams** (green **live** rows while the bridge is open).
3. Inspect a **Frame**: detail (Simple/Full) or **Follow Stream**.
4. For live swaps: **Match / Replace** rules (enabled).
5. To pause on content: **Intercept** rules + Forward/Drop.
6. For testing: right-click frames/stream → **Send … to Replay** → work in a numbered tab → **Live relay session** → **Replay**.
7. Offline: paste hex/binary into **Convert**, or open the **DSL** editor tab on a message body that looks like TDS.

**Ctrl+Z** undoes text edits in Stream Replay where undo support is wired.

## Build

### Prerequisites

- Java 17+

```bat
build.bat
```

Or:

```bat
gradlew.bat test jar
```

JAR: `build\libs\DynamicsSLTrafficProcessor-1.0.jar`

## Install in Burp

1. Extender → Extensions → Add  
2. Extension type: Java  
3. Select `build\libs\DynamicsSLTrafficProcessor-1.0.jar`  
4. Use **DSL → Relay** for capture (recommended)

### Project data (survives Burp restarts & plugin refresh)

Stored in the open Burp project via `Persistence.extensionData()`:

- **While you work:** debounced auto-save (~1.5s) on rule/relay/replay edits and on every TCP Streams capture update.
- **On extension unload / plugin refresh:** immediate flush so frames are not dropped mid-debounce.
- **On load:** match/replace, intercept, relay host/port, TCP Streams (frames + stream names/highlights + frame names/highlights), Stream Replay tabs.

| Data | Notes |
|------|--------|
| Match / Replace rules + enable flags | Full rule table |
| Intercept rules + enable + timeout | Not in-flight held frames |
| Relay Listen/Target host & port | Running state is not auto-restarted |
| TCP Streams capture | **Last ~50 000 frames** and ~**5 MB** of body bytes (older traffic dropped from the project file) |
| Stream Replay tabs | Up to **500 steps** / ~**8 MB** total (per-step cap 512 KB); bodies + **streamKey** + summary restored on load |

**Required:** use a **saved Burp project** (`.burp`). Temporary / unsaved projects discard extension data when closed. After capturing important traffic, save the Burp project (File → Save project). Plugin reload restores from that project file.

---

## Serialization & deserialization

All codec logic lives in `TdsHelper` (`unpack` = deserialize, `pack` = serialize). The Burp **DSL** editor tab and the suite **Convert** tab both use that path. Match/replace re-packs through the same helpers when TDS is recognized.

### End-to-end flow (editor / Convert)

```text
  TDS body (TCP relay capture, or pasted / editor body)
              │
              ▼
     ┌────────────────┐
     │  DESERIALIZE   │  TdsHelper.unpack(body) → JSON
     │  (TDS → JSON)  │
     └────────┬───────┘
              │  you edit JSON (sql, params, …)
              ▼
     ┌────────────────┐
     │   SERIALIZE    │  TdsHelper.pack(packets) → binary
     │  (JSON → TDS)  │  header lengths recomputed
     └────────┬───────┘
              │
              ▼
  relay / replay / send to SQL Server
```

| UI | Deserialize | Serialize |
|----|-------------|-----------|
| Message editor **DSL** tab | `unpack` on open → JSON | `pack` on send if modified |
| Suite **Convert** | Mode **TDS→JSON** | Mode **JSON→TDS** (hex + length) |
| Match / Replace | Unpack when possible | Re-pack with fixed lengths |

### What “the body” actually is

On the wire this is **Microsoft TDS** (MS-TDS), not a custom swimapi blob. Dynamics `SqlExec` / `SqlFetch*` end up as TDS packets such as:

| TDS type byte | Name | Typical role |
|---------------|------|----------------|
| `0x01` | `SQL_BATCH` | Unicode SQL batch |
| `0x03` | `RPC` | Remote procedure call (most Dynamics cursor traffic) |
| `0x04` | `TABULAR_RESULT` | Server result stream (tokens, rows, DONE*) |
| `0x06` | `ATTENTION` | Cancel |
| `0x10` | `TDS7_LOGIN` | Login (may embed first SSPI blob) |
| `0x11` | `SSPI` | Windows integrated auth (Negotiate / NTLM / Kerberos) |
| `0x12` | `PRELOGIN` | Pre-login negotiation |

A body may contain **one or more** TDS packets concatenated. `unpack` walks them in order; `pack` writes them back in array order.

---

### TDS packet header (always 8 bytes)

Every packet starts with a fixed header. Length is **big-endian** and counts the **entire packet including this header**.

| Offset | Size | Field | Notes |
|--------|------|--------|--------|
| 0 | 1 | `type` | e.g. `03` = RPC, `04` = tabular result |
| 1 | 1 | `status` | Bit `0x01` = EOM (end of message) |
| 2 | 2 | `length` | Big-endian total size (header + payload) |
| 4 | 2 | `spid` | Server process id (often 0 on client RPC) |
| 6 | 1 | `packetId` | Packet sequence within the message |
| 7 | 1 | `window` | Usually `0` |

**Example** (188-byte client RPC):

```text
03 01 00 BC 00 00 01 00  | …payload…
│  │  │     │     │  └─ window = 0
│  │  │     │     └──── packetId = 1
│  │  │     └────────── spid = 0
│  │  └──────────────── length = 0x00BC = 188
│  └─────────────────── status = 1 (EOM)
└────────────────────── type = 3 (RPC)
```

On deserialize, these become JSON fields: `type`, `typeName`, `status`, `length`, `spid`, `packetId`, `window`, plus `payloadHex` (payload only, no header).

On serialize, `wrapPacket` rebuilds the 8-byte header and **recomputes `length`** from the new payload size so you can grow/shrink SQL text safely when using structured RPC rebuild.

---

### Deserialization (`unpack`)

1. **Scan** the body for TDS headers while `offset + 8 ≤ body.length`.
2. **Validate** length; if truncated, set `"truncated": true` and take remaining bytes as payload.
3. **Slice** payload = bytes `[offset+8 .. offset+length)`.
4. **Always** store `payloadHex` (lowercase hex of the payload) for safe round-trip.
5. **Deep-decode** by type:
   - `RPC` → `rpc` object
   - `SQL_BATCH` → `sql` string (+ optional headers)
   - `TABULAR_RESULT` → `tokens` / columns / strings
   - `SSPI` / LOGIN7 SSPI field / tabular SSPI token → `sspi` object via `SspiDecoder` (SPNEGO/NTLM/Kerberos + credentials)
   - other types → `utf16Strings` extract + note; still keep `payloadHex`
6. If nothing looks like TDS, emit a single `typeName: "RAW"` object with full body hex.

#### Optional ALL_HEADERS block (RPC / SQL batch)

Many client packets begin the payload with an **ALL_HEADERS** stream (MS-TDS):

```text
DWORD totalLength (LE)   // includes itself
  repeated:
    DWORD headerLength (LE)
    USHORT headerType
    …header data…
```

`peekAllHeadersLength` validates this structure. If present:

- `rpc.allHeadersLen` / `rpc.allHeadersHex` (or packet-level for SQL batch)
- Procedure name / SQL starts **after** that block

If the first dwords do not form a valid header stream, headers length is treated as `0`.

#### RPC payload layout

After optional headers:

```text
USHORT nameLenProcID
  if nameLenProcID == 0xFFFF:
      USHORT procId          // well-known id (see table below)
  else:
      nameLenProcID * UTF-16LE chars = procedure name
USHORT optionFlags
repeated ParameterData:
  BYTE   name length (chars)
  UTF-16LE name (optional)
  BYTE   status flags (e.g. 0x01 = by-ref / output-ish)
  BYTE   type (TDS type token)
  TYPE_INFO + value (type-specific)
```

**Well-known `procId` values** decoded to names:

| procId | Name | Dynamics / sample use |
|--------|------|------------------------|
| 1 | Sp_Cursor | Cursor ops |
| 2 | **Sp_CursorOpen** | Open cursor with SQL text |
| 3 | Sp_CursorPrepare | |
| 4 | Sp_CursorExecute | |
| 5 | Sp_CursorPrepExec | |
| 6 | Sp_CursorUnprepare | |
| 7 | Sp_CursorFetch | |
| 8 | **Sp_CursorOption** | e.g. option + table name `UserRec` |
| 9 | Sp_CursorClose | |
| 10 | Sp_ExecuteSql | |
| 11–14 | Sp_Prepare / Execute / PrepExec / Unprepare | |

#### Parameter / column types that are decoded

| TDS type | `sqlType` | Notes |
|----------|-----------|--------|
| `0x30` / `0x34` / `0x38` / `0x7F` | INT1 / INT2 / INT4 / INT8 | Fixed-width integers |
| `0x32` | BIT | Fixed |
| `0x26` | INTN | `maxLen` + `actual` + LE integer |
| `0x68` | BITN | nullable bit |
| `0xE7` / `0xEF` | **NVARCHAR** / NCHAR | collation + UTF-16LE (`0xFFFF` = NULL) |
| `0xA7` / `0xAF` | BIGVARCHAR / BIGCHAR | collation + Latin-1 |
| `0xA5` / `0xAD` | BIGVARBIN / BIGBINARY | length-prefixed binary (`valueHex`) |
| `0x24` | GUID | nullable fixed |
| `0x3A`–`0x3E`, `0x28`, … | DATETIM4 / FLT* / DATETIME / DATE | Fixed temporal/float |
| `0x6F` / `0x6D` / `0x6C` / `0x6A` / `0x6E` | DATETIMN / FLTN / MONEYN / DECIMALN / NUMERICN | nullable numeric/temporal |

Unknown types stop the param loop and keep remaining data on that param as `rawHex` / `decodeError`.

Each successfully parsed parameter also gets **`rawHex`**: the exact bytes of that parameter record (name + status + type + value). Serialize can rebuild known types from fields, or fall back to `rawHex` for opaque types.

#### Convenience field `rpc.sql`

After params are parsed, the decoder sets `rpc.sql` when it finds a good string:

1. Prefer NVARCHAR/BIGVARCHAR values that look like SQL (`select` / `insert` / `update` / `delete` / `exec` / ` from `).
2. Otherwise use the longest string-typed parameter value.

Editing **`rpc.sql` alone** is enough for most injection tests: on serialize, that value is written into the matching NVARCHAR param (and length fields are updated).

#### SQL_BATCH payload

```text
[optional ALL_HEADERS]
UTF-16LE SQL text for the rest of the payload
```

JSON: `sql`, optional `allHeadersHex`.

#### TABULAR_RESULT (server) tokens

Server payloads are a **token stream**, not RPC params. Decode includes:

| Token | Name | What we surface |
|-------|------|-----------------|
| `0x81` | COLMETADATA | Column count, names, types (INT2/INT4/BIGCHAR/… common in Dynamics SL) |
| `0xA4` | TABNAME | Table name parts (e.g. `userrec`) |
| `0xA5` | COLINFO | column info blob (`rawHex`) |
| `0xA9` | ORDER | order blob |
| `0xE3` | ENVCHANGE | env change type + raw |
| `0xD1` | ROW | **Typed cells** when COLMETADATA was parsed (`values` map by column name) |
| `0xD3` | NBCROW | null-bitmap row (raw fallback) |
| `0x79` | RETURNSTATUS | Integer return status |
| `0xFD` / `0xFE` / `0xFF` | DONE / DONEPROC / DONEINPROC | status, curcmd, **rowCount** (4- or **8-byte** DoneRowCount for TDS 7.2+), `rowCountWidth` |
| `0xAA` / `0xAB` | ERROR / INFO | number, state, class, **USHORT-char MsgText** (not byte length) |
| `0xAC` | RETURNVALUE | param name, type, decoded value when possible |
| `0xED` | SSPI | Token-form SSPI blob → same `SspiDecoder` as packet type `0x11` |

Also `utf16Strings`: scavenged printable UTF-16LE runs.

Round-trip for tabular packets still uses `payloadHex` unless you only change header fields. Client **RPC** remain the primary edit/re-pack path.

---

## Windows integrated authentication (SSPI)

Dynamics SL commonly logs in with **Windows integrated security**. TDS does not “do” NTLM/Kerberos itself; it **carries SSPI tokens** produced by the client OS (Negotiate → NTLM or Kerberos).

### Handshake (typical)

```text
PRELOGIN          Client ↔ Server
LOGIN7            Client → Server   (often empty SQL user/password; may embed first SSPI)
SSPI (0x11)       Both directions   (multi-leg Negotiate / NTLM Type1–3 / Kerberos AP-REQ…)
LOGINACK + ENV…   Server → Client   (success) or ERROR tokens (failure)
RPC / SQL_BATCH   Normal work
```

The extension **relays and decodes** these blobs; it does **not** complete a security context or re-authenticate.

### What is decoded (`SspiDecoder`)

| Layer | Surfaces |
|-------|----------|
| **GSS-API** | `APPLICATION 0` wrapper, mechanism OID (SPNEGO, Kerberos5, NTLMSSP, …) |
| **SPNEGO** | `NegTokenInit` / `NegTokenResp`, mech list, `negState`, inner token |
| **NTLM** | Type 1/2/3, flags, domain / user / workstation / target, **server challenge**, AV pairs (Nb/Dns names), version |
| **Kerberos** | AP-REQ / AP-REP (and related tags), scavenged principals / **SPN** (`MSSQLSvc/host:port`) |

Implementation: `com.bdocyber.helpers.tds.SspiDecoder` (used from `TdsHelper` packet type `0x11`, LOGIN7 embedded SSPI, and tabular SSPI token `0xED`).

### Credentials material (hashes & tickets)

Exposed in **Simple view**, **Full JSON** (`sspi.credentials` and top-level fields), and **Follow Stream (TDS decode)**:

| Material | Format / notes |
|----------|----------------|
| **NetNTLMv2 hash** | `user::domain:challenge:NTproof:blob` — hashcat **`-m 5600`** / john `netntlmv2` |
| **NetNTLMv1 hash** | `user::domain:lm:nt:challenge` — hashcat **`-m 5500`** / john `netntlm` |
| **LM / NT responses** | Full hex of Type3 response buffers |
| **Server challenge** | From NTLM Type2 (16 hex chars) |
| **Kerberos ticket** | Ticket TLV as **base64** + hex (from AP-REQ when present) |
| **Kerberos AP-REQ** | Full AP-REQ base64/hex |
| **Authenticator** | Encrypted authenticator base64 (not decrypted) |

**Follow Stream** remembers the last Type2 challenge in the connection and applies it to later Type3 messages so hashes are **complete** when both sides of the handshake were captured. Viewing Type3 alone still shows responses and a partial hash with `ntlmHashComplete: false`.

**Example Simple view (abbreviated):**

```text
SSPI authentication
  SPNEGO NegTokenResp → NTLM Type3 Authenticate CORP\alice from WS01
  kind: SPNEGO  (SPNEGO (Negotiate))

  NTLM hash (NetNTLMv2, hashcat -m 5600 / john netntlmv2):
    alice::CORP:a0a1…:ntproof…:blob…
  NTLM NT response:  …
  Kerberos ticket (N B, base64):
    …
```

### Security notes

- Treat hashes and tickets as **sensitive engagement data** (offline cracking, pass-the-ticket research).  
- The plugin does **not** validate NTLM, decrypt Kerberos, or store domain passwords.  
- Cleartext TDS + SSPI is common when ENCRYPTION is off; confirm with PRELOGIN options in capture.

---

### Serialization (`pack`)

`pack` iterates the `packets` JSON array and concatenates each rebuilt TDS packet.

#### Per-packet strategy

```text
if type is RPC and "rpc" object present:
    rebuild RPC payload from structured fields (preferred)
else if type is SQL_BATCH and "sql" present:
    rebuild batch payload from headers hex + UTF-16 SQL
else:
    take payloadHex (or rawHex) as the payload unchanged
then:
    wrap with 8-byte header (recomputed length)
```

#### RPC rebuild details

1. Write `allHeadersHex` bytes if non-empty (exact original headers).
2. Write procedure identity:
   - if `procId` present → `FFFF` + procId USHORT LE  
   - else → name length + UTF-16LE `procName`
3. Write `optionFlags` USHORT LE.
4. If `rpc.sql` is set, copy it into the first suitable NVARCHAR param value (and bump that param’s `maxLen` if the new string is longer).
5. For each param in `params`:
   - **INTN / BITN / NVARCHAR / BIGVARCHAR**: rebuild from `name`, `status`, `type`/`sqlType`, `value`, `maxLen`, `collationHex`
   - **other**: emit entire `rawHex` for that parameter (preserves unknown types)
6. Wrap with TDS header.

NVARCHAR rebuild:

```text
nameLen | name | status | 0xE7
maxLen (USHORT LE)     // at least utf16 byte length
collation (5 bytes)    // from collationHex, or default sample collation
byteLen (USHORT LE)    // value.getBytes(UTF-16LE).length
UTF-16LE characters
```

If structured rebuild is unavailable but `payloadHex` + `rpc.sql` exist, a **byte-level NVARCHAR patch** can rewrite the longest `0xE7` string in the original payload (fallback path).

#### SQL_BATCH rebuild

```text
allHeadersHex (optional) + sql.getBytes(UTF-16LE)
```

#### What you should edit for safe re-pack

| Goal | Edit these fields | Avoid |
|------|-------------------|--------|
| Change SQL in Sp_CursorOpen | `rpc.sql` and/or `params[i].value` for the NVARCHAR | Hand-editing `payloadHex` only (easy to desync) |
| Change integer cursor flags | `params[i].value` for INTN | Changing `type` without understanding TYPE_INFO |
| Replay unchanged packet | Leave JSON alone (or only comment fields) | Deleting `payloadHex` on tabular packets |
| Tamper server row data | Limited; prefer match/replace or raw hex | Expecting full ROW re-encode |

---

### Full example: Sp_CursorOpen

**Binary body (188 bytes)** — header + RPC payload with ALL_HEADERS, procId `2`, SQL NVARCHAR.

**Deserialized JSON (abbreviated):**

```json
{
  "direction": "CLIENT_REQUEST",
  "peer": "192.0.2.1:1433",
  "packets": [
    {
      "type": 3,
      "typeName": "RPC",
      "status": 1,
      "length": 188,
      "spid": 0,
      "packetId": 1,
      "window": 0,
      "truncated": false,
      "payloadHex": "16000000…",
      "rpc": {
        "allHeadersLen": 22,
        "allHeadersHex": "16000000…",
        "procId": 2,
        "procName": "Sp_CursorOpen",
        "optionFlags": 0,
        "sql": "Select * from userrec where userid = 'APPAPMANAGER1'",
        "params": [
          {
            "name": "",
            "status": 1,
            "type": 38,
            "typeHex": "0x26",
            "sqlType": "INTN",
            "maxLen": 4,
            "value": 0,
            "rawHex": "…"
          },
          {
            "name": "",
            "status": 0,
            "type": 231,
            "typeHex": "0xE7",
            "sqlType": "NVARCHAR",
            "maxLen": 104,
            "collationHex": "0904d00034",
            "value": "Select * from userrec where userid = 'APPAPMANAGER1'",
            "rawHex": "…"
          },
          {
            "sqlType": "INTN",
            "value": 2
          },
          {
            "sqlType": "INTN",
            "value": 8196
          },
          {
            "sqlType": "INTN",
            "value": 0
          }
        ]
      }
    }
  ]
}
```

**To tamper:** change `rpc.sql` (and the matching `params[].value` is updated on pack via the sql helper). Example:

```json
"sql": "Select * from userrec where userid = 'ADMIN'--"
```

Serialize recalculates:

- NVARCHAR `byteLen` / `maxLen` if needed  
- TDS header `length`  

---

### Hex / Pretty tab confusion

Burp’s **Pretty** view often shows mojibake for TDS because SQL is **UTF-16LE** mixed with binary. Example: you may see `4hSelect…` — that is collation/length bytes misread as Latin-1, then `Select` in UTF-16. Prefer **Hex**, the **DSL** JSON tab (Simple or Full), or **TCP Streams → Follow Stream** (**TDS decode** for structure/auth; UTF-16 mode only for printable strings).

### Common Dynamics/Solomon patterns

| TDS | Meaning |
|-----|---------|
| PRELOGIN + LOGIN7 + SSPI | Session setup; often Windows integrated auth |
| RPC `Sp_CursorOpen` (procId 2) | Open cursor with SQL text (NVARCHAR param) |
| RPC `Sp_CursorOption` (procId 8) | Cursor options (e.g. table name `UserRec`) |
| `TABULAR_RESULT` | Server tokens: COLMETADATA, ROW, RETURNSTATUS, DONEPROC, … |

## Architecture (key classes)

| Class | Role |
|-------|------|
| `TcpRelayService` | TCP bridge; live `ActiveRelaySession` registry; inject API; async capture |
| `ActiveRelaySession` | One live app↔SQL bridge for Stream Replay inject |
| `TdsPacketBuffer` | Reassemble complete TDS PDUs from TCP bytes |
| `TdsHelper` | `unpack` / `pack`, LOGIN7, PRELOGIN, RPC, framing helpers |
| `TdsTokenStream` | Tabular token decode (COLMETADATA heuristics, rows, DONE*, ERROR, …) |
| `SspiDecoder` | SPNEGO / NTLM / Kerberos decode; NetNTLM hashes; ticket export |
| `TdsSimpleView` / `TdsTextFormatter` | Simple/Full UI text; frame one-line summaries; Simple → re-pack SQL |
| `MatchReplaceEngine` | TDS-aware re-pack match/replace (relay hot path) |
| `FollowStreamBuilder` | Follow Stream assembly + Type2/Type3 challenge pairing |
| `TcpStreamsPanel` | TCP Streams / Frames / Follow UI |
| `StreamReplayPanel` / `ReplaySessionPanel` | Repeater-style tabs + per-tab session UI |
| `TcpStreamStore` / `DslProjectPersistence` | Capture store and Burp project persistence |

Proxy HTTP handlers/editors remain only as a thin optional path if a body looks like TDS; they do **not** implement or depend on mitm_relay.

## Protocol notes

Dynamics SL talks to SQL Server over **Microsoft Tabular Data Stream (MS-TDS)** on TCP (usually **1433**). Client APIs such as `swimapi` / Solomon `Sql*` are only the application layer; the wire format is standard TDS (packet types like PRELOGIN, LOGIN7, SSPI, RPC, SQL_BATCH, TABULAR_RESULT), not a proprietary blob.

This extension targets **MS-TDS** as documented in Microsoft **[MS-TDS] v20260330** (see `[MS-TDS]-260330.pdf` in the project root)—the version of the TDS 7.x family used by modern SQL Server. Auth-related SSPI decoding follows **[MS-NLMP]** (NTLM), **RFC 4178** (SPNEGO), and **RFC 4120/4121** (Kerberos).

**Multi-packet tabular results:** SQL Server often splits a single result message across several TDS PDUs (EOM only on the last). Capture stores each PDU as a Frame; **detail / Follow Stream / unpack** reassemble the full message (same direction, consecutive Type=4 PDUs until EOM) so `COLMETADATA` applies to later `ROW` tokens. Simple view renders result sets as an **ASCII table** (or vertical key/value layout when there are many columns).

## License

See `LICENSE`.
