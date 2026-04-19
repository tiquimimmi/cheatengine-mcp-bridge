# TCP/LAN Transport for CE MCP Bridge

**Date:** 2026-04-18
**Status:** Draft
**Scope:** Add TCP socket transport alongside Named Pipes for LAN connectivity and non-Windows CE builds. **Transport-layer only** — no changes to command handlers or tool behavior.

## Problem

The bridge currently uses Windows Named Pipes (`\\.\pipe\CE_MCP_Bridge_v99`) for IPC between the Python MCP server and the Lua plugin inside Cheat Engine. This limits connectivity to the local machine.

Users want to run CE on one machine (e.g., a Mac with a custom CE build) and the MCP Python server on another (e.g., a Windows AI workstation), connected over LAN.

## Solution

Add a TCP socket transport to both the Lua and Python sides, keeping Named Pipes as the default on Windows. The wire protocol (4-byte LE length prefix + JSON-RPC body) is unchanged — only the transport layer differs.

## Scope Boundaries

**In scope:** TCP socket server in Lua, TCP socket client in Python, transport auto-detection, LuaSocket bundling, version handshake, config/env vars, docs and test harness updates.

**Out of scope:** This spec does not change any command handler behavior. Tools that depend on Windows-specific CE APIs (DBVM watches, DBK/kernel operations, DLL injection, Windows symbol loading, etc.) already return appropriate error codes (`DBVM_NOT_LOADED`, `DBK_NOT_LOADED`, `CE_API_UNAVAILABLE`) when their prerequisites are missing. Those errors will surface naturally on non-Windows CE builds — no new error handling is needed. The command surface is the same regardless of transport.

## Architecture

```
                    WINDOWS (local)                         LAN (cross-machine)
AI client ──stdio──▶ mcp_cheatengine.py                   AI client ──stdio──▶ mcp_cheatengine.py
                      │ PipeBridgeClient                                        │ TCPBridgeClient
                      ▼ Named Pipe                                              ▼ TCP socket
                    ce_mcp_bridge.lua                                         ce_mcp_bridge.lua
                      (PipeWorker)                                              (TCPWorker)
                      ▼                                                         ▼
                    Target process                                            Target process
```

## Configuration

### Lua side (`ce_mcp_bridge.lua`)

Three config variables at script top:

```lua
local TRANSPORT_MODE = "auto"   -- "pipe" | "tcp" | "auto"
local TCP_HOST = "127.0.0.1"   -- bind address (change to "0.0.0.0" for LAN access)
local TCP_PORT = 28015          -- TCP listen port
```

**`"auto"` behavior:** If `createPipe` function exists in the CE environment, use pipe. Otherwise, attempt TCP if a socket library is available. On Mac CE builds, TCP is the expected transport.

**Prerequisite for TCP:** The Lua side requires LuaSocket. This is resolved by **bundling the LuaSocket binary** (`socket.so` on macOS, `socket.dll` on Windows) in `MCP_Server/lib/`. The bridge script adds this directory to `package.cpath` at load time. If neither `createPipe` nor a socket library is available, `StartMCPBridge` logs a clear error and does not start — there is no silent fallback.

**Security note:** `TCP_HOST` defaults to `127.0.0.1` (localhost only). Users must explicitly set it to `"0.0.0.0"` to accept LAN connections. This is important because the bridge exposes powerful tools (`evaluate_lua`, `run_command`, `inject_dll`) with no authentication.

### Python side (`mcp_cheatengine.py`)

Single env var controls transport:

```
CE_MCP_URI=pipe                        # Named Pipe (default)
CE_MCP_URI=tcp:192.168.1.100:28015     # TCP to specific host:port
CE_MCP_URI=tcp::28015                  # TCP to localhost:28015
CE_MCP_URI=tcp:192.168.1.100           # TCP to host, default port 28015
```

When `CE_MCP_URI` is unset, defaults to `pipe` on Windows, `tcp::28015` on non-Windows.

**IPv6:** Not supported in this version. The URI parser assumes IPv4. Document as a known limitation.

## Lua Side Changes

### Socket library: bundled LuaSocket

LuaSocket binaries are shipped in `MCP_Server/lib/` and loaded at script startup:

```lua
-- Add bundled lib directory to cpath before any require("socket")
local scriptDir = extractDir(getMainForm().getAutoAttachList().getScript())
    or "."
package.cpath = scriptDir .. "/lib/?.so;" ..
                scriptDir .. "/lib/?.dll;" ..
                package.cpath

local function loadSocketLib()
    local ok, sock = pcall(require, "socket")
    if ok and sock and sock.bind then return sock end
    return nil
end
```

**If LuaSocket is unavailable at runtime:** `detectTransport()` returns `nil`, `StartMCPBridge` logs a clear error and does not start:
```
[MCP] ERROR: TCP transport requested but LuaSocket not found.
Ensure socket.so/socket.dll is in MCP_Server/lib/.
```

**Bundled files:**
| Platform | File | Location |
|----------|------|----------|
| macOS | `socket.so` (+ `socket/core.so`) | `MCP_Server/lib/` |
| Windows | `socket.dll` (+ `socket/core.dll`) | `MCP_Server/lib/` |

These are built from LuaSocket 3.1.0 against the Lua version CE uses (5.3 or LuaJIT depending on build). Build instructions are in `MCP_Server/lib/README.md`.

### Transport detection

```lua
local function detectTransport()
    if TRANSPORT_MODE == "pipe" then return "pipe" end
    if TRANSPORT_MODE == "tcp" then
        if not loadSocketLib() then
            print("[MCP] ERROR: TCP transport requested but no socket library found.")
            return nil
        end
        return "tcp"
    end
    -- auto: use pipe if available, else tcp (if socket lib exists)
    if type(createPipe) == "function" then return "pipe" end
    if loadSocketLib() then return "tcp" end
    print("[MCP] ERROR: No transport available (no createPipe, no socket library).")
    return nil
end
```

### Shared request loop

Extract the common read-header → read-payload → executeCommand → write-response loop. Use a **string-based contract** for `readFn`: both transports return strings. Header bytes are extracted via `string.byte()`. This resolves the type mismatch between pipe (`readBytes` returns table) and TCP (`receive` returns string).

The `thread` parameter is the CE thread object passed by `createThread()`, providing `.Terminated` and `.synchronize()`. Both `PipeWorker(thread)` and `TCPWorker(thread)` receive it the same way.

```lua
-- thread: the CE thread object from createThread(), provides .Terminated and :synchronize()
-- readFn(n): returns a string of exactly n bytes, or nil on error
-- writeFn(data): sends a string (header bytes pre-packed into string)
-- isConnectedFn(): returns true if connection is alive
local function processRequestLoop(thread, readFn, writeFn, isConnectedFn)
    while not thread.Terminated and isConnectedFn() do
        -- read 4-byte LE header as string
        local ok, headerStr = pcall(readFn, 4)
        if not ok or not headerStr or #headerStr < 4 then break end

        local b1, b2, b3, b4 = string.byte(headerStr, 1, 4)
        local len = b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
        if len <= 0 or len >= 32 * 1024 * 1024 then break end

        -- read payload as string
        local ok2, payload = pcall(readFn, len)
        if not ok2 or not payload then break end

        -- execute on main thread via the thread object from createThread()
        local response
        thread.synchronize(function()
            response = executeCommand(payload)
        end)

        -- write response: pack 4-byte LE header + body as single string
        local respLen = #response
        local header = string.char(
            respLen % 256,
            math.floor(respLen / 256) % 256,
            math.floor(respLen / 65536) % 256,
            math.floor(respLen / 16777216) % 256
        )
        writeFn(header .. response)
    end
end
```

**Pipe readFn adapter:** Wraps `pipe.readBytes(n)` to return a string:
```lua
local function pipeReadFn(n)
    local bytes = pipe.readBytes(n)
    if not bytes then return nil end
    -- If it's for the header (table of byte values), convert to string
    if type(bytes) == "table" then
        return string.char(table.unpack(bytes))
    end
    -- pipe.readString returns a string directly
    return bytes
end
```

Actually, the pipe adapter should call `readBytes` for small reads and `readString` for payload reads. But since `processRequestLoop` now uses a uniform string contract, the pipe adapter uses `readString` for both:
```lua
-- Pipe: always read as string
local function pipeReadFn(n)
    if n <= 4 then
        local bytes = pipe.readBytes(n)
        if not bytes then return nil end
        return string.char(table.unpack(bytes))
    end
    return pipe.readString(n)
end
```

**TCP readFn:** LuaSocket's `socket:receive(n)` in `"*a"` or numeric mode blocks until exactly `n` bytes arrive or an error occurs. This provides the same semantics as pipe reads — no partial-read loop needed on the Lua side.
```lua
local function tcpReadFn(n)
    local data, err = client:receive(n)
    if not data then return nil end
    return data
end
```

### TCPWorker

```lua
-- TCPWorker receives the thread object from createThread(), same as PipeWorker
local function TCPWorker(thread)
    local socketLib = loadSocketLib()
    local server = socketLib.bind(TCP_HOST, TCP_PORT)
    server:settimeout(1)  -- 1s accept timeout for clean shutdown checking

    -- Store server socket in serverState for cleanup
    serverState.tcpServer = server

    while not thread.Terminated do
        local client, err = server:accept()
        if client then
            client:settimeout(30)  -- 30s read timeout = dead peer detection
            client:setoption("keepalive", true)
            serverState.tcpClient = client

            local function readFn(n)
                local data, err = client:receive(n)
                if not data then return nil end
                return data
            end

            local function writeFn(data)
                -- Handle partial writes: socket:send() may not send all bytes
                local total = #data
                local sent = 0
                while sent < total do
                    local i, err, partial = client:send(data, sent + 1)
                    if i then
                        sent = i
                    elseif partial and partial > 0 then
                        sent = sent + partial
                    else
                        error("TCP send failed: " .. (err or "unknown"))
                    end
                end
            end

            local function isConnectedFn()
                return client ~= nil and not thread.Terminated
            end

            processRequestLoop(thread, readFn, writeFn, isConnectedFn)
            pcall(function() client:close() end)
            serverState.tcpClient = nil
        end
    end
    pcall(function() server:close() end)
    serverState.tcpServer = nil
end
```

**Dead peer detection:** `client:settimeout(30)` means `client:receive(n)` returns `nil, "timeout"` after 30s of silence. The `readFn` returns `nil`, `processRequestLoop` breaks, and the worker loops back to `accept()`. Combined with `keepalive`, this detects both network drops and crashed clients.

### Fallback: no `createThread`

If the Mac CE build lacks `createThread`, use a timer-based polling server. **Known limitation: the CE GUI freezes during command execution** since `executeCommand` runs synchronously on the main thread. This is acceptable as a degraded mode — document it clearly.

The polling fallback uses a **two-phase state machine** to handle TCP fragmentation correctly. Phase 1 (non-blocking) accumulates header bytes across polls. Phase 2 (blocking) switches to blocking mode once a full header is received, reads the payload, executes, and responds. The GUI freezes only during phase 2.

```lua
local function startPollingTCPServer()
    local socketLib = loadSocketLib()
    local server = socketLib.bind(TCP_HOST, TCP_PORT)
    server:settimeout(0)  -- non-blocking
    serverState.tcpServer = server

    local client = nil
    local headerBuf = ""  -- accumulate partial header reads
    local pollTimer = createTimer(nil)
    pollTimer.Interval = 50  -- 50ms polling

    pollTimer.OnTimer = function()
        -- Phase 0: accept new client
        if not client then
            client = server:accept()
            if client then
                client:settimeout(0)  -- non-blocking for header accumulation
                headerBuf = ""
                serverState.tcpClient = client
            end
            return
        end

        -- Phase 1: accumulate header bytes (non-blocking, handles fragmentation)
        if #headerBuf < 4 then
            local chunk, err, partial = client:receive(4 - #headerBuf)
            if chunk then
                headerBuf = headerBuf .. chunk
            elseif partial and #partial > 0 then
                headerBuf = headerBuf .. partial
            elseif err == "closed" then
                pcall(function() client:close() end)
                client = nil
                headerBuf = ""
                serverState.tcpClient = nil
                return
            end
            -- Still not enough? Wait for next poll
            if #headerBuf < 4 then return end
        end

        -- Phase 2: header complete — switch to blocking for payload + execute
        -- (GUI freezes here until response is sent)
        client:settimeout(30)

        local b1, b2, b3, b4 = string.byte(headerBuf, 1, 4)
        local len = b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
        headerBuf = ""  -- reset for next message

        if len <= 0 or len >= 32 * 1024 * 1024 then
            pcall(function() client:close() end)
            client = nil; serverState.tcpClient = nil
            return
        end

        local payload, err = client:receive(len)
        if not payload then
            pcall(function() client:close() end)
            client = nil; serverState.tcpClient = nil
            return
        end

        local response = executeCommand(payload)
        -- Use sendAll helper for partial write safety
        local total = #response
        local respLen = total
        local header = string.char(
            respLen % 256,
            math.floor(respLen / 256) % 256,
            math.floor(respLen / 65536) % 256,
            math.floor(respLen / 16777216) % 256
        )
        local fullMsg = header .. response
        local sent = 0
        while sent < #fullMsg do
            local i, werr, partial = client:send(fullMsg, sent + 1)
            if i then sent = i
            elseif partial and partial > 0 then sent = sent + partial
            else
                pcall(function() client:close() end)
                client = nil; serverState.tcpClient = nil
                return
            end
        end

        client:settimeout(0)  -- back to non-blocking for next poll
    end

    pollTimer.Enabled = true
    serverState.pollTimer = pollTimer
end
```

### Start/Stop changes

`StartMCPBridge` branches on the detected transport:

```lua
function StartMCPBridge()
    StopMCPBridge()
    local transport = detectTransport()
    if not transport then return end  -- no transport available

    serverState.transportMode = transport

    if transport == "pipe" then
        -- existing PipeWorker path (unchanged)
    elseif type(createThread) == "function" then
        serverState.workerThread = createThread(TCPWorker)
    else
        startPollingTCPServer()  -- timer-based fallback
    end
end
```

`StopMCPBridge` tears down all transport resources:

```lua
function StopMCPBridge()
    -- Existing pipe cleanup (unchanged)
    if serverState.workerPipe then
        serverState.workerPipe.destroy()
        serverState.workerPipe = nil
    end

    -- TCP cleanup
    if serverState.tcpClient then
        pcall(function() serverState.tcpClient:close() end)
        serverState.tcpClient = nil
    end
    if serverState.tcpServer then
        pcall(function() serverState.tcpServer:close() end)
        serverState.tcpServer = nil
    end

    -- Polling timer cleanup
    if serverState.pollTimer then
        serverState.pollTimer.Enabled = false
        serverState.pollTimer.destroy()
        serverState.pollTimer = nil
    end

    -- Thread cleanup (existing)
    if serverState.workerThread then
        serverState.workerThread.terminate()
        serverState.workerThread.waitfor()
        serverState.workerThread.destroy()
        serverState.workerThread = nil
    end

    cleanupZombieState()
end
```

**Interrupting blocking `accept()`:** Closing `serverState.tcpServer` from `StopMCPBridge` causes the blocking `server:accept()` in the worker thread to return with an error, which is caught by the `while not thread.Terminated` loop check. The 1-second accept timeout also ensures the thread checks `thread.Terminated` at least once per second.

Startup log message reflects transport:
```
[MCP v12.0.0] MCP Server Listening on: CE_MCP_Bridge_v99           (pipe mode)
[MCP v12.0.0] MCP Server Listening on: tcp://0.0.0.0:28015         (tcp mode)
[MCP v12.0.0] MCP Server Listening on: tcp://0.0.0.0:28015 (polling) (timer fallback)
```

## Python Side Changes

### Base class

```python
class BaseBridgeClient(ABC):
    """Shared protocol logic: framing, timeout, retry."""

    def send_command(self, method, params=None):
        """Send JSON-RPC request with retry-once on connection failure."""
        # Builds JSON-RPC envelope, calls _exchange_with_timeout
        # Retries once on connection error (calls _connect, then retries)

    def _exchange_with_timeout(self, req_bytes):
        """Run exchange in daemon thread with timeout."""
        # Same timeout logic as current CEBridgeClient._exchange_with_timeout
        # CE_MCP_TIMEOUT env var applies to both transports

    def _exchange_once(self, req_bytes):
        """Send request, read response using abstract I/O methods."""
        # Write: pack 4-byte LE header + body, call _write_bytes
        header = struct.pack('<I', len(req_bytes))
        self._write_bytes(header + req_bytes)

        # Read: 4-byte header via _read_bytes, unpack length
        resp_header = self._read_bytes(4)
        resp_len = struct.unpack('<I', resp_header)[0]
        if resp_len > MAX_RESPONSE_SIZE_BYTES:
            raise ValueError(f"Response too large: {resp_len}")

        # Read response body via _read_bytes, decode JSON
        resp_body = self._read_bytes(resp_len)
        return json.loads(resp_body.decode('utf-8'))

    @abstractmethod
    def _connect(self): ...

    @abstractmethod
    def _read_bytes(self, n) -> bytes: ...

    @abstractmethod
    def _write_bytes(self, data: bytes): ...

    @abstractmethod
    def _close_handle(self): ...

    def close(self):
        self._close_handle()
```

### PipeBridgeClient (Windows only)

Defined only when `_HAS_WIN32 is True`.

```python
class PipeBridgeClient(BaseBridgeClient):
    """Named Pipe transport using win32file."""

    def __init__(self):
        self.handle = None

    def _connect(self):
        self.handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None
        )

    def _read_bytes(self, n):
        hr, data = win32file.ReadFile(self.handle, n)
        return bytes(data)

    def _write_bytes(self, data):
        win32file.WriteFile(self.handle, data)

    def _close_handle(self):
        if self.handle:
            win32file.CloseHandle(self.handle)
            self.handle = None
```

### TCPBridgeClient (cross-platform)

```python
class TCPBridgeClient(BaseBridgeClient):
    """TCP socket transport using stdlib socket."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None

    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    def _read_bytes(self, n):
        # TCP can fragment — loop until exactly n bytes received
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by remote")
            data += chunk
        return data

    def _write_bytes(self, data):
        self.sock.sendall(data)

    def _close_handle(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
```

### Client factory

```python
DEFAULT_TCP_PORT = 28015

def create_bridge_client():
    uri = os.environ.get("CE_MCP_URI", "")

    if not uri:
        # Default: pipe on Windows (if pywin32 available), tcp otherwise
        if _HAS_WIN32:
            return PipeBridgeClient()
        else:
            return TCPBridgeClient("127.0.0.1", DEFAULT_TCP_PORT)

    if uri == "pipe":
        if not _HAS_WIN32:
            raise RuntimeError(
                "Named Pipe transport requires Windows and pywin32. "
                "Use CE_MCP_URI=tcp:HOST:PORT for cross-platform."
            )
        return PipeBridgeClient()

    if uri.startswith("tcp:"):
        parts = uri[4:]  # strip "tcp:"
        host, port = "127.0.0.1", DEFAULT_TCP_PORT
        if ":" in parts:
            h, p = parts.rsplit(":", 1)
            if h: host = h
            if p: port = int(p)
        elif parts:
            host = parts
        return TCPBridgeClient(host, port)

    raise ValueError(
        f"Invalid CE_MCP_URI: {uri}. "
        f"Expected 'pipe' or 'tcp:HOST:PORT'."
    )

ce_client = create_bridge_client()
```

### Conditional Windows imports

```python
if sys.platform == "win32":
    import msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

# ... later, after stdout redirection block ...

try:
    import win32file
    import win32pipe
    import pywintypes
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False
```

`PipeBridgeClient` class definition is guarded by `if _HAS_WIN32:`.

### requirements.txt

Add platform marker for pywin32:

```
pywin32; sys_platform == 'win32'
```

On macOS/Linux, `pip install -r requirements.txt` skips pywin32.

## Wire Protocol

**Unchanged.** Both transports use identical framing:

```
[4 bytes: little-endian uint32 payload length] [UTF-8 JSON-RPC body]
```

- Max message size: 32 MB (enforced on both sides; the CLAUDE.md reference to "16 MB" is outdated — the code uses 32 MB)
- One client at a time (sequential accept loop)
- JSON-RPC 2.0 request/response format

### Timeout interaction

- **Python `CE_MCP_TIMEOUT`** (default 30s): applies to both transports. If the timeout fires, `_close_handle()` is called, which closes the socket/pipe and unblocks the I/O thread.
- **Lua TCP `client:settimeout(30)`**: if no data arrives for 30s, the read returns `nil, "timeout"`, the request loop breaks, and the client is disconnected. This serves as dead-peer detection.
- **Interaction:** If Python times out and closes the TCP socket, the Lua side's next `receive()` returns `nil, "closed"`, the loop breaks gracefully, and the worker accepts a new connection.

### Version handshake (TCP only)

Named Pipes use the versioned pipe name (`CE_MCP_Bridge_v99`) as an implicit compatibility gate — mismatched versions simply can't connect. TCP has no such mechanism, so we add an explicit handshake.

**Lua `cmd_ping` change required:** The current `cmd_ping` (line 1701-1708) returns `version` (app version `"12.0.0"`) but does **not** return the wire protocol version. Two new fields must be added:

```lua
local function cmd_ping(params)
    return {
        success = true,
        version = VERSION,                        -- existing: "12.0.0"
        protocol_version = WIRE_PROTOCOL_VERSION,  -- NEW: 99 (integer)
        transport = serverState.transportMode,      -- NEW: "pipe" or "tcp"
        timestamp = os.time(),
        process_id = getOpenedProcessID() or 0,
        message = "CE MCP Bridge v" .. VERSION .. " alive"
    }
end
```

Where `WIRE_PROTOCOL_VERSION = 99` is extracted from the pipe name constant so both share a single source of truth:
```lua
local WIRE_PROTOCOL_VERSION = 99
local PIPE_NAME = "CE_MCP_Bridge_v" .. WIRE_PROTOCOL_VERSION
```

**Protocol:** On first TCP connect, the Python client sends a `ping` command and checks `protocol_version`:

- **Match:** Connection proceeds normally.
- **Missing field:** Treated as mismatch (old server without the field).
- **Mismatch:** Connection **refused** with clear error: `"Protocol version mismatch: server=XX, expected=99. Update your bridge."` This matches Named Pipe behavior where mismatched pipe names prevent connection entirely.

**Docs that must reflect the `cmd_ping` schema change:**
- `AI_Context/MCP_Bridge_Command_Reference.md` — update ping response example
- `MCP_Server/test_mcp.py` — update ping test assertions to check new fields

```python
# In TCPBridgeClient._connect():
def _connect(self):
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Apply timeout to connect() itself so it doesn't block forever
    connect_timeout = self._get_timeout()  # CE_MCP_TIMEOUT, default 30s
    self.sock.settimeout(connect_timeout)
    self.sock.connect((self.host, self.port))
    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # Clear socket-level timeout — per-exchange timeout is handled by
    # the daemon-thread wrapper in _exchange_with_timeout()
    self.sock.settimeout(None)

    # Version handshake (also runs under _exchange_with_timeout)
    result = self._do_version_handshake()
    server_version = result.get("result", {}).get("protocol_version")
    if str(server_version) != str(WIRE_PROTOCOL_VERSION):
        self._close_handle()
        raise ConnectionError(
            f"Protocol version mismatch: server={server_version}, "
            f"expected={WIRE_PROTOCOL_VERSION}. Update your bridge."
        )

def _do_version_handshake(self):
    """Send ping and validate version. Runs under CE_MCP_TIMEOUT."""
    return self._exchange_with_timeout(
        self._build_request("ping", {})
    )
```

**Timeout coverage:** `socket.connect()` uses `socket.settimeout(connect_timeout)` so a non-routable LAN IP fails in ≤30s instead of the OS default (~120s). The version handshake runs through `_exchange_with_timeout` for consistent timeout handling. After connect, the socket timeout is cleared because per-exchange timeout is handled by the daemon-thread wrapper that closes the socket on timeout.

`WIRE_PROTOCOL_VERSION = 99` is defined alongside `PIPE_NAME` so both reference the same version number.

## AI Context Updates

### CLAUDE.md additions

Add to the **Environment & safety constraints** section:

```markdown
- **Transport:** `CE_MCP_URI` env var controls connection.
  `pipe` (default on Windows), `tcp:HOST:PORT` for LAN/Mac.
  Default TCP port is 28015. Lua script auto-detects:
  pipe if `createPipe` exists, TCP otherwise.
  Set `TCP_HOST = "0.0.0.0"` in the Lua config to accept LAN connections.
```

### AI_Guide_MCP_Server_Implementation.md

Add a new section **"Cross-Platform / LAN Transport"** covering:
- Transport auto-detection logic
- `CE_MCP_URI` syntax
- Lua `TRANSPORT_MODE` / `TCP_HOST` / `TCP_PORT` config
- Network topology diagram (Mac CE <-TCP-> Windows MCP server)
- Socket library requirements (LuaSocket)
- Known limitations (IPv4 only, no auth, no TLS, GUI freeze in polling mode)

### MCP_Bridge_Command_Reference.md

Add a **"Connection Setup"** section at the top with:
- Local Windows setup (unchanged, pipe default)
- LAN setup (set `CE_MCP_URI=tcp:IP:28015`, set `TCP_HOST = "0.0.0.0"` in Lua)
- Mac CE setup (auto-detects TCP, ensure LuaSocket is available, load script)

## Files Modified

| File | Change |
|------|--------|
| `MCP_Server/ce_mcp_bridge.lua` | Add TCP config vars, `loadSocketLib()`, `detectTransport()`, `processRequestLoop()`, `TCPWorker`, polling fallback, TCP version handshake, update `Start/StopMCPBridge`, new `serverState` fields |
| `MCP_Server/mcp_cheatengine.py` | Add `BaseBridgeClient`, `PipeBridgeClient`, `TCPBridgeClient`, `create_bridge_client()`, conditional Windows imports, TCP version handshake |
| `MCP_Server/test_mcp.py` | Add `CE_MCP_URI` support to test harness, transport-aware connection setup, TCP test scenarios |
| `MCP_Server/requirements.txt` | Add platform marker for pywin32 |
| `MCP_Server/lib/README.md` | LuaSocket build instructions for each platform |
| `README.md` | Add cross-platform section, TCP/LAN setup instructions, Mac CE setup guide |
| `CLAUDE.md` | Add transport config docs |
| `AI_Context/AI_Guide_MCP_Server_Implementation.md` | Add cross-platform/LAN section |
| `AI_Context/MCP_Bridge_Command_Reference.md` | Add connection setup section |

## Testing

Manual testing matrix:

| Scenario | Transport | Expected |
|----------|-----------|----------|
| Windows local, no env var | Pipe | Works as before |
| Windows local, `CE_MCP_URI=tcp::28015` | TCP loopback | Works |
| Windows → Mac LAN, `CE_MCP_URI=tcp:192.168.x.x:28015` | TCP LAN | Works |
| Mac local, no env var | TCP loopback | Works (auto-detect) |
| Mac, `CE_MCP_URI=pipe` | — | Error: requires Windows / pywin32 |
| CE without `createThread` on Mac | TCP polling | Works (GUI freezes during phase 2 command execution) |
| CE without LuaSocket | — | Error logged, bridge does not start |
| TCP version mismatch | TCP | Hard failure: "Protocol version mismatch" error |
| Python timeout during TCP exchange | TCP | Socket closed, Lua detects and re-accepts |
| CE script reload during active TCP connection | TCP | Clean teardown via StopMCPBridge |

Run `test_mcp.py` against each transport to validate all ~180 tools work identically.

## Known Limitations

- **IPv4 only.** `CE_MCP_URI` parser does not handle IPv6 bracket notation. IPv6 support is a future enhancement.
- **No authentication.** Anyone who can reach the TCP port can send commands. Rely on network-level security (firewall, trusted LAN).
- **No TLS/encryption.** All traffic is plaintext. Suitable for trusted LANs only.
- **Single client.** Only one MCP server can connect at a time, same as the pipe model.
- **LuaSocket dependency.** TCP mode on the Lua side requires LuaSocket. If the CE build doesn't bundle it, the user must install it manually or the bridge ships the binary.
- **Polling mode GUI freeze.** If `createThread` is unavailable, commands block the CE GUI for their duration.
- **Port 28015 collision.** This port is also used by RethinkDB. If a conflict occurs, change `TCP_PORT` in the Lua config and the port in `CE_MCP_URI` (e.g., `CE_MCP_URI=tcp::52015`).

## Non-Goals

- TLS/encryption
- Authentication (shared secret)
- Multiple concurrent clients
- UDP or WebSocket transport
- IPv6 support (this version)
