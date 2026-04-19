# TCP/LAN Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TCP socket transport alongside Named Pipes so the MCP bridge works over LAN and on non-Windows CE builds.

**Architecture:** Dual transport (pipe + TCP) with shared wire protocol. Python side uses a `BaseBridgeClient` ABC with `PipeBridgeClient` and `TCPBridgeClient` subclasses. Lua side uses a shared `processRequestLoop()` with transport-specific I/O callbacks. Transport is auto-detected or configured via env var.

**Tech Stack:** Python stdlib `socket` + `abc`, LuaSocket for Lua TCP, existing `win32file` for pipe path.

**Spec:** `docs/superpowers/specs/2026-04-18-tcp-lan-transport-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `MCP_Server/mcp_cheatengine.py` | Modify | Refactor client into base + pipe + TCP classes, conditional imports, factory |
| `MCP_Server/ce_mcp_bridge.lua` | Modify | Add TCP transport, shared request loop, transport detection, updated start/stop |
| `MCP_Server/test_mcp.py` | Modify | Transport-aware test client, TCP connection path |
| `MCP_Server/requirements.txt` | Modify | Platform-conditional pywin32 |
| `MCP_Server/lib/README.md` | Create | LuaSocket build/install instructions |
| `README.md` | Modify | Cross-platform setup section |
| `CLAUDE.md` | Modify | Transport config docs |
| `AI_Context/AI_Guide_MCP_Server_Implementation.md` | Modify | Cross-platform/LAN architecture section |
| `AI_Context/MCP_Bridge_Command_Reference.md` | Modify | Connection setup, updated ping schema |

---

### Task 1: Lua — Extract wire protocol version constant and update cmd_ping

**Files:**
- Modify: `MCP_Server/ce_mcp_bridge.lua:5-6` (constants), `MCP_Server/ce_mcp_bridge.lua:1701-1709` (cmd_ping)

This is a standalone, backward-compatible change that establishes the `WIRE_PROTOCOL_VERSION` constant and adds `protocol_version` + `transport` fields to `cmd_ping`. Must be done first since the TCP handshake depends on it.

- [ ] **Step 1: Add WIRE_PROTOCOL_VERSION constant**

At line 5-6 of `ce_mcp_bridge.lua`, replace the hardcoded pipe name:

```lua
-- Before:
local PIPE_NAME = "CE_MCP_Bridge_v99"
local VERSION = "12.0.0"

-- After:
local WIRE_PROTOCOL_VERSION = 99
local PIPE_NAME = "CE_MCP_Bridge_v" .. WIRE_PROTOCOL_VERSION
local VERSION = "12.0.0"
```

- [ ] **Step 2: Add new fields to cmd_ping**

At line 1701-1709 of `ce_mcp_bridge.lua`, update `cmd_ping`:

```lua
local function cmd_ping(params)
    return {
        success = true,
        version = VERSION,
        protocol_version = WIRE_PROTOCOL_VERSION,
        transport = serverState.transportMode or "pipe",
        timestamp = os.time(),
        process_id = getOpenedProcessID() or 0,
        message = "CE MCP Bridge v" .. VERSION .. " alive"
    }
end
```

- [ ] **Step 3: Add transportMode to serverState**

At line 13 of `ce_mcp_bridge.lua`, inside the `serverState` table (after `connected = false,`), add the new field. Do not remove any existing fields:

```lua
-- Add this line after "connected = false," (line 13):
    transportMode = nil,  -- "pipe" or "tcp", set by StartMCPBridge
```

- [ ] **Step 4: Set transportMode in StartMCPBridge**

At line 5732 of `ce_mcp_bridge.lua`, in `StartMCPBridge`, add after `StopMCPBridge()`:

```lua
serverState.transportMode = "pipe"
```

This is temporary — Task 5 will replace this with `detectTransport()`.

- [ ] **Step 5: Verify manually**

Reload the Lua script in CE. Send a `ping` command via the existing pipe connection. Verify the response now includes `protocol_version: 99` and `transport: "pipe"`.

- [ ] **Step 6: Commit**

```bash
git add MCP_Server/ce_mcp_bridge.lua
git commit -m "feat: add WIRE_PROTOCOL_VERSION constant and protocol_version/transport to ping response"
```

---

### Task 2: Python — Refactor CEBridgeClient into BaseBridgeClient + PipeBridgeClient

**Files:**
- Modify: `MCP_Server/mcp_cheatengine.py:96-283` (imports, client class, singleton)

Pure refactor — no new functionality. The existing pipe transport must work identically after this change.

- [ ] **Step 1: Make Windows imports conditional and separate FastMCP**

**Note:** The `msvcrt` block at lines 12-19 is already guarded by `if sys.platform == "win32"`. No change needed there.

The import block at lines 96-111 bundles win32 imports with `FastMCP` and the `fastmcp_server` monkey-patch. These must be separated because `FastMCP` is cross-platform but win32 is not. Restructure lines 96-114 as follows:

```python
# Cross-platform MCP SDK import
from mcp.server.fastmcp import FastMCP

# Windows-only imports for Named Pipe transport
try:
    import win32file
    import win32pipe
    import win32con
    import pywintypes
    _HAS_WIN32 = True
    # Patch FastMCP's stdio_server reference (Windows CRLF fix)
    if sys.platform == "win32":
        import mcp.server.fastmcp.server as fastmcp_server
        fastmcp_server.stdio_server = _patched_stdio_server
except ImportError:
    _HAS_WIN32 = False

# Restore stdout for MCP usage after imports are complete
sys.stdout = _mcp_stdout
```

**Key changes from the original:**
- `from mcp.server.fastmcp import FastMCP` moved **before** the try/except block (it's cross-platform)
- `except ImportError` now sets `_HAS_WIN32 = False` instead of calling `sys.exit(1)` — the server can still run with TCP transport
- The `fastmcp_server` monkey-patch stays inside the win32 guard
- `sys.stdout = _mcp_stdout` restore (line 114) stays after the block

- [ ] **Step 2: Add WIRE_PROTOCOL_VERSION constant**

At line 135 of `mcp_cheatengine.py`, alongside the existing constants:

```python
PIPE_NAME = r"\\.\pipe\CE_MCP_Bridge_v99"
WIRE_PROTOCOL_VERSION = 99
```

- [ ] **Step 3: Extract BaseBridgeClient**

Replace the `CEBridgeClient` class (lines 161-282) with `BaseBridgeClient` that contains the shared logic. Use `abc.ABC` and `abstractmethod`. The key methods to move to base:

```python
from abc import ABC, abstractmethod

class BaseBridgeClient(ABC):
    """Shared wire protocol: 4-byte LE framing, JSON-RPC, timeout, retry."""

    def __init__(self):
        pass

    @abstractmethod
    def _connect(self):
        """Establish transport connection."""
        ...

    @abstractmethod
    def _read_bytes(self, n: int) -> bytes:
        """Read exactly n bytes from transport."""
        ...

    @abstractmethod
    def _write_bytes(self, data: bytes) -> None:
        """Write all bytes to transport."""
        ...

    @abstractmethod
    def _close_handle(self) -> None:
        """Close transport handle/socket."""
        ...

    @abstractmethod
    def _is_connected(self) -> bool:
        """Return True if transport handle is open."""
        ...

    def _exchange_once(self, req_bytes: bytes):
        """Send request bytes, receive JSON-RPC response. Uses abstract I/O.

        Args:
            req_bytes: UTF-8 encoded JSON-RPC request (already encoded)
        """
        header = struct.pack('<I', len(req_bytes))
        self._write_bytes(header)
        self._write_bytes(req_bytes)

        resp_header = self._read_bytes(4)
        resp_len = struct.unpack('<I', resp_header)[0]
        if resp_len > MAX_RESPONSE_SIZE_BYTES:
            raise ValueError(f"Response exceeds {MAX_RESPONSE_SIZE_BYTES} bytes: {resp_len}")

        resp_body = self._read_bytes(resp_len)
        return json.loads(resp_body.decode('utf-8'))

    def _exchange_with_timeout(self, req_bytes: bytes, method: str = ""):
        """Run _exchange_once in a daemon thread with CE_MCP_TIMEOUT.

        Args:
            req_bytes: UTF-8 encoded JSON-RPC request (already encoded)
        """
        # Copy the existing timeout logic from CEBridgeClient._exchange_with_timeout
        # (lines 203-231) — daemon thread, join with timeout, close handle on timeout

    def _build_request(self, method: str, params: dict) -> bytes:
        """Build and encode a JSON-RPC request."""
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": int(time.time() * 1000)
        }
        return json.dumps(request).encode('utf-8')

    def send_command(self, method: str, params: dict = None):
        """Send command with retry-once on connection failure.

        Catches (ConnectionError, TimeoutError, OSError) for transport-agnostic
        error handling. Subclass I/O methods should convert transport-specific
        errors to these types (e.g., PipeBridgeClient wraps pywintypes.error).
        """
        max_retries = 2
        last_error = None
        for attempt in range(max_retries):
            if not self._is_connected():
                self._connect()

            try:
                req_bytes = self._build_request(method, params)
                response = self._exchange_with_timeout(req_bytes, method)
                if 'error' in response:
                    return {"success": False, "error": str(response['error'])}
                if 'result' in response:
                    return response['result']
                return response

            except (ConnectionError, TimeoutError, OSError) as e:
                self._close_handle()
                last_error = e
                if attempt < max_retries - 1:
                    continue

        if last_error:
            raise last_error
        raise ConnectionError("Unknown communication error")

    def close(self):
        self._close_handle()
```

- [ ] **Step 4: Create PipeBridgeClient**

Guard with `if _HAS_WIN32:` so it's only defined on Windows:

```python
if _HAS_WIN32:
    class PipeBridgeClient(BaseBridgeClient):
        """Named Pipe transport using win32file."""

        def __init__(self):
            super().__init__()
            self.handle = None

        def _connect(self):
            self.handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None
            )

        def _read_bytes(self, n):
            try:
                hr, data = win32file.ReadFile(self.handle, n)
                return bytes(data)
            except pywintypes.error as e:
                raise ConnectionError(f"Pipe read failed: {e}") from e

        def _write_bytes(self, data):
            try:
                win32file.WriteFile(self.handle, data)
            except pywintypes.error as e:
                raise ConnectionError(f"Pipe write failed: {e}") from e

        def _close_handle(self):
            if self.handle:
                try:
                    win32file.CloseHandle(self.handle)
                except Exception:
                    pass
                self.handle = None

        def _is_connected(self):
            return self.handle is not None
```

- [ ] **Step 5: Temporarily instantiate PipeBridgeClient as the singleton**

Replace line 283:

```python
# Before:
ce_client = CEBridgeClient()

# After:
ce_client = PipeBridgeClient()
```

This is temporary — Task 3 adds the factory.

- [ ] **Step 6: Remove the old CEBridgeClient class**

Delete the old class entirely. Verify no references remain.

- [ ] **Step 7: Test the refactor on Windows**

Run the MCP server and verify existing pipe transport works:
- Start CE, load `ce_mcp_bridge.lua`
- Run `python MCP_Server/mcp_cheatengine.py` (it should connect over pipe as before)
- Or run `python MCP_Server/test_mcp.py` if CE is attached to a process

- [ ] **Step 8: Commit**

```bash
git add MCP_Server/mcp_cheatengine.py
git commit -m "refactor: extract BaseBridgeClient ABC from CEBridgeClient, rename to PipeBridgeClient"
```

---

### Task 3: Python — Add TCPBridgeClient and client factory

**Files:**
- Modify: `MCP_Server/mcp_cheatengine.py` (add TCP class, factory, env var parsing)

- [ ] **Step 1: Add socket import**

At the top of `mcp_cheatengine.py` (near other stdlib imports):

```python
import socket as socket_module  # avoid shadowing with local vars
```

- [ ] **Step 2: Add DEFAULT_TCP_PORT constant**

Near the other constants:

```python
DEFAULT_TCP_PORT = 28015
```

- [ ] **Step 3: Add TCPBridgeClient class**

After `PipeBridgeClient`:

```python
class TCPBridgeClient(BaseBridgeClient):
    """TCP socket transport using stdlib socket. Cross-platform."""

    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = None

    def _connect(self):
        self.sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
        connect_timeout = CE_MCP_TIMEOUT_SECONDS if CE_MCP_TIMEOUT_SECONDS > 0 else 30
        self.sock.settimeout(connect_timeout)
        self.sock.connect((self.host, self.port))
        self.sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_KEEPALIVE, 1)
        self.sock.settimeout(None)  # per-exchange timeout handled by daemon thread

        # TCP version handshake
        req_json = self._build_request("ping", {})
        result = self._exchange_with_timeout(req_json, "ping")
        ping_result = result.get("result", {})
        server_version = ping_result.get("protocol_version")
        if str(server_version) != str(WIRE_PROTOCOL_VERSION):
            self._close_handle()
            raise ConnectionError(
                f"Protocol version mismatch: server={server_version}, "
                f"expected={WIRE_PROTOCOL_VERSION}. Update your CE MCP bridge."
            )
        debug_log(f"TCP handshake OK: protocol_version={server_version}, "
                  f"transport={ping_result.get('transport')}")

    def _read_bytes(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("TCP connection closed by remote")
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

    def _is_connected(self):
        return self.sock is not None
```

- [ ] **Step 4: Add create_bridge_client factory**

Replace the direct singleton instantiation:

```python
def create_bridge_client():
    """Create transport client based on CE_MCP_URI env var."""
    uri = os.environ.get("CE_MCP_URI", "")

    if not uri:
        if _HAS_WIN32:
            debug_log("CE_MCP_URI not set, using Named Pipe (Windows default)")
            return PipeBridgeClient()
        else:
            debug_log(f"CE_MCP_URI not set, using TCP localhost:{DEFAULT_TCP_PORT} (non-Windows default)")
            return TCPBridgeClient("127.0.0.1", DEFAULT_TCP_PORT)

    if uri == "pipe":
        if not _HAS_WIN32:
            raise RuntimeError(
                "Named Pipe transport requires Windows and pywin32. "
                "Use CE_MCP_URI=tcp:HOST:PORT for cross-platform."
            )
        debug_log("CE_MCP_URI=pipe, using Named Pipe")
        return PipeBridgeClient()

    if uri.startswith("tcp:"):
        parts = uri[4:]  # strip "tcp:"
        host, port = "127.0.0.1", DEFAULT_TCP_PORT
        if ":" in parts:
            h, p = parts.rsplit(":", 1)
            if h:
                host = h
            if p:
                port = int(p)
        elif parts:
            host = parts
        debug_log(f"CE_MCP_URI={uri}, using TCP {host}:{port}")
        return TCPBridgeClient(host, port)

    raise ValueError(
        f"Invalid CE_MCP_URI: {uri!r}. "
        f"Expected 'pipe' or 'tcp:HOST:PORT'."
    )

ce_client = create_bridge_client()
```

- [ ] **Step 5: Verify pipe still works**

With `CE_MCP_URI` unset on Windows, verify the factory selects `PipeBridgeClient` and everything works as before.

- [ ] **Step 6: Commit**

```bash
git add MCP_Server/mcp_cheatengine.py
git commit -m "feat: add TCPBridgeClient and create_bridge_client factory with CE_MCP_URI support"
```

---

### Task 4: Lua — Add TCP transport config and socket loading

**Files:**
- Modify: `MCP_Server/ce_mcp_bridge.lua:1-20` (config block), new functions near line 5600

This task adds the config variables, `loadSocketLib()`, and `detectTransport()` but does NOT yet wire them into Start/StopMCPBridge. That happens in Task 5.

- [ ] **Step 1: Add TCP config variables**

After the `VERSION` line at the top of `ce_mcp_bridge.lua`:

```lua
local WIRE_PROTOCOL_VERSION = 99
local PIPE_NAME = "CE_MCP_Bridge_v" .. WIRE_PROTOCOL_VERSION
local VERSION = "12.0.0"

-- Transport configuration
local TRANSPORT_MODE = "auto"   -- "pipe" | "tcp" | "auto"
local TCP_HOST = "127.0.0.1"   -- bind address (change to "0.0.0.0" for LAN)
local TCP_PORT = 28015          -- TCP listen port
```

- [ ] **Step 2: Add LuaSocket cpath setup and loadSocketLib**

Before the `PipeWorker` function (around line 5600), add:

```lua
-- ============================================================================
-- TCP SOCKET LIBRARY LOADING
-- ============================================================================

-- Add bundled lib directory to cpath for LuaSocket
local function setupSocketCpath()
    local scriptPath = nil
    pcall(function()
        scriptPath = extractDir(getMainForm().getAutoAttachList().getScript())
    end)
    if scriptPath then
        package.cpath = scriptPath .. "/lib/?.so;" ..
                        scriptPath .. "/lib/?.dll;" ..
                        package.cpath
    end
end
setupSocketCpath()

local _socketLib = nil
local function loadSocketLib()
    if _socketLib then return _socketLib end
    local ok, sock = pcall(require, "socket")
    if ok and sock and type(sock.bind) == "function" then
        _socketLib = sock
        return sock
    end
    return nil
end
```

- [ ] **Step 3: Add detectTransport**

After `loadSocketLib`:

```lua
local function detectTransport()
    if TRANSPORT_MODE == "pipe" then return "pipe" end
    if TRANSPORT_MODE == "tcp" then
        if not loadSocketLib() then
            log("[MCP] ERROR: TCP transport requested but LuaSocket not found.")
            log("[MCP] Ensure socket.so/socket.dll is in MCP_Server/lib/.")
            return nil
        end
        return "tcp"
    end
    -- auto: pipe if available, else tcp
    if type(createPipe) == "function" then return "pipe" end
    if loadSocketLib() then return "tcp" end
    log("[MCP] ERROR: No transport available (no createPipe, no socket library).")
    return nil
end
```

- [ ] **Step 4: Verify script loads without errors**

Reload the Lua script in CE (`File → Execute Script`). Verify it loads and the pipe server starts as before. The new functions (`loadSocketLib`, `detectTransport`) are defined but not yet called from `StartMCPBridge`.

- [ ] **Step 5: Commit**

```bash
git add MCP_Server/ce_mcp_bridge.lua
git commit -m "feat: add TCP config vars, loadSocketLib, and detectTransport"
```

---

### Task 5: Lua — Add processRequestLoop, TCPWorker, and updated Start/Stop

**Files:**
- Modify: `MCP_Server/ce_mcp_bridge.lua:5605-5752` (PipeWorker, Start/Stop area)

This is the core Lua change. Refactor PipeWorker to use the shared loop, add TCPWorker, add polling fallback, update Start/StopMCPBridge.

- [ ] **Step 1: Add processRequestLoop**

Before `PipeWorker`, add the shared request loop:

```lua
-- ============================================================================
-- SHARED REQUEST LOOP (used by both PipeWorker and TCPWorker)
-- ============================================================================

local function processRequestLoop(thread, readFn, writeFn, isConnectedFn)
    while not thread.Terminated and isConnectedFn() do
        local ok, headerStr = pcall(readFn, 4)
        if not ok or not headerStr or #headerStr < 4 then break end

        local b1, b2, b3, b4 = string.byte(headerStr, 1, 4)
        local len = b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
        if len <= 0 or len >= 32 * 1024 * 1024 then break end

        local ok2, payload = pcall(readFn, len)
        if not ok2 or not payload then break end

        local response
        thread.synchronize(function()
            response = executeCommand(payload)
        end)

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

- [ ] **Step 2: Refactor PipeWorker to use processRequestLoop**

Replace the inline request loop in `PipeWorker` (lines 5638-5678) with a call to `processRequestLoop`. Keep the outer accept loop and pipe creation as-is. The key change is inside the `while not thread.Terminated and pipe.Connected do` block:

```lua
local function PipeWorker(thread)
    log("Worker Thread Started - Waiting for connection...")

    while not thread.Terminated do
        local pipe = createPipe(PIPE_NAME, 262144, 262144)
        if not pipe then
            log("Fatal: Failed to create pipe")
            return
        end
        serverState.workerPipe = pipe

        pcall(function() pipe.acceptConnection() end)

        if pipe.Connected and not thread.Terminated then
            log("Client Connected")
            serverState.connected = true

            -- Pipe readFn: header as byte table → string, payload as string
            local function readFn(n)
                if n <= 4 then
                    local bytes = pipe.readBytes(n)
                    if not bytes then return nil end
                    return string.char(table.unpack(bytes))
                end
                return pipe.readString(n)
            end

            local function writeFn(data)
                -- Split header (first 4 bytes) and body for pipe API
                local headerBytes = {string.byte(data, 1, 4)}
                pipe.writeBytes(headerBytes)
                if #data > 4 then
                    pipe.writeString(string.sub(data, 5))
                end
            end

            local function isConnectedFn()
                return pipe.Connected
            end

            processRequestLoop(thread, readFn, writeFn, isConnectedFn)

            serverState.connected = false
            log("Client Disconnected")
        end

        -- Preserve original cleanup order: nil before destroy prevents race
        -- with StopMCPBridge which also tries to destroy workerPipe
        serverState.workerPipe = nil
        pcall(function()
            if pipe then pipe.destroy() end
        end)

        if not thread.Terminated then
            sleep(50)
        end
    end
end
```

- [ ] **Step 3: Verify pipe still works after refactor**

Reload Lua script in CE. Connect via existing pipe. Send `ping`. Verify it works identically.

- [ ] **Step 4: Add TCPWorker**

After `PipeWorker`:

```lua
-- ============================================================================
-- TCP SOCKET SERVER (THREAD-BASED)
-- ============================================================================

local function TCPWorker(thread)
    local socketLib = loadSocketLib()
    local server, err = socketLib.bind(TCP_HOST, TCP_PORT)
    if not server then
        log("[MCP] ERROR: Failed to bind TCP server: " .. (err or "unknown"))
        return
    end
    server:settimeout(1)  -- 1s accept timeout for shutdown checking
    serverState.tcpServer = server
    log(string.format("[MCP v%s] MCP Server Listening on: tcp://%s:%d",
        VERSION, TCP_HOST, TCP_PORT))

    while not thread.Terminated do
        local client, acceptErr = server:accept()
        if client then
            client:settimeout(30)
            client:setoption("keepalive", true)
            serverState.tcpClient = client
            log("TCP Client Connected")
            serverState.connected = true

            local function readFn(n)
                local data, readErr = client:receive(n)
                if not data then return nil end
                return data
            end

            local function writeFn(data)
                local total = #data
                local sent = 0
                while sent < total do
                    local i, sendErr, partial = client:send(data, sent + 1)
                    if i then
                        sent = i
                    elseif partial and partial > 0 then
                        sent = sent + partial
                    else
                        error("TCP send failed: " .. (sendErr or "unknown"))
                    end
                end
            end

            local function isConnectedFn()
                return client ~= nil and not thread.Terminated
            end

            processRequestLoop(thread, readFn, writeFn, isConnectedFn)

            pcall(function() client:close() end)
            serverState.tcpClient = nil
            serverState.connected = false
            log("TCP Client Disconnected")
        end
    end

    pcall(function() server:close() end)
    serverState.tcpServer = nil
end
```

- [ ] **Step 5: Add polling TCP fallback**

After `TCPWorker`:

```lua
-- ============================================================================
-- TCP POLLING FALLBACK (no createThread available)
-- Known limitation: GUI freezes during command execution
-- ============================================================================

local function startPollingTCPServer()
    local socketLib = loadSocketLib()
    local server, err = socketLib.bind(TCP_HOST, TCP_PORT)
    if not server then
        log("[MCP] ERROR: Failed to bind TCP server: " .. (err or "unknown"))
        return
    end
    server:settimeout(0)
    serverState.tcpServer = server
    log(string.format("[MCP v%s] MCP Server Listening on: tcp://%s:%d (polling)",
        VERSION, TCP_HOST, TCP_PORT))

    local client = nil
    local headerBuf = ""
    local pollTimer = createTimer(nil)
    pollTimer.Interval = 50

    pollTimer.OnTimer = function()
        if not client then
            client = server:accept()
            if client then
                client:settimeout(0)
                headerBuf = ""
                serverState.tcpClient = client
                serverState.connected = true
                log("TCP Client Connected (polling)")
            end
            return
        end

        if #headerBuf < 4 then
            local chunk, readErr, partial = client:receive(4 - #headerBuf)
            if chunk then
                headerBuf = headerBuf .. chunk
            elseif partial and #partial > 0 then
                headerBuf = headerBuf .. partial
            elseif readErr == "closed" then
                pcall(function() client:close() end)
                client = nil
                headerBuf = ""
                serverState.tcpClient = nil
                serverState.connected = false
                log("TCP Client Disconnected (polling)")
                return
            end
            if #headerBuf < 4 then return end
        end

        client:settimeout(30)
        local b1, b2, b3, b4 = string.byte(headerBuf, 1, 4)
        local len = b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
        headerBuf = ""

        if len <= 0 or len >= 32 * 1024 * 1024 then
            pcall(function() client:close() end)
            client = nil; serverState.tcpClient = nil; serverState.connected = false
            return
        end

        local payload, readErr = client:receive(len)
        if not payload then
            pcall(function() client:close() end)
            client = nil; serverState.tcpClient = nil; serverState.connected = false
            return
        end

        local response = executeCommand(payload)
        local respLen = #response
        local hdr = string.char(
            respLen % 256,
            math.floor(respLen / 256) % 256,
            math.floor(respLen / 65536) % 256,
            math.floor(respLen / 16777216) % 256
        )
        local fullMsg = hdr .. response
        local sent = 0
        while sent < #fullMsg do
            local i, sendErr, partial = client:send(fullMsg, sent + 1)
            if i then sent = i
            elseif partial and partial > 0 then sent = sent + partial
            else
                pcall(function() client:close() end)
                client = nil; serverState.tcpClient = nil; serverState.connected = false
                return
            end
        end
        client:settimeout(0)
    end

    pollTimer.Enabled = true
    serverState.pollTimer = pollTimer
end
```

- [ ] **Step 6: Update StopMCPBridge**

Replace the existing `StopMCPBridge` (lines 5706-5730) to handle TCP resources:

```lua
function StopMCPBridge()
    serverState.running = false

    -- Pipe cleanup (existing)
    if serverState.workerPipe then
        pcall(function() serverState.workerPipe.destroy() end)
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
        pcall(function() serverState.pollTimer.destroy() end)
        serverState.pollTimer = nil
    end

    -- Thread cleanup (existing)
    if serverState.workerThread then
        serverState.workerThread.terminate()
        serverState.workerThread.waitfor()
        pcall(function() serverState.workerThread.destroy() end)
        serverState.workerThread = nil
    end

    -- Legacy v10 timer cleanup (preserve from original, lines 5721-5724)
    if serverState.timer then
        serverState.timer.destroy()
        serverState.timer = nil
    end

    serverState.connected = false
    serverState.running = false
    serverState.transportMode = nil

    cleanupZombieState()
    log("Server Stopped")
end
```

- [ ] **Step 7: Update StartMCPBridge**

Replace the existing `StartMCPBridge` (lines 5732-5749). **Preserve the auto-start call at lines 5751-5752** (`-- Auto-start` / `StartMCPBridge()`) — it must remain after the function definition:

```lua
function StartMCPBridge()
    StopMCPBridge()

    local transport = detectTransport()
    if not transport then
        log("[MCP] Bridge not started: no transport available.")
        return
    end

    serverState.transportMode = transport
    serverState.running = true

    if transport == "pipe" then
        log(string.format("[MCP v%s] MCP Server Listening on: %s",
            VERSION, PIPE_NAME))
        serverState.workerThread = createThread(PipeWorker)
    elseif type(createThread) == "function" then
        serverState.workerThread = createThread(TCPWorker)
    else
        startPollingTCPServer()
    end
end
```

- [ ] **Step 8: Verify pipe transport still works**

Set `TRANSPORT_MODE = "pipe"` (or leave as `"auto"` on Windows). Reload script. Verify pipe works.

- [ ] **Step 9: Verify TCP transport (if LuaSocket available)**

Set `TRANSPORT_MODE = "tcp"`. Reload script. On the Python side, set `CE_MCP_URI=tcp::28015`. Verify connection and `ping`.

- [ ] **Step 10: Commit**

```bash
git add MCP_Server/ce_mcp_bridge.lua
git commit -m "feat: add TCPWorker, polling fallback, processRequestLoop, transport-aware Start/StopMCPBridge"
```

---

### Task 6: Python — Update test_mcp.py for dual transport

**Files:**
- Modify: `MCP_Server/test_mcp.py:16-92` (imports, MCPTestClient), `MCP_Server/test_mcp.py:346-356` (ping test)

- [ ] **Step 1: Make imports conditional**

Replace line 16 of `test_mcp.py`:

```python
# Before:
import win32file

# After:
import socket as socket_module
try:
    import win32file
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False
```

- [ ] **Step 2: Add CE_MCP_URI parsing and transport constants**

After the existing constants at lines 23-25 (`PIPE_NAME`, `MAX_RESPONSE_BYTES`, `EXPECTED_VERSION_PREFIX`), add the new constants:

```python
# existing constants stay as-is (lines 23-25)
DEFAULT_TCP_PORT = 28015
WIRE_PROTOCOL_VERSION = 99

def _parse_test_uri():
    """Parse CE_MCP_URI env var for test transport."""
    import os
    uri = os.environ.get("CE_MCP_URI", "")
    if not uri:
        if _HAS_WIN32:
            return "pipe", None, None
        else:
            return "tcp", "127.0.0.1", DEFAULT_TCP_PORT
    if uri == "pipe":
        return "pipe", None, None
    if uri.startswith("tcp:"):
        parts = uri[4:]
        host, port = "127.0.0.1", DEFAULT_TCP_PORT
        if ":" in parts:
            h, p = parts.rsplit(":", 1)
            if h: host = h
            if p: port = int(p)
        elif parts:
            host = parts
        return "tcp", host, port
    raise ValueError(f"Invalid CE_MCP_URI: {uri}")

TEST_TRANSPORT, TEST_HOST, TEST_PORT = _parse_test_uri()
```

- [ ] **Step 3: Add TCP support to MCPTestClient**

Refactor `MCPTestClient` to support both pipe and TCP:

```python
class MCPTestClient:
    def __init__(self):
        self.handle = None  # pipe handle
        self.sock = None    # tcp socket
        self.transport = TEST_TRANSPORT
        self.request_id = 0

    def connect(self) -> bool:
        try:
            if self.transport == "pipe":
                if not _HAS_WIN32:
                    print("ERROR: Pipe transport requires Windows + pywin32")
                    return False
                self.handle = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None, win32file.OPEN_EXISTING, 0, None
                )
                print(f"Connected to {PIPE_NAME}")
            else:
                self.sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((TEST_HOST, TEST_PORT))
                self.sock.settimeout(30)
                print(f"Connected to tcp://{TEST_HOST}:{TEST_PORT}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def _read_bytes(self, n: int) -> bytes:
        if self.transport == "pipe":
            _, data = win32file.ReadFile(self.handle, n)
            return bytes(data)
        else:
            data = b""
            while len(data) < n:
                chunk = self.sock.recv(n - len(data))
                if not chunk:
                    raise RuntimeError("TCP connection closed")
                data += chunk
            return data

    def _write_bytes(self, data: bytes):
        if self.transport == "pipe":
            win32file.WriteFile(self.handle, data)
        else:
            self.sock.sendall(data)

    def send_command(self, method: str, params: dict = None) -> dict:
        if self.transport == "pipe" and not self.handle:
            raise RuntimeError("Not connected (pipe)")
        if self.transport == "tcp" and not self.sock:
            raise RuntimeError("Not connected (tcp)")

        if params is None:
            params = {}
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        }

        data = json.dumps(request).encode('utf-8')
        header = struct.pack('<I', len(data))
        self._write_bytes(header)
        self._write_bytes(data)

        resp_header = self._read_bytes(4)
        resp_len = struct.unpack('<I', resp_header)[0]
        if resp_len <= 0 or resp_len > MAX_RESPONSE_BYTES:
            raise RuntimeError(f"Invalid response length: {resp_len}")

        resp_data = self._read_bytes(resp_len)
        return json.loads(resp_data.decode('utf-8'))

    def close(self):
        if self.handle:
            win32file.CloseHandle(self.handle)
            self.handle = None
        if self.sock:
            self.sock.close()
            self.sock = None
```

- [ ] **Step 4: Update ping test assertions**

Update the ping test (lines 346-356) to validate new fields:

```python
all_tests["ping"] = TestCase(
    "Ping", "ping",
    validators=[
        has_field("success", bool), field_equals("success", True),
        has_field("version", str), version_check(EXPECTED_VERSION_PREFIX),
        has_field("protocol_version", int),
        field_equals("protocol_version", WIRE_PROTOCOL_VERSION),
        has_field("transport", str),
        has_field("message", str), has_field("timestamp", int),
    ]
)
```

- [ ] **Step 5: Test with pipe transport**

```bash
python MCP_Server/test_mcp.py
```

- [ ] **Step 6: Test with TCP transport (if available)**

```bash
CE_MCP_URI=tcp::28015 python MCP_Server/test_mcp.py
```

- [ ] **Step 7: Commit**

```bash
git add MCP_Server/test_mcp.py
git commit -m "feat: add TCP transport support to test harness with CE_MCP_URI"
```

---

### Task 7: Update requirements.txt

**Files:**
- Modify: `MCP_Server/requirements.txt`

- [ ] **Step 1: Add platform marker**

```
# Cheat Engine MCP Bridge - Python Dependencies
# Install: pip install -r requirements.txt

# MCP SDK (Model Context Protocol) - Required for AI agent communication
mcp>=1.0.0

# Windows API bindings - Required for Named Pipe transport (Windows only)
pywin32>=306; sys_platform == 'win32'
```

- [ ] **Step 2: Commit**

```bash
git add MCP_Server/requirements.txt
git commit -m "fix: make pywin32 conditional on Windows in requirements.txt"
```

---

### Task 8: Create LuaSocket lib directory and README

**Files:**
- Create: `MCP_Server/lib/README.md`
- Create: `MCP_Server/lib/.gitkeep`

- [ ] **Step 1: Create lib directory with README**

```markdown
# LuaSocket Binaries for CE MCP Bridge

The TCP transport requires LuaSocket. Place the compiled binaries here.

## Required Files

| Platform | Files |
|----------|-------|
| macOS | `socket/core.so` |
| Windows | `socket/core.dll` |

## Building LuaSocket

### Prerequisites
- Lua 5.3 or 5.4 headers (match your CE build's Lua version)
- C compiler (gcc/clang on macOS, MSVC/MinGW on Windows)

### macOS
```sh
git clone https://github.com/lunarmodules/luasocket.git
cd luasocket
make LUAINC=/path/to/lua/include macosx
cp src/socket.so.* ../MCP_Server/lib/socket/core.so
```

### Windows
```sh
git clone https://github.com/lunarmodules/luasocket.git
cd luasocket
# Use the Lua headers from your CE installation
nmake /f makefile LUAINC=C:\path\to\lua\include
copy src\socket\core.dll ..\MCP_Server\lib\socket\core.dll
```

### Alternative: LuaRocks
```sh
luarocks install luasocket
# Copy the resulting .so/.dll to MCP_Server/lib/socket/
```

## Verifying

In Cheat Engine's Lua console:
```lua
package.cpath = "<path_to_MCP_Server>/lib/?.so;" ..
                "<path_to_MCP_Server>/lib/?.dll;" ..
                package.cpath
local socket = require("socket")
print(socket._VERSION)  -- should print "LuaSocket 3.1.0" or similar
```
```

- [ ] **Step 2: Add .gitkeep for socket subdirectory**

Create `MCP_Server/lib/socket/.gitkeep` so the directory structure exists.

- [ ] **Step 3: Add .gitignore for binaries**

Create `MCP_Server/lib/.gitignore`:
```
# LuaSocket binaries (platform-specific, not committed)
*.so
*.dll
*.dylib
```

- [ ] **Step 4: Commit**

```bash
git add MCP_Server/lib/
git commit -m "feat: add MCP_Server/lib/ for LuaSocket binaries with build instructions"
```

---

### Task 9: Update documentation — CLAUDE.md, README.md, AI Context

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `AI_Context/AI_Guide_MCP_Server_Implementation.md`
- Modify: `AI_Context/MCP_Bridge_Command_Reference.md`

- [ ] **Step 1: Update CLAUDE.md**

In the **Environment & safety constraints** section, add a new bullet:

```markdown
- **Transport:** `CE_MCP_URI` env var controls connection. `pipe` (default on Windows with pywin32), `tcp:HOST:PORT` for LAN/Mac. Default TCP port is 28015. The Lua script auto-detects: pipe if `createPipe` exists, TCP otherwise. Set `TCP_HOST = "0.0.0.0"` in the Lua config to accept LAN connections. Set `TRANSPORT_MODE` at the top of `ce_mcp_bridge.lua` to force a specific transport (`"pipe"`, `"tcp"`, or `"auto"`).
```

Also update the **Pipe name** bullet to mention the shared `WIRE_PROTOCOL_VERSION`:

```markdown
- **Pipe name** and **TCP port**: Pipe is `\\.\pipe\CE_MCP_Bridge_v99`, TCP default port is `28015`. `WIRE_PROTOCOL_VERSION = 99` is the shared version constant in both files. Keep pipe name and `WIRE_PROTOCOL_VERSION` in sync. The Python side also defines `WIRE_PROTOCOL_VERSION` for the TCP handshake.
```

- [ ] **Step 2: Update README.md**

Add a **Cross-Platform / LAN Setup** section after the Quick Start section. Include:

```markdown
### Cross-Platform / LAN Setup

The bridge supports TCP socket transport for connecting over a network or running on non-Windows CE builds (e.g., custom macOS builds).

#### LAN Setup (Windows CE → Remote MCP Server)

1. In `ce_mcp_bridge.lua`, set:
   ```lua
   local TRANSPORT_MODE = "tcp"
   local TCP_HOST = "0.0.0.0"  -- accept connections from any interface
   local TCP_PORT = 28015
   ```
2. Load the Lua script in CE as usual.
3. On the MCP server machine, set the environment variable:
   ```
   CE_MCP_URI=tcp:192.168.x.x:28015
   ```
   (Replace with the CE machine's LAN IP)

#### macOS CE Setup

1. Ensure LuaSocket is available (see `MCP_Server/lib/README.md`).
2. The bridge auto-detects TCP transport when `createPipe` is unavailable.
3. On the MCP server machine: `CE_MCP_URI=tcp:MAC_IP:28015`

#### Transport Configuration

| Env Var | Values | Default |
|---------|--------|---------|
| `CE_MCP_URI` | `pipe`, `tcp:HOST:PORT`, `tcp::PORT`, `tcp:HOST` | `pipe` (Windows), `tcp::28015` (other) |

**Security:** TCP transport has no authentication. Only use on trusted networks. `TCP_HOST` defaults to `127.0.0.1` (localhost) — set to `0.0.0.0` explicitly for LAN access.
```

Also update the **Requirements** section to note cross-platform support:

```markdown
- **Windows:** `pip install -r MCP_Server/requirements.txt` (includes pywin32)
- **macOS/Linux:** `pip install -r MCP_Server/requirements.txt` (pywin32 skipped automatically)
```

- [ ] **Step 3: Update AI_Guide_MCP_Server_Implementation.md**

Add a new section **"Cross-Platform / LAN Transport"** at the end:

```markdown
## Cross-Platform / LAN Transport

### Architecture

The bridge supports dual transport: Named Pipes (Windows local) and TCP sockets (LAN/cross-platform).

```
Mac/Linux                                     Windows
┌─────────────────┐                           ┌─────────────────┐
│ AI Client       │                           │ Cheat Engine     │
│ mcp_cheatengine │── TCP ──────────────────▶ │ ce_mcp_bridge    │
│ (TCPBridgeClient)│    tcp:192.168.x.x:28015 │ (TCPWorker)      │
└─────────────────┘                           └─────────────────┘
```

### Transport Selection

**Lua side** (`ce_mcp_bridge.lua`):
- `TRANSPORT_MODE = "auto"` (default): pipe if `createPipe` exists, else TCP
- `TRANSPORT_MODE = "pipe"`: force Named Pipe
- `TRANSPORT_MODE = "tcp"`: force TCP socket

**Python side** (`mcp_cheatengine.py`):
- `CE_MCP_URI` env var: `pipe` | `tcp:HOST:PORT`

### Wire Protocol

Both transports use identical framing: `[4-byte LE uint32 length][UTF-8 JSON-RPC body]`.

### TCP Version Handshake

TCP connections perform a `ping` handshake to verify `protocol_version` matches. Mismatch = hard failure. This replaces the implicit version gate from the pipe name (`CE_MCP_Bridge_v99`).

### Known Limitations

- IPv4 only, no TLS, no authentication
- Single client at a time
- Polling mode (no createThread) freezes GUI during commands
```

- [ ] **Step 4: Update MCP_Bridge_Command_Reference.md**

Add a **Connection Setup** section at the top, and update the `ping` response example to include `protocol_version` and `transport` fields.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md AI_Context/AI_Guide_MCP_Server_Implementation.md AI_Context/MCP_Bridge_Command_Reference.md
git commit -m "docs: add TCP/LAN transport setup instructions and updated ping schema"
```

---

### Task 10: Final verification

- [ ] **Step 1: Verify pipe transport (Windows)**

With `CE_MCP_URI` unset:
1. Load Lua script in CE
2. Run `python MCP_Server/test_mcp.py`
3. Verify all tests pass

- [ ] **Step 2: Verify TCP transport (Windows loopback)**

Set `TRANSPORT_MODE = "tcp"` in Lua script. Reload.
```bash
CE_MCP_URI=tcp::28015 python MCP_Server/test_mcp.py
```
Verify all tests pass.

- [ ] **Step 3: Verify TCP transport (LAN, if second machine available)**

Set `TCP_HOST = "0.0.0.0"` in Lua. From another machine:
```bash
CE_MCP_URI=tcp:WINDOWS_IP:28015 python MCP_Server/test_mcp.py
```

- [ ] **Step 4: Verify error cases**

- `CE_MCP_URI=pipe` on non-Windows → clear error message
- TCP to wrong port → connection refused
- TCP version mismatch (modify `WIRE_PROTOCOL_VERSION` temporarily) → hard failure

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: TCP/LAN transport for CE MCP Bridge — complete implementation"
```
