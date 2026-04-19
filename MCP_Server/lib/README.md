# LuaSocket Binaries for CE MCP Bridge

The TCP transport requires LuaSocket. Place the compiled binaries here.

## Required Files

| Platform | Files |
|----------|-------|
| macOS | `socket/core.so` |
| Windows | `socket/core.dll` |

If your LuaSocket build also produces Lua wrapper files such as `socket.lua`, place them directly under `MCP_Server/lib/` (NOT under `lib/socket/`), so `require("socket")` resolves via `lib/?.lua` → `lib/socket.lua`. The bridge also falls back to `require("socket.core")` when only the compiled core module is present.

## Building LuaSocket

### Prerequisites
- Lua 5.3 or 5.4 headers (match your CE build's Lua version)
- C compiler (gcc/clang on macOS, MSVC/MinGW on Windows)

### macOS
```sh
git clone https://github.com/lunarmodules/luasocket.git
cd luasocket
make LUAINC=/path/to/lua/include macosx
mkdir -p ../MCP_Server/lib/socket
cp src/socket.so.* ../MCP_Server/lib/socket/core.so
```

### Windows
```sh
git clone https://github.com/lunarmodules/luasocket.git
cd luasocket
# Use the Lua headers from your CE installation
nmake /f makefile LUAINC=C:\path\to\lua\include
mkdir ..\MCP_Server\lib\socket
copy src\socket\core.dll ..\MCP_Server\lib\socket\core.dll
```

### Alternative: LuaRocks
```sh
luarocks install luasocket
# Copy the resulting .so/.dll (and socket.lua if needed) to MCP_Server/lib/socket/
```

## Verifying

In Cheat Engine's Lua console:
```lua
package.path = "<path_to_MCP_Server>/lib/?.lua;" ..
               "<path_to_MCP_Server>/lib/?/init.lua;" ..
               package.path
package.cpath = "<path_to_MCP_Server>/lib/?.so;" ..
                "<path_to_MCP_Server>/lib/?.dll;" ..
                "<path_to_MCP_Server>/lib/?/core.so;" ..
                "<path_to_MCP_Server>/lib/?/core.dll;" ..
                package.cpath
local socket = package.loaded.socket or require("socket")
print(socket._VERSION or "socket loaded")
```
