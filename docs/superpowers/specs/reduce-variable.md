# Reduce Local Variables in ce_mcp_bridge.lua

## Objective

Refactor `MCP_Server/ce_mcp_bridge.lua` so the file stays under Lua 5.3's 200 locals-per-chunk limit (currently at ~260), with no behavior change to the MCP bridge.

## Constraints

- Preserve all JSON-RPC method names.
- Preserve all existing aliases.
- Preserve transport behavior (pipe / tcp / fifo / auto).
- Keep the refactor low-risk and purely structural.
- Avoid changing helper behavior unless required for scoping.

---

## Current state (verified)

- **260 top-level locals** total (233 `local function` + 27 `local` vars/tables).
- **173 `local function cmd_*`** handlers — the primary source of the limit breach.
- **`commandHandlers`** is a monolithic table literal at **line 5352** (closing ~line 5583) that maps string keys to `cmd_*` references and includes aliases.
- **1 cross-call**: `cmd_aob_scan_module_unique` (line 3728) calls `cmd_aob_scan_module` directly (line 3733).
- **Intentionally shadowed helpers**: `requireProcess` is declared 4 times, `sanitizeFilename` twice across different unit sections. These shadow each other by design — code between declarations uses the nearest-above version. This refactor will **not** touch them.
- After converting 173 `cmd_*` locals to table assignments, top-level locals drop to ~87, well under 200.

---

## Proposed approach

Declare `local commandHandlers = {}` early, convert `cmd_*` locals to table-assigned functions, delete the giant dispatcher literal, keep only alias assignments. This removes 173 locals with minimal structural risk.

---

## Ordered steps

### 1. Move the dispatcher table declaration to the top

The `commandHandlers` table already exists as a monolithic literal at line 5352. Replace it with an empty table declared **before the first handler section**:

```lua
local commandHandlers = {}
```

The giant literal at line 5352-5583 will be deleted in step 4.

---

### 2. Convert top-level `cmd_*` handlers into table functions

For each command handler, change:

```lua
local function cmd_read_memory(params)
  ...
end
```

to:

```lua
function commandHandlers.read_memory(params)
  ...
end
```

Apply this to all 173 `cmd_*` handlers. Strip the `cmd_` prefix since the table key is already the method name.

---

### 3. Preserve shared helpers as locals

Keep true shared helpers as `local function`/`local` where that improves readability and reuse:

- `toHex`, `parseAddress`, `paginate`
- JSON encode/decode helpers
- Transport helpers
- Section-specific utility tables
- Intentionally-shadowed helpers (`requireProcess` x4, `sanitizeFilename` x2)

These contribute ~60 locals total, well within budget. Do not touch them.

---

### 4. Delete the giant dispatcher table, keep only aliases

Delete the monolithic `commandHandlers = { ... }` literal (lines 5352-5583). After step 2, all handlers are already on the table. Add only alias assignments:

```lua
-- Aliases
commandHandlers.read_bytes = commandHandlers.read_memory
commandHandlers.pattern_scan = commandHandlers.aob_scan
commandHandlers.set_execution_breakpoint = commandHandlers.set_breakpoint
-- ... all other aliases from the old table
```

---

### 5. Fix the one known cross-call

`cmd_aob_scan_module_unique` (line ~3728) calls `cmd_aob_scan_module(params)` directly. Update to:

```lua
commandHandlers.aob_scan_module(params)
```

No other `cmd_*` → `cmd_*` cross-calls exist.

---

### 6. Keep transport/boot logic unchanged

Do not restructure:

- `executeCommand`
- socket loading
- transport detection
- worker loops
- server startup

Only change them where needed to reference the new `commandHandlers` table (e.g., if `executeCommand` uses `commandHandlers[method]` it already works).

---

## Validation steps

### Static validation

1. Count top-level locals: `grep -c "^local " ce_mcp_bridge.lua` — must be under 200 (target: ~87).
2. Count `commandHandlers` keys: extract all `commandHandlers.XXX` assignments and `commandHandlers.XXX = commandHandlers.YYY` aliases. Total key count must match pre-refactor dispatcher entry count.
3. Verify `executeCommand` still resolves handlers via `commandHandlers[method]` — no change expected.
4. Search for any remaining `cmd_` references that are now broken: `grep "cmd_" ce_mcp_bridge.lua` should return zero handler-name references (only comment/string occurrences).

### Runtime validation

If CE is available, run `test_mcp.py` (the project's only test harness). Otherwise, smoke-test:

- `ping`
- `get_process_info`
- `read_memory`
- `write_memory`
- `aob_scan_module_unique` (exercises the cross-call fix)
- One transport startup path

---

## Risks

| Risk | Detail | Mitigation |
|------|--------|------------|
| Missed aliases | An alias from the old dispatcher is skipped, silently removing an RPC method | Diff old dispatcher keys against new `commandHandlers` keys + alias assignments |
| Broken cross-call | `cmd_aob_scan_module_unique` → `cmd_aob_scan_module` reference breaks | Explicitly fix this one known case (step 5) |
| Shadowed helper breakage | Moving `requireProcess` or `sanitizeFilename` could break intentional shadowing | Don't touch them — they stay as `local function` in their current positions |
| Accidental behavior changes | Temptation to "clean up" unrelated logic during rename | Keep this refactor purely structural |

---

## Fallback plan

If direct table-assignment is still not enough or becomes messy, split handlers by unit into subtables:

```lua
local commandHandlers = {}
local processHandlers = {}
local memoryHandlers = {}
```

then merge into `commandHandlers`. Only use if the single-table approach proves insufficient (unlikely given 87 << 200).

Alternatively, wrap section-only helpers in `do...end` scopes to further reduce locals if needed:

```lua
do
  local function sectionHelper() ... end
  function commandHandlers.some_method(params)
    sectionHelper()
  end
end
```
