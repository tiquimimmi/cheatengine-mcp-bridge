# Cheat Engine MCP Bridge — macOS Quick Reference

This reference covers only the tools that work on macOS CE (via FIFO/TCP transport).
Windows-only tools (DBVM hypervisor, DBK kernel driver, kernel memory, DLL injection, Windows shell) are excluded.

## Safety Rules

1. Prefer hardware breakpoints (debug registers) over software breakpoints.
2. Clear breakpoints when done — there are only 4 DR slots.
3. Always check `arch` in responses for 32/64-bit handling.

## Core Workflows

### Find and freeze a value
```
get_process_info → scan_all(value, type) → get_scan_results
→ [change value in game] → next_scan(new_value) → get_scan_results
→ read_integer(address) → write_integer(address, new_value)
```

### Find what writes to an address
```
set_data_breakpoint(address, access_type="w") → [trigger in game]
→ get_breakpoint_hits → disassemble(hit_address) → remove_breakpoint
```

### AOB signature scan
```
aob_scan(pattern, protection="+X") or aob_scan_module(pattern, module)
→ disassemble(address) → generate_signature(address)
```

### Trace a pointer chain
```
get_process_info → read_pointer_chain(base, offsets)
→ dissect_structure(resolved_address, size)
```

## Tool Categories

### Process & Modules
- `get_process_info(refresh_symbols=false)` — PID, name, arch, modules. Only pass `refresh_symbols=true` when symbols are stale.
- `enum_modules(offset, limit)` — list loaded modules
- `get_thread_list(offset, limit)` — list threads
- `open_process(process_id_or_name)` — attach to a process
- `get_process_list()` — list all processes
- `get_opened_process_id()` / `get_opened_process_handle()`

### Symbols
- `get_symbol_address(symbol)` — resolve symbol to address
- `get_address_info(address)` — reverse lookup
- `get_rtti_classname(address)` — C++ class name
- `register_symbol(name, address)` / `unregister_symbol(name)`
- `enum_registered_symbols()`

### Memory Reading
- `read_memory(address, size)` — raw bytes
- `read_integer(address, type)` — types: byte/word/dword/qword/float/double
- `read_string(address, max_length, wide)` — ASCII/Unicode
- `read_pointer(address, offsets)` — single deref
- `read_pointer_chain(base, offsets)` — multi-level deref
- `checksum_memory(address, size)` — CRC32

### Memory Writing
- `write_integer(address, value, type)` — numeric write
- `write_memory(address, bytes)` — raw bytes
- `write_string(address, value, wide)` — string write

### Scanning
- `scan_all(value, type, protection)` — first scan
- `next_scan(value, scan_type)` — refine scan
- `get_scan_results(offset, limit)` — fetch results
- `aob_scan(pattern, protection, limit)` — AOB pattern scan
- `aob_scan_unique(pattern)` — single-match AOB
- `aob_scan_module(pattern, module_name)` — scan within module
- `aob_scan_module_unique(pattern, module_name)` — unique match in module
- `search_string(string, wide, limit)` — string search
- `generate_signature(address)` — create AOB from address
- `get_memory_regions(max)` — list memory regions

### Persistent Scans
- `create_persistent_scan(name)` → `persistent_scan_first_scan` → `persistent_scan_next_scan` → `persistent_scan_get_results` → `persistent_scan_destroy`

### Analysis & Disassembly
- `disassemble(address, count)` — disassemble instructions
- `get_instruction_info(address)` — single instruction detail
- `find_function_boundaries(address)` — find function start/end
- `analyze_function(address)` — call targets and references
- `find_references(address)` — data/code xrefs
- `find_call_references(function_address)` — who calls this
- `dissect_structure(address, size)` — auto-detect fields

### Debugging & Breakpoints
- `set_breakpoint(address, capture_registers, capture_stack)` — execution BP (hardware)
- `set_data_breakpoint(address, access_type, size)` — read/write/access BP
- `get_breakpoint_hits(id, clear)` — retrieve hits with registers
- `remove_breakpoint(id)` / `clear_all_breakpoints()`
- `list_breakpoints()` — list active BPs

### Debugger Control
- `debug_process(interface)` — attach debugger
- `debug_is_debugging()` — check if debugging
- `debug_continue(method)` — run/step
- `debug_break_thread(thread_id)` — break a thread
- `debug_detach()` — detach debugger
- `pause_process()` / `unpause_process()`

### Debug Context
- `debug_get_context(extra_regs)` — read registers
- `debug_set_context(registers)` — write registers

### Memory Management
- `allocate_memory(size, base_address, protection)` — alloc in target
- `free_memory(address, size)` — free allocated
- `get_memory_protection(address)` — query page protection
- `set_memory_protection(address, size, read, write, execute)` — change protection
- `full_access(address, size)` — set RWX
- `copy_memory(source, size, dest)` — memcpy in target
- `compare_memory(addr1, addr2, size)` — memcmp

### Scripting & Code
- `auto_assemble(script)` — run AA script
- `auto_assemble_check(script)` — validate AA script
- `assemble_instruction(address, instruction)` — assemble single instruction
- `evaluate_lua(code)` — run Lua in CE
- `generate_code_injection_script(address)` — template for code injection
- `generate_api_hook_script(module, function, ...)` — template for API hook

### Cheat Table
- `load_table(filename, merge)` / `save_table(filename)`
- `get_address_list()` — list table entries
- `create_memory_record(description, address, var_type)`
- `get_memory_record_value(id)` / `set_memory_record_value(id, value)`
- `delete_memory_record(id)`

### Structure Management
- `create_structure(name)` / `delete_structure(structure_id)`
- `add_element_to_structure(structure_id, name, offset, type)`
- `get_structure_elements(structure_id)`
- `export_structure_to_xml(structure_id)`

### File & Clipboard
- `file_exists(filename)` / `delete_file(filename)`
- `get_file_list(path)` / `get_directory_list(path)`
- `read_clipboard()` / `write_clipboard(text)`
- `write_region_to_file(address, size, filename)`
- `read_region_from_file(filename, destination)`
- `md5_memory(address, size)` / `md5_file(filename)`

### Utility
- `ping()` — connectivity check
- `beep()` / `speak_text(text)` / `play_sound(filename)`

## Excluded (Windows-only)

These tools require DBVM, DBK kernel driver, or Windows APIs and will return errors on macOS:

- `get_physical_address`, `start_dbvm_watch`, `stop_dbvm_watch`, `poll_dbvm_watch`
- `dbk_get_cr0/cr3/cr4`, `read/write_process_memory_cr3`, `map/unmap_memory`
- `dbk_writes_ignore_write_protection`, `get_physical_address_cr3`
- `allocate_kernel_memory`, `enable_kernel_symbols`
- `inject_dll`, `inject_dotnet_dll`
- `create_section`, `map_view_of_section`
- `run_command`, `shell_execute` (require `CE_MCP_ALLOW_SHELL=1` and may not work on macOS)
- `create_process`
- Input automation (`get_pixel`, `set_mouse_pos`, `key_down`, etc.) — uses Windows APIs
- Window tools (`find_window`, `send_window_message`, etc.) — uses Windows APIs
