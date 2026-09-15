# Netcat (OpenBSD) — Static Binary Analysis

Static reverse-engineering analysis of the `nc.openbsd` binary (the OpenBSD
netcat implementation shipped on Debian/Kali as `/usr/bin/nc.openbsd`),
performed using `readelf`, `objdump`, `strings`, **radare2/Cutter**, and
**Ghidra**.

The goal was to identify the binary's structure, imported functions, and
behavioral capabilities purely through static analysis — without executing
the binary — as practice for malware triage workflows where dynamic
execution isn't always safe or possible.

## Target Binary

| Property | Value |
|---|---|
| File | `nc.openbsd` |
| Format | ELF64, PIE (Position-Independent Executable), x86-64 |
| Linking | Dynamically linked, `stripped` (no symbol table) |
| Libraries | `libbsd.so.0`, `libresolv.so.2`, `libc.so.6` |
| Entry point | `0x4e80` |
| Security | `BIND_NOW` + `PIE` flags set (full RELRO-style hardening) |
| Packing | None detected — no UPX or packer signatures in strings/sections |

See [`analysis/file.txt`](analysis/file.txt) and
[`analysis/readelf_header.txt`](analysis/readelf_header.txt) for raw tool output.

## Methodology

1. **Triage** — `file` and `readelf -h` to confirm format, architecture, and
   whether the binary is stripped/packed before going further.
2. **Structure mapping** — `readelf -S` (sections) and `readelf -l` (program
   headers) to understand the binary's memory layout.
3. **Import/library analysis** — `readelf -d` and `objdump -T` to enumerate
   dynamic dependencies and imported (undefined) symbols — this is the
   fastest way to infer *capability* before reading any disassembly.
4. **String extraction** — `strings -n 6` to pull human-readable indicators
   (usage text, error messages, protocol strings) that hint at functionality.
5. **Disassembly & function discovery** — `objdump -d` for raw disassembly,
   and `radare2` (`aaa` auto-analysis + `afl`) to recover a function list
   from the stripped binary based on control-flow analysis rather than
   symbol names.
6. **Interactive review in Ghidra / Cutter** — used their decompiler views
   to read the two largest recovered functions in pseudo-C rather than raw
   assembly, to confirm the connection-handling and proxy-negotiation logic
   inferred from the imports/strings.

## Key Findings

### Imported functions reveal a socket-based network utility
Grepping the dynamic symbol table for networking/exec-related imports:

```
accept4  bind  close  connect  fwrite  getaddrinfo  getsockname
getsockopt  listen  read  readpassphrase  recvfrom  sendmsg
setsockopt  socket  strdup  write
```

This is exactly the import profile expected of netcat — full BSD sockets
API usage (`socket`/`bind`/`listen`/`accept4`/`connect`), `getaddrinfo` for
DNS resolution, and `readpassphrase` for password-prompt input.
Full list: [`analysis/r2_imports.txt`](analysis/r2_imports.txt) /
[`analysis/objdump_dynsymbols.txt`](analysis/objdump_dynsymbols.txt).

### No `execve`/`system`/`popen` import — this build cannot spawn a shell
A classic "netcat as a backdoor" concern is the `-e` flag (execute a
program, e.g. `/bin/sh`, and pipe it to the socket). Searching both the
import table and extracted strings for `execve`, `/bin/sh`, `popen`, and
`system` returned **no matches**. This confirms that OpenBSD netcat (unlike
some GNU/traditional netcat forks) is compiled **without** `-e` support —
a deliberate upstream security decision to prevent trivial reverse-shell
usage of the stock binary.

### Strings confirm SOCKS proxy and TCP hardening support
Extracted strings show proxy-related error/status messages (`"General
SOCKS server failure"`, `"Proxy authentication failed"`,
`"Proxy-Authorization: Basic %s"`) and TCP hardening options (`"TCP MD5SIG
password"`, `-S` MD5 signature flag, `-M`/`-m` TTL controls) — matching
OpenBSD netcat's documented `-x`/`-X` proxy support and `-S` TCP-MD5
option. Full list: [`analysis/strings_output.txt`](analysis/strings_output.txt).

### Function recovery on a stripped binary
`readelf`/`objdump` show the binary is stripped (no `.symtab`), so function
names aren't available directly. radare2's `aaa` analysis pass recovered
17 internal (non-import) functions purely from control-flow structure.
The largest, `fcn.00005d50` (97 basic blocks) and `fcn.00005070` (73 basic
blocks), are disproportionately larger than the rest and were inspected
in Ghidra/Cutter's decompiler — consistent with the main connection-setup
and proxy-negotiation logic. Full list:
[`analysis/r2_functions.txt`](analysis/r2_functions.txt).

## Repository Structure

```
netcat-re/
├── README.md                              this file
└── analysis/
    ├── file.txt                           `file` output — format identification
    ├── readelf_header.txt                 ELF header
    ├── readelf_sections.txt               section headers
    ├── readelf_program_headers.txt        program headers / segments
    ├── readelf_dynamic.txt                dynamic section — linked libraries
    ├── objdump_dynsymbols.txt             full dynamic symbol table
    ├── objdump_disasm_entry_excerpt.txt   disassembly excerpt (file start)
    ├── objdump_disasm_entry_point.txt     disassembly of the entry point (_start)
    ├── r2_imports.txt                     radare2 import listing
    ├── r2_functions.txt                   radare2 recovered function list (afl)
    └── strings_output.txt                 extracted printable strings (≥6 chars)
```

## Tools Used

- `readelf`, `objdump`, `strings`, `file` — binutils static inspection
- **radare2** — command-line disassembly, auto-analysis, and function recovery
- **Cutter** — radare2's GUI frontend, used for visual CFG/decompiler review
- **Ghidra** — decompiler cross-check on the two largest recovered functions

## Notes

This was a static-only analysis — the binary was never executed. All
findings above are inferred from headers, imports, strings, and control-flow
structure, which is intentionally the same constraint faced when triaging
an unknown/suspicious binary before it's safe to detonate in a sandbox.
