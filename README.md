# ShadowForge

EDR evasion research framework — C++17, x64, Windows.

> **Educational / Lab use only.** Do not use against systems you do not own.

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **PE Parser** | Full PE32/PE32+ analysis — headers, sections, imports, exports |
| 2 | **Direct Syscalls** | Runtime SSN resolution via EAT sorting + x64 `syscall` stub |
| 3 | **NTDLL Unhooker** | Reads clean ntdll from disk, overwrites hooked `.text` section |
| 4 | **ETW Patcher** | Patches `EtwEventWrite` / `EtwEventWriteFull` with `xor rax,rax; ret` |
| 5 | **APC Injector** | Process injection via `NtQueueApcThread` using direct syscalls |
| 6 | **Shellcode Obfuscator** | Multi-layer encryption: RC4-drop + byte permutation + UUID encoding |

## Architecture

```
ShadowForge/
├── asm/
│   ├── syscall_stub.asm          # MASM (Visual Studio)
│   └── syscall_stub.S            # GAS  (MinGW-w64)
├── include/
│   ├── shadowforge.h             # Common types, macros, console helpers
│   ├── pe_parser.h
│   ├── syscalls.h
│   ├── unhooker.h
│   ├── etw_patcher.h
│   ├── obfuscator.h
│   └── injector.h
├── src/
│   ├── main.cpp                  # Interactive CLI
│   ├── pe_parser.cpp
│   ├── syscalls.cpp
│   ├── unhooker.cpp
│   ├── etw_patcher.cpp
│   ├── obfuscator.cpp
│   └── injector.cpp
├── tools/
│   └── encrypt_shellcode.py      # Offline shellcode encryption tool
├── CMakeLists.txt
└── toolchain-mingw64.cmake       # Cross-compilation from WSL
```

## Build

### WSL / Linux (MinGW-w64 cross-compilation)

```bash
sudo apt install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 mingw-w64-x86-64-dev cmake
cd ShadowForge
cmake -B build -DCMAKE_TOOLCHAIN_FILE=toolchain-mingw64.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Windows (Visual Studio / MSVC)

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Binary output: `build/bin/ShadowForge.exe`

## Obfuscation Pipeline

The shellcode obfuscator uses a **multi-layer approach** to defeat static signature detection:

1. **RC4-drop(3072)** — Stream cipher with the first 3072 keystream bytes discarded
2. **Fisher-Yates byte permutation** — Deterministic byte-level shuffle with seeded LCG
3. **UUID encoding** — Encrypted bytes stored as UUID strings (legitimate-looking data)

Additional protections:
- **Runtime key derivation** from system entropy (no static key in binary)
- **Sandbox detection** — timing checks, RAM/CPU count heuristics
- **Staged decryption** — chunk-by-chunk with random timing jitter
- **Arithmetic reconstruction** — shellcode bytes rebuilt via XOR at runtime

### Offline encryption tool

```bash
# Encrypt raw shellcode binary
python3 tools/encrypt_shellcode.py payload.bin -o encrypted.h

# Encrypt from hex string
python3 tools/encrypt_shellcode.py --hex "FC4883E4F0..." -o encrypted.h

# With custom key derivation
python3 tools/encrypt_shellcode.py payload.bin --key-string "my_secret" -o encrypted.h
```

## Techniques Reference

| Technique | Bypasses |
|-----------|----------|
| Direct syscalls | Usermode API hooks (CrowdStrike, SentinelOne, Defender ATP) |
| NTDLL unhooking | EDR inline hooks on `Nt*` functions |
| ETW patching | ETW-based telemetry and behavioral analysis |
| APC injection | Process-level monitoring when combined with above |
| Multi-layer obfuscation | Static signature detection, YARA rules |
| Sandbox detection | Automated analysis environments |

## Disclaimer

This tool is intended **strictly for educational purposes and authorized security research**. The author is not responsible for any misuse. Always obtain proper authorization before testing against any system.
