# Reverse-Engineering & Patching Tools (`tools/`)

This directory contains the disassembly, verification, and GUI/CLI patching tools for the **Godox Firmware Patcher — Untested / Special Requests (`SR#`)** repository.

## Tool Overview

| Script | Purpose |
|---|---|
| [`disasm.py`](disasm.py) | Recursive-descent ARM Thumb / Thumb-2 disassembler powered by [Capstone](https://www.capstone-engine.org/). Automatically unwraps STMicroelectronics DfuSe (`.dfu`) containers (`unwrap_dfuse`), resolves literal pools (`[pc, #imm]`), and recovers inline Keil ARMCC `__ARM_common_switch8` byte jump tables on Cortex-M0 binaries. |
| [`fwversion.py`](fwversion.py) | Central registry (`SPECIAL_REQUESTS`) for `SR#` community requests, output filename formatting, and STMicroelectronics DfuSe suffix CRC32 calculation/verification (`verify_dfuse_crc`, `update_dfuse_crc`). |
| [`patcher_core.py`](patcher_core.py) | Core firmware identification (`identify_firmware`) and deterministic build/verification engine (`build_selected_tiers`). |
| [`patcher_gui.py`](patcher_gui.py) | Cross-platform Drag-and-Drop GUI (Windows native `WM_DROPFILES` + optional `tkinterdnd2`) and headless CLI (`--tier SR001`). Includes prominent **Untested Hardware** warnings and confirmation dialogs. |
| [`build_executable.py`](build_executable.py) | PyInstaller build script that packages `patcher_gui.py`, `patcher_core.py`, `fwversion.py`, and `AD200/patch.py` into a standalone executable (`dist/GodoxFirmwarePatcher-Untested.exe` on Windows or `dist/GodoxFirmwarePatcher-Untested.app` on macOS). |

---

## Usage

### 1. Regenerate Disassembly (`AD200/disasm/`)
Place `AD200 V2.6.dfu` inside `AD200/` and run:
```bash
python tools/disasm.py
```
This unwraps the DfuSe container (`Element 0` at `.dfu` offset `0x0125`, base `0x08003000`, `40,612` bytes) and writes:
* `AD200/disasm/AD200_V2.6.asm` (annotated assembly with both flash addresses and `.dfu` offsets)
* `AD200/disasm/AD200_V2.6.functions.csv` (309 discovered functions with `payload_offset` and `dfu_offset`)
* `AD200/disasm/AD200_V2.6.strings.txt` (extracted ASCII strings)

### 2. Run the Patcher (GUI or Headless CLI)
```bash
# Launch the interactive Drag-and-Drop GUI:
python tools/patcher_gui.py

# Run headlessly from the command line:
python tools/patcher_gui.py "AD200/AD200 V2.6.dfu" --tier SR001
```

### 3. Build Standalone Executable (`.exe` / `.app`)
```bash
pip install pyinstaller tkinterdnd2
python tools/build_executable.py
```
