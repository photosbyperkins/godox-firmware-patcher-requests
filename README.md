# Godox Firmware Patcher — Untested / Special Requests (`SR#`)

> [!CAUTION]
> **SPECIAL REQUEST FIRMWARES ARE UNTESTED — FLASH AT YOUR OWN PERIL**
>
> Unlike the main [godox-firmware-patcher](https://github.com/photosbyperkins/godox-firmware-patcher) repository (which provides verified `S / R / X` performance tiers), **this repository contains experimental Special Request (`SR#`) patches that have NOT been tested on physical hardware.**
>
> * Every patch in this repository is developed strictly through **static ARM Cortex-M0 / Thumb-2 reverse engineering** in response to specific community repair, diagnostic, or custom modification requests.
> * **These builds are unverified by the author.** Whether a request targets unowned hardware or involves an experimental modification the author is unwilling to test on studio gear, no guarantee is made that a patched image will flash cleanly or operate safely.
> * **You assume 100% of the risk** of bricking, hardware damage, capacitor fault, or thermal runaway by building and flashing firmware from this repository.

---

## 1. Special Requests (`SR#`) Registry

Rather than building the standard `S / R / X / R+ / X+` performance tiers from the main repository, this repository uses a **`SR###` (Special Request)** numbering scheme tied directly to individual community hardware/firmware requests:

| SR ID | Model | OEM Base Firmware | Output Filename | Boot LCD Readout | Request Source | Modification Summary |
|---|---|---|---|---|---|---|
| **`SR001`** | **Godox AD200** *(Original / Non-Pro)* | `AD200 V2.6.dfu`<br>*(40,921 B)* | `AD200_V2.6_SR001_e2_ntc_bypass.dfu` | **`S-2.6`** *(hold `MODE` at power-on; stock shows `U-2.6`)* | [Reddit `r/Godox` Comment](https://www.reddit.com/r/Godox/comments/1x7729i/comment/ph762sq/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button) | **NTC Sensor Fault Bypass Only:** Replaces the entry instruction of `fn_080096b4` (`0x080096B4`, `.dfu` `0x67D9`) with `bx lr` (`70 47`) so a shorted/failing NTC thermistor or faulty PCB sense trace no longer triggers immediate `E2` / over-temperature lockout (`[0x200000E8] = 1`) or `E0` (`[0x200000E8] = 2`) 1.1 seconds after power-on. **Software shot-counter protection (`fn_08007944`) remains 100% factory stock.** |

---

## 2. Background on `SR001` (Godox AD200 Original — False `E2` / Overheat at Boot)

### The Community Request
From [`r/Godox` comment `ph762sq`](https://www.reddit.com/r/Godox/comments/1x7729i/comment/ph762sq/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button):

> *"Could you make this for the normal ad200? I have THREE that constantly yell E2 barely after being on, and two had their board replaced!"*

### What Disassembly of `AD200 V2.6.dfu` Revealed

Full static disassembly ([`AD200/disasm/AD200_V2.6.asm`](AD200/disasm/AD200_V2.6.asm)) and reverse engineering ([`FINDINGS.md`](FINDINGS.md)) uncovered the exact mechanism behind this failure:

1. **1.1-Second Boot Trip (`fn_080096b4` at `0x080096B4`):**
   * Every `100 ms` (`20` main-loop ticks of `5.0 ms`), `fn_08009720` calls `fn_080096b4`, which inspects the 10-bit filtered ADC reading at `[0x20000022]` (`ADC_IN11` on pin `PC1` — the physical NTC thermistor divider).
   * If `[0x20000022] < 152` (`0x98`) for more than `10` consecutive 100 ms ticks (**`1.1 seconds` after power-on — matching *"barely after being on"* to the second!**), `fn_080096b4` sets the thermal fault state `[0x200000E8] = 1` and calls `fn_080051cc` (`0x080051CC`).
   * Conversely, if `[0x20000022] > 950` (`0x03B6`) for `1.1 seconds` (open circuit), it sets `[0x200000E8] = 2`, which displays **`E0`** on the LCD (`fn_08005274`).
2. **Why Replacement Boards Still Say `E2` (V2.2 Firmware Changelog):**
   * According to Godox's official `AD200_Firmware_Instructions_V2.6.pdf`, firmware **V2.2** included the change:
     > *"2. To replace the error code prompts with specific icons when high-temperature alarm starts."*
   * On firmware **V1.x – V2.1** (frequently shipped on older units and replacement mainboards), `[0x200000E8] == 1` caused `fn_08005274` to display **`E2`** on the 7-segment LCD.
   * On firmware **V2.2 – V2.6**, Godox removed `0xE2` from `fn_08005274` and instead routed `[0x200000E8] == 1` to blink the **over-temperature thermometer icon** (`0x080088A0`) while still calling `fn_080051cc` to lock out the strobe.
3. **Firmware Bug in `fn_080051cc` (`0x080051CC`) Causes a Permanent 10-Minute Charge Lockout When Tripped at Boot:**
   * When `fn_080051cc` is called during normal shooting after the software shot-counter reaches 6000, `[0x200000CF]` (`[r0,#3]`) holds `50` (`5.0 s`), which is copied into the charge-inhibit countdown timer `[0x200000CE]` (`[r0,#2]`).
   * However, when `fn_080096b4` calls `fn_080051cc` **1.1 seconds after power-on** (before any flash has fired), `[0x200000CF]` is still **`0`**! `fn_080051cc` copies `0` into `[0x200000CE]` while setting the HV charge-inhibit flag `[0x20000083] = 1` and the 10-minute timer `[0x200000D8] = 6000`. Because `fn_08007ad4` (`0x08007AFA`) only decrements `[0x200000CE]` and clears `[0x20000083]` when `[0x200000CE] != 0`, **the strobe is completely locked out from charging for the full 10 minutes!**
4. **What `SR001` Patches (and What It Leaves Untouched):**
   * **Patched (`.dfu` offset `0x67D9`, flash `0x080096B4`):** `70 b5` (`push {r4, r5, r6, lr}`) $\rightarrow$ `70 47` (`bx lr`). `fn_080096b4` returns immediately; `[0x200000E8]` stays `0` (`OK`).
   * **Patched (`.dfu` offset `0x58BF`, flash `0x0800879A`):** `13 20` (`movs r0, #0x13` = `'U'`) $\rightarrow$ `14 20` (`movs r0, #0x14` = `'S'`). Holding **`MODE`** while turning the AD200 on displays **`S-2.6`** instead of `U-2.6`.
   * **Patched (`.dfu` offset `0x9FD5`–`0x9FD8`):** Recomputes the 4-byte STMicroelectronics DfuSe suffix CRC32 (`0x3EBB4967` $\rightarrow$ `0x2FBD2F2E`) so **Godox G2** accepts the file.
   * **Left 100% Stock:** The software shot-counter (`fn_08007944` / `fn_08007ad4`) and all four heat tables (`0x0800CC42`–`0x0800CCF1`) are **completely unmodified** in `SR001`.

> [!WARNING]
> **Thermal Safety Implication of `SR001`:**
> Because `SR001` disables physical NTC thermistor polling (`fn_080096b4`), the AD200 will rely **solely** on its factory software shot-counter (`fn_08007944`, which trips after 40 full-power normal shots or 20 full-power HSS shots on the fresnel/bare-bulb heads) for thermal protection. If you power-cycle the strobe while the flash head is physically hot, the software shot counter resets to zero in RAM. Allow the head to cool naturally after heavy bursts.

---

## 3. Checksums & Verification (`AD200 V2.6`)

| Image Type | Filename | Size (Bytes) | DfuSe CRC32 | SHA-256 Checksum |
|---|---|---:|---|---|
| **Official OEM Base** | `AD200 V2.6.dfu` | `40,921` | `0x3EBB4967` | `aafad9dc8fc739c1681ad473366bdd10b36ffa1fac91737218f0cf133a1b4af2` |
| **Patched (`SR001`)** | `AD200_V2.6_SR001_e2_ntc_bypass.dfu` | `40,921` | `0x2FBD2F2E` | `f76b859f2dcc1c5225f0b64ea4407e28b9afff5ba1910a30646fde922483d1f9` |

---

## 4. How to Build & Flash `SR001`

Because official Godox firmware binaries are copyrighted by Godox Photo Equipment Co., Ltd., this repository distributes **open-source patchers and disassembly documentation only** — no `.dfu` or `.bin` files are hosted in the repository.

### Step 1: Download Official `AD200 V2.6.dfu` & Godox G2
1. Download the official **Godox AD200 Firmware V2.6** archive (which contains `AD200 V2.6.dfu`) and the **Godox G2** firmware launcher from [Godox Firmware Downloads](https://www.godox.com/firmware-flash/).

### Step 2: Generate `AD200_V2.6_SR001_e2_ntc_bypass.dfu`

#### Option A: Standalone Drag-and-Drop GUI (`GodoxFirmwarePatcher-Untested`)
1. Launch `GodoxFirmwarePatcher-Untested.exe` (Windows) or `GodoxFirmwarePatcher-Untested.app` (macOS), or run `python tools/patcher_gui.py`.
2. Drag and drop `AD200 V2.6.dfu` into the window.
3. Select **`SR001 · E2 / NTC Sensor Fault Bypass`** and click **Build Untested Patch**.
4. Confirm the untested-hardware warning dialog. The patcher writes `AD200_V2.6_SR001_e2_ntc_bypass.dfu` alongside your original `.dfu` file and verifies both its DfuSe CRC32 and SHA-256 hash.

#### Option B: Command-Line Python Patcher (Zero Dependencies)
```bash
# Run the AD200 model patcher directly:
python AD200/patch.py "path/to/AD200 V2.6.dfu"

# Or run the unified patcher in headless CLI mode:
python tools/patcher_gui.py "path/to/AD200 V2.6.dfu" --tier SR001
```

### Step 3: Flash with Godox G2 & Verify On-Screen Version (`S-2.6`)
1. Turn **OFF** the AD200, remove the battery, or follow the official `AD200_Firmware_Instructions_V2.6.pdf` procedure to connect the AD200 to your PC via USB-C / Micro-USB data cable.
2. Open **Godox G2**, select `AD200_V2.6_SR001_e2_ntc_bypass.dfu`, and click **Upgrade**.
3. **Verify the Custom Build on the Strobe LCD:**
   * With the AD200 turned **OFF**, press and **hold the `MODE` button**, then flip the power switch **ON**.
   * Stock firmware displays `U-2.6`.
   * **`SR001` custom firmware displays `S-2.6`** on the 7-segment LCD.

---

## 5. Repository Structure

| Path | Description |
|---|---|
| [`FINDINGS.md`](FINDINGS.md) | Comprehensive reverse-engineering audit of `AD200 V2.6.dfu` (DfuSe layout, STM32F0xx clock/timer tree, ADC channels, `E0`/`E1`/`E2`/`E3`/`E9` error logic, `fn_080096b4` NTC fault mechanism, and `fn_08007944` shot-counter tables) |
| [`AD200/README.md`](AD200/README.md) | Model-specific technical documentation and exact byte-patch tables for the Godox AD200 (`V2.6`) |
| [`AD200/patch.py`](AD200/patch.py) | Standalone zero-dependency Python 3 patcher for `AD200 V2.6.dfu` (`SR001`) |
| [`AD200/disasm/`](AD200/disasm/) | Full Capstone ARM Cortex-M0 disassembly (`AD200_V2.6.asm`), function table (`AD200_V2.6.functions.csv`), and string table (`AD200_V2.6.strings.txt`) |
| [`tools/disasm.py`](tools/disasm.py) | Recursive-descent ARM Thumb-2 / Cortex-M0 disassembler with automatic STMicroelectronics DfuSe (`.dfu`) container unwrapping and Keil `__ARM_common_switch8` jump-table recovery |
| [`tools/fwversion.py`](tools/fwversion.py) | `SR#` Special Request registry, filename formatting, and DfuSe suffix CRC32 calculation/verification |
| [`tools/patcher_core.py`](tools/patcher_core.py) | Shared SHA-256 verification and build engine |
| [`tools/patcher_gui.py`](tools/patcher_gui.py) | Cross-platform Tkinter Drag-and-Drop GUI + headless CLI (`--tier SR001`) |
| [`tools/build_executable.py`](tools/build_executable.py) | PyInstaller build script for Windows (`.exe`) and macOS (`.app`) bundles |
| [`tools/README.md`](tools/README.md) | Documentation for the reverse-engineering and patching toolchain |
