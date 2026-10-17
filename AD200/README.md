# Godox AD200 (Original / Non-Pro) — `V2.6` (`SR001`)

> [!CAUTION]
> **SPECIAL REQUEST FIRMWARES ARE UNTESTED — FLASH AT YOUR OWN PERIL:**
> `SR001` was developed strictly via static ARM Cortex-M0 disassembly in response to a community repair request ([Reddit `r/Godox` comment `ph762sq`](https://www.reddit.com/r/Godox/comments/1x7729i/comment/ph762sq/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button)) and has **not** been tested on physical hardware.

| Item | Value |
|---|---|
| **OEM image** | `AD200 V2.6.dfu` (`40,921` bytes, DfuSe CRC32 `0x3EBB4967`), SHA-256 `aafad9dc8fc739c1681ad473366bdd10b36ffa1fac91737218f0cf133a1b4af2` |
| **Flash payload** | `40,612` bytes at `.dfu` offset `0x0125`–`0x9FC8`, mapped to `0x08003000`–`0x0800CEA4` (`dfu_offset = 0x125 + (flash_addr - 0x08003000)`) |
| **Special Request build** | **`SR001`**: `AD200_V2.6_SR001_e2_ntc_bypass.dfu` (`40,921` bytes, DfuSe CRC32 `0x2FBD2F2E`), SHA-256 `f76b859f2dcc1c5225f0b64ea4407e28b9afff5ba1910a30646fde922483d1f9` |
| **Boot LCD version readout** | Hold **`MODE`** while turning power **ON**: stock displays `U-2.6`; **`SR001` displays `S-2.6`** |
| **Flashing utility** | **Godox G2** (STMicroelectronics DfuSe `.dfu` format) |
| **Patcher** | [`patch.py`](patch.py) · Full audit: [`../FINDINGS.md`](../FINDINGS.md) |
| **Disassembly artifacts** | [`disasm/AD200_V2.6.asm`](disasm/AD200_V2.6.asm) · [`disasm/AD200_V2.6.functions.csv`](disasm/AD200_V2.6.functions.csv) · [`disasm/AD200_V2.6.strings.txt`](disasm/AD200_V2.6.strings.txt) |

---

## 1. Special Request `SR001`: `E2` / NTC Sensor Fault Bypass

### Problem Addressed
Units with a shorted/drifted NTC thermistor or damaged sense trace on `PC1` (`ADC_IN11`, filtered 10-bit reading stored at `[0x20000022]`) read `< 152` (`0x98`) immediately upon power-up. After `11` polling ticks of `100 ms` (**`1.1 seconds` after turning on**), `fn_080096b4` (`0x080096B4`) sets `[0x200000E8] = 1` and calls `fn_080051cc` (`0x080051CC`):
* On firmware **V1.x – V2.1** (common on older units and replacement boards), `[0x200000E8] == 1` displays **`E2`** on the LCD and locks out the flash.
* On firmware **V2.2 – V2.6**, Godox replaced the `E2` text prompt with a blinking thermometer icon (`0x080088A0`) while still calling `fn_080051cc`, which locks out HV charging (`[0x20000083] = 1`) for a full 10 minutes (`6000` steps at `[0x200000D8]`).

### Byte-Level Patch Specification (`SR001`)

| `.dfu` Offset | Payload Offset | Flash Address | Stock Bytes | Stock Instruction / Meaning | `SR001` Bytes | `SR001` Instruction / Effect |
|---:|---:|---:|---|---|---|---|
| **`0x58BF`** | `0x579A` | `0x0800879A` | `13 20` | `movs r0, #0x13` (`'U'` in `U-2.6`) | **`14 20`** | `movs r0, #0x14` (**`'S'` in `S-2.6`** when holding `MODE` at power-on) |
| **`0x67D9`** | `0x66B4` | `0x080096B4` | `70 b5` | `push {r4, r5, r6, lr}` (entry of `fn_080096b4`) | **`70 47`** | `bx lr` (returns immediately; `[0x200000E8]` stays `0`, bypassing hardware NTC `E2`/`E0` faults) |
| **`0x9FD5`** | *(Suffix)* | *(N/A)* | `67 49 bb 3e` | DfuSe CRC32 `0x3EBB4967` | **`2e 2f bd 2f`** | Recomputed DfuSe CRC32 **`0x2FBD2F2E`** |

---

## 2. Software Shot-Counter Reference (`fn_08007944` & `fn_08007ad4` — Left 100% Stock in `SR001`)

For future reference and comparison with newer Godox strobes, the original AD200's software shot-counter (`fn_08007944` at `0x08007944`, drained by `fn_08007ad4` at `0x08007AD4`, struct base `0x200000CC`) operates as follows:

* **Accumulator (`[0x200000D6]`):** Adds points per flash from one of four 22-entry halfword tables (`0x0800CC42`–`0x0800CCF1`).
* **Cooldown Threshold:** **`6000` (`0x1770`)** across all heads.
* **No Gradual Leaky-Bucket Drain — Pure `30.0 s` Idle Cliff Reset (`[0x200000D4]`):**
  * Every flash outside the over-temp window resets `[0x200000D4]` to **`300` steps (`30.0 s`)** (`0x08007A08`).
  * `fn_08007ad4` decrements `[0x200000D4]` every `0.100 s`; only when `30.0 s` elapse with zero flashes does it clear the accumulator `[0x200000D6]` to `0` (`0x08007AF6`).
* **Over-Temp Penalty Window (`[0x200000D8]` = `6000` steps = `10.0 min`):**
  * Reaching `6000` points inhibits HV charging for `5.0 s` (`[0x200000CE] = 50`) and activates a 10-minute over-temp window (`[0x20000084] = 1`).
  * Any flash fired during the 10-minute window increments the forced recycle delay `[0x200000CF]` by `+5` (`+0.5 s` per shot) from `5.0 s` up to a maximum of **`10.0 s` (`100` steps)** (`0x080079CE`–`0x080079F6`) and reloads the 10-minute timer.

### Stock Heat Lookup Tables (`0x0800CC42`–`0x0800CCF1`, Unmodified in `SR001`)

| Table | Flash Address | `.dfu` Offset | Selector (`[0x20000085]` HSS, `[0x2000000A]` Head) | Values (`0` $\rightarrow$ `21` = `1/1`) | `1/1` Shots to `6000` |
|---|---|---|---|---|---:|
| **A** | `0x0800CC42` | `0x9D67` | Normal (`0`), Heads $\notin \{2,3,4\}$ | `6×3, 12×3, 20×3, 30×3, 40×3, 60×3, 80, 100, 120, 150` | **40** |
| **B** | `0x0800CC6E` | `0x9D93` | Normal (`0`), Heads $\in \{2,3,4\}$ | `6×3, 8×3, 15×3, 23×3, 30×3, 40×3, 50, 60, 75, 100` | **60** |
| **C** | `0x0800CC9A` | `0x9DBF` | HSS (`1`), Heads $\notin \{2,3,4\}$ | `60×9, 80×3, 100×3, 150×3, 200×3, 300` | **20** |
| **D** | `0x0800CCC6` | `0x9DEB` | HSS (`1`), Heads $\in \{2,3,4\}$ | `30×9, 40×3, 44×3, 60×3, 75×3, 120` | **50** |
