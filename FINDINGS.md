# Reverse-Engineering Findings — Godox AD200 (`V2.6` Untested Edition)

> [!CAUTION]
> **UNTESTED SPECIAL REQUEST FIRMWARE — FLASH AT YOUR OWN PERIL:**
> All findings and patches in this document are derived strictly from static reverse engineering of the official `AD200 V2.6.dfu` image (`SHA-256: aafad9dc8fc739c1681ad473366bdd10b36ffa1fac91737218f0cf133a1b4af2`) without physical hardware testing.

## Status Legend
* ✅ **Verified in code:** Confirmed directly from ARM Cortex-M0 instruction decoding, literal pools, and peripheral register configurations in [`AD200/disasm/AD200_V2.6.asm`](AD200/disasm/AD200_V2.6.asm).
* 🔶 **Partial / Inferred:** Supported by firmware structure or official Godox documentation, without physical bench probing.
* ⚠️ **Unverified on hardware:** Not yet tested on a physical AD200 unit.

---

## 1. DfuSe (`.dfu`) Container Format & Checksum

Unlike newer Godox Pro II strobes (which use raw or XOR/ciphered `.bin` files flashed via **Godox G3**), the original **Godox AD200** uses a standard **STMicroelectronics DfuSe v1.1a (`.dfu`)** image flashed via **Godox G2**.

| Region | `.dfu` File Offset | Size (Bytes) | Contents & Verification | Status |
|---|---:|---:|---|---|
| **DfuSe Prefix** | `0x0000`–`0x000A` | `11` | Signature `b"DfuSe\x01"`, `dwImageSize = 40905` (`0x9FC9`), `bTargets = 1` | ✅ |
| **Target Prefix** | `0x000B`–`0x011C` | `274` | Signature `b"Target"`, `bAlternateSetting = 0`, `bTargetNamed = 1`, `szTargetName = "ST..."`, `dwTargetSize = 40620` (`0x9EAC`), `dwNbElements = 1` | ✅ |
| **Element 0 Header** | `0x011D`–`0x0124` | `8` | `dwElementAddress = 0x08003000`, `dwElementSize = 40612` (`0x9EA4`) | ✅ |
| **Flash Payload** | `0x0125`–`0x9FC8` | `40,612` | Raw STM32L0xx application image mapped to `0x08003000`–`0x0800CEA4`.<br>**Offset conversion:** $\text{dfu\_offset} = \text{0x0125} + (\text{flash\_addr} - \text{0x08003000})$ | ✅ |
| **DfuSe Suffix** | `0x9FC9`–`0x9FD8` | `16` | `bcdDevice = 0x0000`, `idProduct = 0xDF11`, `idVendor = 0x0483` (STMicroelectronics in DFU mode), `bcdDFU = 0x011A`, `ucDfuSignature = b"UFD"`, `bLength = 16`, and **`dwCRC` at `0x9FD5`–`0x9FD8`** | ✅ |

### DfuSe Suffix CRC32 (`0x9FD5`–`0x9FD8`)
* **Formula:** Standard ST DfuSe CRC32 over `dfu[:-4]` (`0x0000`–`0x9FD4`):
  $$\text{dwCRC} = \text{zlib.crc32}(\text{dfu[:-4]}) \oplus \text{0xFFFFFFFF}$$
* **Stock `AD200 V2.6.dfu` `dwCRC`:** `0x3EBB4967` (`67 49 BB 3E` little-endian at `0x9FD5`).
* **Patched `SR001` `dwCRC`:** `0x2FBD2F2E` (`2E 2F BD 2F` little-endian at `0x9FD5`).
* **Critical Requirement:** Any modification to the payload without updating `dwCRC` at `0x9FD5` will cause **Godox G2** (which uses ST's DfuSe library) to reject the file as corrupted before flashing begins.

---

## 2. MCU Architecture, Clock Tree, and `0.100 s` Step Timer

| Component | Value / Address | Evidence in `AD200_V2.6.asm` | Status |
|---|---|---|---|
| **MCU Family** | **STM32L0xx** (ARM Cortex-M0+, Thumb / ARMv6-M) | Vector table at `0x08003000` (`38 07 00 20 d9 30 00 08 ...`), STM32L0 IOPORT peripheral base addresses (`GPIOA = 0x50000000`, `GPIOB = 0x50000400`, `GPIOC = 0x50000800`, `GPIOD = 0x50000C00`, `GPIOH = 0x50001C00`), `TIM21 = 0x40010800`, `TIM22 = 0x40011400`, and internal Data EEPROM at `0x08080000` (`fn_08005008` / `fn_08005020`) | ✅ |
| **Bootloader Partition** | `0x08000000`–`0x08002FFF` (`12 KB`) | Application vector table starts at `0x08003000`; `SystemInit` (`fn_0800b4cc` at `0x0800B506`–`0x0800B50A`) writes `0x08003000` directly to the Cortex-M0+ `SCB->VTOR` register (`0xE000ED08`) | ✅ |
| **System Clock (`HCLK`)** | **16.0 MHz (`HSI16`)** | `SystemClock_Config` (`fn_0800b434` at `0x0800B434`–`0x0800B494`) sets `PWR_REGULATOR_VOLTAGE_SCALE1` (`0x40007000`), enables `HSI16` (`16.0 MHz`) and `LSI`, and selects `RCC_SYSCLKSOURCE_HSI` with `AHB`/`APB1`/`APB2` dividers = `1` | ✅ |
| **Hardware Tick (`TIM2`)** | **200 µs (5.0 kHz)** | `fn_08008f44` (`0x08008F44`–`0x08008F8C`) initializes `TIM2` (`0x40000000`, handle `0x20000104`) with `Prescaler = 15` ($\div 16 \rightarrow 1\,\text{MHz}$) and `Period = 199` (`0xC7`, $\div 200 \rightarrow 200\,\mu\text{s}$) | ✅ |
| **Main-Loop Pace** | **5.0 ms (200 Hz)** | `TIM2_IRQHandler` (`fn_0800b5cc` $\rightarrow$ `HAL_TIM_IRQHandler` `fn_08006fdc` $\rightarrow$ `HAL_TIM_PeriodElapsedCallback` `fn_0800b800`) increments `[0x20000008]`; at `25` (`0x19` at `0x0800B80A`), it resets `[0x20000008] = 0` and sets `[0x20000009] = 1` ($200\,\mu\text{s} \times 25 = 5.0\,\text{ms}$). `main` (`0x0800C2FA`) waits for `[0x20000009] == 1` before running each main-loop pass | ✅ |
| **Thermal & Shot-Counter Step** | **0.100 s (100 ms / 10 Hz)** | `fn_08007ad4` (`0x08007ADA`–`0x08007AE6`, counter `[0x200000CD]`, `cmp r0, #0x14; blo`) divides the 5.0 ms main-loop pass by `20` (`100 ms`); `fn_08009720` (`0x0800973E`–`0x0800974C`, counter `[0x200000E7]`, `cmp r1, #0x14; bls`) divides by `21` (`105 ms`) | ✅ |

---

## 3. ADC Channel Mapping (`fn_08008aec` & `fn_080032e8`)

`fn_08008aec` (`0x08008AEC`) configures `ADC1` (`0x40012400`) in continuous DMA scan mode (`DMA1_Channel1`, buffer at `0x200002DC`, `20` halfwords = `4` oversamples $\times$ `5` channels) across `CH3`, `CH10`, `CH11`, `CH12`, and `CH17` (`VREFINT`). Every 5.0 ms pass, `fn_080032e8` (`0x080032E8`–`0x0800342A`) bubble-sorts the 4 samples for each channel, averages the middle two, and right-shifts by 2 (`12-bit 0..4095` $\rightarrow$ **`10-bit 0..1023`**):

| DMA Slot | STM32L0 Channel / Pin | Filtered 10-bit RAM Address | Function & Consumers | Status |
|---:|---|---|---|---|
| **0** | `ADC_IN3` (`PA3`) | `[0x20000024]` (`[0x20000008,#0x1C]`) | **Flash Head ID Resistor:** Read by `fn_08005574` (`0x08005574`) $\rightarrow$ `fn_0800595c` (`0x0800595C`) to classify the attached head into `[0x2000000A]` (`0..6`) | ✅ |
| **1** | `ADC_IN10` (`PC0`) | `[0x20000016]` (`[0x20000008,#0x0E]`) | **Battery Voltage Sense:** Read by `fn_080036bc` (`0x080036BC`) and `fn_080038ac` (`0x080038AC`, low-battery shutoff below `0x26C = 620`, battery bar thresholds `770 / 728 / 685`) | ✅ |
| **2** | **`ADC_IN11` (`PC1`)** | **`[0x20000022]`** (`[0x20000008,#0x1A]`) | **Physical NTC Thermistor Sense (biased by `PC3` HIGH in `fn_08009720`):** Read **exclusively** by **`fn_080096b4`** (`0x080096B4`) to detect `E0` (open sensor) and `E2` / over-temperature lockout (`[0x200000E8]`) | ✅ |
| **3** | `ADC_IN12` (`PC2`) | `[0x20000020]` (`[0x20000008,#0x18]`) | **HV Capacitor Voltage Sense:** Copied by `fn_0800569c` to `[0x20000080]`; monitored by `fn_080040b4` (`E1` under-charge check) and charge controller `fn_080052e4` | ✅ |
| **4** | `ADC_IN17` (`VREFINT`) | *(sorted in `0x2000033C`, not stored)* | Internal reference voltage channel | ✅ |

---

## 4. Error Code Architecture (`E0`, `E1`, `E2`, `E3`, `E9`)

### 4.1 How Error Codes Are Evaluated (`fn_08005274`) and Rendered (`0x0800872C`)
Every 5.0 ms main-loop pass (`fn_0800864c` at `0x08008728`), the firmware calls **`fn_08005274`** (`0x08005274`–`0x080052AA`), which updates the active error byte at **`[0x20000006]`** (`[r0,#4]` where `r0 = 0x20000002`).

When `[0x20000006] != 0`, `fn_0800864c` (`0x0800872C`–`0x08008747`) suppresses the normal mode UI and calls `fn_080085e0` (`0x080085E0`) to draw **`E`** (`0x0E`) at digit `0x10` followed by the lower nibble (`[0x20000006] & 0x0F`) at digit `0x12` on the 7-segment LCD, while `fn_08009648` sounds the error beep pattern.

| Error Code | Value in `[0x20000006]` | Condition in `fn_08005274` (`0x08005274`) | Root Cause & Producer Routine | Status |
|---|---|---|---|---|
| **`E0`** | `0xE0` | `[0x200000E8] == 2` (`0x0800527A`) | **Open / Disconnected NTC Thermistor:** Set by `fn_080096b4` (`0x080096CE`) when NTC ADC `[0x20000022] > 950` (`0x03B6`) for $> 10$ polling ticks (`~1.15 s`) | ✅ |
| **`E1`** | `0xE1` | `[0x2000009A] == 1` (`0x08005282`) | **HV Capacitor Charge Failure:** Set by `fn_080040b4` (`0x080040B4`–`0x0800412E`) if the HV capacitor voltage `[0x20000080]` stays below `200` (`0xC8`) and fails to rise by at least `+10` ADC counts across `4` consecutive `0.5 s` intervals (`2.0 s` total) while charging | ✅ |
| **`E2`** *(V1.x–V2.1)* / **Thermometer Icon** *(V2.2–V2.6)* | `[0x200000E8] == 1` *(pre-V2.2: `0xE2`; V2.2+: icon at `0x080088A0`)* | `[0x200000E8] == 1` or `[0x20000084] == 1` | **NTC Over-Temperature / Shorted Sensor (`[0x200000E8] = 1`):** Set by `fn_080096b4` (`0x080096EC`) when NTC ADC `[0x20000022] < 152` (`0x98`) for $> 10$ polling ticks (`~1.15 s`), calling `fn_080051cc` (`0x080051CC`). *(See §4.2 below for why V1.x–V2.1 boards display `E2` whereas V2.2–V2.6 blinks the thermometer icon.)* | ✅ |
| **`E3`** | `0xE3` | `[0x200000C5] == 1` (`0x0800528A`) | **Hardware Over-Voltage / IGBT Fault Pin (`PA2`):** Set by `fn_0800b848` (`0x0800B848`–`0x0800B88A`) when `GPIOA` pin `PA2` (`0x50000010` bit 2) reads HIGH continuously for `200` main-loop ticks (`1.0 s`) while `[0x20000080] > 580` (`0x244`), triggering emergency dump `fn_08005850` | ✅ |
| **`E9`** | `0xE9` | `[0x200000F6] != 0x7B` (`0x08005292`) | **Data EEPROM Check Byte Mismatch:** Set at boot if EEPROM validation byte `[0x200000F6]` (loaded from STM32L0 Data EEPROM `0x08080000` by `fn_08005020`) does not equal `0x7B` (`123`) | ✅ |

### 4.2 Why V1.x–V2.1 Units Display `E2` and V2.2–V2.6 Units Blink the Thermometer Icon
A full instruction scan of `AD200 V2.6.dfu` confirms that `fn_08005274` loads `0xE0` (`0x0800529A`), `0xE1` (`0x0800529E`), `0xE3` (`0x080052A4`), and `0xE9` (`0x08005296`) — while `0xE2` does not appear anywhere in the V2.6 binary. Cross-referencing Godox's official `AD200_Firmware_Instructions_V2.6.pdf` release history explains why:

> **V2.2 Changelog:** *"2. To replace the error code prompts with specific icons when high-temperature alarm starts."*

* On **firmware V1.x – V2.1** (including old-stock replacement PCBs), `[0x200000E8] == 1` wrote `0xE2` into `[0x20000006]`, causing the screen to yell **`E2`** and beep `~1.15 seconds` after power-on whenever the NTC thermistor circuit read low (`< 152`).
* On **firmware V2.2 – V2.6**, Godox removed the `0xE2` assignment from `fn_08005274` and instead routed `[0x200000E8] == 1` and `[0x20000084] == 1` to `loc_080088a0` (`0x080088A0`), which blinks the thermometer icon while **still** executing the exact same `fn_080051cc` lockout!

---

## 5. Deep-Dive: NTC Thermistor Polling (`fn_080096b4`) & The Boot Lockout Bug (`fn_080051cc`)

### 5.1 Verbatim Disassembly of `fn_080096b4` (`0x080096B4`–`0x0800971C`)
Called every `21` main-loop ticks (`105 ms`) by `fn_08009720` (`0x0800974E`), which first biases the NTC divider by setting `PC3` (`GPIOC` `0x50000800` pin `0x08`) HIGH. Base pointer `r4 = 0x200000E5`:
* `[r4, #0]` (`0x200000E5`): Consecutive high-ADC (`> 950`) debounce counter
* `[r4, #1]` (`0x200000E6`): Consecutive low-ADC (`< 152`) debounce counter
* `[r4, #2]` (`0x200000E7`): `5.0 ms` $\rightarrow$ `105 ms` prescaler counter (`0..21` in `fn_08009720`)
* `[r4, #3]` (`0x200000E8`): Hardware NTC state (`0` = Normal, `1` = Over-temp / Shorted `E2`, `2` = Open circuit `E0`)

```armasm
; ---------------- fn_080096b4 ----------------
; Flash 0x080096B4 (Payload offset 0x66B4, .dfu offset 0x67D9)
; called from: 0x0800974e (fn_08009720)
fn_080096b4:
    080096b4  70b5       push      {r4, r5, r6, lr}        ; <-- SR001 patches to: 70 47 (bx lr)
    080096b6  1748       ldr       r0, [pc, #0x5c]         ; =0x20000022 (10-bit NTC ADC on PC1)
    080096b8  1749       ldr       r1, [pc, #0x5c]         ; =0x000003b6 (950)
    080096ba  0088       ldrh      r0, [r0]
    080096bc  174c       ldr       r4, [pc, #0x5c]         ; =0x200000e5
    080096be  8842       cmp       r0, r1
    080096c0  07d9       bls       #0x80096d2              ; if ADC <= 950, branch to loc_080096d2

    ; --- Branch 1: ADC > 950 (Open / Disconnected NTC -> E0) ---
    080096c2  2078       ldrb      r0, [r4]                ; r0 = [0x200000e5] high-ADC counter
    080096c4  401c       adds      r0, r0, #1
    080096c6  c0b2       uxtb      r0, r0
    080096c8  2070       strb      r0, [r4]
    080096ca  0a28       cmp       r0, #0xa                ; > 10 ticks (~1.15 s)?
    080096cc  13d9       bls       #0x80096f6
    080096ce  0220       movs      r0, #2                  ; state = 2 (E0)
    080096d0  10e0       b         #0x80096f4

loc_080096d2:
    ; --- Branch 2: ADC < 152 (Hot / Shorted NTC -> E2 / Thermal Lockout) ---
    080096d2  0025       movs      r5, #0
    080096d4  2570       strb      r5, [r4]                ; reset high-ADC counter [0x200000e5] = 0
    080096d6  9828       cmp       r0, #0x98               ; compare ADC against 152 (0x98)
    080096d8  0ed2       bhs       #0x80096f8              ; if ADC >= 152, check hysteresis recovery
    080096da  6078       ldrb      r0, [r4, #1]            ; r0 = [0x200000e6] low-ADC counter
    080096dc  401c       adds      r0, r0, #1
    080096de  c0b2       uxtb      r0, r0
    080096e0  6070       strb      r0, [r4, #1]
    080096e2  0a28       cmp       r0, #0xa                ; > 10 ticks (~1.15 s)?
    080096e4  07d9       bls       #0x80096f6
    080096e6  e078       ldrb      r0, [r4, #3]            ; r0 = [0x200000e8]
    080096e8  0128       cmp       r0, #1
    080096ea  01d0       beq       #0x80096f0
    080096ec  fbf76efd   bl        #0x80051cc              ; call fn_080051cc (locks out charging & sets 10-min timer)
loc_080096f0:
    080096f0  6570       strb      r5, [r4, #1]            ; reset low-ADC counter = 0
    080096f2  0120       movs      r0, #1                  ; state = 1 (Over-temp / E2)
loc_080096f4:
    080096f4  e070       strb      r0, [r4, #3]            ; store [0x200000e8]
loc_080096f6:
    080096f6  70bd       pop       {r4, r5, r6, pc}

loc_080096f8:
    ; --- Branch 3: Hysteresis Recovery (ADC >= 271 / 0x010F) ---
    080096f8  ff21       movs      r1, #0xff
    080096fa  1031       adds      r1, #0x10               ; r1 = 271 (0x010f)
    080096fc  8842       cmp       r0, r1
    080096fe  01d2       bhs       #0x8009704
    08009700  6570       strb      r5, [r4, #1]
    08009702  70bd       pop       {r4, r5, r6, pc}
loc_08009704:
    08009704  e078       ldrb      r0, [r4, #3]
    08009706  0128       cmp       r0, #1
    08009708  01d1       bne       #0x800970e
    0800970a  fef7d1f9   bl        #0x8007ab0              ; fn_08007ab0 (clear thermal lockout state)
loc_0800970e:
    0800970e  6570       strb      r5, [r4, #1]
    08009710  e570       strb      r5, [r4, #3]            ; [0x200000e8] = 0 (Normal)
    08009712  70bd       pop       {r4, r5, r6, pc}
```

### 5.2 The Uninitialized `[0x200000CF]` Boot Lockout Bug in `fn_080051cc` (`0x080051CC`)
Look at the exact instructions of `fn_080051cc` (`0x080051CC`–`0x080051E6`) when called by `fn_080096b4` at `0x080096EC` **`~1.15 seconds` after power-on** (before any flash has been fired):

```armasm
; ---------------- fn_080051cc ----------------
; called from: 0x080096ec
fn_080051cc:
    080051cc  0648       ldr       r0, [pc, #0x18]  ; =0x200000cc (shot-counter struct)
    080051ce  074a       ldr       r2, [pc, #0x1c]  ; =0x20000083 (HV charge inhibit flag)
    080051d0  c178       ldrb      r1, [r0, #3]     ; r1 = [0x200000cf] (0 at boot!)
    080051d2  8170       strb      r1, [r0, #2]     ; [0x200000ce] = r1 (sets countdown to 0!)
    080051d4  0121       movs      r1, #1
    080051d6  1170       strb      r1, [r2]         ; [0x20000083] = 1 (INHIBIT HV CHARGING)
    080051d8  054a       ldr       r2, [pc, #0x14]  ; =0x00001770 (6000 steps = 600.0 s = 10 min)
    080051da  8281       strh      r2, [r0, #0xc]   ; [0x200000d8] = 6000
    080051dc  0548       ldr       r0, [pc, #0x14]  ; =0x20000084 (over-temp window flag)
    080051de  0170       strb      r1, [r0]         ; [0x20000084] = 1
    080051e0  0549       ldr       r1, [pc, #0x14]  ; =0x20000082 (flash ready flag)
    080051e2  0020       movs      r0, #0
    080051e4  0870       strb      r0, [r1]         ; [0x20000082] = 0 (NOT READY)
    080051e6  7047       bx        lr
```

And in the 100 ms timer drain routine `fn_08007ad4` (`0x08007AFA`–`0x08007B0E`):
* `[0x20000083]` (charge inhibit) is **only** cleared when `[0x200000CE]` (`[r3,#2]`) decrements from `1` to `0` (`0x08007AFA`: `ldrb r0, [r3, #2]; cmp r0, #0; beq 0x8007b10`).
* Because `[0x200000CF]` (`[r3,#3]`) is only initialized to `50` (`0x32` = `5.0 s`) when a flash is fired in `fn_08007944` (`0x08007A08`), a hardware NTC trip at boot copies `0` into `[0x200000CE]` while setting `[0x20000083] = 1` — **leaving `[0x20000083] = 1` stuck for the entire 10-minute (`600 s`) duration of `[0x200000D8]`!**

---

## 6. Software Shot-Counter Thermal Protection (`fn_08007944` & `fn_08007ad4`)

> [!NOTE]
> **Unmodified in `SR001`:**
> Per the design of `SR001`, the software shot-counter architecture documented below is left **100% factory stock** so the strobe retains full software thermal protection when the physical NTC check (`fn_080096b4`) is bypassed.

### 6.1 Accumulator & Timer Structure (`0x200000CC`)

| Offset | Address | Type | Purpose | Status |
|---|---|---|---|---|
| `[r3, #0]` | `0x200000CC` | `uint8` | Short post-flash charge inhibit (`3` ticks, set at `0x0800BA4C`) | ✅ |
| `[r3, #1]` | `0x200000CD` | `uint8` | `5.0 ms` $\rightarrow$ `100 ms` prescaler counter (`0..20` in `fn_08007ad4`) | ✅ |
| `[r3, #2]` | `0x200000CE` | `uint8` | Active post-trip charge-inhibit countdown (in `0.100 s` steps; clears `[0x20000083]` and `[0x200000D6]` on reaching `0` at `0x08007B0C`–`0x08007B0E`) | ✅ |
| `[r3, #3]` | `0x200000CF` | `uint8` | Current forced recycle delay reload value (`50` = `5.0 s` on normal flash `0x08007A08`; increments by `+5` = `+0.5 s` per shot taken during the 10-min over-temp window, capped at `100` = `10.0 s` at `0x080079CE`–`0x080079DE`) | ✅ |
| `[r3, #4]` | `0x200000D0` | `uint8` | Computed TTL flash power level (`0..100`), mapped in `fn_08007944` (`0x08007978`–`0x080079AE`) via thresholds `50/60/70/80/90/100` (`0x32..0x64`) to heat table indices `3, 6, 9, 12, 15, 18, 21` | ✅ |
| `[r3, #5]` | `0x200000D1` | `uint8` | Pre-flash / trigger state flag (`0x08009264`, `0x0800B07C`) | ✅ |
| `[r3, #6]` | `0x200000D2` | `uint8` | Flash sequence active flag (`0x080055CE`, `0x08009D5E`, `0x0800BC7C`) | ✅ |
| `[r3, #8]` | `0x200000D4` | `uint16` | **Idle cliff-reset timer:** Loaded with **`300` (`0x012C` = `30.0 s`)** on every flash outside the over-temp window (`0x08007A0E`). Decremented every `0.100 s` in `fn_08007ad4` (`0x08007AEA`); when it hits `0`, the accumulator `[0x200000D6]` is **cleared to `0`** (`0x08007AF8`). *(Unlike Pro II models, the original AD200 has no gradual leaky-bucket subtraction — only this 30.0-second idle reset!)* | ✅ |
| `[r3, #0xA]` | `0x200000D6` | `uint16` | **Heat accumulator:** Trips thermal protection at **`>= 6000` (`0x1770`)** (`0x08007A52`); cleared to `0` when `[r3, #2]` expires (`0x08007B0C`) or when `[r3, #8]` expires (`0x08007AF8`) | ✅ |
| `[r3, #0xC]` | `0x200000D8` | `uint16` | **10-minute over-temp window timer:** Loaded with **`6000` (`0x1770` = `600.0 s` = `10.0 min`)** when accumulator reaches `6000` (`0x08007A5E`), on any shot during the over-temp window (`0x080079E8`), or in `fn_080051cc` (`0x080051DA`) | ✅ |
| `[r3, #0xE]` | `0x200000DA` | `uint16` | Multi-pulse HSS window timeout (`3` ticks of `5.0 ms` = `15 ms`; set at `0x08008A7C` and `0x0800BAFE` alongside HSS flag `[0x20000085] = 1`; decremented every `5.0 ms` in `fn_08007ad4` at `0x08007B24`) | ✅ |

### 6.2 Power-to-Index Mapping (`0x0800CBEC`)
In Manual / Multi modes, `fn_08007944` (`0x08007944`–`0x080079C4`) calls `fn_080059c8` to map the current flash power setting (`0..83` via `0x0800CBEC`, an 84-byte table descending from `21` down to `0`) into `[0x20000072]`, yielding a table index **`0..21`** where **index `21` is `1/1` full power** and index `0` is minimum power (`1/128` or `1/256`). In TTL mode (`[0x2000003F] & 3 == 0`), `[0x200000D0]` (`0..100`) is mapped directly via thresholds `50/60/70/80/90/100` to indices `3, 6, 9, 12, 15, 18, 21`.

### 6.3 The Four 22-Entry Halfword Heat Lookup Tables (`0x0800CC42`–`0x0800CCF1`)
Selected directly in `fn_08007944` (`0x08007A10`–`0x08007A6A`) by attached head ID `[0x2000000A]` ($\in \{2,3,4\}$ vs. $\notin \{2,3,4\}$) and the HSS flag `[0x20000085]`:

| Table | Flash Address | Payload Offset | `.dfu` Offset | Mode & Head Group | 22 Halfword Entries (Index `0` $\rightarrow$ `21` = `1/1`) | Max Entry (`1/1`) | Continuous `1/1` Shots to `6000` | Status |
|---|---|---|---|---|---|---:|---:|---|
| **Table A** | `0x0800CC42` | `0x9C42` | `0x9D67` | **Normal** (`[0x20000085]=0`), Heads $\notin \{2,3,4\}$ | `6, 6, 6, 12, 12, 12, 20, 20, 20, 30, 30, 30, 40, 40, 40, 60, 60, 60, 80, 100, 120, 150` | `150` | **40 shots** | ✅ |
| **Table B** | `0x0800CC6E` | `0x9C6E` | `0x9D93` | **Normal** (`[0x20000085]=0`), Heads $\in \{2,3,4\}$ | `6, 6, 6, 8, 8, 8, 15, 15, 15, 23, 23, 23, 30, 30, 30, 40, 40, 40, 50, 60, 75, 100` | `100` | **60 shots** | ✅ |
| **Table C** | `0x0800CC9A` | `0x9C9A` | `0x9DBF` | **HSS** (`[0x20000085]=1`), Heads $\notin \{2,3,4\}$ | `60, 60, 60, 60, 60, 60, 60, 60, 60, 80, 80, 80, 100, 100, 100, 150, 150, 150, 200, 200, 200, 300` | `300` | **20 shots** | ✅ |
| **Table D** | `0x0800CCC6` | `0x9CC6` | `0x9DEB` | **HSS** (`[0x20000085]=1`), Heads $\in \{2,3,4\}$ | `30, 30, 30, 30, 30, 30, 30, 30, 30, 40, 40, 40, 44, 44, 44, 60, 60, 60, 75, 75, 75, 120` | `120` | **50 shots** | ✅ |

---

## 7. Boot Version Display (`loc_08008798` in `fn_0800864c`) & `SR001` Patch Summary

When the user holds the **`MODE`** button while flipping the power switch on (`[0x2000004D] == 1` at `0x08008744`), `fn_0800864c` branches to **`loc_08008798`** (`0x08008798`–`0x080087CE`), which renders `U-2.6` on the 7-segment LCD via `fn_080085e0` (7-segment font table `0x0800C4B4`) and `fn_0800c260` (icon/punctuation segment setter):

| Display Element | Instruction Address | `.dfu` Offset | Stock Instruction | Font Entry (`0x0800C4B4`) / Segment | Stock Glyph | `SR001` Patched Instruction | `SR001` Glyph |
|---|---|---|---|---|---|---|---|
| **Digit 5 (Prefix)** | **`0x0800879A`** | **`0x58BF`** | `13 20` (`movs r0, #0x13`) | `0x0800C4B4[0x13] = 0xA7` (`B,C,D,E,F`) | **`U`** | **`14 20` (`movs r0, #0x14`)** | **`S`** (`0x0800C4B4[0x14] = 0xCB`) |
| **Dash (`-`)** | `0x080087A0` | `0x58C5` | `08 21; 01 20` (`fn_0800c260(1, 8)`) | Segment `(1, 8)` | **`-`** | *(unchanged)* | **`-`** |
| **Decimal (`.`)** | `0x080087A8` | `0x58CD` | `0a 21; 03 20` (`fn_0800c260(3, 10)`) | Segment `(3, 10)` | **`.`** | *(unchanged)* | **`.`** |
| **Digit 9 (Major)** | `0x080087B2` | `0x58D7` | `02 20` (`movs r0, #0x02`) | `0x0800C4B4[0x02] = 0x6D` (`A,B,D,E,G`) | **`2`** | *(unchanged)* | **`2`** |
| **Digit 11 (Minor)** | `0x080087BA` | `0x58DF` | `06 20` (`movs r0, #0x06`) | `0x0800C4B4[0x06] = 0xEB` (`A,C,D,E,F,G`) | **`6`** | *(unchanged)* | **`6`** |

### Complete Byte-Diff Table for `SR001` (`AD200_V2.6_SR001_e2_ntc_bypass.dfu`)

| `.dfu` Offset | Payload Offset | Flash Address | Stock Bytes | `SR001` Bytes | Effect |
|---:|---:|---:|---|---|---|
| **`0x58BF`** | `0x579A` | `0x0800879A` | `13 20` | **`14 20`** | Changes boot version readout from `U-2.6` to **`S-2.6`** |
| **`0x67D9`** | `0x66B4` | `0x080096B4` | `70 b5` | **`70 47`** | Replaces `push {r4, r5, r6, lr}` at entry of `fn_080096b4` with `bx lr` (bypasses hardware NTC thermistor check) |
| **`0x9FD5`** | *(DfuSe suffix)* | *(N/A)* | `67 49 bb 3e` | **`2e 2f bd 2f`** | Updates DfuSe suffix CRC32 (`0x3EBB4967` $\rightarrow$ `0x2FBD2F2E`) |
