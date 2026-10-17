#!/usr/bin/env python3
"""
Godox AD200 (Original / Non-Pro) — Special Request Firmware Patcher
===================================================================
⚠️  WARNING — UNTESTED SPECIAL REQUEST FIRMWARE  ⚠️
This Special Request firmware (`SR001`) has NOT been tested on physical
hardware. It was developed strictly through static ARM Cortex-M0 disassembly
of official `AD200 V2.6.dfu`. Flash at your own peril!

Supported Special Requests (base V2.6):
---------------------------------------
- SR001 (`AD200_V2.6_SR001_e2_ntc_bypass.dfu`, LCD boot display: `S-2.6`):
  Requested by Reddit user (https://www.reddit.com/r/Godox/comments/1x7729i/comment/ph762sq/):
    "Could you make this for the normal ad200? I have THREE that constantly
     yell E2 barely after being on, and two had their board replaced!"

  Modifications in SR001:
  1. Bypass hardware NTC thermistor polling (`fn_080096b4` at `0x080096B4`,
     payload offset `0x66B4`, `.dfu` offset `0x67D9`):
     `70 b5` (`push {r4, r5, r6, lr}`) -> `70 47` (`bx lr`).
     Prevents a shorted/degraded NTC thermistor or board sense trace (`ADC_IN11`
     on `PC1`, stored at `[0x20000022]`) from setting `[0x200000E8] = 1` (`E2` /
     blinking thermometer + 10-minute charge inhibit lockout via `fn_080051cc`)
     or `[0x200000E8] = 2` (`E0`) 1.1 seconds after power-on.
  2. Update boot version indicator (`fn_08008780` at `0x0800879A`, payload
     offset `0x579A`, `.dfu` offset `0x58BF`):
     `13 20` (`movs r0, #0x13` = `'U'`) -> `14 20` (`movs r0, #0x14` = `'S'`).
     Holding `MODE` during power-on displays `S-2.6` instead of `U-2.6`.
  3. Recompute the 4-byte STMicroelectronics DfuSe suffix CRC32 at `.dfu` offset
     `0x9FD5` (`zlib.crc32(data[:-4]) ^ 0xFFFFFFFF`) so Godox G2 accepts the file.

  Note: Software shot-counter thermal protection (`fn_08007944` / `fn_08007ad4`
  and all four heat lookup tables `0x0800CC42`–`0x0800CCF1`) is left 100% STOCK.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import fwversion  # noqa: E402

OEM_FILENAME = "AD200 V2.6.dfu"
EXPECTED_SHA256 = "aafad9dc8fc739c1681ad473366bdd10b36ffa1fac91737218f0cf133a1b4af2"
EXPECTED_SIZE = 40921  # 0x9FD9 bytes (293-byte DfuSe header + 40,612-byte payload + 16-byte suffix)

OUT_PREFIX = "AD200"
BASE_VER_STR = "V2.6"

# Memory & DfuSe container layout
FLASH_BASE = 0x08003000
DFUSE_PAYLOAD_OFFSET = 0x0125  # 293-byte DfuSe v1 prefix + target prefix + 8-byte element header


def flash_to_dfu_offset(flash_addr: int) -> int:
    """Convert an MCU flash address (0x08003000+) to its byte offset inside `AD200 V2.6.dfu`."""
    return DFUSE_PAYLOAD_OFFSET + (flash_addr - FLASH_BASE)


# Patch 1: Bypass NTC thermistor polling routine `fn_080096b4`
# Flash 0x080096B4 -> Payload 0x66B4 -> .dfu offset 0x67D9
NTC_POLL_FLASH_ADDR = 0x080096B4
NTC_POLL_DFU_OFFSET = flash_to_dfu_offset(NTC_POLL_FLASH_ADDR)  # 0x67D9
NTC_POLL_STOCK_BYTES = b"\x70\xb5"    # push {r4, r5, r6, lr}
NTC_POLL_PATCH_BYTES = b"\x70\x47"    # bx lr

# Patch 2: Boot version display prefix in `fn_0800864c` (`loc_08008798`, shown when holding MODE at power-on)
# Flash 0x0800879A -> Payload 0x579A -> .dfu offset 0x58BF
# Font table `0x0800C4B4` index 0x13 = 'U' (0xA7), index 0x14 = 'S' (0xCB)
VER_PREFIX_FLASH_ADDR = 0x0800879A
VER_PREFIX_DFU_OFFSET = flash_to_dfu_offset(VER_PREFIX_FLASH_ADDR)  # 0x58BF
VER_PREFIX_STOCK_BYTES = b"\x13\x20"  # movs r0, #0x13 ('U' -> "U-2.6")
VER_PREFIX_PATCH_BYTES = b"\x14\x20"  # movs r0, #0x14 ('S' -> "S-2.6")


def load_base(input_path: str):
    if not os.path.exists(input_path):
        print(f"[-] Error: Base firmware not found: {input_path}")
        return None
    with open(input_path, "rb") as f:
        data = bytearray(f.read())
    if len(data) != EXPECTED_SIZE:
        raise ValueError(f"File size is {len(data)} bytes, expected {EXPECTED_SIZE} bytes")
    file_hash = hashlib.sha256(data).hexdigest()
    if file_hash != EXPECTED_SHA256:
        raise ValueError(f"SHA-256 mismatch (got {file_hash}, expected {EXPECTED_SHA256})")
    if not fwversion.verify_dfuse_crc(bytes(data)):
        raise ValueError("Input DfuSe (.dfu) suffix CRC32 verification failed")
    return data


def apply_ntc_bypass(data: bytearray) -> None:
    """Patch `fn_080096b4` to return immediately (`bx lr`), keeping `[0x200000E8] == 0`."""
    actual = bytes(data[NTC_POLL_DFU_OFFSET:NTC_POLL_DFU_OFFSET + 2])
    if actual != NTC_POLL_STOCK_BYTES:
        raise ValueError(
            f"Unexpected bytes at fn_080096b4 (dfu 0x{NTC_POLL_DFU_OFFSET:X}): "
            f"got {actual.hex()}, expected {NTC_POLL_STOCK_BYTES.hex()}"
        )
    data[NTC_POLL_DFU_OFFSET:NTC_POLL_DFU_OFFSET + 2] = NTC_POLL_PATCH_BYTES


def apply_version_indicator(data: bytearray) -> None:
    """Change boot version display from `U-2.6` to `S-2.6` when holding MODE at power-on."""
    actual = bytes(data[VER_PREFIX_DFU_OFFSET:VER_PREFIX_DFU_OFFSET + 2])
    if actual != VER_PREFIX_STOCK_BYTES:
        raise ValueError(
            f"Unexpected bytes at fn_08008780 version prefix (dfu 0x{VER_PREFIX_DFU_OFFSET:X}): "
            f"got {actual.hex()}, expected {VER_PREFIX_STOCK_BYTES.hex()}"
        )
    data[VER_PREFIX_DFU_OFFSET:VER_PREFIX_DFU_OFFSET + 2] = VER_PREFIX_PATCH_BYTES


def build_profile(base_data: bytearray, profile: str, output_dir: str) -> str:
    if profile != "SR001":
        raise ValueError(f"Unsupported Special Request profile for AD200: {profile!r} (only 'SR001' is defined)")

    data = bytearray(base_data)
    apply_ntc_bypass(data)
    apply_version_indicator(data)
    new_crc = fwversion.update_dfuse_crc(data)

    out_name = fwversion.sr_output_name(OUT_PREFIX, BASE_VER_STR, profile, ext=".dfu")
    output_path = os.path.join(output_dir, out_name)
    with open(output_path, "wb") as f:
        f.write(data)

    out_hash = hashlib.sha256(data).hexdigest()
    print(
        f"[+] Built {fwversion.sr_label(profile)}: {os.path.basename(output_path)} "
        f"(DfuSe CRC32: 0x{new_crc:08X}, SHA256: {out_hash})"
    )
    return out_hash


def find_base_file(script_dir: str, filename: str) -> str:
    if len(sys.argv) > 1:
        if sys.argv[1] in ("-h", "--help"):
            print(f"Usage: python patch.py [path_to_{filename!r}]")
            print(f"Builds Special Request (SR001) custom firmware from official OEM '{filename}'.")
            sys.exit(0)
        candidate = sys.argv[1]
        if os.path.exists(candidate):
            return candidate
        print(f"[-] Error: Specified file not found: {candidate}")
        sys.exit(1)

    candidates = [
        os.path.join(script_dir, filename),
        os.path.join(script_dir, filename.replace(" ", "_")),
        os.path.join(script_dir, "..", "_local_godox_assets", "AD200", filename),
        os.path.join(script_dir, "..", filename),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c

    print(f"[-] Error: Official base firmware '{filename}' not found.")
    print("    To build custom firmwares, please obtain the official firmware:")
    print("    1. Download official AD200 V2.6 from https://www.godox.com/firmware-flash/")
    print(f"    2. Place '{filename}' in this directory, or run:")
    print(f"       python patch.py \"<path_to_{filename}>\"")
    sys.exit(1)


def main() -> None:
    print("=" * 74)
    print("  [!] SPECIAL REQUEST FIRMWARES ARE UNTESTED -- FLASH AT YOUR OWN PERIL [!]")
    print("  This build was created strictly from static disassembly without hardware")
    print("  testing. It bypasses the NTC thermistor check (fn_080096b4) for AD200")
    print("  units suffering from false E2/overheat lockouts at boot.")
    print("=" * 74)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_file = find_base_file(script_dir, OEM_FILENAME)
    base_data = load_base(base_file)
    if not base_data:
        sys.exit(1)

    print(f"[*] Building Godox AD200 Special Request Firmware from: {base_file}")
    build_profile(base_data, "SR001", script_dir)
    print("[+] Build complete. Flash via Godox G2 firmware upgrade utility.")


if __name__ == "__main__":
    main()
