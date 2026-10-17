#!/usr/bin/env python3
"""
Shared Special Request (SR#) registry, versioning, and DfuSe CRC32 helpers
for the Godox Untested / Special Request Firmware Patcher.

WARNING — UNTESTED SPECIAL REQUEST FIRMWARE
-------------------------------------------
This repository and patcher build experimental Special Request (`SR#`)
firmwares developed strictly via static ARM Thumb-2 / Cortex-M0 disassembly
for specific community requests. These builds are NOT tested on physical
hardware. Flash at your own peril!

Special Request (SR#) Scheme
----------------------------
Unlike the main tested repository (which builds general-purpose S/R/X performance
tiers), this repository tracks targeted community requests using `SR###` IDs:

    <Model>_<BaseVersion>_<SR#>_<slug>.<ext>
    e.g. AD200_V2.6_SR001_e2_ntc_bypass.dfu
"""

import hashlib
import struct
import zlib
from typing import Dict, Any

# Registry of community Special Requests (SR#)
SPECIAL_REQUESTS: Dict[str, Dict[str, Any]] = {
    "SR001": {
        "sr_id": "SR001",
        "code": 1,
        "name": "E2 / NTC Sensor Fault Bypass",
        "slug": "e2_ntc_bypass",
        "model_id": "AD200",
        "base_version": "V2.6",
        "display_version": "S-2.6",
        "requester_url": (
            "https://www.reddit.com/r/Godox/comments/1x7729i/comment/ph762sq/"
            "?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button"
        ),
        "requester_quote": (
            "Could you make this for the normal ad200? I have THREE that constantly "
            "yell E2 barely after being on, and two had their board replaced!"
        ),
        "summary": (
            "Bypasses NTC thermistor polling (fn_080096b4) to stop false E2 / E0 "
            "thermal lockouts at power-on · Keeps software shot-counter protection 100% stock"
        ),
    },
}


def sr_output_name(prefix: str, base_ver: str, sr_id: str, ext: str = ".dfu") -> str:
    """('AD200', 'V2.6', 'SR001', '.dfu') -> 'AD200_V2.6_SR001_e2_ntc_bypass.dfu'"""
    sr = SPECIAL_REQUESTS[sr_id]
    if not ext.startswith("."):
        ext = "." + ext
    return f"{prefix}_{base_ver}_{sr_id}_{sr['slug']}{ext}"


def sr_label(sr_id: str) -> str:
    """'SR001' -> 'SR001: E2 / NTC Sensor Fault Bypass (LCD: S-2.6)'"""
    sr = SPECIAL_REQUESTS[sr_id]
    return f"{sr_id}: {sr['name']} (LCD: {sr['display_version']})"


def compute_dfuse_crc(data_without_crc: bytes) -> int:
    """
    Compute the standard STMicroelectronics DfuSe suffix CRC32 over all bytes
    preceding the final 4-byte dwCRC field.
    ST DfuSe specifies `zlib.crc32(data[:-4]) ^ 0xFFFFFFFF`.
    """
    return (zlib.crc32(data_without_crc) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def verify_dfuse_crc(data: bytes) -> bool:
    """Verify the DfuSe header signature ('DfuSe\\x01') and trailing 4-byte CRC32."""
    if len(data) < 27 or data[:6] != b"DfuSe\x01":
        return False
    stored_crc = struct.unpack_from("<I", data, len(data) - 4)[0]
    expected_crc = compute_dfuse_crc(data[:-4])
    return stored_crc == expected_crc


def update_dfuse_crc(data: bytearray) -> int:
    """Recompute and write the trailing 4-byte DfuSe CRC32 in-place. Returns the new CRC32."""
    if len(data) < 27 or bytes(data[:6]) != b"DfuSe\x01":
        raise ValueError("Buffer is not a valid STMicroelectronics DfuSe (.dfu) image")
    if bytes(data[-8:-5]) != b"UFD":
        raise ValueError("DfuSe suffix signature ('UFD') missing at offset -8..-5")
    new_crc = compute_dfuse_crc(bytes(data[:-4]))
    struct.pack_into("<I", data, len(data) - 4, new_crc)
    return new_crc


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
