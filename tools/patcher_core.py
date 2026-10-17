#!/usr/bin/env python3
"""
Core detection and patching engine for the Godox Special Request (Untested) Firmware Patcher.

Wraps the per-model `patch.py` scripts and `tools/fwversion.py` so both the
GUI drag-and-drop application and CLI mode share a single source of truth
for SHA-256 verification, model metadata, Special Request (`SR#`) details,
and `.dfu` / `.bin` image generation.
"""

from dataclasses import dataclass
import hashlib
import importlib.util
import os
import sys
from typing import Dict, List, Optional, Tuple

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

import fwversion  # noqa: E402


def get_bundle_root() -> str:
    """Return the root directory containing model subdirectories (supports PyInstaller _MEIPASS)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS  # type: ignore[attr-defined]
    return os.path.abspath(os.path.join(TOOLS_DIR, ".."))


@dataclass(frozen=True)
class TierOption:
    tier_key: str          # e.g. "SR001"
    tier_code: int         # e.g. 1
    name: str              # e.g. "E2 / NTC Sensor Fault Bypass"
    version_str: str       # e.g. "V2.6-SR001"
    display_version: str   # e.g. "S-2.6" (as shown on strobe LCD when holding MODE at power-on)
    output_filename: str   # e.g. "AD200_V2.6_SR001_e2_ntc_bypass.dfu"
    expected_sha256: str   # Verified target SHA-256 of the patched image
    summary: str           # Concise modification summary
    details: str           # Short tag
    requester_url: str = ""
    requester_quote: str = ""


@dataclass(frozen=True)
class ModelSpec:
    model_id: str          # Directory name, e.g. "AD200"
    display_name: str      # e.g. "Godox AD200 (Original / Non-Pro)"
    category: str          # e.g. "200Ws Modular Pocket Strobe (Untested)"
    oem_filename: str      # e.g. "AD200 V2.6.dfu"
    base_version_str: str  # e.g. "V2.6"
    expected_size: int
    expected_sha256: str
    hardware_notes: str
    flash_tool: str        # e.g. "Godox G2"
    tiers: Tuple[TierOption, ...]

    @property
    def base_version_display(self) -> str:
        return self.base_version_str


# Verified model & Special Request (SR#) specifications
MODEL_SPECS: Tuple[ModelSpec, ...] = (
    ModelSpec(
        model_id="AD200",
        display_name="Godox AD200 (Original)",
        category="200Ws Pocket Strobe · UNTESTED HARDWARE",
        oem_filename="AD200 V2.6.dfu",
        base_version_str="V2.6",
        expected_size=40921,
        expected_sha256="aafad9dc8fc739c1681ad473366bdd10b36ffa1fac91737218f0cf133a1b4af2",
        hardware_notes="UNTESTED ON HARDWARE · STM32L0xx DfuSe (.dfu) · Flash via Godox G2",
        flash_tool="Godox G2",
        tiers=(
            TierOption(
                tier_key="SR001",
                tier_code=1,
                name="E2 / NTC Sensor Fault Bypass",
                version_str="V2.6-SR001",
                display_version="S-2.6",
                output_filename="AD200_V2.6_SR001_e2_ntc_bypass.dfu",
                expected_sha256="f76b859f2dcc1c5225f0b64ea4407e28b9afff5ba1910a30646fde922483d1f9",
                summary=(
                    "Bypasses NTC thermistor polling (fn_080096b4) to stop false E2 / E0 "
                    "thermal lockouts 1.1s after power-on · Stock shot-counter protection"
                ),
                details="LCD: S-2.6 · NTC bypass",
                requester_url=fwversion.SPECIAL_REQUESTS["SR001"]["requester_url"],
                requester_quote=fwversion.SPECIAL_REQUESTS["SR001"]["requester_quote"],
            ),
        ),
    ),
)

MODEL_BY_SHA256: Dict[str, ModelSpec] = {m.expected_sha256: m for m in MODEL_SPECS}
MODEL_BY_ID: Dict[str, ModelSpec] = {m.model_id: m for m in MODEL_SPECS}
PATCHED_BY_SHA256: Dict[str, Tuple[ModelSpec, TierOption]] = {
    tier.expected_sha256: (model, tier)
    for model in MODEL_SPECS
    for tier in model.tiers
}


@dataclass(frozen=True)
class DetectionResult:
    status: str  # "oem_match", "already_patched", "size_match_hash_mismatch", "unknown"
    file_path: str
    file_size: int
    file_sha256: str
    model: Optional[ModelSpec] = None
    existing_tier: Optional[TierOption] = None
    message: str = ""


def identify_firmware(file_path: str) -> DetectionResult:
    """Read a firmware file and identify whether it is a supported OEM image, an already-patched SR# image, or unknown."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        data = f.read()

    file_size = len(data)
    file_sha256 = hashlib.sha256(data).hexdigest()

    # 1. Exact OEM base firmware match
    if file_sha256 in MODEL_BY_SHA256:
        model = MODEL_BY_SHA256[file_sha256]
        return DetectionResult(
            status="oem_match",
            file_path=file_path,
            file_size=file_size,
            file_sha256=file_sha256,
            model=model,
            message=f"Verified OEM firmware: {model.display_name} ({model.base_version_display})",
        )

    # 2. Already-patched custom firmware match
    if file_sha256 in PATCHED_BY_SHA256:
        model, tier = PATCHED_BY_SHA256[file_sha256]
        return DetectionResult(
            status="already_patched",
            file_path=file_path,
            file_size=file_size,
            file_sha256=file_sha256,
            model=model,
            existing_tier=tier,
            message=(
                f"This file is already patched to {tier.tier_key}: {tier.name} (LCD: {tier.display_version}). "
                f"Drop the original OEM '{model.oem_filename}' ({model.base_version_display}) to rebuild."
            ),
        )

    # 3. File size matches one of our models, but SHA-256 differs
    for model in MODEL_SPECS:
        if file_size == model.expected_size:
            return DetectionResult(
                status="size_match_hash_mismatch",
                file_path=file_path,
                file_size=file_size,
                file_sha256=file_sha256,
                model=model,
                message=(
                    f"Size matches {model.display_name}, but checksum does not match official {model.base_version_display} "
                    f"(got {file_sha256[:12]}...)."
                ),
            )

    # 4. Unknown file
    supported_list = ", ".join(f"{m.display_name} ({m.oem_filename})" for m in MODEL_SPECS)
    return DetectionResult(
        status="unknown",
        file_path=file_path,
        file_size=file_size,
        file_sha256=file_sha256,
        message=f"Unrecognized file ({file_size:,} B). Supported OEM bases: {supported_list}.",
    )


def _load_model_patcher(model_id: str):
    """Dynamically load <model_id>/patch.py from source tree or PyInstaller bundle."""
    bundle_root = get_bundle_root()
    patch_script = os.path.join(bundle_root, model_id, "patch.py")
    if not os.path.isfile(patch_script):
        raise FileNotFoundError(f"Model patcher script not found: {patch_script}")

    spec = importlib.util.spec_from_file_location(f"godox_patch_{model_id}", patch_script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not create module spec for {patch_script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class BuiltOutput:
    tier: TierOption
    output_path: str
    sha256: str
    verified: bool


def build_selected_tiers(
    source_file_path: str,
    model: ModelSpec,
    tier_keys: List[str],
    output_dir: Optional[str] = None,
) -> List[BuiltOutput]:
    """
    Build one or more Special Request (`SR#`) firmware images from a verified OEM base image.
    Writes output `.dfu`/`.bin` files to `output_dir` (defaults to the directory of `source_file_path`)
    and verifies the resulting SHA-256 against `TierOption.expected_sha256`.
    """
    with open(source_file_path, "rb") as f:
        base_data = bytearray(f.read())

    if len(base_data) != model.expected_size:
        raise ValueError(
            f"Size mismatch for {model.display_name}: expected {model.expected_size} bytes, got {len(base_data)}"
        )

    actual_sha = hashlib.sha256(base_data).hexdigest()
    if actual_sha != model.expected_sha256:
        raise ValueError(
            f"SHA-256 mismatch for {model.display_name}: expected {model.expected_sha256}, got {actual_sha}"
        )

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(source_file_path))

    os.makedirs(output_dir, exist_ok=True)
    patcher_mod = _load_model_patcher(model.model_id)

    tier_map = {t.tier_key: t for t in model.tiers}
    results: List[BuiltOutput] = []

    for key in tier_keys:
        if key not in tier_map:
            raise ValueError(f"Special Request '{key}' is not supported on {model.display_name}")
        tier_opt = tier_map[key]
        out_hash = patcher_mod.build_profile(base_data, key, output_dir)
        out_path = os.path.join(output_dir, tier_opt.output_filename)
        verified = (out_hash == tier_opt.expected_sha256)
        if not verified:
            raise RuntimeError(
                f"Output SHA-256 verification failed for {tier_opt.output_filename}: "
                f"expected {tier_opt.expected_sha256}, got {out_hash}"
            )
        results.append(
            BuiltOutput(
                tier=tier_opt,
                output_path=out_path,
                sha256=out_hash,
                verified=verified,
            )
        )

    return results
