"""Conservative JPEG/PNG recovery and decoder-backed validation."""

from __future__ import annotations

import binascii
import io
import struct
from hashlib import md5, sha256
from typing import Any

from PIL import Image, ImageFile, ImageStat

from app.services.image_scanner import scan_image_fragments


JPEG_SOI = b"\xff\xd8\xff"
JPEG_EOI = b"\xff\xd9"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_IEND = b"IEND"


def detect_image_format(filename: str, data: bytes) -> str | None:
    if data.startswith(JPEG_SOI) or JPEG_SOI in data[:4096]:
        return "jpeg"
    if data.startswith(PNG_SIGNATURE) or PNG_SIGNATURE in data[:4096]:
        return "png"
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension in {"jpg", "jpeg"}:
        return "jpeg"
    return "png" if extension == "png" else None


def _decode(data: bytes, allow_truncated: bool = False) -> dict[str, Any]:
    previous = ImageFile.LOAD_TRUNCATED_IMAGES
    ImageFile.LOAD_TRUNCATED_IMAGES = allow_truncated
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            return {
                "ok": True,
                "format": image.format,
                "width": image.width,
                "height": image.height,
                "mode": image.mode,
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        ImageFile.LOAD_TRUNCATED_IMAGES = previous


def _append_png_iend(data: bytes) -> bytes:
    return data + struct.pack(">I", 4) + PNG_IEND + struct.pack(">I", binascii.crc32(PNG_IEND) & 0xFFFFFFFF)


def _repair_jpeg_structure(data: bytes) -> tuple[bytes, list[str]]:
    """Repair conservative JPEG container damage before the entropy stream."""
    if not data.startswith(JPEG_SOI):
        return data, []

    repaired = bytearray(data)
    operations: list[str] = []
    position = 2

    while position + 4 <= len(repaired):
        if repaired[position] != 0xFF:
            position += 1
            continue
        while position < len(repaired) and repaired[position] == 0xFF:
            position += 1
        if position >= len(repaired):
            break
        marker = repaired[position]
        marker_start = position - 1
        position += 1

        if marker == 0xDA:  # SOS: the remainder is entropy-coded image data.
            if position + 2 > len(repaired):
                break
            if repaired[position] == 0x20:
                repaired[position] = 0
                operations.append("Repaired corrupted SOS segment length")
            segment_length = int.from_bytes(repaired[position : position + 2], "big")
            entropy_start = position + segment_length
            if entropy_start <= len(repaired):
                entropy = bytes(repaired[entropy_start:]).replace(b"\xff\x20", b"\xff\x00")
                if entropy != bytes(repaired[entropy_start:]):
                    repaired[entropy_start:] = entropy
                    operations.append("Repaired JPEG stuffed-zero markers in entropy data")
            break

        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if position + 2 > len(repaired):
            break

        if repaired[position] == 0x20:
            repaired[position] = 0
            operations.append(f"Repaired corrupted JPEG marker length at offset {marker_start}")
        segment_length = int.from_bytes(repaired[position : position + 2], "big")
        if segment_length < 2 or position + segment_length > len(repaired):
            break

        # Replace a damaged JFIF APP0 header with the canonical 16-byte form.
        if marker == 0xE0 and bytes(repaired[position + 2 : position + 7]) == b"JFIF\x20":
            end = position + segment_length
            canonical = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x00\x01\x00\x01\x00\x00"
            repaired[marker_start:end] = canonical
            operations.append("Repaired corrupted JFIF APP0 header")
            position = marker_start + len(canonical)
            continue
        position += segment_length

    return bytes(repaired), operations


def _repair_jpeg_null_spaces(data: bytes) -> tuple[bytes, list[str]]:
    """Repair only JPEG fields whose binary meaning disambiguates NUL bytes.

    A known transfer failure changed some 0x00 bytes to 0x20. Quantization
    values and entropy bytes can legitimately be 0x20, so this routine repairs
    only table identifiers, component selectors, and Huffman count vectors
    when JPEG segment lengths prove that a 0x20 must actually be zero.
    """
    scan_start = data.find(b"\xff\xda")
    if scan_start < 0:
        return data, []

    repaired = bytearray(data)
    operations: list[str] = []
    position = 2
    while position + 4 <= scan_start:
        if repaired[position] != 0xFF:
            position += 1
            continue
        while position < scan_start and repaired[position] == 0xFF:
            position += 1
        if position >= scan_start:
            break
        marker = repaired[position]
        position += 1
        if marker == 0xDA:
            break
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if position + 2 > scan_start:
            break
        segment_length = int.from_bytes(repaired[position : position + 2], "big")
        segment_end = position + segment_length
        if segment_length < 2 or segment_end > len(repaired):
            break
        payload = position + 2

        if marker == 0xDB:  # DQT table selector is not a quantization value.
            cursor = payload
            while cursor < segment_end:
                table_info = repaired[cursor]
                if table_info == 0x20:
                    repaired[cursor] = 0
                    operations.append("Repaired JPEG quantization-table selector")
                    table_info = 0
                table_size = 64 * (2 if table_info >> 4 else 1)
                cursor += 1 + table_size
                if cursor > segment_end:
                    break

        elif marker == 0xC0:  # SOF0 component quantization selectors.
            component_count = repaired[payload + 5] if payload + 5 < segment_end else 0
            for index in range(component_count):
                selector = payload + 6 + index * 3 + 2
                if selector < segment_end and repaired[selector] == 0x20:
                    repaired[selector] = 0
                    operations.append("Repaired JPEG component quantization selector")

        elif marker == 0xC4:  # DHT counts must sum to the table's symbol bytes.
            cursor = payload
            while cursor + 17 <= segment_end:
                if repaired[cursor] == 0x20:
                    repaired[cursor] = 0
                    operations.append("Repaired JPEG Huffman-table selector")
                counts_start = cursor + 1
                counts = list(repaired[counts_start : counts_start + 16])
                expected_symbols = segment_end - (counts_start + 16)
                trial = [0 if value == 0x20 else value for value in counts]
                if sum(counts) != expected_symbols and sum(trial) == expected_symbols:
                    for index, value in enumerate(trial):
                        if value != counts[index]:
                            repaired[counts_start + index] = value
                    operations.append("Repaired JPEG Huffman zero-count bytes")
                    counts = trial
                cursor = counts_start + 16 + sum(counts)

        position = segment_end

    # SOS selectors and spectral bounds have fixed positions and are safe to
    # repair when the same NUL-to-space signature is present.
    sos_payload = scan_start + 4
    if sos_payload < len(repaired):
        component_count = repaired[sos_payload]
        for index in range(component_count):
            selector = sos_payload + 1 + index * 2 + 1
            if selector < len(repaired) and repaired[selector] == 0x20:
                repaired[selector] = 0
                operations.append("Repaired JPEG scan-table selector")
        spectral_start = sos_payload + 1 + component_count * 2
        for offset in (0, 2):
            position = spectral_start + offset
            if position < len(repaired) and repaired[position] == 0x20:
                repaired[position] = 0
                operations.append("Repaired JPEG scan spectral field")

    return bytes(repaired), operations


def _render_partial_image(data: bytes, image_format: str) -> tuple[bytes | None, dict[str, Any] | None]:
    """Render decoder-readable partial pixels into a new valid image container."""
    previous = ImageFile.LOAD_TRUNCATED_IMAGES
    ImageFile.LOAD_TRUNCATED_IMAGES = True
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            output = io.BytesIO()
            if image_format == "jpeg":
                if image.mode not in {"1", "L", "RGB", "CMYK"}:
                    image = image.convert("RGB")
                image.save(output, format="JPEG", quality=95, optimize=False)
            else:
                image.save(output, format="PNG")
            rendered = output.getvalue()
        return rendered, _decode(rendered)
    except Exception:
        return None, None
    finally:
        ImageFile.LOAD_TRUNCATED_IMAGES = previous


def _visual_validation(data: bytes) -> dict[str, Any]:
    """Check whether decoded output contains any usable tonal variation."""
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            preview = image.convert("L")
            preview.thumbnail((128, 128))
            minimum, maximum = preview.getextrema()
            mean = ImageStat.Stat(preview).mean[0]
            return {
                "ok": True,
                "minimum": minimum,
                "maximum": maximum,
                "mean": round(mean, 3),
                "uniform": minimum == maximum,
            }
    except Exception as exc:
        return {"ok": False, "uniform": False, "error": str(exc)}


def recover_image(filename: str, original: bytes) -> tuple[bytes, dict[str, Any]]:
    """Recover only defensible container damage; never synthesize pixel data."""
    image_format = detect_image_format(filename, original)
    if image_format is None:
        raise ValueError("Only JPEG and PNG images are supported")

    original_hashes = {"md5": md5(original).hexdigest(), "sha256": sha256(original).hexdigest()}
    scan = scan_image_fragments(original, image_format)
    strict_original = _decode(original)
    candidate = original
    operations: list[str] = []
    warnings: list[str] = []
    embedded_candidate_extracted = False

    if image_format == "jpeg":
        jpeg_candidates = scan["candidates"]
        if jpeg_candidates:
            selected = jpeg_candidates[0]
            # A damaged file can contain thumbnails or accidental SOI/EOI
            # byte pairs before the real image. Prefer the largest candidate
            # that Pillow can actually decode when the outer container fails.
            if not strict_original["ok"]:
                valid_candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
                for possible in jpeg_candidates:
                    possible_bytes = original[possible["offset"] : possible["end_offset"]]
                    possible_decode = _decode(possible_bytes)
                    if possible_decode.get("ok"):
                        valid_candidates.append((possible, possible_decode))
                if valid_candidates:
                    selected, selected_decode = max(
                        valid_candidates,
                        key=lambda item: (
                            item[1].get("width", 0) * item[1].get("height", 0),
                            item[0].get("length", 0),
                        ),
                    )
                    candidate = original[selected["offset"] : selected["end_offset"]]
                    embedded_candidate_extracted = selected["offset"] > 0
                    if embedded_candidate_extracted:
                        operations.append(
                            f"Extracted largest decoder-valid embedded JPEG at offset {selected['offset']}"
                        )
                        warnings.append(
                            "Extracted a decoder-valid JPEG candidate; altered pixel content inside it was not reconstructed"
                        )
            if not embedded_candidate_extracted:
                soi = selected["offset"]
                if soi > 0:
                    candidate = candidate[soi:]
                    operations.append(f"Removed {soi} bytes before JPEG SOI marker")
        null_space_signature = b"JFIF\x20" in candidate[:128]
        if not candidate.startswith(JPEG_SOI):
            warnings.append("JPEG SOI marker is missing; pixel data cannot be safely reconstructed")
        if candidate.startswith(JPEG_SOI) and not candidate.endswith(JPEG_EOI):
            candidate += JPEG_EOI
            operations.append("Appended missing JPEG EOI marker")
        candidate, jpeg_operations = _repair_jpeg_structure(candidate)
        operations.extend(jpeg_operations)
        if null_space_signature:
            candidate, null_space_operations = _repair_jpeg_null_spaces(candidate)
            operations.extend(null_space_operations)
    else:
        png_candidates = scan["candidates"]
        if png_candidates:
            signature = png_candidates[0]["offset"]
            if signature > 0:
                candidate = candidate[signature:]
                operations.append(f"Removed {signature} bytes before PNG signature")
        if candidate.startswith(PNG_SIGNATURE) and PNG_IEND not in candidate[-64:]:
            candidate = _append_png_iend(candidate)
            operations.append("Appended missing PNG IEND chunk")
        if not candidate.startswith(PNG_SIGNATURE):
            warnings.append("PNG signature is missing; pixel data cannot be safely reconstructed")

    strict_repaired = _decode(candidate)
    truncated_repaired = None
    rendered_partial = False
    visual_validation: dict[str, Any] | None = None
    decoded = strict_repaired
    if not strict_repaired["ok"]:
        truncated_repaired = _decode(candidate, allow_truncated=True)
        if truncated_repaired["ok"]:
            rendered, rendered_decode = _render_partial_image(candidate, image_format)
            if rendered is not None and rendered_decode and rendered_decode["ok"]:
                visual_validation = _visual_validation(rendered)
                if visual_validation.get("uniform"):
                    warnings.append(
                        "Decoder produced a uniform image; no recoverable scene detail was validated"
                    )
                else:
                    candidate = rendered
                    strict_repaired = rendered_decode
                    decoded = rendered_decode
                    rendered_partial = True

    if strict_original["ok"]:
        status = "ORIGINAL_VALID"
        confidence = 100
        warnings.append(
            "JPEG container decoded successfully; pixel content was not reconstructed. "
            "Visible artifacts inside a readable image require a trusted reference or an "
            "optional image-restoration model."
        )
    elif strict_repaired["ok"] and not rendered_partial:
        status = "VALIDATED_REPAIR"
        confidence = 92
    elif rendered_partial:
        status = "PARTIAL_RECOVERY"
        confidence = 55
        warnings.append("Output was re-encoded from decoder-readable data; missing pixels were not reconstructed")
    else:
        status = "FAILED_RECOVERY"
        confidence = 0
        warnings.append("Image decoder could not render the recovered bytes")
        decoder_error = (decoded or strict_repaired).get("error")
        if decoder_error:
            warnings.append(f"Decoder detail: {decoder_error}")

    report = {
        "file_name": filename,
        "format": image_format,
        "status": status,
        "confidence": confidence,
        "original_size": len(original),
        "repaired_size": len(candidate),
        "original_hashes": original_hashes,
        "operations": operations,
        "warnings": warnings,
        "original_decode": strict_original,
        "repaired_decode": decoded or strict_repaired,
        "visual_validation": visual_validation,
        "pixel_data_reconstructed": False,
        "pixel_recovery_confidence": 0 if strict_original["ok"] else confidence,
        "content_recovery_status": (
            "decoded_without_pixel_repair"
            if strict_original["ok"]
            else "decoded_embedded_candidate"
            if embedded_candidate_extracted
            else "pixel_repair_not_validated"
        ),
        "realism_assessment": (
            "Original image decoded successfully. No repair or pixel reconstruction was performed."
            if status == "ORIGINAL_VALID"
            else None
        ),
        "confidence_scope": "container_and_decoder_only",
        "validation_scope": "Pillow decoder load()",
        "scanner": scan,
    }
    return candidate, report
