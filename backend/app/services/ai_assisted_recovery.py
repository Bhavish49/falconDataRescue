"""Evidence-safe AI assistance for image recovery.

AI is used for visual similarity, reference matching, and review metadata. It
never writes recovered bytes and never upgrades a failed decoder result.
"""

from __future__ import annotations

import io
import math
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageFile, ImageStat

from app.config import get_settings


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png"}


def _visual_metrics(data: bytes) -> dict[str, Any]:
    """Return cheap, deterministic metrics used to gate AI review."""
    previous = ImageFile.LOAD_TRUNCATED_IMAGES
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            preview = image.convert("L")
            preview.thumbnail((256, 256))
            minimum, maximum = preview.getextrema()
            mean = ImageStat.Stat(preview).mean[0]
            histogram = np.asarray(preview.histogram(), dtype=np.float64)
            histogram /= max(histogram.sum(), 1.0)
            entropy = float(-(histogram[histogram > 0] * np.log2(histogram[histogram > 0])).sum())
            return {
                "ok": True,
                "width": image.width,
                "height": image.height,
                "minimum": int(minimum),
                "maximum": int(maximum),
                "mean": round(float(mean), 3),
                "entropy": round(entropy, 3),
                "uniform": minimum == maximum,
            }
    except Exception as exc:
        return {"ok": False, "uniform": False, "error": str(exc)}
    finally:
        ImageFile.LOAD_TRUNCATED_IMAGES = previous


@lru_cache(maxsize=1)
def _load_dinov2() -> tuple[Any, str | None]:
    settings = get_settings()
    if not settings.ai_visual_enabled:
        return None, "disabled_by_configuration"
    try:
        from transformers import Dinov2Model

        model = Dinov2Model.from_pretrained(
            settings.ai_visual_model,
            local_files_only=not settings.ai_allow_model_download,
        )
        model.eval()
        return model, None
    except Exception as exc:
        return None, f"model_unavailable: {exc}"


def _embedding(data: bytes) -> tuple[list[float] | None, str | None]:
    model, error = _load_dinov2()
    if error:
        return None, error
    try:
        import torch

        with Image.open(io.BytesIO(data)) as image:
            image.load()
            image = image.convert("RGB").resize((224, 224), Image.Resampling.BICUBIC)
            pixels = np.asarray(image, dtype=np.float32) / 255.0
        pixels = (pixels - np.asarray([0.485, 0.456, 0.406], dtype=np.float32)) / np.asarray(
            [0.229, 0.224, 0.225], dtype=np.float32
        )
        inputs = {"pixel_values": torch.from_numpy(pixels).permute(2, 0, 1).unsqueeze(0)}
        with torch.inference_mode():
            output = model(**inputs)
            vector = output.last_hidden_state[:, 0, :].squeeze(0)
            vector = vector / vector.norm(p=2).clamp_min(1e-12)
        return vector.cpu().tolist(), None
    except Exception as exc:
        return None, f"embedding_failed: {exc}"


def _cosine(left: list[float], right: list[float]) -> float:
    a = np.asarray(left, dtype=np.float32)
    b = np.asarray(right, dtype=np.float32)
    denominator = float(np.linalg.norm(a) * np.linalg.norm(b))
    return float(np.dot(a, b) / denominator) if denominator else 0.0


def _reference_match(vector: list[float], reference_dir: str) -> dict[str, Any]:
    directory = Path(reference_dir) if reference_dir else None
    if directory is None or not directory.is_dir():
        return {"status": "not_configured", "matches": []}

    matches: list[dict[str, Any]] = []
    for path in directory.rglob("*"):
        if path.suffix.lower() not in IMAGE_EXTENSIONS or not path.is_file():
            continue
        try:
            candidate = path.read_bytes()
            candidate_vector, error = _embedding(candidate)
            if candidate_vector is not None:
                matches.append({"file_name": path.name, "score": round(_cosine(vector, candidate_vector), 5)})
            elif error:
                continue
        except OSError:
            continue
    matches.sort(key=lambda item: item["score"], reverse=True)
    return {"status": "completed", "matches": matches[:5]}


def analyze_image_recovery(
    filename: str,
    original: bytes,
    candidate: bytes,
    report: dict[str, Any],
) -> dict[str, Any]:
    """Review an image candidate without modifying it or changing its status."""
    settings = get_settings()
    result: dict[str, Any] = {
        "status": "blocked" if report.get("status") == "FAILED_RECOVERY" else "completed",
        "provider": "local-evidence-ai",
        "model": settings.ai_visual_model if settings.ai_visual_enabled else None,
        "role": "ranking_and_validation_only",
        "reference_match": {"status": "not_run", "matches": []},
    }

    original_metrics = _visual_metrics(original)
    candidate_metrics = _visual_metrics(candidate)
    result["original_visual_metrics"] = original_metrics
    result["candidate_visual_metrics"] = candidate_metrics

    if report.get("status") == "FAILED_RECOVERY":
        result["reason"] = "decoder_failed_or_visual_output_was_uniform"
        result["assessment"] = "AI review blocked: no validated image candidate exists."
        return result
    if report.get("content_recovery_status") == "decoded_without_pixel_repair":
        result["reason"] = "container_valid_but_pixel_repair_not_attempted"
        result["assessment"] = (
            "The JPEG is readable, but no pixel content was reconstructed. "
            "A reference image or image-restoration model is required to repair visible artifacts."
        )
    if not candidate_metrics.get("ok") or candidate_metrics.get("uniform"):
        result["status"] = "blocked"
        result["reason"] = "candidate_is_not_visually_valid"
        result["assessment"] = "AI review blocked: candidate has no usable visual variation."
        return result

    vector, error = _embedding(candidate)
    if vector is None:
        result["status"] = "unavailable"
        result["reason"] = error or "embedding_model_unavailable"
        result["assessment"] = "Deterministic recovery passed; visual similarity AI is unavailable."
        return result

    result["embedding"] = {"model": settings.ai_visual_model, "dimension": len(vector)}
    result["reference_match"] = _reference_match(vector, settings.ai_reference_dir)
    result["assessment"] = "AI visual features generated for similarity ranking; bytes were not invented."
    return result


def get_visual_ai_status() -> dict[str, Any]:
    """Report whether the local visual model is actually ready to run."""
    settings = get_settings()
    if not settings.ai_visual_enabled:
        return {
            "status": "disabled",
            "provider": "local-evidence-ai",
            "model": settings.ai_visual_model,
            "reference_dir_configured": bool(settings.ai_reference_dir),
        }
    _model, error = _load_dinov2()
    return {
        "status": "ready" if error is None else "unavailable",
        "provider": "local-evidence-ai",
        "model": settings.ai_visual_model,
        "reference_dir_configured": bool(settings.ai_reference_dir),
        "reason": error,
    }
