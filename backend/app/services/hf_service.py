"""
Hugging Face Inference Service for Forensic Reasoning, Anomaly Detection & Report Generation.
"""

from __future__ import annotations

import httpx
import structlog
from app.config import get_settings

logger = structlog.get_logger()

HF_INFERENCE_URL = "https://api-inference.huggingface.co/models"


async def query_huggingface_llm(prompt: str, system_prompt: str | None = None) -> dict:
    """Send forensic reasoning prompt to Hugging Face Inference API."""
    settings = get_settings()
    api_key = settings.huggingface_api_key
    model = settings.hf_model or "meta-llama/Llama-3.1-8B-Instruct"

    if not api_key:
        return {
            "status": "not_configured",
            "provider": "huggingface",
            "model": model,
            "error": "HUGGINGFACE_API_KEY is not configured; no remote AI review was performed.",
        }

    url = f"{HF_INFERENCE_URL}/{model}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    formatted_prompt = prompt
    if system_prompt:
        formatted_prompt = f"System: {system_prompt}\n\nUser: {prompt}\n\nAssistant:"

    payload = {
        "inputs": formatted_prompt,
        "parameters": {
            "max_new_tokens": settings.llm_max_tokens,
            "temperature": settings.llm_temperature,
            "return_full_text": False
        }
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            
            if resp.status_code == 200:
                result = resp.json()
                generated_text = ""
                if isinstance(result, list) and len(result) > 0 and "generated_text" in result[0]:
                    generated_text = result[0]["generated_text"]
                elif isinstance(result, dict) and "generated_text" in result:
                    generated_text = result["generated_text"]
                else:
                    generated_text = str(result)

                return {
                    "status": "success",
                    "provider": "huggingface",
                    "model": model,
                    "response": generated_text
                }
            else:
                logger.error("hf.error", status=resp.status_code, body=resp.text)
                return {
                    "status": "error",
                    "provider": "huggingface",
                    "model": model,
                    "error": f"Hugging Face API Error ({resp.status_code}): {resp.text}"
                }
    except Exception as e:
        logger.error("hf.exception", error=str(e))
        return {
            "status": "error",
            "provider": "huggingface",
            "model": model,
            "error": str(e)
        }
