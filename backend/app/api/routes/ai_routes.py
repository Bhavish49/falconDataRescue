"""
API routes for AI Copilot, Reasoning & Hugging Face Inference.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from app.services.hf_service import query_huggingface_llm
from app.services.ai_assisted_recovery import get_visual_ai_status

router = APIRouter(prefix="/ai", tags=["ai"])


class AIPromptRequest(BaseModel):
    prompt: str
    system_prompt: str | None = "You are an expert digital forensics investigator and data recovery engineer. Provide precise technical insights on file corruption, timestomping, and bitstream artifacts."


@router.post("/analyze")
async def analyze_with_ai(payload: AIPromptRequest):
    """Run forensic analysis prompt through Hugging Face LLM Inference API."""
    result = await query_huggingface_llm(payload.prompt, payload.system_prompt)
    return result


@router.get("/status")
async def visual_ai_status():
    """Return the real local visual-AI readiness state without scoring evidence."""
    return get_visual_ai_status()
