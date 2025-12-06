"""extract and repair json from llm responses"""

from __future__ import annotations

import json
import re
from typing import Any

CODE_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)
COMMENT_PATTERN = re.compile(r"//.*?$|/\*.*?\*/", re.DOTALL | re.MULTILINE)
TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_code_fence(text: str) -> str:
    match = CODE_FENCE.search(text)
    if match:
        return match.group(1).strip()
    return text.strip()


def _extract_json_object(text: str) -> str:
    match = JSON_OBJECT.search(text)
    if match:
        return match.group(0)
    return text


def repair_json(text: str) -> str:
    """remove comments and trailing commas"""
    text = COMMENT_PATTERN.sub("", text)
    text = TRAILING_COMMA.sub(r"\1", text)
    return text.strip()


def extract_json_payload(text: str) -> str:
    """extract json from model response"""
    candidate = _strip_code_fence(text)
    candidate = _extract_json_object(candidate)
    candidate = repair_json(candidate)
    return candidate


def safe_json_loads(text: str) -> Any:
    """parse text as json after repair"""
    payload = extract_json_payload(text)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse JSON payload: {exc}") from exc
