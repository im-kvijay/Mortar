import json
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from enum import IntEnum


class Priority(IntEnum):
    """content priorities"""
    CRITICAL = 100
    HIGH = 80
    MEDIUM = 50
    LOW = 20
    EXPENDABLE = 5


@dataclass(slots=True)
class RollingSummary:
    objective: str = ""
    contract: str = ""
    discoveries: List[str] = field(default_factory=list)
    hypotheses: List[str] = field(default_factory=list)
    areas: List[str] = field(default_factory=list)
    iteration: int = 0

    def to_text(self) -> str:
        parts = [f"[Context] {self.contract}"]
        if self.objective:
            parts.append(f"Goal: {self.objective[:100]}")
        if self.discoveries:
            parts.append(f"Found({len(self.discoveries)}): {'; '.join(d[:60] for d in self.discoveries[-5:])}")
        if self.hypotheses:
            parts.append(f"Investigating: {'; '.join(h[:40] for h in self.hypotheses[-3:])}")
        if self.areas:
            parts.append(f"Covered: {', '.join(self.areas[-10:])}")
        return " | ".join(parts)

    def add_discovery(self, content: str) -> None:
        if content and content not in self.discoveries:
            self.discoveries.append(content[:100])
            if len(self.discoveries) > 15:
                self.discoveries = self.discoveries[-15:]

    def add_hypothesis(self, content: str) -> None:
        if content and content not in self.hypotheses:
            self.hypotheses.append(content[:60])
            if len(self.hypotheses) > 8:
                self.hypotheses = self.hypotheses[-8:]

    def add_area(self, area: str) -> None:
        if area and area not in self.areas:
            self.areas.append(area)
            if len(self.areas) > 20:
                self.areas = self.areas[-20:]


class ContextCompressor:
    __slots__ = ('t_max', 't_retained', 'summary', '_stats')

    def __init__(self, t_max: int = 80000, t_retained: int = 30000):
        if t_max <= 0:
            raise ValueError(f"t_max must be positive, got {t_max}")
        if t_retained <= 0:
            raise ValueError(f"t_retained must be positive, got {t_retained}")
        if t_retained > t_max:
            t_retained = int(t_max * 0.4)

        self.t_max = t_max
        self.t_retained = t_retained
        self.summary = RollingSummary()
        self._stats = {"compressions": 0, "tokens_saved": 0}

    def estimate_tokens(self, content: Any) -> int:
        if isinstance(content, str):
            tokens = int(len(content) / 3.5)
        elif isinstance(content, dict):
            tokens = sum(self.estimate_tokens(k) + self.estimate_tokens(v) for k, v in content.items())
        elif isinstance(content, list):
            tokens = sum(self.estimate_tokens(item) for item in content)
        else:
            tokens = 1

        return tokens

    def get_priority(self, block: Dict[str, Any]) -> int:
        block_type = block.get("type", "")

        if block_type == "thinking":
            return Priority.EXPENDABLE

        if block_type == "tool_result":
            content = str(block.get("content", ""))
            if "recorded" in content.lower() or "added" in content.lower():
                return Priority.HIGH
            return Priority.LOW

        if block_type == "tool_use":
            name = block.get("name", "")
            if name in ("record_discovery", "record_attack_hypothesis"):
                return Priority.HIGH
            if name in ("analysis_complete", "attack_analysis_complete"):
                return Priority.CRITICAL
            return Priority.MEDIUM

        if block_type == "text":
            text = block.get("text", "")
            if any(kw in text.lower() for kw in ["vulnerability", "critical", "exploit"]):
                return Priority.HIGH
            if "PEER" in text or "A2A" in text:
                return Priority.LOW
            return Priority.MEDIUM

        return Priority.LOW

    def compress_block(self, block: Dict[str, Any]) -> Dict[str, Any]:
        block_type = block.get("type", "")

        if block_type == "thinking":
            thinking = block.get("thinking", "")
            if len(thinking) > 300:
                return {"type": "thinking", "thinking": f"{thinking[:150]}...[compressed]...{thinking[-100:]}"}
            return block

        if block_type == "tool_result":
            content = block.get("content", "")
            if isinstance(content, str) and len(content) > 150:
                return {**block, "content": content[:100] + "...[truncated]"}
            return block

        if block_type == "text":
            text = block.get("text", "")
            if len(text) > 400:
                if "function " in text:
                    sigs = re.findall(r"function\s+\w+\s*\([^)]*\)", text)
                    if sigs:
                        return {"type": "text", "text": f"[Functions: {', '.join(sigs[:5])}]"}
                return {"type": "text", "text": text[:200] + "...[compressed]"}
            return block

        return block

    def process(self, messages: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
        current_tokens = self.estimate_tokens(messages)

        if current_tokens <= self.t_max:
            return messages, 0

        initial_tokens = current_tokens
        self.summary.iteration += 1

        self._extract_summary_info(messages)

        scored: List[Tuple[int, int, Dict[str, Any]]] = []
        for idx, msg in enumerate(messages):
            content = msg.get("content", [])
            if isinstance(content, str):
                score = Priority.MEDIUM
            else:
                score = max((self.get_priority(b) for b in content if isinstance(b, dict)), default=Priority.LOW)

            if idx >= len(messages) - 10:
                score += 20

            if idx == 0:
                score = Priority.CRITICAL + 50

            scored.append((score, idx, msg))

        scored.sort(key=lambda x: x[0], reverse=True)

        compressed: List[Dict[str, Any]] = []
        current_tokens = 0
        kept_indices = set()
        compressed_msgs: Dict[int, Dict[str, Any]] = {}

        if messages:
            compressed.append(messages[0])
            current_tokens = self.estimate_tokens(messages[0])
            kept_indices.add(0)

        summary_msg = {"role": "user", "content": self.summary.to_text()}
        summary_tokens = self.estimate_tokens(summary_msg)
        compressed.append(summary_msg)
        current_tokens += summary_tokens

        for score, idx, msg in scored:
            if idx in kept_indices:
                continue

            msg_tokens = self.estimate_tokens(msg)

            if current_tokens + msg_tokens <= self.t_retained:
                kept_indices.add(idx)
                current_tokens += msg_tokens
            elif score >= Priority.HIGH:
                compressed_msg = self._compress_message(msg)
                compressed_tokens = self.estimate_tokens(compressed_msg)
                if current_tokens + compressed_tokens <= self.t_retained:
                    kept_indices.add(idx)
                    compressed_msgs[idx] = compressed_msg
                    current_tokens += compressed_tokens

        result = [compressed[0], compressed[1]]
        for idx in sorted(kept_indices):
            if idx == 0:
                continue
            if idx in compressed_msgs:
                result.append(compressed_msgs[idx])
            else:
                result.append(messages[idx])

        tokens_saved = initial_tokens - self.estimate_tokens(result)
        self._stats["compressions"] += 1
        self._stats["tokens_saved"] += tokens_saved

        return result, tokens_saved

    def _compress_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        content = msg.get("content", [])
        if isinstance(content, str):
            if len(content) > 200:
                return {**msg, "content": content[:150] + "...[truncated]"}
            return msg

        compressed_content = [self.compress_block(b) if isinstance(b, dict) else b for b in content]
        return {**msg, "content": compressed_content}

    def _extract_summary_info(self, messages: List[Dict[str, Any]]) -> None:
        for msg in messages[-50:] if len(messages) > 50 else messages:
            content = msg.get("content", [])
            if isinstance(content, str):
                continue

            for block in content:
                if not isinstance(block, dict):
                    continue

                if block.get("type") == "tool_use":
                    name = block.get("name", "")
                    inp = block.get("input", {})

                    if name == "record_discovery":
                        self.summary.add_discovery(str(inp.get("content", "")))
                        self.summary.add_area(str(inp.get("discovery_type", "")))

                    elif name == "record_attack_hypothesis":
                        self.summary.add_hypothesis(str(inp.get("description", "")))

                    elif name in ("trace_state_variable", "analyze_function_symbolically"):
                        self.summary.add_area(str(inp.get("variable_name", inp.get("function_name", ""))))

    def get_stats(self) -> Dict[str, Any]:
        return {
            "compressions": self._stats["compressions"],
            "tokens_saved": self._stats["tokens_saved"],
        }


def create_compressor(t_max: int = 80000, t_retained: int = 30000) -> ContextCompressor:
    return ContextCompressor(t_max=t_max, t_retained=t_retained)
