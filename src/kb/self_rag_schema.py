"""structured selfrag response schemas"""

from typing import List, Literal
from pydantic import BaseModel, Field, validator


class PatternJudgment(BaseModel):
    """reflection output for a single pattern"""

    pattern_id: str = Field(..., description="Unique identifier of the pattern being judged.")
    relevance: Literal["Relevant", "Irrelevant"] = Field(..., description="Whether the pattern matches the query.")
    quality: Literal["HighQuality", "LowQuality"] = Field(..., description="Whether the pattern is reliable.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model confidence in the judgment.")
    reason: str = Field(..., description="One sentence explaining the judgment.")

    @validator("reason")
    def _strip_reason(cls, value: str) -> str:
        return value.strip()


class SelfRAGResponse(BaseModel):
    """batch of pattern judgments"""

    prompt_version: str = Field(..., description="Version of the reflection prompt/schema.")
    judgments: List[PatternJudgment]
