"""Port of server/tools/types.ts"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel

IndicatorType = Literal["sha256", "sha1", "md5", "ip", "domain", "url"]
Verdict = Literal["malicious", "suspicious", "clean", "unknown"]


class NormalizedFinding(BaseModel):
    source: str
    label: str
    detail: Optional[str] = None


class Indicator(BaseModel):
    type: IndicatorType
    value: str


class NormalizedToolResult(BaseModel):
    tool: str
    action: str
    success: bool
    indicator: Indicator
    verdict: Verdict
    confidence: float  # 0-100
    findings: list[NormalizedFinding]
    references: list[str]
    raw: Optional[dict] = None
    timestamp: str


class DecryptedCredential(BaseModel):
    apiKey: str
    baseUrl: Optional[str] = None


class AdapterExecuteInput(BaseModel):
    action: str
    indicatorValue: str
    credential: DecryptedCredential
