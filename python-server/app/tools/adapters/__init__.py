"""Port of server/tools/adapters/index.ts"""
from __future__ import annotations

from typing import Optional, Protocol

from app.tools.adapters import abuseipdb, otx, shodan, virustotal
from app.tools.types import AdapterExecuteInput, NormalizedToolResult


class ToolAdapter(Protocol):
    async def execute(self, input: AdapterExecuteInput) -> NormalizedToolResult: ...
    async def test_connection(self, api_key: str, base_url: Optional[str]) -> dict: ...


ADAPTERS: dict[str, object] = {
    "virustotal": virustotal,
    "otx": otx,
    "shodan": shodan,
    "abuseipdb": abuseipdb,
}


def get_adapter(tool_id: str):
    return ADAPTERS.get(tool_id)
