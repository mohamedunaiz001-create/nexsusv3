from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """The standard envelope every endpoint should return."""

    success: bool = True
    data: T | None = None
    message: str = ""
    errors: list[str] = []


class HealthStatus(BaseModel):
    status: str
    app_name: str
    app_env: str
    version: str
