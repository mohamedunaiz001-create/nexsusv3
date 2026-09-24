"""Pydantic schemas for Provider and ProviderCredential management."""

from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, Field, HttpUrl
from uuid import UUID


# Provider schemas
class ProviderBase(BaseModel):
    name: str = Field(
        ..., min_length=1, max_length=100, description="Unique provider name"
    )
    provider_type: str = Field(
        ..., pattern="^(cloud|local)$", description="Provider type: cloud or local"
    )
    base_url: Optional[HttpUrl] = Field(
        None, description="Base URL for local/custom providers"
    )
    is_enabled: bool = Field(True, description="Whether the provider is enabled")


class ProviderCreate(ProviderBase):
    pass


class ProviderUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    provider_type: Optional[str] = Field(None, pattern="^(cloud|local)$")
    base_url: Optional[HttpUrl] = None
    is_enabled: Optional[bool] = None


class ProviderResponse(ProviderBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProviderWithHealth(ProviderResponse):
    """Provider with health status for dashboard display."""

    health_status: Optional[str] = None
    health_latency_ms: Optional[float] = None
    health_last_checked: Optional[datetime] = None
    health_last_error: Optional[str] = None
    configured: bool = False


# Provider Credential schemas
class ProviderCredentialBase(BaseModel):
    label: str = Field(
        ..., min_length=1, max_length=100, description="Human-readable label"
    )
    secret_ref: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Reference to secret (e.g., env:OPENAI_API_KEY, vault:providers/openai)",
    )
    masked_preview: Optional[str] = Field(
        None, max_length=20, description="Masked preview for display (e.g., ...ab12)"
    )
    is_active: bool = Field(True, description="Whether this credential is active")


class ProviderCredentialCreate(ProviderCredentialBase):
    pass


class ProviderCredentialUpdate(BaseModel):
    label: Optional[str] = Field(None, min_length=1, max_length=100)
    secret_ref: Optional[str] = Field(None, min_length=1, max_length=255)
    masked_preview: Optional[str] = Field(None, max_length=20)
    is_active: Optional[bool] = None


class ProviderCredentialResponse(ProviderCredentialBase):
    id: UUID
    provider: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProviderCredentialWithSecretRef(ProviderCredentialResponse):
    """Response that includes the secret reference for admin operations."""

    pass


# Model discovery schemas
class ModelInfoResponse(BaseModel):
    id: str
    provider: str
    context_window: Optional[int] = None
    supports_tools: bool = False
    supports_vision: bool = False
    supports_streaming: bool = True
    role: str = "general"
    known: bool = True


class ProviderModelsResponse(BaseModel):
    provider: str
    models: List[ModelInfoResponse]
    unavailable_reason: Optional[str] = None


# Test connection schemas
class TestConnectionRequest(BaseModel):
    """Optional: override credential for testing."""

    secret_ref: Optional[str] = None


class TestConnectionResponse(BaseModel):
    provider: str
    ok: bool
    detail: Optional[str] = None
    latency_ms: float


# Credential rotation
class RotateCredentialsRequest(BaseModel):
    secret_ref: str = Field(
        ..., min_length=1, max_length=255, description="New secret reference"
    )
    masked_preview: Optional[str] = Field(None, max_length=20)


class RotateCredentialsResponse(BaseModel):
    success: bool
    message: str
    credential_id: UUID
    new_masked_preview: Optional[str] = None


# Bulk operations
class BulkEnableDisableRequest(BaseModel):
    provider_names: List[str] = Field(..., min_length=1)
    is_enabled: bool


class BulkEnableDisableResponse(BaseModel):
    success: bool
    message: str
    updated: List[str]
    failed: List[Dict[str, str]]
