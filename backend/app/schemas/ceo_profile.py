import uuid

from pydantic import BaseModel, ConfigDict


class CEOProfileBase(BaseModel):
    name: str
    description: str | None = None
    system_prompt: str | None = None
    provider: str = "ollama"
    model: str = "llama3"
    temperature: float = 0.2
    memory_enabled: bool = False


class CEOProfileCreate(CEOProfileBase):
    pass


class CEOProfileUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    system_prompt: str | None = None
    provider: str | None = None
    model: str | None = None
    temperature: float | None = None
    memory_enabled: bool | None = None


class CEOProfileRead(CEOProfileBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_active: bool
