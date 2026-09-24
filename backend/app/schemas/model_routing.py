import uuid

from pydantic import BaseModel, ConfigDict


class AgentModelAssignmentBase(BaseModel):
    provider: str
    model: str
    fallback_chain: list[str] = []  # ["provider:model", ...], tried in order
    priority: int = 0


class AgentModelAssignmentCreate(AgentModelAssignmentBase):
    agent_type: str


class AgentModelAssignmentUpdate(BaseModel):
    provider: str | None = None
    model: str | None = None
    fallback_chain: list[str] | None = None
    priority: int | None = None


class AgentModelAssignmentRead(AgentModelAssignmentBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_type: str


class RoutingPolicyBase(BaseModel):
    name: str
    description: str | None = None
    rules: dict = {}


class RoutingPolicyCreate(RoutingPolicyBase):
    pass


class RoutingPolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    rules: dict | None = None
    is_active: bool | None = None


class RoutingPolicyRead(RoutingPolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_active: bool
