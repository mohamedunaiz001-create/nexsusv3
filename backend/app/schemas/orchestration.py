from pydantic import BaseModel


class ObjectiveRequest(BaseModel):
    objective: str


class TaskRead(BaseModel):
    id: str
    description: str
    assigned_agent: str | None
    status: str
    attempts: int
    error: str | None = None
    result: dict | None = None


class RunRead(BaseModel):
    id: str
    objective: str
    status: str
    started_at: str
    finished_at: str | None
    final_report: str | None
    error: str | None
    tasks: list[TaskRead] = []


class AgentSnapshot(BaseModel):
    agent_type: str
    name: str
    model: str
    status: str
    enabled: bool
    last_run_at: str | None
    last_error: str | None
    run_count: int


class AgentDetail(BaseModel):
    agent_type: str
    name: str
    model: str
    description: str
    status: str
    enabled: bool
    last_run_at: str | None
    last_error: str | None
    run_count: int
    last_task_description: str | None
    last_result: dict | None
    history: list[dict] = []
