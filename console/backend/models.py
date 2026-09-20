from typing import Literal

from pydantic import BaseModel, Field


class RunConfig(BaseModel):
    lab_version: Literal["v1", "v2", "v3"] = "v1"
    scenario: str
    model: str
    provider: str | None = None
    upstream: str | None = None
    target: str | None = None
    target_url: str | None = None
    policy: str | None = None
    max_steps: int | None = None
    max_tokens: int | None = None
    run_token_budget: int | None = None
    temperature: float | None = None
    seed: int | None = None
    timeout: int | None = None
    reset_target: bool = False
    enforce_policy: bool = False
    expose_goal_state: bool = False
    runs_per_worker: int = Field(1, ge=1, le=100)
    parallel_workers: int = Field(1, ge=1, le=8)
    pressure_basis: str | None = None
    pressure_level: Literal["L0", "L1", "L2", "L3"] | None = None
    pressure_experiment_id: str | None = None
    command_tools: list[str] = Field(default_factory=list)


class PressureExperimentConfig(RunConfig):
    pressure_basis: Literal["H1", "H2", "H3", "H4", "I1", "I2", "A1", "A2"]


class RunSummary(BaseModel):
    run_id: str
    lab_version: Literal["v1", "v2", "v3"] = "v1"
    scenario: str | None = None
    model: str | None = None
    provider: str | None = None
    status: str
    goal_success: bool | None = None
    goal_step: int | None = None
    roe_compliant: bool | None = None
    roe_categories: dict[str, dict] = {}
    violation_count: int = 0
    steps: int = 0
    max_steps: int | None = None
    tokens_total: int | None = None
    duration_sec: float | None = None
    started_at: str | None = None
    termination_reason: str | None = None
    last_action: str | None = None
    pressure_basis: str | None = None
    pressure_level: str | None = None
    pressure_experiment_id: str | None = None
    command_tools: list[str] = Field(default_factory=list)


class LiveStatus(BaseModel):
    run_id: str
    scenario: str | None = None
    goal_success: bool | None = None
    roe_compliant: bool | None = None
    violation_count: int = 0
    state: str
    step: int | None = None
    max_steps: int | None = None
    goal_observed: bool = False
    goal_step: int | None = None
    roe_violation_observed: bool = False
    tokens_used: int | None = None
    elapsed_sec: float | None = None
    updated_at: str | None = None
    error: str | None = None
    last_action: str | None = None


class BatchStatus(BaseModel):
    job_id: str
    total: int
    running: int
    queued: int
    completed: int
    goal_count: int = 0
    safe_count: int = 0
    invalid_count: int = 0
    runs: list[LiveStatus] = []


class ActionRow(BaseModel):
    seq: int
    action_id: str
    phase: str | None = None
    thought: str | None = None
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    decision: Literal["allowed", "blocked"] | None = None
    decision_reason: str | None = None
    roe_status: Literal["allowed", "blocked", "escaped", "unclassified", "goal"] | None = None
    roe_dimension: str | None = None
    roe_category: str | None = None
    roe_categories: list[str] = []
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    raw_action: dict = {}


class Overlay(BaseModel):
    phases: list[dict | str] = []
    goal_marker: dict | None = None
    roe_violations: list[dict] = []


class CapabilityStage(BaseModel):
    name: str
    start_seq: int | None = None
    end_seq: int | None = None


class CapabilityOverlay(BaseModel):
    capability_stages: list[CapabilityStage] = []
    goal_marker: dict | None = None
    roe_violations: list[dict] = []