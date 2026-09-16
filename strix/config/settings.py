"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"]
ApiType = Literal["responses", "chat_completions"]

DEFAULT_MAX_TURNS = 500

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_LLM")
    api_type: ApiType | None = Field(
        default=None,
        validation_alias=AliasChoices("STRIX_API_TYPE", "STRIX_FORCE_API"),
        description="Force 'responses' or 'chat_completions' API path",
    )
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
        repr=False,
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    extra_headers: dict[str, str] | None = Field(
        default=None,
        alias="LLM_EXTRA_HEADERS",
        repr=False,
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="STRIX_REASONING_EFFORT")
    force_required_tool_choice: bool = Field(
        default=False,
        alias="STRIX_FORCE_REQUIRED_TOOL_CHOICE",
    )
    prompt_cache: bool = Field(
        default=True,
        alias="STRIX_PROMPT_CACHE",
    )
    disable_streaming: bool = Field(
        default=False,
        alias="LLM_DISABLE_STREAMING",
    )
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")
    stream_idle_timeout: int = Field(default=300, ge=0, alias="LLM_STREAM_IDLE_TIMEOUT")
    max_tool_calls_per_turn: int = Field(
        default=32,
        ge=0,
        alias="LLM_MAX_TOOL_CALLS_PER_TURN",
    )


class DedupeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_DEDUPE_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="STRIX_DEDUPE_REASONING_EFFORT",
    )
    api_key: str | None = Field(default=None, alias="DEDUPE_LLM_API_KEY", repr=False)
    api_base: str | None = Field(default=None, alias="DEDUPE_LLM_API_BASE")
    extra_headers: dict[str, str] | None = Field(
        default=None,
        alias="DEDUPE_LLM_EXTRA_HEADERS",
        repr=False,
    )


class ContextSettings(BaseSettings):
    """Context-window management: per-tool-output caps and history compaction."""

    model_config = _BASE_CONFIG

    auto_compact: bool = Field(default=True, alias="STRIX_CONTEXT_AUTO_COMPACT")
    compact_buffer_tokens: int = Field(default=20_000, gt=0, alias="STRIX_CONTEXT_BUFFER_TOKENS")
    keep_tokens: int = Field(default=8_000, gt=0, alias="STRIX_CONTEXT_KEEP_TOKENS")
    fallback_context_tokens: int = Field(
        default=200_000, gt=0, alias="STRIX_CONTEXT_FALLBACK_TOKENS"
    )
    summary_max_tokens: int = Field(default=4_096, gt=0, alias="STRIX_CONTEXT_SUMMARY_TOKENS")
    tool_output_max_tokens: int = Field(default=8_000, gt=0, alias="STRIX_TOOL_OUTPUT_MAX_TOKENS")
    tool_output_max_lines: int = Field(default=2_000, gt=0, alias="STRIX_TOOL_OUTPUT_MAX_LINES")
    # Floor above the truncation-notice size so a preview always fits.
    tool_output_max_bytes: int = Field(
        default=50 * 1024, ge=1024, alias="STRIX_TOOL_OUTPUT_MAX_BYTES"
    )


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/usestrix/strix-sandbox:1.3.0",
        alias="STRIX_IMAGE",
    )
    backend: str = Field(default="docker", alias="STRIX_RUNTIME_BACKEND")
    # Max screenshot/image tool outputs kept live per agent context (0 = none).
    max_context_images: int = Field(default=3, ge=0, alias="STRIX_MAX_CONTEXT_IMAGES")


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=True, alias="STRIX_TELEMETRY")


WebSearchProvider = Literal["auto", "perplexity", "exa"]
ExaSearchType = Literal["auto", "fast", "instant", "deep-lite", "deep", "deep-reasoning"]


class IntegrationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(
        default=None,
        alias="PERPLEXITY_API_KEY",
        repr=False,
    )
    exa_api_key: str | None = Field(
        default=None,
        alias="EXA_API_KEY",
        repr=False,
    )
    web_search_provider: WebSearchProvider = Field(
        default="auto",
        alias="STRIX_WEB_SEARCH_PROVIDER",
    )
    exa_search_type: ExaSearchType = Field(
        default="auto",
        alias="STRIX_EXA_SEARCH_TYPE",
    )
    exa_num_results: int = Field(
        default=5,
        ge=1,
        le=100,
        alias="STRIX_EXA_NUM_RESULTS",
    )
    postman_api_key: str | None = Field(
        default=None,
        alias="POSTMAN_API_KEY",
        repr=False,
    )


class ViewerSettings(BaseSettings):
    model_config = _BASE_CONFIG

    # Base URL of the Strix relay the local viewer proxies to for email
    # verification and encrypted report delivery. The browser never talks to
    # the relay directly; the local server is the only caller.
    app_url: str = Field(default="https://app.strix.ai", alias="STRIX_APP_URL")


EnvironmentMode = Literal["local_lab", "public_target"]


class GovernanceSettings(BaseSettings):
    model_config = _BASE_CONFIG

    environment_mode: EnvironmentMode = Field(
        default="local_lab",
        alias="STRIX_ENVIRONMENT_MODE",
        description=(
            "Operating mode: 'local_lab' for full authority testing, "
            "'public_target' for strict rate-limited validation"
        ),
    )
    require_scope_confirmation: bool = Field(
        default=True,
        alias="STRIX_REQUIRE_SCOPE_CONFIRMATION",
        description="Require explicit scope confirmation before testing any asset",
    )
    public_target_rate_limit_min: int = Field(
        default=2,
        alias="STRIX_PUBLIC_RATE_LIMIT_MIN",
        description="Minimum rate limit requests per second for public targets",
    )
    public_target_rate_limit_max: int = Field(
        default=5,
        alias="STRIX_PUBLIC_RATE_LIMIT_MAX",
        description="Maximum rate limit requests per second for public targets",
    )
    local_lab_allow_container_escape: bool = Field(
        default=True,
        alias="STRIX_LOCAL_LAB_ALLOW_CONTAINER_ESCAPE",
        description="Allow container escape techniques in local lab mode",
    )
    local_lab_allow_custom_scripts: bool = Field(
        default=True,
        alias="STRIX_LOCAL_LAB_ALLOW_CUSTOM_SCRIPTS",
        description="Allow custom script execution in local lab mode",
    )
    local_lab_aggressive_fuzzing: bool = Field(
        default=True,
        alias="STRIX_LOCAL_LAB_AGGRESSIVE_FUZZING",
        description="Enable aggressive fuzzing techniques in local lab mode",
    )
    authorized_targets: list[str] = Field(
        default_factory=list,
        alias="STRIX_AUTHORIZED_TARGETS",
        description="List of pre-authorized targets for public target mode",
    )
    evidence_vault_path: str = Field(
        default="~/local-sec-vault",
        alias="STRIX_EVIDENCE_VAULT_PATH",
        description="Base path for local evidence vault storage",
    )
    pii_detection_enabled: bool = Field(
        default=True,
        alias="STRIX_PII_DETECTION_ENABLED",
        description="Enable PII detection and masking in responses",
    )
    pii_mask_threshold: int = Field(
        default=3,
        alias="STRIX_PII_MASK_THRESHOLD",
        description="Minimum number of PII patterns to trigger automatic masking",
    )


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    dedupe: DedupeSettings = Field(default_factory=DedupeSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    context: ContextSettings = Field(default_factory=ContextSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    viewer: ViewerSettings = Field(default_factory=ViewerSettings)
    governance: GovernanceSettings = Field(default_factory=GovernanceSettings)
