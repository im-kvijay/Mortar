import os
import warnings
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass, field


def safe_int(value: Optional[str], default: int, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
    if value is None:
        return default
    try:
        result = int(value)
        if min_val is not None and result < min_val:
            warnings.warn(
                f"Value {result} is below minimum {min_val}, using default {default}",
                RuntimeWarning,
                stacklevel=2
            )
            return default
        if max_val is not None and result > max_val:
            warnings.warn(
                f"Value {result} exceeds maximum {max_val}, using default {default}",
                RuntimeWarning,
                stacklevel=2
            )
            return default
        return result
    except (ValueError, TypeError):
        return default


def safe_float(value: Optional[str], default: float, min_val: Optional[float] = None, max_val: Optional[float] = None) -> float:
    if value is None:
        return default
    try:
        result = float(value)
        if min_val is not None and result < min_val:
            warnings.warn(
                f"Value {result} is below minimum {min_val}, using default {default}",
                RuntimeWarning,
                stacklevel=2
            )
            return default
        if max_val is not None and result > max_val:
            warnings.warn(
                f"Value {result} exceeds maximum {max_val}, using default {default}",
                RuntimeWarning,
                stacklevel=2
            )
            return default
        return result
    except (ValueError, TypeError):
        return default


def validate_api_key(key: Optional[str], key_name: str) -> bool:
    if not key:
        return False
    if not isinstance(key, str):
        warnings.warn(
            f"{key_name} must be a string",
            RuntimeWarning,
            stacklevel=2
        )
        return False

    if len(key) < 20:
        warnings.warn(
            f"{key_name} appears too short (min 20 characters expected)",
            RuntimeWarning,
            stacklevel=2
        )
        return False

    if len(key) > 500:
        warnings.warn(
            f"{key_name} appears too long (max 500 characters)",
            RuntimeWarning,
            stacklevel=2
        )
        return False

    import re
    if not re.match(r'^[A-Za-z0-9_\-\.]+$', key):
        warnings.warn(
            f"{key_name} contains invalid characters (only alphanumeric, -, _, . allowed)",
            RuntimeWarning,
            stacklevel=2
        )
        return False

    return True


@dataclass
class MortarCConfig:
    PROJECT_ROOT: Path = field(default_factory=lambda: Path(
        os.getenv("MORTAR_C_ROOT")
        or os.getenv("MORTARC_ROOT")
        or os.getenv("CRYPTOSEC_ROOT")
        or Path(__file__).parent.parent.absolute()
    ))

    @property
    def DATA_DIR(self) -> Path:
        return self.PROJECT_ROOT / "data"

    @property
    def LOGS_DIR(self) -> Path:
        return self.DATA_DIR / "logs"

    @property
    def LOGS_RAW_DIR(self) -> Path:
        return self.LOGS_DIR / "raw"

    @property
    def LOGS_DB_PATH(self) -> Path:
        return self.LOGS_DIR / "analytics.db"

    @property
    def RUNS_DIR(self) -> Path:
        return self.DATA_DIR / "runs"

    @property
    def KB_DIR(self) -> Path:
        return self.DATA_DIR / "kb"

    @property
    def KNOWLEDGE_GRAPHS_DIR(self) -> Path:
        return self.DATA_DIR / "knowledge_graphs"

    @property
    def TRAINING_DIR(self) -> Path:
        return self.PROJECT_ROOT / "training"

    @property
    def DVD_DIR(self) -> Path:
        return self.TRAINING_DIR / "damn-vulnerable-defi"

    @property
    def JIT_CACHE_FILE(self) -> Path:
        return self.DATA_DIR / "cache" / "jit_research_cache.json"

    @property
    def CACHE_DIR(self) -> Path:
        return self.DATA_DIR / "cache"

    @property
    def SEMANTIC_CACHE_DIR(self) -> Path:
        return self.CACHE_DIR / "semantic"

    @property
    def CONTEXT_CHAR_BUDGET(self) -> int:
        return safe_int(os.getenv("CONTEXT_CHAR_BUDGET"), default=6000, min_val=100, max_val=100000)

    @property
    def CONTEXT_SECTION_BUDGET(self) -> int:
        return safe_int(os.getenv("CONTEXT_SECTION_BUDGET"), default=2000, min_val=100, max_val=50000)

    @property
    def CONTEXT_TOKEN_BUDGET(self) -> int:
        explicit = os.getenv("CONTEXT_TOKEN_BUDGET")
        if explicit:
            return safe_int(explicit, default=1500, min_val=100, max_val=50000)
        return self.CONTEXT_CHAR_BUDGET // 4

    DEFAULT_BACKEND_TYPE: str = os.getenv("BACKEND", "openrouter")

    MODEL_GROK_4_FAST: str = "x-ai/grok-4.1-fast"
    MODEL_GROK_4: str = "x-ai/grok-4.1"

    FORCE_GROK_FAST: bool = bool(os.getenv("FORCE_GROK_FAST", "1") == "1")
    DEFAULT_MODEL: str = os.getenv("MODEL", MODEL_GROK_4_FAST)
    MODEL_ALIASES: Dict[str, str] = field(default_factory=lambda: {
        "grok-4-fast": "x-ai/grok-4.1-fast",
        "grok-4.1-fast": "x-ai/grok-4.1-fast",
        "x-ai/grok-4-fast": "x-ai/grok-4.1-fast",
        "x-ai/grok-4-fast-reasoning": "x-ai/grok-4.1-fast",
        "x-ai/grok-4.1-fast": "x-ai/grok-4.1-fast",
        "x-ai/grok-4.1": "x-ai/grok-4.1",
        "x-ai/grok-4.1-fast:free": "x-ai/grok-4.1-fast:free",
        "x-ai/grok-4.1:free": "x-ai/grok-4.1:free",
    })

    VERIFICATION_HYPOTHESIS_LIMIT: int = safe_int(os.getenv("VERIFICATION_HYPOTHESIS_LIMIT"), default=20, min_val=1, max_val=100)
    VERIFICATION_CONTRACT_TIMEOUT: int = safe_int(os.getenv("VERIFICATION_CONTRACT_TIMEOUT"), default=1800, min_val=60, max_val=7200)
    VERIFICATION_HYPOTHESIS_TIMEOUT_MAX: int = safe_int(os.getenv("VERIFICATION_HYPOTHESIS_TIMEOUT_MAX"), default=300, min_val=30, max_val=600)
    VERIFICATION_MIN_TIME_REMAINING: int = safe_int(os.getenv("VERIFICATION_MIN_TIME_REMAINING"), default=60, min_val=5, max_val=300)
    MODEL_REGISTRY = {
        "x-ai/grok-4.1-fast:free": {
            "provider": "xai",
            "name": "Grok-4.1 Fast (Free)",
            "capabilities": {"thinking": True, "tools": True, "vision": False},
            "thinking_type": "extended",
            "reasoning_support": "openrouter_unified",
            "reasoning_default": {"enabled": True, "effort": "high"},
        },
        "x-ai/grok-4.1-fast": {
            "provider": "xai",
            "name": "Grok-4.1 Fast",
            "capabilities": {"thinking": True, "tools": True, "vision": False},
            "thinking_type": "extended",
            "reasoning_support": "openrouter_unified",
            "reasoning_default": {"enabled": True, "effort": "high"},
        },
        "x-ai/grok-4.1": {
            "provider": "xai",
            "name": "Grok-4.1",
            "capabilities": {"thinking": True, "tools": True, "vision": True},
            "thinking_type": "extended",
            "reasoning_support": "openrouter_unified",
            "reasoning_default": {"enabled": True, "effort": "high"},
        },
        "x-ai/grok-4": {
            "provider": "xai",
            "name": "Grok-4",
            "capabilities": {"thinking": True, "tools": True, "vision": True},
            "thinking_type": "extended",
            "reasoning_support": "always_on",
        },
        "x-ai/grok-3-mini": {
            "provider": "xai",
            "name": "Grok-3 Mini",
            "capabilities": {"thinking": True, "tools": True, "vision": False},
            "thinking_type": "extended",
            "reasoning_support": "effort",
            "reasoning_default": {"effort": "low"},
        },
    }

    REASONING_EFFORT: str = os.getenv("REASONING_EFFORT", "high")
    REASONING_EXCLUDE: bool = os.getenv("REASONING_EXCLUDE", "0") == "1"
    GLM_THINKING_TYPE: str = os.getenv("GLM_THINKING_TYPE", "enabled")

    def __post_init__(self) -> None:
        self.DEDUP_MODE = (self.DEDUP_MODE or "exact").lower()
        if self.DEDUP_MODE not in {"off", "exact", "hints"}:
            warnings.warn(
                f"[config] Invalid DEDUP_MODE='{self.DEDUP_MODE}', defaulting to 'exact'",
                RuntimeWarning,
                stacklevel=2,
            )
            self.DEDUP_MODE = "exact"
        self.SEMANTIC_BACKEND = (self.SEMANTIC_BACKEND or "keyword").lower()
        if self.SEMANTIC_BACKEND not in {"keyword", "auto", "faiss", "chroma", "neural", "tfidf"}:
            warnings.warn(
                f"[config] Invalid SEMANTIC_BACKEND='{self.SEMANTIC_BACKEND}', defaulting to 'keyword'",
                RuntimeWarning,
                stacklevel=2,
            )
            self.SEMANTIC_BACKEND = "keyword"

    def get_model_capability(self, model: str, capability: str) -> bool:
        if model in self.MODEL_REGISTRY:
            return self.MODEL_REGISTRY[model]["capabilities"].get(capability, False)
        return False

    def get_thinking_type(self, model: str) -> Optional[str]:
        if model in self.MODEL_REGISTRY:
            return self.MODEL_REGISTRY[model].get("thinking_type")
        return None

    EXTENDED_THINKING_BUDGET: int = safe_int(os.getenv("THINKING_BUDGET"), default=0)
    ENABLE_INTERLEAVED_THINKING: bool = bool(os.getenv("ENABLE_INTERLEAVED", "0") == "1")

    EXTENDED_THINKING_TEMPERATURE: float = 1.0
    NORMAL_TEMPERATURE: float = 0.7

    MAX_OUTPUT_TOKENS: int = 32000
    MAX_TOKENS_FULL: int = 32000

    PREMIUM_MODEL: str = MODEL_GROK_4_FAST

    DEFAULT_COST_LIMIT_PER_CONTRACT: Optional[float] = None
    DEFAULT_COST_LIMIT_PER_SPECIALIST: Optional[float] = None
    MODEL_PRICING = {
        "x-ai/grok-4.1-fast:free": {"input": 0.00, "output": 0.00, "reasoning_output": 0.00},
        "x-ai/grok-4.1-fast": {"input": 0.20, "output": 0.50, "reasoning_output": 0.50},
        "x-ai/grok-4.1": {"input": 1.00, "output": 3.00, "reasoning_output": 3.00},
    }

    MAX_TEAM_ROUNDS: int = 10
    MAX_ORCHESTRATOR_ROUNDS: int = safe_int(os.getenv("MAX_ORCHESTRATOR_ROUNDS"), default=10, min_val=1, max_val=50)
    ORCHESTRATOR_TIMEOUT_SECONDS: int = safe_int(os.getenv("ORCHESTRATOR_TIMEOUT_SECONDS"), default=7200, min_val=300, max_val=28800)

    QUALITY_THRESHOLD: float = 0.80
    MIN_DISCOVERY_CONFIDENCE: float = 0.5
    HIGH_DISCOVERY_CONFIDENCE: float = 0.85

    DEDUP_MODE: str = field(default_factory=lambda: os.getenv("DEDUP_MODE", "exact"))
    SEMANTIC_BACKEND: str = os.getenv("SEMANTIC_BACKEND", "keyword").lower()
    SEMANTIC_TOP_K: int = safe_int(os.getenv("SEMANTIC_TOP_K"), default=10, min_val=1, max_val=100)

    ENABLE_GLM_THINKING: bool = os.getenv("ENABLE_GLM_THINKING", "0") == "1"

    ENABLE_CONTEXT_COMPRESSION: bool = os.getenv("ENABLE_CONTEXT_COMPRESSION", "1") != "0"
    CONTEXT_COMPRESSION_T_MAX: int = safe_int(os.getenv("CONTEXT_T_MAX"), default=250000, min_val=10000, max_val=1000000)
    CONTEXT_COMPRESSION_T_RETAINED: int = safe_int(os.getenv("CONTEXT_T_RETAINED"), default=100000, min_val=5000, max_val=500000)

    USE_CONSOLIDATED_TOOLS: bool = os.getenv("USE_CONSOLIDATED_TOOLS", "0") == "1"

    SLITHER_TIMEOUT: int = safe_int(os.getenv("SLITHER_TIMEOUT"), default=180, min_val=30, max_val=600)
    JIT_MAX_COST_PER_REQUEST: float = 0.10
    JIT_REQUEST_TIMEOUT: int = 60
    JIT_MAX_REQUESTS_PER_ROUND: int = 5
    JIT_CONFIDENCE_WEIGHT_OLD: float = 0.7
    JIT_CONFIDENCE_WEIGHT_NEW: float = 0.3
    JIT_CACHE_MAX_SIZE: int = safe_int(os.getenv("JIT_CACHE_MAX_SIZE"), default=1000, min_val=100, max_val=10000)
    JIT_THINKING_BUDGET_SINGLE: int = 6000
    JIT_MAX_TOKENS: int = 8000

    MIN_HYPOTHESIS_CONFIDENCE: float = 0.50
    MIN_POC_CONFIDENCE: float = 0.80
    ATTACK_HIGH_CONFIDENCE_THRESHOLD: float = 0.85
    ATTACK_STOP_COUNT: int = 3
    COMPOSITIONAL_ATTACK_CONFIDENCE: float = 0.70
    MAX_HYPOTHESES: int = safe_int(os.getenv("MAX_HYPOTHESES"), default=500, min_val=50, max_val=5000)

    KB_MODE: str = os.getenv("KB_MODE", "observe")
    KB_EXPLORATION_FRACTION: float = safe_float(os.getenv("KB_EXPLORATION_FRACTION"), default=0.25, min_val=0.0, max_val=1.0)
    KB_SECOND_PASS_ON_EMPTY: bool = os.getenv("SECOND_PASS_ON_EMPTY", "1") != "0"
    KB_SUGGESTIONS_ADDITIVE: bool = os.getenv("KB_SUGGESTIONS_ADDITIVE", "1") != "0"
    HYPOTHESIS_BUDGET: int = safe_int(os.getenv("HYPOTHESIS_BUDGET"), default=12, min_val=1, max_val=50)
    COVERAGE_FLOOR: float = safe_float(os.getenv("COVERAGE_FLOOR"), default=0.35, min_val=0.0, max_val=1.0)

    ENSEMBLE_CORROBORATION_REQUIRED: bool = os.getenv("ENSEMBLE_CORROBORATION_REQUIRED", "1") != "0"
    CRITICAL_IMPACT_TAGS: List[str] = field(default_factory=lambda: [
        "AUTHZ_BYPASS",
        "CONFIG_CAPTURE",
        "VALUE_EXTRACTED",
        "MARKET_CORRUPTION",
        "PRICE_MANIPULATION",
        "INVARIANT_BREAK",
    ])
    ENSEMBLE_ACCEPT_SAT_NO_TAGS: bool = os.getenv("ENSEMBLE_ACCEPT_SAT_NO_TAGS", "1") != "0"
    Z3_MAX_FAILED_CONSTRAINT_RATIO: float = safe_float(os.getenv("Z3_MAX_FAILED_CONSTRAINT_RATIO"), default=0.25, min_val=0.0, max_val=1.0)

    ATTACK_QUALITY_BREADTH_WEIGHT: float = 0.20
    ATTACK_QUALITY_QUALITY_WEIGHT: float = 0.30
    ATTACK_QUALITY_EVIDENCE_WEIGHT: float = 0.50
    ATTACK_QUALITY_BREADTH_CAP: int = 10

    ENABLE_ECON_SIM: bool = os.getenv("ENABLE_ECON_SIM", "1") != "0"
    ECON_SIM_MAX_STEPS: int = safe_int(os.getenv("ECON_SIM_MAX_STEPS"), default=6, min_val=1, max_val=20)
    ECON_SIM_MIN_MARGIN: float = safe_float(os.getenv("ECON_SIM_MIN_MARGIN"), default=0.05, min_val=0.0, max_val=1.0)

    ENABLE_PATTERN_SYNTHESIS: bool = os.getenv("ENABLE_PATTERN_SYNTHESIS", "0") == "1"
    PATTERN_SYNTHESIS_MAX_COMBINATIONS: int = safe_int(os.getenv("PATTERN_SYNTHESIS_MAX_COMBINATIONS"), default=100, min_val=10, max_val=1000)
    ENTROPY_WEIGHT: float = 0.3
    MCTS_MAX_ITERATIONS: int = 200
    MCTS_MAX_DEPTH: int = 8
    MCTS_EXPLORATION_CONSTANT: float = 1.41
    MCTS_VALUE_WEIGHT: float = 0.7
    MCTS_POLICY_TOP_K: int = 5
    MCTS_EARLY_STOP_VALUE: float = 0.90

    POC_MAX_TOKENS: int = 8000
    POC_THINKING_BUDGET: int = 8000
    POC_TEMPERATURE: float = 0.2

    @property
    def POC_OUTPUT_DIR(self) -> Path:
        return self.DATA_DIR / "pocs"

    POC_EXECUTION_MODE: str = "local"
    POC_EXECUTION_TIMEOUT: int = 300

    GRAPH_FILE_PATTERN: str = "{contract_name}_final.json"
    AUTO_SAVE_GRAPH: bool = True

    ENABLE_LOGGING: bool = True
    LOG_AI_CALLS: bool = True
    LOG_AI_CALLS_LIMIT: int = safe_int(os.getenv("LOG_AI_CALLS_LIMIT"), default=200, min_val=10, max_val=10000)
    LOG_GRAPH_UPDATES: bool = True
    LOG_DECISIONS: bool = True
    LOG_COSTS: bool = True
    LOG_TO_SQLITE: bool = True
    DEBUG_LLM_CALLS: bool = bool(os.getenv("DEBUG_LLM", "0") == "1")
    ENABLE_STREAMING: bool = bool(os.getenv("ENABLE_STREAMING", "0") == "1")
    @property
    def ANTHROPIC_API_KEY(self) -> Optional[str]:
        return os.getenv("ANTHROPIC_API_KEY")

    @property
    def XAI_API_KEY(self) -> Optional[str]:
        return os.getenv("XAI_API_KEY")

    @property
    def OPENROUTER_API_KEY(self) -> Optional[str]:
        return os.getenv("OPENROUTER_API_KEY")

    @property
    def COMETAPI_API_KEY(self) -> Optional[str]:
        return os.getenv("COMETAPI_API_KEY")

    @property
    def NOVITA_API_KEY(self) -> Optional[str]:
        return os.getenv("NOVITA_API_KEY")

    def ensure_directories(self):
        directories = [
            self.DATA_DIR,
            self.LOGS_DIR,
            self.LOGS_RAW_DIR,
            self.LOGS_RAW_DIR / "research",
            self.LOGS_RAW_DIR / "attacks",
            self.LOGS_RAW_DIR / "decisions",
            self.LOGS_RAW_DIR / "graph_updates",
            self.LOGS_RAW_DIR / "kb_updates",
            self.KB_DIR,
            self.KNOWLEDGE_GRAPHS_DIR,
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def get_model_pricing(self, model_name: str) -> dict:
        if model_name not in self.MODEL_PRICING:
            warnings.warn(f"Unknown model '{model_name}', using fallback pricing", RuntimeWarning)
        return self.MODEL_PRICING.get(model_name, {"input": 3.00, "output": 15.00, "reasoning_output": 15.00})

    def validate(self):
        if self.DEFAULT_BACKEND_TYPE == "grok":
            if not self.XAI_API_KEY:
                raise ValueError(
                    "XAI_API_KEY environment variable not set. "
                    "Set it with: export XAI_API_KEY='your-xai-key'"
                )
            if not validate_api_key(self.XAI_API_KEY, "XAI_API_KEY"):
                warnings.warn(
                    "XAI_API_KEY format validation failed. "
                    "Please ensure it is a valid API key.",
                    RuntimeWarning,
                    stacklevel=2
                )

        if self.DEFAULT_BACKEND_TYPE == "openrouter":
            if not self.OPENROUTER_API_KEY:
                raise ValueError(
                    "OPENROUTER_API_KEY environment variable not set. "
                    "Set it with: export OPENROUTER_API_KEY='your-key'"
                )
            if not validate_api_key(self.OPENROUTER_API_KEY, "OPENROUTER_API_KEY"):
                warnings.warn(
                    "OPENROUTER_API_KEY format validation failed. "
                    "Please ensure it is a valid API key.",
                    RuntimeWarning,
                    stacklevel=2
                )

        if not self.PROJECT_ROOT.exists():
            raise ValueError(f"Project root does not exist: {self.PROJECT_ROOT}")

        self.ensure_directories()

    def summary(self) -> str:
        api_status = "Set" if self.XAI_API_KEY else "NOT SET"

        return f"""
Mortar-C Configuration:
  Project Root: {self.PROJECT_ROOT}
  Data Dir: {self.DATA_DIR}
  Backend: {self.DEFAULT_BACKEND_TYPE}
  Model: {self.DEFAULT_MODEL}
  Thinking Budget: {self.EXTENDED_THINKING_BUDGET} tokens
  Grok Effort: {self.MODEL_REGISTRY.get(self.DEFAULT_MODEL, {}).get('reasoning_default', {}).get('effort', 'n/a')}
  Agentic: True (agents decide when to stop)
  Quality Threshold: {self.QUALITY_THRESHOLD}
  Cost Limit: {self.DEFAULT_COST_LIMIT_PER_CONTRACT or 'Unlimited'}
  Logging: {'Enabled' if self.ENABLE_LOGGING else 'Disabled'}
  API Key: {api_status}
""".strip()


config = MortarCConfig()
if os.getenv("MORTAR_C_SKIP_VALIDATION") != "1" and os.getenv("CRYPTOSEC_SKIP_VALIDATION") != "1":
    try:
        config.validate()
    except ValueError as e:
        print(f"[WARNING]  Configuration warning: {e}")

PROJECT_ROOT = config.PROJECT_ROOT
DATA_DIR = config.DATA_DIR
LOGS_DIR = config.LOGS_DIR
KB_DIR = config.KB_DIR

DEFAULT_BACKEND = config.DEFAULT_BACKEND_TYPE
DEFAULT_MODEL = config.DEFAULT_MODEL
THINKING_BUDGET = config.EXTENDED_THINKING_BUDGET
QUALITY_THRESHOLD = config.QUALITY_THRESHOLD

if __name__ == "__main__":
    print(config.summary())
    print()

    print("paths:")
    print(f"  project root: {config.PROJECT_ROOT}")
    print(f"  data dir: {config.DATA_DIR}")
    print(f"  logs dir: {config.LOGS_DIR}")
    print(f"  kb dir: {config.KB_DIR}")
    print(f"  knowledge graphs: {config.KNOWLEDGE_GRAPHS_DIR}")
    print(f"  training: {config.TRAINING_DIR}")
    print(f"  dvd: {config.DVD_DIR}")
    print()

    print("model pricing:")
    for model, pricing in config.MODEL_PRICING.items():
        print(f"  {model}:")
        print(f"    input: ${pricing['input']}/m tokens")
        print(f"    output: ${pricing['output']}/m tokens")
    print()
