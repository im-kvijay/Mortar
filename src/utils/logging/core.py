"""
Research Logger Core Implementation

This module contains the ResearchLogger class, which provides
comprehensive dual-layer logging (JSON + SQLite) for the entire
audit pipeline.

The logger captures:
- AI calls (prompt, thinking, output, cost, timing)
- Graph updates (nodes, edges, relationships)
- Specialist decisions (continue/stop, reasoning)
- Pattern confidence updates (Bayesian learning)
- Attack attempts (success/fail, evidence)
- System metrics (costs, timing, memory)
"""

import json
import sqlite3
import sys
import threading
from pathlib import Path
from datetime import datetime, UTC
from typing import Dict, Any, Optional, List

# Add src to path for config
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config import config
from utils.logging.types import LogCategory, LogEntry
from utils.correlation import get_audit_id


class ResearchLogger:
    """
    Dual-layer logging system

    Usage:
        logger = ResearchLogger(project_root="/path/to/Mortar-C")
        logger.log_ai_call("StateFlow", "UnstoppableVault", round=1,
                          prompt="...", response="...", cost=0.05)
        logger.log_graph_update("Invariant", "UnstoppableVault",
                               node_type="invariant", data={...})
    """

    def __init__(self, project_root: Optional[str] = None):
        # Use config default
        self.project_root = Path(project_root or str(config.PROJECT_ROOT))
        self.logs_dir = config.LOGS_DIR
        self.raw_dir = config.LOGS_RAW_DIR
        self.db_path = config.LOGS_DB_PATH

        # Thread safety for AI call count (Issue 2 fix)
        self._count_lock = threading.Lock()
        self._ai_call_count = 0

        # Ensure directories exist
        for category in LogCategory:
            (self.raw_dir / category.value).mkdir(parents=True, exist_ok=True)

        # Initialize SQLite database (if logging enabled)
        if config.LOG_TO_SQLITE:
            self._init_database()

    def _init_database(self):
        """Initialize SQLite database with tables"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            # Agent calls table (AI API calls)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    contract_name TEXT,
                    round_num INTEGER,
                    event_type TEXT NOT NULL,
                    prompt_tokens INTEGER,
                    output_tokens INTEGER,
                    thinking_tokens INTEGER,
                    cost REAL,
                    duration_seconds REAL,
                    model TEXT,
                    metadata TEXT
                )
            """)

            # Graph updates table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS graph_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    round_num INTEGER,
                    update_type TEXT NOT NULL,
                    node_type TEXT,
                    edge_type TEXT,
                    node_id TEXT,
                    metadata TEXT
                )
            """)

            # Specialist decisions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS specialist_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    round_num INTEGER NOT NULL,
                    decision TEXT NOT NULL,
                    reasoning TEXT,
                    confidence REAL,
                    discoveries_count INTEGER,
                    metadata TEXT
                )
            """)

            # Pattern updates table (Bayesian learning)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pattern_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    pattern_name TEXT NOT NULL,
                    contract_name TEXT,
                    update_type TEXT NOT NULL,
                    old_confidence REAL,
                    new_confidence REAL,
                    successes INTEGER,
                    failures INTEGER,
                    metadata TEXT
                )
            """)

            # Attack attempts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attacker_name TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    hypothesis TEXT,
                    result TEXT NOT NULL,
                    poc_code TEXT,
                    evidence TEXT,
                    cost REAL,
                    metadata TEXT
                )
            """)

            # Performance metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    contract_name TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    total_cost REAL,
                    total_duration_seconds REAL,
                    quality_score REAL,
                    num_rounds INTEGER,
                    num_agents INTEGER,
                    metadata TEXT
                )
            """)

            # Create indexes for common queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_calls_contract ON agent_calls(contract_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_calls_agent ON agent_calls(agent_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_graph_updates_contract ON graph_updates(contract_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_attempts_contract ON attack_attempts(contract_name)")

            conn.commit()

    def _now(self) -> str:
        """Get current timestamp in ISO format"""
        return datetime.now().isoformat()

    def _get_audit_id(self) -> Optional[str]:
        """Get current audit ID from correlation context"""
        return get_audit_id()

    def _save_json(self, category: LogCategory, filename: str, data: Dict[str, Any]):
        """Save raw JSON log file with audit_id"""
        # Inject audit_id if available and not already present
        audit_id = self._get_audit_id()
        if audit_id and "audit_id" not in data:
            data["audit_id"] = audit_id

        filepath = self.raw_dir / category.value / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def log_ai_call(
        self,
        agent_name: str,
        contract_name: str,
        round_num: int,
        event_type: str,
        prompt: str,
        response: str,
        thinking: Optional[str] = None,
        cost: float = 0.0,
        duration_seconds: float = 0.0,
        model: str = "x-ai/grok-4.1-fast",
        prompt_tokens: int = 0,
        output_tokens: int = 0,
        thinking_tokens: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log an AI API call

        Saves to:
        - JSON: data/logs/raw/research/YYYY-MM-DD_ContractName_AgentName_rN.json
        - SQLite: agent_calls table
        """
        # Thread-safe AI call count check and increment (Issue 2 fix)
        if getattr(config, "LOG_AI_CALLS_LIMIT", None):
            with self._count_lock:
                if self._ai_call_count >= config.LOG_AI_CALLS_LIMIT:
                    return
                self._ai_call_count += 1

        timestamp = self._now()

        # Save raw JSON
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{agent_name}_r{round_num}.json"
        json_data = {
            "timestamp": timestamp,
            "agent_name": agent_name,
            "contract_name": contract_name,
            "round_num": round_num,
            "event_type": event_type,
            "prompt": prompt,
            "response": response,
            "thinking": thinking,
            "cost": cost,
            "duration_seconds": duration_seconds,
            "model": model,
            "tokens": {
                "prompt": prompt_tokens,
                "output": output_tokens,
                "thinking": thinking_tokens,
            },
            "metadata": metadata or {}
        }
        self._save_json(LogCategory.RESEARCH, filename, json_data)

        # Save to SQLite
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO agent_calls
                (timestamp, agent_name, contract_name, round_num, event_type,
                 prompt_tokens, output_tokens, thinking_tokens, cost, duration_seconds, model, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, agent_name, contract_name, round_num, event_type,
                prompt_tokens, output_tokens, thinking_tokens, cost, duration_seconds, model,
                json.dumps(metadata or {})
            ))
            conn.commit()

    def log_graph_update(
        self,
        agent_name: str,
        contract_name: str,
        round_num: int,
        update_type: str,  # "add_node", "add_edge", "update_node", etc.
        node_type: Optional[str] = None,
        edge_type: Optional[str] = None,
        node_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log a knowledge graph update

        Saves to:
        - JSON: data/logs/raw/graph_updates/...
        - SQLite: graph_updates table
        """
        timestamp = self._now()

        # Save raw JSON
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{agent_name}_graph_r{round_num}.json"
        json_data = {
            "timestamp": timestamp,
            "agent_name": agent_name,
            "contract_name": contract_name,
            "round_num": round_num,
            "update_type": update_type,
            "node_type": node_type,
            "edge_type": edge_type,
            "node_id": node_id,
            "data": data or {},
            "metadata": metadata or {}
        }

        # Create graph_updates subdirectory if it doesn't exist
        graph_dir = self.raw_dir / "graph_updates"
        graph_dir.mkdir(exist_ok=True)
        self._save_json(LogCategory.RESEARCH, f"../graph_updates/{filename}", json_data)

        # Save to SQLite (use context manager to ensure connection cleanup)
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO graph_updates
                (timestamp, agent_name, contract_name, round_num, update_type,
                 node_type, edge_type, node_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, agent_name, contract_name, round_num, update_type,
                node_type, edge_type, node_id,
                json.dumps({**(metadata or {}), **(data or {})})
            ))
            conn.commit()

    def log_discovery(
        self,
        agent_name: str,
        contract_name: str,
        discovery_type: str,
        content: str,
        confidence: float,
        evidence: List[str],
        round_num: Optional[int] = None,
        severity: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log a specialist's discovery (V3 Enhanced)

        Saves to:
        - JSON: data/logs/raw/discoveries/...
        - SQLite: discoveries table

        Args:
            agent_name: Name of the agent making the discovery
            contract_name: Contract being analyzed
            discovery_type: Type of discovery (vulnerability, invariant, etc.)
            content: Discovery description
            confidence: Confidence level (0.0-1.0)
            evidence: List of evidence strings
            round_num: Optional round number
            severity: Optional severity level
            metadata: Additional data
        """
        timestamp = self._now()

        # Save raw JSON
        discovery_id = f"{agent_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{agent_name}_discovery.json"
        json_data = {
            "timestamp": timestamp,
            "discovery_id": discovery_id,
            "agent_name": agent_name,
            "contract_name": contract_name,
            "round_num": round_num,
            "discovery_type": discovery_type,
            "content": content,
            "confidence": confidence,
            "severity": severity,
            "evidence": evidence,
            "metadata": metadata or {}
        }

        # Create discoveries subdirectory if it doesn't exist
        discoveries_dir = self.raw_dir / "discoveries"
        discoveries_dir.mkdir(exist_ok=True)

        filepath = discoveries_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        # Save to SQLite (use context manager to ensure connection cleanup)
        if config.LOG_TO_SQLITE:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()

                # Create table if not exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS discoveries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        discovery_id TEXT NOT NULL,
                        agent_name TEXT NOT NULL,
                        contract_name TEXT NOT NULL,
                        round_num INTEGER,
                        discovery_type TEXT NOT NULL,
                        content TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        severity TEXT,
                        evidence TEXT,
                        metadata TEXT
                    )
                """)

                cursor.execute("""
                    INSERT INTO discoveries
                    (timestamp, discovery_id, agent_name, contract_name, round_num,
                     discovery_type, content, confidence, severity, evidence, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, discovery_id, agent_name, contract_name, round_num,
                    discovery_type, content, confidence, severity,
                    json.dumps(evidence),
                    json.dumps(metadata or {})
                ))

                conn.commit()

    def log_specialist_decision(
        self,
        agent_name: str,
        contract_name: str,
        round_num: int,
        decision: str,  # "continue", "stop", "need_more_info"
        reasoning: str,
        confidence: float,
        discoveries_count: int,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log a specialist's decision to continue/stop

        Saves to:
        - JSON: data/logs/raw/decisions/...
        - SQLite: specialist_decisions table
        """
        timestamp = self._now()

        # Save raw JSON
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{agent_name}_decision_r{round_num}.json"
        json_data = {
            "timestamp": timestamp,
            "agent_name": agent_name,
            "contract_name": contract_name,
            "round_num": round_num,
            "decision": decision,
            "reasoning": reasoning,
            "confidence": confidence,
            "discoveries_count": discoveries_count,
            "metadata": metadata or {}
        }
        self._save_json(LogCategory.DECISION, filename, json_data)

        # Save to SQLite (use context manager to ensure connection cleanup)
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO specialist_decisions
                (timestamp, agent_name, contract_name, round_num, decision,
                 reasoning, confidence, discoveries_count, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, agent_name, contract_name, round_num, decision,
                reasoning, confidence, discoveries_count,
                json.dumps(metadata or {})
            ))
            conn.commit()

    def log_pattern_update(
        self,
        pattern_name: str,
        contract_name: str,
        update_type: str,  # "success", "failure", "new_pattern"
        old_confidence: float,
        new_confidence: float,
        successes: int,
        failures: int,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log Bayesian pattern confidence update

        Saves to:
        - JSON: data/logs/raw/kb_updates/...
        - SQLite: pattern_updates table
        """
        timestamp = self._now()

        # Save raw JSON
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{pattern_name}_update.json"
        json_data = {
            "timestamp": timestamp,
            "pattern_name": pattern_name,
            "contract_name": contract_name,
            "update_type": update_type,
            "old_confidence": old_confidence,
            "new_confidence": new_confidence,
            "successes": successes,
            "failures": failures,
            "bayesian_formula": f"({successes}+1) / ({successes}+{failures}+2) = {new_confidence:.4f}",
            "metadata": metadata or {}
        }
        self._save_json(LogCategory.KB_UPDATE, filename, json_data)

        # Save to SQLite (use context manager to ensure connection cleanup)
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pattern_updates
                (timestamp, pattern_name, contract_name, update_type,
                 old_confidence, new_confidence, successes, failures, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, pattern_name, contract_name, update_type,
                old_confidence, new_confidence, successes, failures,
                json.dumps(metadata or {})
            ))
            conn.commit()

    def log_performance_metrics(
        self,
        contract_name: str,
        stage: str,  # "research", "attack", "validation"
        total_cost: float,
        total_duration_seconds: float,
        quality_score: float,
        num_rounds: int,
        num_agents: int,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log performance metrics for analytics

        Saves to SQLite: performance_metrics table
        """
        timestamp = self._now()

        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO performance_metrics
                (timestamp, contract_name, stage, total_cost, total_duration_seconds,
                 quality_score, num_rounds, num_agents, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, contract_name, stage, total_cost, total_duration_seconds,
                quality_score, num_rounds, num_agents,
                json.dumps(metadata or {})
            ))
            conn.commit()

    def query_costs(self, contract_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query costs from database"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            if contract_name:
                cursor.execute("""
                    SELECT agent_name, SUM(cost) as total_cost, COUNT(*) as num_calls
                    FROM agent_calls
                    WHERE contract_name = ?
                    GROUP BY agent_name
                """, (contract_name,))
            else:
                cursor.execute("""
                    SELECT contract_name, SUM(cost) as total_cost, COUNT(*) as num_calls
                    FROM agent_calls
                    GROUP BY contract_name
                """)

            results = [
                {
                    "name": row[0],
                    "total_cost": row[1],
                    "num_calls": row[2]
                }
                for row in cursor.fetchall()
            ]

        return results

    def query_quality_scores(self) -> List[Dict[str, Any]]:
        """Query quality scores from database"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT contract_name, stage, quality_score, num_rounds, total_cost
                FROM performance_metrics
                ORDER BY timestamp DESC
            """)

            results = [
                {
                    "contract": row[0],
                    "stage": row[1],
                    "quality_score": row[2],
                    "num_rounds": row[3],
                    "total_cost": row[4]
                }
                for row in cursor.fetchall()
            ]

        return results

    # ============================================================================
    # ATTACK LAYER LOGGING (Phase 2)
    # ============================================================================

    def log_jit_request(
        self,
        attacker_name: str,
        contract_name: str,
        question: str,
        specialist_type: str,
        urgency: str,
        mode: str,
        response: Any,
        cost: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log JIT research request

        Args:
            attacker_name: Which attacker requested
            contract_name: Contract being analyzed
            question: Research question
            specialist_type: Which specialist answered
            urgency: high/medium/low
            mode: single/cached
            response: JIT response object
            cost: Cost of request
            metadata: Additional data
        """
        timestamp = self._now()

        # Save raw JSON
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{attacker_name}_jit.json"
        json_data = {
            "timestamp": timestamp,
            "attacker_name": attacker_name,
            "contract_name": contract_name,
            "question": question,
            "specialist_type": specialist_type,
            "urgency": urgency,
            "mode": mode,
            "answer": response.answer if hasattr(response, 'answer') else str(response),
            "confidence": response.confidence if hasattr(response, 'confidence') else 0.0,
            "cost": cost,
            "cached": response.cached if hasattr(response, 'cached') else False,
            "metadata": metadata or {}
        }

        # Create jit_research subdirectory
        jit_dir = self.raw_dir / "jit_research"
        jit_dir.mkdir(exist_ok=True)

        filepath = jit_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_attack_hypothesis(
        self,
        attacker_name: str,
        contract_name: str,
        hypothesis: Any,
        round_num: int,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log attack hypothesis generation

        Args:
            attacker_name: Which attacker generated hypothesis
            contract_name: Contract being analyzed
            hypothesis: AttackHypothesis object
            round_num: Round number
            metadata: Additional data
        """
        timestamp = self._now()

        # Save raw JSON
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{attacker_name}_hyp_r{round_num}.json"
        json_data = {
            "timestamp": timestamp,
            "attacker_name": attacker_name,
            "contract_name": contract_name,
            "round_num": round_num,
            "hypothesis_id": hypothesis.hypothesis_id if hasattr(hypothesis, 'hypothesis_id') else "unknown",
            "attack_type": hypothesis.attack_type if hasattr(hypothesis, 'attack_type') else "unknown",
            "description": hypothesis.description if hasattr(hypothesis, 'description') else str(hypothesis),
            "confidence": hypothesis.confidence if hasattr(hypothesis, 'confidence') else 0.0,
            "metadata": metadata or {}
        }

        # Create attacks subdirectory
        attack_dir = self.raw_dir / "attacks"
        attack_dir.mkdir(exist_ok=True)

        filepath = attack_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_poc_generation(
        self,
        attacker_name: str,
        contract_name: str,
        hypothesis_id: str,
        poc_path: str,
        generation_method: str,
        cost: float,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log PoC generation

        Args:
            attacker_name: Which attacker requested PoC
            contract_name: Contract being analyzed
            hypothesis_id: Hypothesis ID
            poc_path: Path to generated PoC
            generation_method: ai/template/hybrid
            cost: Generation cost
            metadata: Additional data
        """
        timestamp = self._now()

        # Save raw JSON
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_poc_{hypothesis_id}.json"
        json_data = {
            "timestamp": timestamp,
            "attacker_name": attacker_name,
            "contract_name": contract_name,
            "hypothesis_id": hypothesis_id,
            "poc_path": poc_path,
            "generation_method": generation_method,
            "cost": cost,
            "metadata": metadata or {}
        }

        # Create pocs subdirectory
        poc_dir = self.raw_dir / "pocs"
        poc_dir.mkdir(exist_ok=True)

        filepath = poc_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_poc_execution(
        self,
        contract_name: str,
        hypothesis_id: str,
        poc_path: str,
        success: bool,
        exit_code: int,
        gas_used: Optional[int],
        profit: Optional[str],
        error_message: Optional[str],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log PoC execution results

        Args:
            contract_name: Contract being analyzed
            hypothesis_id: Hypothesis ID
            poc_path: Path to PoC
            success: True if exploit succeeded
            exit_code: Process exit code
            gas_used: Gas consumption
            profit: Estimated profit
            error_message: Error if failed
            metadata: Additional data
        """
        timestamp = self._now()

        # Save raw JSON
        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_poc_exec_{hypothesis_id}.json"
        json_data = {
            "timestamp": timestamp,
            "contract_name": contract_name,
            "hypothesis_id": hypothesis_id,
            "poc_path": poc_path,
            "success": success,
            "exit_code": exit_code,
            "gas_used": gas_used,
            "profit": profit,
            "error_message": error_message,
            "metadata": metadata or {}
        }

        # Create poc_executions subdirectory
        exec_dir = self.raw_dir / "poc_executions"
        exec_dir.mkdir(exist_ok=True)

        filepath = exec_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    # ============================================================================
    # VERIFICATION LAYER LOGGING (Phase 3)
    # ============================================================================

    def log_verification_decision(
        self,
        hypothesis_id: str,
        attacker: str,
        verified: bool,
        confidence: float,
        reasoning: str,
        issues: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log verification layer decision

        Args:
            hypothesis_id: Hypothesis ID
            attacker: Attacker type
            verified: True if passed verification
            confidence: Verification confidence
            reasoning: Detailed reasoning
            issues: Issues found
            metadata: Additional data
        """
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_verification_{hypothesis_id}.json"
        json_data = {
            "timestamp": timestamp,
            "hypothesis_id": hypothesis_id,
            "attacker": attacker,
            "verified": verified,
            "confidence": confidence,
            "reasoning": reasoning,
            "issues": issues,
            "metadata": metadata or {}
        }

        verif_dir = self.raw_dir / "verification"
        verif_dir.mkdir(exist_ok=True)

        filepath = verif_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_impact_assessment(
        self,
        hypothesis_id: str,
        severity: str,
        economic_impact: float,
        attack_cost: float,
        roi: float,
        reasoning: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log impact amplification assessment

        Args:
            hypothesis_id: Hypothesis ID
            severity: Immunefi severity level
            economic_impact: Economic impact in USD
            attack_cost: Attack cost in USD
            roi: Return on investment %
            reasoning: Detailed reasoning
            metadata: Additional data
        """
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_impact_{hypothesis_id}.json"
        json_data = {
            "timestamp": timestamp,
            "hypothesis_id": hypothesis_id,
            "severity": severity,
            "economic_impact_usd": economic_impact,
            "attack_cost_usd": attack_cost,
            "roi_percent": roi,
            "reasoning": reasoning,
            "metadata": metadata or {}
        }

        impact_dir = self.raw_dir / "impact"
        impact_dir.mkdir(exist_ok=True)

        filepath = impact_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_resolution(
        self,
        hypothesis_id: str,
        recommended_fix: str,
        complexity: str,
        alternatives: int,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log resolution layer fix recommendations

        Args:
            hypothesis_id: Hypothesis ID
            recommended_fix: Primary fix strategy
            complexity: Fix complexity level
            alternatives: Number of alternative fixes
            metadata: Additional data
        """
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_resolution_{hypothesis_id}.json"
        json_data = {
            "timestamp": timestamp,
            "hypothesis_id": hypothesis_id,
            "recommended_fix": recommended_fix,
            "complexity": complexity,
            "alternatives_count": alternatives,
            "metadata": metadata or {}
        }

        resolution_dir = self.raw_dir / "resolution"
        resolution_dir.mkdir(exist_ok=True)

        filepath = resolution_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_rejection_analysis(
        self,
        contract_name: str,
        total_rejections: int,
        breakdown: Dict[str, int],
        anti_patterns: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log rejection analysis results

        Args:
            contract_name: Contract analyzed
            total_rejections: Total rejections
            breakdown: Rejection breakdown by type
            anti_patterns: Anti-patterns discovered
            metadata: Additional data
        """
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_rejection_analysis.json"
        json_data = {
            "timestamp": timestamp,
            "contract_name": contract_name,
            "total_rejections": total_rejections,
            "rejection_breakdown": breakdown,
            "anti_patterns": anti_patterns,
            "metadata": metadata or {}
        }

        rejection_dir = self.raw_dir / "rejection_analysis"
        rejection_dir.mkdir(exist_ok=True)

        filepath = rejection_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_error(
        self,
        agent_name: str,
        contract_name: Optional[str],
        error_type: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Log structured error information for research components.

        Provides a consistent sink for failures (required by MoA incremental mode).
        """
        timestamp = self._now()
        contract_label = contract_name or "unknown_contract"

        payload = {
            "timestamp": timestamp,
            "agent_name": agent_name,
            "contract_name": contract_label,
            "error_type": error_type,
            "error_message": error_message,
            "context": context or {}
        }

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_label}_{agent_name}_error.json"
        self._save_json(LogCategory.ERROR, filename, payload)

        if config.LOG_TO_SQLITE:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS errors (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        agent_name TEXT NOT NULL,
                        contract_name TEXT,
                        error_type TEXT NOT NULL,
                        error_message TEXT NOT NULL,
                        context TEXT
                    )
                """)
                cursor.execute(
                    """
                    INSERT INTO errors
                    (timestamp, agent_name, contract_name, error_type, error_message, context)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp,
                        agent_name,
                        contract_label,
                        error_type,
                        error_message,
                        json.dumps(context or {})
                    )
                )
                conn.commit()

        # Ensure error surfaces in stdout for quick debugging
        self.error(f"{agent_name} failed during {error_type}: {error_message}")

    # ============================================================================
    # UNIQUE IMPROVEMENTS LOGGING (Phase 3+)
    # ============================================================================

    def log_confidence_calibration(
        self,
        hypothesis_id: str,
        raw_confidence: float,
        calibrated_confidence: float,
        attacker_multiplier: float,
        pattern_multiplier: float,
        combined_multiplier: float,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log confidence calibration"""
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_calibration_{hypothesis_id}.json"
        json_data = {
            "timestamp": timestamp,
            "hypothesis_id": hypothesis_id,
            "raw_confidence": raw_confidence,
            "calibrated_confidence": calibrated_confidence,
            "attacker_multiplier": attacker_multiplier,
            "pattern_multiplier": pattern_multiplier,
            "combined_multiplier": combined_multiplier,
            "confidence_change": calibrated_confidence - raw_confidence,
            "metadata": metadata or {}
        }

        calib_dir = self.raw_dir / "calibration"
        calib_dir.mkdir(exist_ok=True)

        filepath = calib_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_chain_validation(
        self,
        hypothesis_id: str,
        valid: bool,
        confidence: float,
        violations: List[str],
        gas_estimate: int,
        capital_required: float,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log exploit chain validation"""
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_chain_{hypothesis_id}.json"
        json_data = {
            "timestamp": timestamp,
            "hypothesis_id": hypothesis_id,
            "valid": valid,
            "confidence": confidence,
            "violations": violations,
            "gas_estimate": gas_estimate,
            "capital_required": capital_required,
            "metadata": metadata or {}
        }

        chain_dir = self.raw_dir / "chain_validation"
        chain_dir.mkdir(exist_ok=True)

        filepath = chain_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    def log_cross_validation(
        self,
        hypothesis_id: str,
        validation_type: str,
        passed: bool,
        contradictions: List[str],
        should_proceed: bool,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log cross-layer validation"""
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_cross_{validation_type}_{hypothesis_id}.json"
        json_data = {
            "timestamp": timestamp,
            "hypothesis_id": hypothesis_id,
            "validation_type": validation_type,
            "passed": passed,
            "contradictions": contradictions,
            "should_proceed": should_proceed,
            "metadata": metadata or {}
        }

        cross_dir = self.raw_dir / "cross_validation"
        cross_dir.mkdir(exist_ok=True)

        filepath = cross_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

    # ========================================================================
    # ENHANCED LOGGING FOR CONTINUOUS LEARNING MOAT
    # ========================================================================

    def log_attack_chain_trace(
        self,
        chain_id: str,
        contract_name: str,
        hypothesis_id: str,
        stages: Dict[str, Any],
        total_cost: float,
        total_duration_seconds: float,
        final_outcome: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log complete attack chain from hypothesis to resolution

        Enables end-to-end analysis of attack lifecycle.

        Args:
            chain_id: Unique chain identifier
            contract_name: Contract being analyzed
            hypothesis_id: Initial hypothesis ID
            stages: Dict of stage_name → stage_data
            total_cost: Total cost for entire chain
            total_duration_seconds: Total duration
            final_outcome: "true_positive"|"false_positive"|"false_negative"|"inconclusive"
            metadata: Additional data
        """
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{chain_id}.json"
        json_data = {
            "timestamp": timestamp,
            "chain_id": chain_id,
            "contract_name": contract_name,
            "hypothesis_id": hypothesis_id,
            "stages": stages,
            "total_cost": total_cost,
            "total_duration_seconds": total_duration_seconds,
            "final_outcome": final_outcome,
            "metadata": metadata or {}
        }

        chain_dir = self.raw_dir / "attack_chains"
        chain_dir.mkdir(exist_ok=True)

        filepath = chain_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        # Also save to SQLite for queries
        if config.LOG_TO_SQLITE:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()

                # Create table if not exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS attack_chains (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        chain_id TEXT NOT NULL,
                        contract_name TEXT NOT NULL,
                        hypothesis_id TEXT NOT NULL,
                        total_cost REAL,
                        total_duration_seconds REAL,
                        final_outcome TEXT,
                        stages_json TEXT,
                        metadata TEXT
                    )
                """)

                cursor.execute("""
                    INSERT INTO attack_chains
                    (timestamp, chain_id, contract_name, hypothesis_id, total_cost,
                     total_duration_seconds, final_outcome, stages_json, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, chain_id, contract_name, hypothesis_id, total_cost,
                    total_duration_seconds, final_outcome, json.dumps(stages, default=str),
                    json.dumps(metadata or {}, default=str)
                ))

                conn.commit()

    def log_ground_truth(
        self,
        contract_name: str,
        hypothesis_id: str,
        our_prediction: str,
        our_confidence: float,
        ground_truth: str,
        ground_truth_source: str,
        correct: bool,
        notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log ground truth validation for measuring accuracy

        Args:
            contract_name: Contract analyzed
            hypothesis_id: Hypothesis ID
            our_prediction: What we predicted
            our_confidence: Our confidence (0.0-1.0)
            ground_truth: Actual truth
            ground_truth_source: Where truth came from ("dvd_solution", "manual_review", etc)
            correct: Whether we were correct
            notes: Additional notes
            metadata: Additional data
        """
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_{hypothesis_id}_truth.json"
        json_data = {
            "timestamp": timestamp,
            "contract_name": contract_name,
            "hypothesis_id": hypothesis_id,
            "our_prediction": our_prediction,
            "our_confidence": our_confidence,
            "ground_truth": ground_truth,
            "ground_truth_source": ground_truth_source,
            "correct": correct,
            "notes": notes,
            "metadata": metadata or {}
        }

        truth_dir = self.raw_dir / "ground_truth"
        truth_dir.mkdir(exist_ok=True)

        filepath = truth_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        # SQLite
        if config.LOG_TO_SQLITE:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ground_truth (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        contract_name TEXT NOT NULL,
                        hypothesis_id TEXT NOT NULL,
                        our_prediction TEXT,
                        our_confidence REAL,
                        ground_truth TEXT,
                        ground_truth_source TEXT,
                        correct INTEGER,
                        notes TEXT,
                        metadata TEXT
                    )
                """)

                cursor.execute("""
                    INSERT INTO ground_truth
                    (timestamp, contract_name, hypothesis_id, our_prediction, our_confidence,
                     ground_truth, ground_truth_source, correct, notes, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, contract_name, hypothesis_id, our_prediction, our_confidence,
                    ground_truth, ground_truth_source, 1 if correct else 0, notes,
                    json.dumps(metadata or {}, default=str)
                ))

                conn.commit()

    def log_kb_learning_event(
        self,
        event_type: str,
        pattern_id: str,
        trigger: str,
        contract_name: str,
        old_confidence: Optional[float] = None,
        new_confidence: Optional[float] = None,
        evidence: Optional[str] = None,
        generalization_notes: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log KB learning events for audit trail

        Args:
            event_type: "pattern_updated"|"pattern_created"|"pattern_deprecated"
            pattern_id: Pattern ID
            trigger: What triggered the learning
            contract_name: Contract context
            old_confidence: Previous confidence
            new_confidence: New confidence
            evidence: Supporting evidence
            generalization_notes: Notes on generalization
            metadata: Additional data
        """
        timestamp = self._now()

        # Ensure pattern_id is never None (defensive check for database constraint)
        if pattern_id is None:
            pattern_id = "unknown"

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{event_type}_{pattern_id}.json"
        json_data = {
            "timestamp": timestamp,
            "event_type": event_type,
            "pattern_id": pattern_id,
            "trigger": trigger,
            "contract_name": contract_name,
            "old_confidence": old_confidence,
            "new_confidence": new_confidence,
            "confidence_change": (new_confidence - old_confidence) if (old_confidence and new_confidence) else None,
            "evidence": evidence,
            "generalization_notes": generalization_notes,
            "metadata": metadata or {}
        }

        kb_dir = self.raw_dir / "kb_learning"
        kb_dir.mkdir(exist_ok=True)

        filepath = kb_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        # SQLite
        if config.LOG_TO_SQLITE:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS kb_learning_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        pattern_id TEXT NOT NULL,
                        trigger TEXT,
                        contract_name TEXT,
                        old_confidence REAL,
                        new_confidence REAL,
                        confidence_change REAL,
                        evidence TEXT,
                        generalization_notes TEXT,
                        metadata TEXT
                    )
                """)

                cursor.execute("""
                    INSERT INTO kb_learning_events
                    (timestamp, event_type, pattern_id, trigger, contract_name,
                     old_confidence, new_confidence, confidence_change, evidence,
                     generalization_notes, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, event_type, pattern_id, trigger, contract_name,
                    old_confidence, new_confidence,
                    (new_confidence - old_confidence) if (old_confidence and new_confidence) else None,
                    evidence, generalization_notes,
                    json.dumps(metadata or {}, default=str)
                ))

                conn.commit()

    def log_pattern_synthesis(
        self,
        new_pattern_id: str,
        source_hypothesis_id: str,
        contract_name: str,
        synthesis_reason: str,
        pattern_details: Dict[str, Any],
        similar_patterns: List[str],
        generalization_potential: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log automatic pattern synthesis from successful attacks

        Args:
            new_pattern_id: New pattern ID
            source_hypothesis_id: Hypothesis that generated this
            contract_name: Source contract
            synthesis_reason: Why was this synthesized
            pattern_details: Pattern data
            similar_patterns: Similar existing patterns
            generalization_potential: "high"|"medium"|"low"
            metadata: Additional data
        """
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_synthesis_{new_pattern_id}.json"
        json_data = {
            "timestamp": timestamp,
            "new_pattern_id": new_pattern_id,
            "source_hypothesis_id": source_hypothesis_id,
            "contract_name": contract_name,
            "synthesis_reason": synthesis_reason,
            "pattern_details": pattern_details,
            "similar_patterns": similar_patterns,
            "generalization_potential": generalization_potential,
            "metadata": metadata or {}
        }

        synth_dir = self.raw_dir / "pattern_synthesis"
        synth_dir.mkdir(exist_ok=True)

        filepath = synth_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        # SQLite
        if config.LOG_TO_SQLITE:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS pattern_synthesis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        new_pattern_id TEXT NOT NULL,
                        source_hypothesis_id TEXT,
                        contract_name TEXT,
                        synthesis_reason TEXT,
                        generalization_potential TEXT,
                        pattern_details_json TEXT,
                        similar_patterns_json TEXT,
                        metadata TEXT
                    )
                """)

                cursor.execute("""
                    INSERT INTO pattern_synthesis
                    (timestamp, new_pattern_id, source_hypothesis_id, contract_name,
                     synthesis_reason, generalization_potential, pattern_details_json,
                     similar_patterns_json, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, new_pattern_id, source_hypothesis_id, contract_name,
                    synthesis_reason, generalization_potential,
                    json.dumps(pattern_details, default=str),
                    json.dumps(similar_patterns),
                    json.dumps(metadata or {}, default=str)
                ))

                conn.commit()

    def log_cost_roi(
        self,
        contract_name: str,
        total_cost: float,
        findings: Dict[str, int],
        economic_impact_discovered: float,
        roi_ratio: float,
        cost_breakdown: Dict[str, float],
        optimization_opportunities: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log cost ROI analysis for optimization

        Args:
            contract_name: Contract analyzed
            total_cost: Total USD cost
            findings: Dict of severity → count
            economic_impact_discovered: Total USD impact found
            roi_ratio: economic_impact / total_cost
            cost_breakdown: Stage costs
            optimization_opportunities: List of optimization notes
            metadata: Additional data
        """
        timestamp = self._now()

        filename = f"{datetime.now().strftime('%Y-%m-%d')}_{contract_name}_roi.json"
        json_data = {
            "timestamp": timestamp,
            "contract_name": contract_name,
            "total_cost": total_cost,
            "findings": findings,
            "economic_impact_discovered": economic_impact_discovered,
            "roi_ratio": roi_ratio,
            "cost_breakdown": cost_breakdown,
            "optimization_opportunities": optimization_opportunities,
            "metadata": metadata or {}
        }

        roi_dir = self.raw_dir / "cost_roi"
        roi_dir.mkdir(exist_ok=True)

        filepath = roi_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=str)

        # SQLite
        if config.LOG_TO_SQLITE:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cost_roi (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        contract_name TEXT NOT NULL,
                        total_cost REAL,
                        findings_json TEXT,
                        economic_impact_discovered REAL,
                        roi_ratio REAL,
                        cost_breakdown_json TEXT,
                        optimization_opportunities_json TEXT,
                        metadata TEXT
                    )
                """)

                cursor.execute("""
                    INSERT INTO cost_roi
                    (timestamp, contract_name, total_cost, findings_json,
                     economic_impact_discovered, roi_ratio, cost_breakdown_json,
                     optimization_opportunities_json, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, contract_name, total_cost,
                    json.dumps(findings),
                    economic_impact_discovered, roi_ratio,
                    json.dumps(cost_breakdown),
                    json.dumps(optimization_opportunities),
                    json.dumps(metadata or {}, default=str)
                ))

                conn.commit()

    # ========================================================================
    # CONVENIENCE METHODS
    # ========================================================================

    # Convenience methods (no-op if logging disabled)
    def debug(self, message: str):
        """Debug log message (maps to INFO when logging enabled)"""
        if config.ENABLE_LOGGING:
            audit_id = self._get_audit_id()
            prefix = f"[DEBUG] [audit:{audit_id}]" if audit_id else "[DEBUG]"
            print(f"{prefix} {message}", flush=True)
            sys.stdout.flush()

    def info(self, message: str):
        """Info log message"""
        if config.ENABLE_LOGGING:
            audit_id = self._get_audit_id()
            prefix = f"[INFO] [audit:{audit_id}]" if audit_id else "[INFO]"
            print(f"{prefix} {message}", flush=True)
            sys.stdout.flush()

    def warning(self, message: str):
        """Warning log message"""
        if config.ENABLE_LOGGING:
            audit_id = self._get_audit_id()
            prefix = f"[WARN] [audit:{audit_id}]" if audit_id else "[WARN]"
            print(f"{prefix} {message}", flush=True)
            sys.stdout.flush()

    def error(self, message: str):
        """Error log message"""
        audit_id = self._get_audit_id()
        prefix = f"[ERROR] [audit:{audit_id}]" if audit_id else "[ERROR]"
        print(f"{prefix} {message}", flush=True)
        sys.stdout.flush()


# Alias for backwards compatibility
ResearchLogger = ResearchLogger
