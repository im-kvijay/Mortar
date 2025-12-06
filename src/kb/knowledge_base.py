"""knowledge base with bayesian learning"""
import copy
import json
import hashlib
import logging
import re
import os
import threading
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, UTC
from enum import Enum

from config import config
from src.kb.knowledge_stats import KnowledgeStats

logger = logging.getLogger(__name__)

try:
    from filelock import FileLock, Timeout
    FILELOCK_AVAILABLE = True
except ImportError:
    FILELOCK_AVAILABLE = False
    logger.warning("filelock not installed - cross-process safety disabled. Install with: pip install filelock")


class PatternStatus(Enum):
    """vulnerability pattern status"""
    UNVALIDATED = "unvalidated"
    TESTING = "testing"
    VALIDATED = "validated"
    FAILED = "failed"
    DEPRECATED = "deprecated"


@dataclass
class VulnerabilityPattern:
    """reusable attack pattern learned from exploits"""
    id: str
    name: str
    vuln_type: str
    description: str
    preconditions: List[str]
    attack_steps: List[str]
    indicators: List[str]
    successful_exploits: int = 0
    failed_attempts: int = 0
    confidence: float = 0.5
    status: PatternStatus = PatternStatus.UNVALIDATED
    contracts_vulnerable: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    synthesized: bool = False
    source_patterns: List[str] = field(default_factory=list)
    discovered_by: Optional[str] = None
    source_contract: Optional[str] = None

    def update_confidence(self, success: bool):
        """update bayesian confidence"""
        if success:
            self.successful_exploits += 1
        else:
            self.failed_attempts += 1
        self.confidence = (self.successful_exploits + 1) / (self.successful_exploits + self.failed_attempts + 2)
        self.updated_at = datetime.now(UTC)

    def to_dict(self) -> Dict:
        """convert to dict"""
        d = asdict(self)
        d['status'] = self.status.value
        d['created_at'] = self.created_at.isoformat()
        d['updated_at'] = self.updated_at.isoformat()
        return d


@dataclass
class AttackAttempt:
    """attack attempt record"""
    id: str
    contract_name: str
    attacker_name: str
    pattern_id: Optional[str]
    hypothesis: str
    success: bool
    evidence: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> Dict:
        """convert to dict"""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d


@dataclass
class AntiPattern:
    """false positive anti-patterns for suppression"""
    id: str
    name: str
    description: str
    trigger_indicators: List[str]
    context_conditions: List[str]
    false_positive_count: int = 0
    true_positive_override: int = 0
    suppression_confidence: float = 0.5
    source_hypothesis_type: str = ""
    source_attacker: str = ""
    example_contracts: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def update_confidence(self, is_false_positive: bool):
        """update suppression confidence"""
        if is_false_positive:
            self.false_positive_count += 1
        else:
            self.true_positive_override += 1
        self.suppression_confidence = (self.false_positive_count + 1) / (self.false_positive_count + self.true_positive_override + 2)
        self.updated_at = datetime.now(UTC)

    def should_suppress(self, threshold: float = 0.7) -> bool:
        """check if should suppress"""
        return self.suppression_confidence >= threshold

    def to_dict(self) -> Dict:
        """convert to dict"""
        d = asdict(self)
        d['created_at'] = self.created_at.isoformat()
        d['updated_at'] = self.updated_at.isoformat()
        return d


@dataclass
class SpecialistAccuracy:
    """specialist accuracy per vulnerability type"""
    specialist_name: str
    vuln_type: str
    true_positives: int = 0
    false_positives: int = 0
    total_hypotheses: int = 0
    precision: float = 0.5
    recall_proxy: float = 0.5
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def record_outcome(self, is_valid: bool):
        """record hypothesis outcome"""
        self.total_hypotheses += 1
        if is_valid:
            self.true_positives += 1
        else:
            self.false_positives += 1
        if self.true_positives + self.false_positives > 0:
            self.precision = self.true_positives / (self.true_positives + self.false_positives)
        else:
            self.precision = 0.5
        self.recall_proxy = (self.true_positives + 1) / (self.total_hypotheses + 2)
        self.updated_at = datetime.now(UTC)

    def get_weight(self) -> float:
        """get contribution weight"""
        if self.precision + self.recall_proxy == 0:
            return 0.5
        f1_like = 2 * (self.precision * self.recall_proxy) / (self.precision + self.recall_proxy)
        sample_weight = min(1.0, self.total_hypotheses / 10)
        return 0.5 + (f1_like - 0.5) * sample_weight

    def to_dict(self) -> Dict:
        """convert to dict"""
        d = asdict(self)
        d['updated_at'] = self.updated_at.isoformat()
        return d


class KnowledgeBase:
    """persistent shared knowledge for all agents"""

    GRAPH_CACHE_VERSION = "2025-11-11"

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        enable_graph_rag: bool = False,
        enable_synthesis: Optional[bool] = None,
        pattern_backend_type: Optional[str] = None,
        pattern_model: Optional[str] = None,
        disable_storage: bool = False,
    ):
        """init kb"""
        from config import config

        if data_dir is None:
            data_dir = config.KB_DIR
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.disable_storage = disable_storage

        self.contracts_file = self.data_dir / "contracts.json"
        self.patterns_file = self.data_dir / "patterns.json"
        self.attempts_file = self.data_dir / "attempts.json"
        self.anti_patterns_file = self.data_dir / "anti_patterns.json"
        self.specialist_accuracy_file = self.data_dir / "specialist_accuracy.json"

        self._lock = threading.RLock()

        self._file_locks: Dict[Path, Any] = {}
        if FILELOCK_AVAILABLE and not disable_storage:
            for json_file in [self.contracts_file, self.patterns_file, self.attempts_file, self.anti_patterns_file, self.specialist_accuracy_file]:
                lock_file = json_file.with_suffix('.json.lock')
                self._file_locks[json_file] = FileLock(str(lock_file), timeout=30)

        if self.disable_storage:
            self.contract_knowledge = {}
            self.patterns = {}
            self.attempts = []
            self.anti_patterns: Dict[str, AntiPattern] = {}
            self.specialist_accuracy: Dict[str, SpecialistAccuracy] = {}
        else:
            self.contract_knowledge: Dict[str, Dict] = self._load_json(self.contracts_file)
            self.patterns: Dict[str, VulnerabilityPattern] = self._load_patterns()
            self.attempts: List[AttackAttempt] = self._load_attempts()
            self.anti_patterns: Dict[str, AntiPattern] = self._load_anti_patterns()
            self.specialist_accuracy: Dict[str, SpecialistAccuracy] = self._load_specialist_accuracy()

        self._dirty_contracts = False
        self._dirty_patterns = False
        self._dirty_attempts = False
        self._dirty_anti_patterns = False
        self._dirty_specialist_accuracy = False

        self.enable_graph_rag = enable_graph_rag and not self.disable_storage
        self.graph_rag = None
        self.graph_cache_dir = config.DATA_DIR / "cache" / "graph_rag"
        self.graph_cache_dir.mkdir(parents=True, exist_ok=True)
        self.graph_manifest_file = self.graph_cache_dir / "manifest.json"
        self.graph_payload_file = self.graph_cache_dir / "graph.pkl"
        self.self_rag = None
        if enable_graph_rag:
            self._initialize_graph_rag()

        if enable_synthesis is None:
            enable_synthesis = config.ENABLE_PATTERN_SYNTHESIS
        self.enable_synthesis = enable_synthesis and not self.disable_storage
        self.pattern_synthesizer = None
        self.pattern_backend_type = pattern_backend_type
        self.pattern_model = pattern_model
        if self.enable_synthesis:
            self._initialize_synthesis()

        self.stats = KnowledgeStats(self)

        if not disable_storage:
            try:
                from utils.shutdown import register_cleanup
                register_cleanup(self.flush, f"kb_flush_{id(self)}")
                logger.debug("KB cleanup handler registered")
            except ImportError:
                logger.warning("Shutdown module not available - KB may not flush on exit")

    def store_contract_knowledge(self, knowledge):
        """store knowledge from research layer"""
        from collections.abc import Mapping

        with self._lock:
            contract_name = None
            record: Dict[str, Any]

            if hasattr(knowledge, "contract_name") and hasattr(knowledge, "to_dict"):
                contract_name = getattr(knowledge, "contract_name")
                record = knowledge.to_dict()
            elif isinstance(knowledge, Mapping):
                record = dict(knowledge)
                contract_name = record.get("contract_name") or record.get("name") or record.get("contract")
            else:
                raise TypeError("store_contract_knowledge expects an object with contract_name/to_dict or a mapping containing 'contract_name'.")

            if not contract_name:
                raise ValueError("Knowledge record must include 'contract_name'.")

            record["contract_name"] = contract_name
            self.contract_knowledge[contract_name] = record
            self._dirty_contracts = True
            if not self.disable_storage:
                logger.debug(f"Stored knowledge for {contract_name} (pending flush)")

    def get_contract_knowledge(self, contract_name: str) -> Optional[Dict]:
        """get knowledge about a specific contract"""
        return self.contract_knowledge.get(contract_name)

    def add_pattern(self, pattern: VulnerabilityPattern):
        """add a new vulnerability pattern"""
        with self._lock:
            self.patterns[pattern.id] = pattern
            self._dirty_patterns = True
            logger.debug(f"Added pattern: {pattern.name} (confidence: {pattern.confidence:.2f}) (pending flush)")

    def get_pattern(self, pattern_id: str) -> Optional[VulnerabilityPattern]:
        """get a specific pattern"""
        with self._lock:
            return self.patterns.get(pattern_id)

    def get_patterns_by_type(self, vuln_type: str) -> List[VulnerabilityPattern]:
        """get all patterns of a specific type"""
        return [p for p in self.patterns.values() if p.vuln_type == vuln_type]

    def get_high_confidence_patterns(self, threshold: float = 0.7) -> List[VulnerabilityPattern]:
        """get patterns with confidence >= threshold"""
        return [p for p in self.patterns.values() if p.confidence >= threshold]

    def get_relevant_patterns(self, contract_name: str, top_k: int = 10) -> List[VulnerabilityPattern]:
        """get most relevant patterns for a contract"""
        knowledge = self.get_contract_knowledge(contract_name)
        if not knowledge:
            patterns = sorted(self.get_high_confidence_patterns(), key=lambda p: p.confidence, reverse=True)[:top_k]
            return [self._localize_pattern(p, contract_name) for p in patterns]

        scored_patterns = []
        for pattern in self.patterns.values():
            score = self._calculate_pattern_relevance(pattern, knowledge)
            scored_patterns.append((score, pattern))

        scored_patterns.sort(reverse=True, key=lambda x: x[0])
        top_patterns = [p for _, p in scored_patterns[:top_k]]
        return [self._localize_pattern(p, contract_name) for p in top_patterns]

    def _calculate_pattern_relevance(self, pattern: VulnerabilityPattern, knowledge: Dict) -> float:
        """calculate how relevant a pattern is for a contract"""
        score = pattern.confidence
        invariants = knowledge.get("invariants", [])
        assumptions = knowledge.get("trust_assumptions", [])
        all_knowledge = invariants + assumptions

        for precond in pattern.preconditions:
            for item in all_knowledge:
                if any(word in item.lower() for word in precond.lower().split()):
                    score += 0.1
        return score

    def _replace_tokens(self, text: str, tokens: List[str], replacement: str) -> str:
        """replace tokens in text"""
        updated = text
        for token in tokens:
            if not token:
                continue
            if token.lower() == replacement.lower():
                continue
            pattern = re.compile(rf"\b{re.escape(token)}\b", flags=re.IGNORECASE)
            updated = pattern.sub(replacement, updated)
        return updated

    def _localize_pattern(self, pattern: VulnerabilityPattern, contract_name: str) -> VulnerabilityPattern:
        """produce a copy of the pattern whose narrative references the current contract"""
        clone = copy.deepcopy(pattern)
        tokens: List[str] = []
        if getattr(pattern, "source_contract", None):
            tokens.append(pattern.source_contract)
        tokens.extend(pattern.contracts_vulnerable or [])

        if tokens:
            clone.name = self._replace_tokens(clone.name, tokens, contract_name)
            clone.description = self._replace_tokens(clone.description, tokens, contract_name)
            clone.preconditions = [self._replace_tokens(item, tokens, contract_name) for item in clone.preconditions]
            clone.attack_steps = [self._replace_tokens(item, tokens, contract_name) for item in clone.attack_steps]
            clone.indicators = [self._replace_tokens(item, tokens, contract_name) for item in clone.indicators]
        return clone

    def update_pattern(self, pattern_id: str, success: bool, contract_name: Optional[str] = None):
        """update pattern based on validation result"""
        with self._lock:
            pattern = self.patterns.get(pattern_id)
            if not pattern:
                logger.warning(f"Pattern {pattern_id} not found")
                return

            pattern.update_confidence(success)

            if success and contract_name and contract_name not in pattern.contracts_vulnerable:
                pattern.contracts_vulnerable.append(contract_name)

            self._dirty_patterns = True

            logger.info(f"Updated pattern {pattern.name}: success={success}, confidence={pattern.confidence:.2f}, exploits={pattern.successful_exploits}, failures={pattern.failed_attempts} (pending flush)")

    def update_discovery_confidence(self, contract_name: str, discovery_description: str, success: bool) -> bool:
        """update discovery confidence based on verification result"""
        knowledge = self.contract_knowledge.get(contract_name, {})
        discoveries = knowledge.get("discoveries", [])

        if not discoveries:
            return False

        found = False
        for discovery in discoveries:
            disc_desc = discovery.get("description") or discovery.get("content") or str(discovery)
            if disc_desc in discovery_description or discovery_description in disc_desc:
                successes = discovery.get("_successful_verifications", 0)
                failures = discovery.get("_failed_verifications", 0)

                if success:
                    successes += 1
                else:
                    failures += 1

                old_confidence = discovery.get("confidence", 0.85)
                new_confidence = (successes + 1) / (successes + failures + 2)

                discovery["_successful_verifications"] = successes
                discovery["_failed_verifications"] = failures
                discovery["confidence"] = new_confidence
                discovery["_last_verified"] = True

                logger.info(f"Updated discovery confidence for {contract_name}: {old_confidence:.3f} → {new_confidence:.3f} ({'success' if success else 'failure'})")
                found = True
                break

        if found:
            knowledge["discoveries"] = discoveries
            self.contract_knowledge[contract_name] = knowledge
            self._dirty_contracts = True

        return found

    def record_attempt(self, attempt: AttackAttempt):
        """record an attack attempt (success or failure)"""
        with self._lock:
            self.attempts.append(attempt)
            self._dirty_attempts = True

        if attempt.pattern_id:
            self.update_pattern(attempt.pattern_id, attempt.success, attempt.contract_name)

    def get_successful_attempts(self) -> List[AttackAttempt]:
        """get all successful attacks"""
        return [a for a in self.attempts if a.success]

    def record_false_positive(self, hypothesis: Any, rejection_reason: str, contract_name: str) -> AntiPattern:
        """record false positives as anti-patterns"""
        attack_type = getattr(hypothesis, 'attack_type', 'unknown')
        description = getattr(hypothesis, 'description', str(hypothesis))[:100]
        pattern_hash = hashlib.md5(f"{attack_type}:{description}".encode()).hexdigest()[:8]
        anti_pattern_id = f"anti_{attack_type}_{pattern_hash}"

        if anti_pattern_id in self.anti_patterns:
            anti_pattern = self.anti_patterns[anti_pattern_id]
            anti_pattern.update_confidence(is_false_positive=True)
            if contract_name not in anti_pattern.example_contracts:
                anti_pattern.example_contracts.append(contract_name)
            logger.debug(f"Updated anti-pattern {anti_pattern.name}: suppression confidence {anti_pattern.suppression_confidence:.3f}")
        else:
            trigger_indicators = []
            if hasattr(hypothesis, 'preconditions'):
                trigger_indicators.extend(hypothesis.preconditions[:3])
            if hasattr(hypothesis, 'attack_steps'):
                trigger_indicators.extend([s[:50] for s in hypothesis.attack_steps[:2]])

            context_conditions = [rejection_reason]
            if "not exploitable" in rejection_reason.lower():
                context_conditions.append("Code path not reachable in practice")
            if "access control" in rejection_reason.lower():
                context_conditions.append("Protected by access control not visible in static analysis")
            if "slippage" in rejection_reason.lower() or "price" in rejection_reason.lower():
                context_conditions.append("Price impact makes attack economically infeasible")

            anti_pattern = AntiPattern(
                id=anti_pattern_id,
                name=f"FP: {attack_type} - {description[:40]}",
                description=f"False positive pattern: {description}",
                trigger_indicators=trigger_indicators,
                context_conditions=context_conditions,
                false_positive_count=1,
                true_positive_override=0,
                suppression_confidence=0.6,
                source_hypothesis_type=attack_type,
                source_attacker=getattr(hypothesis, 'attacker_name', 'unknown'),
                example_contracts=[contract_name]
            )
            self.anti_patterns[anti_pattern_id] = anti_pattern
            logger.info(f"Created new anti-pattern: {anti_pattern.name}")

        self._dirty_anti_patterns = True
        return anti_pattern

    def get_matching_anti_patterns(self, hypothesis: Any, threshold: float = 0.7) -> List[AntiPattern]:
        """find anti-patterns that match a hypothesis"""
        matching = []
        attack_type = getattr(hypothesis, 'attack_type', 'unknown')
        description = getattr(hypothesis, 'description', str(hypothesis)).lower()
        preconditions = getattr(hypothesis, 'preconditions', [])

        for anti_pattern in self.anti_patterns.values():
            if anti_pattern.suppression_confidence < threshold:
                continue
            if anti_pattern.source_hypothesis_type != attack_type:
                continue

            indicator_matches = 0
            for indicator in anti_pattern.trigger_indicators:
                indicator_lower = indicator.lower()
                if indicator_lower in description:
                    indicator_matches += 1
                for precond in preconditions:
                    if indicator_lower in precond.lower():
                        indicator_matches += 1

            if indicator_matches >= 2:
                matching.append(anti_pattern)

        return matching

    def should_suppress_hypothesis(self, hypothesis: Any, threshold: float = 0.75) -> tuple[bool, Optional[AntiPattern]]:
        """check if a hypothesis should be suppressed based on anti-patterns"""
        matching = self.get_matching_anti_patterns(hypothesis, threshold)

        if not matching:
            return False, None

        best_match = max(matching, key=lambda ap: ap.suppression_confidence)
        return best_match.should_suppress(threshold), best_match

    def record_specialist_outcome(self, specialist_name: str, vuln_type: str, is_valid: bool) -> SpecialistAccuracy:
        """record a specialist's hypothesis outcome for accuracy tracking"""
        with self._lock:
            accuracy_key = f"{specialist_name}:{vuln_type}"

            if accuracy_key not in self.specialist_accuracy:
                self.specialist_accuracy[accuracy_key] = SpecialistAccuracy(specialist_name=specialist_name, vuln_type=vuln_type)

            accuracy = self.specialist_accuracy[accuracy_key]
            old_precision = accuracy.precision
            accuracy.record_outcome(is_valid)

            logger.info(f"Updated specialist accuracy {specialist_name}:{vuln_type}: precision {old_precision:.3f} → {accuracy.precision:.3f} (TP={accuracy.true_positives}, FP={accuracy.false_positives})")

            self._dirty_specialist_accuracy = True
            return accuracy

    def get_specialist_weight(self, specialist_name: str, vuln_type: str) -> float:
        """get the contribution weight for a specialist on a vulnerability type"""
        accuracy_key = f"{specialist_name}:{vuln_type}"

        if accuracy_key not in self.specialist_accuracy:
            return 0.5

        return self.specialist_accuracy[accuracy_key].get_weight()

    def adjust_hypothesis_confidence(self, hypothesis: Any, specialist_name: str) -> float:
        """adjust hypothesis confidence based on specialist accuracy"""
        original_confidence = getattr(hypothesis, 'confidence', 0.5)
        attack_type = getattr(hypothesis, 'attack_type', 'unknown')

        weight = self.get_specialist_weight(specialist_name, attack_type)
        adjustment_factor = 0.5 + weight
        adjusted_confidence = min(1.0, original_confidence * adjustment_factor)

        return adjusted_confidence

    def _validate_kb_schema(self, data: dict, file_path: Path) -> bool:
        """validate KB JSON schema before loading"""
        file_name = file_path.stem

        if file_name == "patterns":
            if not isinstance(data, dict):
                return False
            return True

        elif file_name == "contracts":
            if not isinstance(data, dict):
                return False
            return True

        elif file_name == "index":
            required_keys = ["patterns", "discoveries", "contracts"]
            if not isinstance(data, dict):
                return False
            for key in required_keys:
                if key not in data:
                    return False
            return True

        return isinstance(data, dict)

    def _load_json(self, file_path: Path) -> Dict:
        """load JSON file with proper locking"""
        if not file_path.exists():
            return {}

        file_lock = self._file_locks.get(file_path)

        try:
            if file_lock:
                with file_lock:
                    with open(file_path, 'r', encoding="utf-8") as f:
                        return json.load(f)
            else:
                with open(file_path, 'r', encoding="utf-8") as f:
                    return json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError as e:
            logger.warning(f"Corrupted JSON in {file_path}: {e}")
            logger.info("Attempting to recover from backup...")
            backup_path = file_path.with_suffix('.json.bak')
            if backup_path.exists():
                try:
                    with open(backup_path, 'r', encoding="utf-8") as f:
                        data = json.load(f)
                    if not self._validate_kb_schema(data, file_path):
                        logger.error("Backup validation failed - schema mismatch")
                        logger.error("Recovery failed - returning empty dict")
                        return {}
                    logger.info("Successfully recovered from backup (validated)")

                    try:
                        with open(file_path, 'w', encoding="utf-8") as f:
                            json.dump(data, f, indent=2)
                        logger.info(f"Restored primary file {file_path} from backup")
                    except Exception as restore_err:
                        logger.error(f"Failed to restore primary file from backup: {restore_err}")

                    return data
                except json.JSONDecodeError as backup_err:
                    logger.error(f"Backup is also corrupted: {backup_err}")
                except Exception as backup_exc:
                    logger.error(f"Backup recovery error: {backup_exc}")
            logger.error("Recovery failed - returning empty dict")
            return {}
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return {}

    def _save_json(self, file_path: Path, data: Dict):
        """save to JSON file with atomic write"""
        try:
            file_lock = self._file_locks.get(file_path)

            def _perform_save():
                if file_path.exists():
                    backup_path = file_path.with_suffix('.json.bak')
                    try:
                        with open(file_path, 'r', encoding="utf-8") as src:
                            with open(backup_path, 'w', encoding="utf-8") as dst:
                                dst.write(src.read())
                    except Exception as e:
                        logger.warning(f"Failed to create backup for {file_path}: {e}")

                temp_fd, temp_path = tempfile.mkstemp(dir=file_path.parent, prefix=f".{file_path.stem}_", suffix=".json.tmp")

                try:
                    with os.fdopen(temp_fd, 'w', encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
                        f.flush()
                        os.fsync(f.fileno())

                    if os.name == 'nt' and file_path.exists():
                        file_path.unlink()
                    os.rename(temp_path, file_path)

                except Exception as e:
                    try:
                        if os.path.exists(temp_path):
                            os.unlink(temp_path)
                    except Exception:
                        pass
                    raise e

            if file_lock:
                with file_lock:
                    _perform_save()
            else:
                _perform_save()

        except Exception as e:
            logger.error(f"Error saving {file_path}: {e}")
            logger.error("Data may not have been persisted!")
            raise

    def _load_patterns(self) -> Dict[str, VulnerabilityPattern]:
        """load patterns from JSON"""
        if not self.patterns_file.exists():
            return {}

        try:
            with open(self.patterns_file, 'r', encoding="utf-8") as f:
                data = json.load(f)

            patterns = {}
            for pid, pdata in data.items():
                pattern = VulnerabilityPattern(
                    id=pdata["id"],
                    name=pdata["name"],
                    vuln_type=pdata["vuln_type"],
                    description=pdata["description"],
                    preconditions=pdata["preconditions"],
                    attack_steps=pdata["attack_steps"],
                    indicators=pdata["indicators"],
                    successful_exploits=pdata.get("successful_exploits", 0),
                    failed_attempts=pdata.get("failed_attempts", 0),
                    confidence=pdata.get("confidence", 0.5),
                    status=PatternStatus(pdata.get("status", "unvalidated")),
                    contracts_vulnerable=pdata.get("contracts_vulnerable", []),
                    discovered_by=pdata.get("discovered_by"),
                    source_contract=pdata.get("source_contract"),
                    synthesized=pdata.get("synthesized", False),
                    source_patterns=pdata.get("source_patterns", []),
                )
                patterns[pid] = pattern

            return patterns
        except Exception as e:
            logger.error(f"Error loading patterns: {e}")
            return {}

    def _save_patterns(self):
        """save patterns to JSON"""
        data = {pid: p.to_dict() for pid, p in self.patterns.items()}
        self._save_json(self.patterns_file, data)

    def _load_attempts(self) -> List[AttackAttempt]:
        """load attempts from JSON"""
        if not self.attempts_file.exists():
            return []

        try:
            with open(self.attempts_file, 'r', encoding="utf-8") as f:
                data = json.load(f)

            attempts = []
            for adata in data:
                attempt = AttackAttempt(
                    id=adata["id"],
                    contract_name=adata["contract_name"],
                    attacker_name=adata["attacker_name"],
                    pattern_id=adata.get("pattern_id"),
                    hypothesis=adata["hypothesis"],
                    success=adata["success"],
                    evidence=adata.get("evidence")
                )
                attempts.append(attempt)

            return attempts
        except Exception as e:
            logger.error(f"Error loading attempts: {e}")
            return []

    def _save_attempts(self):
        """save attempts to JSON"""
        data = [a.to_dict() for a in self.attempts]
        self._save_json(self.attempts_file, data)

    def _load_anti_patterns(self) -> Dict[str, AntiPattern]:
        """load anti-patterns from JSON"""
        if not self.anti_patterns_file.exists():
            return {}

        try:
            with open(self.anti_patterns_file, 'r', encoding="utf-8") as f:
                data = json.load(f)

            anti_patterns = {}
            for apid, apdata in data.items():
                anti_pattern = AntiPattern(
                    id=apdata["id"],
                    name=apdata["name"],
                    description=apdata["description"],
                    trigger_indicators=apdata.get("trigger_indicators", []),
                    context_conditions=apdata.get("context_conditions", []),
                    false_positive_count=apdata.get("false_positive_count", 0),
                    true_positive_override=apdata.get("true_positive_override", 0),
                    suppression_confidence=apdata.get("suppression_confidence", 0.5),
                    source_hypothesis_type=apdata.get("source_hypothesis_type", ""),
                    source_attacker=apdata.get("source_attacker", ""),
                    example_contracts=apdata.get("example_contracts", [])
                )
                anti_patterns[apid] = anti_pattern

            logger.debug(f"Loaded {len(anti_patterns)} anti-patterns")
            return anti_patterns
        except Exception as e:
            logger.error(f"Error loading anti-patterns: {e}")
            return {}

    def _save_anti_patterns(self):
        """save anti-patterns to JSON"""
        data = {apid: ap.to_dict() for apid, ap in self.anti_patterns.items()}
        self._save_json(self.anti_patterns_file, data)

    def _load_specialist_accuracy(self) -> Dict[str, SpecialistAccuracy]:
        """load specialist accuracy records from JSON"""
        if not self.specialist_accuracy_file.exists():
            return {}

        try:
            with open(self.specialist_accuracy_file, 'r', encoding="utf-8") as f:
                data = json.load(f)

            accuracy_records = {}
            for key, sadata in data.items():
                accuracy = SpecialistAccuracy(
                    specialist_name=sadata["specialist_name"],
                    vuln_type=sadata["vuln_type"],
                    true_positives=sadata.get("true_positives", 0),
                    false_positives=sadata.get("false_positives", 0),
                    total_hypotheses=sadata.get("total_hypotheses", 0),
                    precision=sadata.get("precision", 0.5),
                    recall_proxy=sadata.get("recall_proxy", 0.5)
                )
                accuracy_records[key] = accuracy

            logger.debug(f"Loaded {len(accuracy_records)} specialist accuracy records")
            return accuracy_records
        except Exception as e:
            logger.error(f"Error loading specialist accuracy: {e}")
            return {}

    def _save_specialist_accuracy(self):
        """save specialist accuracy records to JSON"""
        data = {key: sa.to_dict() for key, sa in self.specialist_accuracy.items()}
        self._save_json(self.specialist_accuracy_file, data)

    def flush(self):
        """flush all pending writes to disk"""
        if self.disable_storage:
            with self._lock:
                self._dirty_contracts = False
                self._dirty_patterns = False
                self._dirty_attempts = False
                self._dirty_anti_patterns = False
                self._dirty_specialist_accuracy = False
            return

        with self._lock:
            needs_flush = []

            if self._dirty_contracts:
                contracts_snapshot = dict(self.contract_knowledge)
                needs_flush.append(('contracts', contracts_snapshot))
                self._dirty_contracts = False

            if self._dirty_patterns:
                patterns_snapshot = {pid: p for pid, p in self.patterns.items()}
                needs_flush.append(('patterns', patterns_snapshot))
                self._dirty_patterns = False

            if self._dirty_attempts:
                attempts_snapshot = list(self.attempts)
                needs_flush.append(('attempts', attempts_snapshot))
                self._dirty_attempts = False

            if self._dirty_anti_patterns:
                anti_patterns_snapshot = {apid: ap for apid, ap in self.anti_patterns.items()}
                needs_flush.append(('anti_patterns', anti_patterns_snapshot))
                self._dirty_anti_patterns = False

            if self._dirty_specialist_accuracy:
                specialist_snapshot = {key: sa for key, sa in self.specialist_accuracy.items()}
                needs_flush.append(('specialist_accuracy', specialist_snapshot))
                self._dirty_specialist_accuracy = False

        writes_performed = 0
        failures = []

        for data_type, snapshot in needs_flush:
            try:
                if data_type == 'contracts':
                    self._save_json(self.contracts_file, snapshot)
                elif data_type == 'patterns':
                    data = {pid: p.to_dict() for pid, p in snapshot.items()}
                    self._save_json(self.patterns_file, data)
                elif data_type == 'attempts':
                    data = [a.to_dict() for a in snapshot]
                    self._save_json(self.attempts_file, data)
                elif data_type == 'anti_patterns':
                    data = {apid: ap.to_dict() for apid, ap in snapshot.items()}
                    self._save_json(self.anti_patterns_file, data)
                elif data_type == 'specialist_accuracy':
                    data = {key: sa.to_dict() for key, sa in snapshot.items()}
                    self._save_json(self.specialist_accuracy_file, data)

                writes_performed += 1
            except Exception as e:
                logger.error(f"ERROR flushing {data_type}: {e}")
                failures.append((data_type, e))

        if writes_performed > 0:
            logger.debug(f"Flushed {writes_performed} file(s) to disk")

        if failures:
            failure_summary = ", ".join([f"{dt}: {str(e)}" for dt, e in failures])
            raise RuntimeError(f"KB flush failed for {len(failures)} files: {failure_summary}")

    def save(self):
        """save all KB data to disk (DEPRECATED - use flush() instead)"""
        if self.disable_storage:
            self._dirty_contracts = False
            self._dirty_patterns = False
            self._dirty_attempts = False
            self._dirty_anti_patterns = False
            self._dirty_specialist_accuracy = False
            return

        self._save_patterns()
        self._save_json(self.contracts_file, self.contract_knowledge)
        self._save_attempts()
        self._save_anti_patterns()
        self._save_specialist_accuracy()

        self._dirty_contracts = False
        self._dirty_patterns = False
        self._dirty_attempts = False
        self._dirty_anti_patterns = False
        self._dirty_specialist_accuracy = False

    def find_pattern_for_hypothesis(self, hypothesis: Any) -> Optional[VulnerabilityPattern]:
        """find best matching pattern for a hypothesis"""
        attack_type = hypothesis.attack_type if hasattr(hypothesis, 'attack_type') else None
        if not attack_type:
            return None

        candidates = [p for p in self.patterns.values() if attack_type in p.vuln_type]

        if not candidates:
            return None

        return max(candidates, key=lambda p: p.confidence)

    def synthesize_pattern_from_hypothesis(self, hypothesis: Any, success: bool) -> Optional[VulnerabilityPattern]:
        """synthesize new vulnerability pattern from successful hypothesis"""
        if not success:
            return None

        import hashlib

        pattern_id = f"synth_{hashlib.md5(hypothesis.description.encode()).hexdigest()[:8]}"

        pattern = VulnerabilityPattern(
            id=pattern_id,
            name=f"Synthesized: {hypothesis.description[:60]}",
            vuln_type=hypothesis.attack_type if hasattr(hypothesis, 'attack_type') else "unknown",
            description=hypothesis.description if hasattr(hypothesis, 'description') else "Synthesized from successful attack",
            preconditions=hypothesis.preconditions if hasattr(hypothesis, 'preconditions') else [],
            attack_steps=hypothesis.attack_steps if hasattr(hypothesis, 'attack_steps') else [],
            indicators=[],
            successful_exploits=1,
            failed_attempts=0,
            confidence=0.75,
            status=PatternStatus.VALIDATED,
            discovered_by="system_synthesis",
            source_contract=hypothesis.contract_name if hasattr(hypothesis, 'contract_name') else None
        )

        return pattern

    def get_stats(self) -> Dict:
        """get KB statistics"""
        return self.stats.get_stats()

    def print_stats(self):
        """print KB statistics"""
        self.stats.print_stats()

    def get_effectiveness_metrics(self) -> Dict[str, Any]:
        """get metrics tracking kb effectiveness over time"""
        return self.stats.get_effectiveness_metrics()

    def print_effectiveness_metrics(self):
        """print kb effectiveness metrics"""
        self.stats.print_effectiveness_metrics()

    def get_improvement_recommendations(self) -> List[str]:
        """analyze KB metrics and provide recommendations for improvement"""
        return self.stats.get_improvement_recommendations()

    def _initialize_graph_rag(self):
        """initialize GraphRAG and SelfRAG systems"""
        try:
            from src.kb.graph_rag import GraphRAG
            from src.kb.self_rag import SelfRAG

            logger.info("Initializing GraphRAG...")
            fingerprint = self._graph_fingerprint()
            cache_loaded = False

            if len(self.patterns) >= 3:
                cache_loaded = self._try_load_graph_cache(GraphRAG, fingerprint)
            else:
                logger.info("Not enough patterns to build graph (need ≥3)")

            if not cache_loaded:
                self.graph_rag = GraphRAG(knowledge_base=self)
                if len(self.patterns) >= 3:
                    self.graph_rag.build_graph(similarity_threshold=0.3)
                    self.graph_rag.leiden_cluster(resolution=1.0)
                    stats = self.graph_rag.get_stats()
                    logger.info(f"GraphRAG initialized: {stats.num_nodes} nodes, {stats.num_edges} edges, {stats.num_communities} communities")
                    self._persist_graph_cache(fingerprint)

            self.self_rag = SelfRAG(graph_rag=self.graph_rag)
            logger.info("SelfRAG initialized")

        except Exception as e:
            logger.warning(f"GraphRAG initialization failed: {e}")
            self.graph_rag = None
            self.self_rag = None

    def _initialize_synthesis(self):
        """initialize Pattern Synthesizer"""
        try:
            from src.kb.pattern_synthesizer import PatternSynthesizer

            logger.info("Initializing Pattern Synthesizer...")
            backend_choice = "grok"

            self.pattern_synthesizer = PatternSynthesizer(
                llm_backend=backend_choice,
                llm_model=self.pattern_model,
                thinking_budget=4000,
                dedup_threshold=0.85
            )
            logger.info("Pattern Synthesizer ready")

        except Exception as e:
            logger.warning(f"Pattern Synthesizer initialization failed: {e}")
            self.pattern_synthesizer = None

    def _graph_fingerprint(self) -> str:
        """compute a fingerprint for the current pattern set"""
        items = []
        for pattern_id, pattern in self.patterns.items():
            desc_hash = hashlib.sha1(pattern.description.encode()).hexdigest()
            preconds = "|".join(sorted(pattern.preconditions))
            steps = "|".join(sorted(pattern.attack_steps))
            items.append(f"{pattern_id}|{pattern.name}|{pattern.vuln_type}|{desc_hash}|{preconds}|{steps}|{pattern.synthesized}")
        items.sort()
        raw = "|".join(items) + f"|{self.GRAPH_CACHE_VERSION}"
        return hashlib.sha1(raw.encode()).hexdigest()

    def _try_load_graph_cache(self, graph_cls, fingerprint: str) -> bool:
        """attempt to load GraphRAG from cache"""
        if not self.graph_manifest_file.exists() or not self.graph_payload_file.exists():
            return False
        try:
            manifest = json.loads(self.graph_manifest_file.read_text())
        except json.JSONDecodeError:
            logger.info("GraphRAG cache manifest unreadable; rebuilding")
            return False

        if manifest.get("fingerprint") != fingerprint:
            logger.info("GraphRAG cache fingerprint mismatch; rebuilding")
            return False

        try:
            self.graph_rag = graph_cls.load_from_disk(self, self.graph_payload_file)
            stats = self.graph_rag.get_stats()
            logger.info(f"GraphRAG cache hit: {stats.num_nodes} nodes, {stats.num_edges} edges, {stats.num_communities} communities")
            return True
        except Exception as exc:
            logger.warning(f"Failed to load GraphRAG cache: {exc}")
            return False

    def _persist_graph_cache(self, fingerprint: str) -> None:
        """persist the current GraphRAG state and manifest"""
        if not self.graph_rag or not self.graph_rag.built:
            return
        try:
            self.graph_rag.save_to_disk(self.graph_payload_file)
            manifest = {
                "fingerprint": fingerprint,
                "updated_at": datetime.now(UTC).isoformat(),
                "version": self.GRAPH_CACHE_VERSION,
            }
            self.graph_manifest_file.write_text(json.dumps(manifest, indent=2))
            logger.debug("GraphRAG cache updated")
        except Exception as exc:
            logger.warning(f"Failed to persist GraphRAG cache: {exc}")

    def synthesize_patterns(self, target_level: int = 1, max_combinations: Optional[int] = None) -> int:
        """synthesize new patterns from existing base patterns"""
        if not self.enable_synthesis or not self.pattern_synthesizer:
            logger.info("Pattern synthesis not enabled")
            return 0

        base_patterns = list(self.patterns.values())
        if len(base_patterns) < 2:
            logger.info("Need at least 2 patterns to synthesize")
            return 0

        logger.info(f"\n{'='*60}")
        logger.info("STARTING PATTERN SYNTHESIS")
        logger.info(f"Base patterns: {len(base_patterns)}")
        logger.info(f"Target level: {target_level}")
        logger.info(f"{'='*60}\n")

        synthesized = self.pattern_synthesizer.batch_synthesize(patterns=base_patterns, target_level=target_level, max_patterns=max_combinations)

        added = 0
        for pattern in synthesized:
            if not any(p.name == pattern.name for p in self.patterns.values()):
                self.add_pattern(pattern)
                added += 1

        logger.info(f"\nSynthesis complete: {added} new patterns added")

        if self.enable_graph_rag and added > 0:
            self._rebuild_graph()

        return added

    def _rebuild_graph(self):
        """rebuild GraphRAG graph from current patterns"""
        if not self.enable_graph_rag or not self.graph_rag:
            logger.info("GraphRAG not enabled")
            return

        logger.info(f"Rebuilding graph with {len(self.patterns)} patterns...")
        self.graph_rag.build_graph(similarity_threshold=0.3)
        self.graph_rag.leiden_cluster(resolution=1.0)

        stats = self.graph_rag.get_stats()
        logger.info(f"Graph rebuilt: {stats.num_nodes} nodes, {stats.num_edges} edges")
        fingerprint = self._graph_fingerprint()
        self._persist_graph_cache(fingerprint)
