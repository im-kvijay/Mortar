""" """
import threading
import tempfile
import shutil
from pathlib import Path
import pytest

from src.kb.knowledge_base import (
    KnowledgeBase,
    VulnerabilityPattern,
    AttackAttempt,
    SpecialistAccuracy,
    PatternStatus
)

@pytest.fixture
def temp_kb_dir():

    temp_dir = Path(tempfile.mkdtemp(prefix="kb_test_"))
    yield temp_dir
    # cleanup
    if temp_dir.exists():
        shutil.rmtree(temp_dir)

def test_concurrent_pattern_updates(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir)

    # add a pattern
    pattern = VulnerabilityPattern(
        id="test_pattern",
        name="Test Pattern",
        vuln_type="reentrancy",
        description="Test concurrent updates",
        preconditions=["Contract has reentrancy"],
        attack_steps=["Call vulnerable function"],
        indicators=["Missing guard"]
    )
    kb.add_pattern(pattern)

    # track results
    results = {"success_count": 0, "failure_count": 0}
    results_lock = threading.Lock()

    def update_worker(worker_id: int, success: bool, iterations: int):
        """Worker that updates pattern repeatedly"""
        for i in range(iterations):
            kb.update_pattern("test_pattern", success, f"Contract{worker_id}_{i}")

            # track what we did
            with results_lock:
                if success:
                    results["success_count"] += 1
                else:
                    results["failure_count"] += 1

    # create 10 workers, half doing successes, half doing failures
    threads = []
    iterations_per_worker = 50

    for i in range(10):
        success = i % 2 == 0
        t = threading.Thread(
            target=update_worker,
            args=(i, success, iterations_per_worker)
        )
        threads.append(t)

    # start all threads
    for t in threads:
        t.start()

    # wait for completion
    for t in threads:
        t.join()
    final_pattern = kb.get_pattern("test_pattern")
    expected_total = 10 * iterations_per_worker
    actual_total = final_pattern.successful_exploits + final_pattern.failed_attempts
    assert actual_total == expected_total, (
        f"Lost updates detected! Expected {expected_total}, got {actual_total}"
    )
    assert final_pattern.successful_exploits == results["success_count"]
    assert final_pattern.failed_attempts == results["failure_count"]

    # flush and verify persistence
    kb.flush()

    # reload and verify data persisted correctly
    kb2 = KnowledgeBase(data_dir=temp_kb_dir)
    reloaded = kb2.get_pattern("test_pattern")

    assert reloaded is not None
    assert reloaded.successful_exploits == final_pattern.successful_exploits
    assert reloaded.failed_attempts == final_pattern.failed_attempts
    assert reloaded.confidence == final_pattern.confidence

def test_concurrent_attempts_recording(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir)

    def record_worker(worker_id: int, num_attempts: int):
        """Worker that records attack attempts"""
        for i in range(num_attempts):
            attempt = AttackAttempt(
                id=f"attempt_{worker_id}_{i}",
                contract_name=f"Contract{worker_id}",
                attacker_name="TestAttacker",
                pattern_id=None,
                hypothesis=f"Hypothesis {worker_id}-{i}",
                success=(i % 3 == 0)  # every 3rd attempt succeeds
            )
            kb.record_attempt(attempt)

    # create 8 workers
    threads = []
    attempts_per_worker = 100
    num_workers = 8

    for i in range(num_workers):
        t = threading.Thread(
            target=record_worker,
            args=(i, attempts_per_worker)
        )
        threads.append(t)

    # start all threads
    for t in threads:
        t.start()

    # wait for completion
    for t in threads:
        t.join()
    expected_total = num_workers * attempts_per_worker
    actual_total = len(kb.attempts)

    assert actual_total == expected_total, (
        f"Lost attempts! Expected {expected_total}, got {actual_total}"
    )

    # flush and verify persistence
    kb.flush()

    # reload and verify
    kb2 = KnowledgeBase(data_dir=temp_kb_dir)
    assert len(kb2.attempts) == expected_total

def test_concurrent_specialist_accuracy_updates(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir)

    def update_specialist_worker(worker_id: int, specialist_name: str, vuln_type: str):
        """Worker that updates specialist accuracy"""
        for i in range(50):
            # alternate between valid and invalid
            is_valid = (worker_id + i) % 2 == 0
            kb.record_specialist_outcome(specialist_name, vuln_type, is_valid)
    threads = []
    for i in range(4):
        t = threading.Thread(
            target=update_specialist_worker,
            args=(i, "TestSpecialist", "reentrancy")
        )
        threads.append(t)

    # start all threads
    for t in threads:
        t.start()

    # wait for completion
    for t in threads:
        t.join()
    accuracy_key = "TestSpecialist:reentrancy"
    accuracy = kb.specialist_accuracy.get(accuracy_key)

    assert accuracy is not None
    assert accuracy.total_hypotheses == 4 * 50  # all updates recorded
    assert accuracy.true_positives + accuracy.false_positives == 4 * 50

    # flush and verify persistence
    kb.flush()

    # reload and verify
    kb2 = KnowledgeBase(data_dir=temp_kb_dir)
    reloaded = kb2.specialist_accuracy.get(accuracy_key)
    assert reloaded.total_hypotheses == 4 * 50

def test_concurrent_read_write_mix(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir)

    # add initial patterns
    for i in range(10):
        pattern = VulnerabilityPattern(
            id=f"pattern_{i}",
            name=f"Pattern {i}",
            vuln_type="reentrancy",
            description=f"Pattern {i}",
            preconditions=[],
            attack_steps=[],
            indicators=[]
        )
        kb.add_pattern(pattern)

    errors = []
    errors_lock = threading.Lock()

    def writer_worker():
        for i in range(50):
            # update existing pattern
            pattern_id = f"pattern_{i % 10}"
            kb.update_pattern(pattern_id, success=True)

    def reader_worker():
        for i in range(100):
            pattern_id = f"pattern_{i % 10}"
            pattern = kb.get_pattern(pattern_id)
            if pattern is None:
                with errors_lock:
                    errors.append(f"Pattern {pattern_id} not found!")
            elif pattern.successful_exploits < 0 or pattern.failed_attempts < 0:
                with errors_lock:
                    errors.append(f"Pattern {pattern_id} has negative counts!")

    # create mixed workload
    threads = []

    # 4 writers
    for _ in range(4):
        threads.append(threading.Thread(target=writer_worker))

    # 8 readers
    for _ in range(8):
        threads.append(threading.Thread(target=reader_worker))

    # start all threads
    for t in threads:
        t.start()

    # wait for completion
    for t in threads:
        t.join()
    assert len(errors) == 0, f"Found {len(errors)} consistency errors: {errors}"

def test_flush_during_updates(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir)

    # add initial pattern
    pattern = VulnerabilityPattern(
        id="test_pattern",
        name="Test Pattern",
        vuln_type="reentrancy",
        description="Test",
        preconditions=[],
        attack_steps=[],
        indicators=[]
    )
    kb.add_pattern(pattern)

    flush_complete = threading.Event()

    def updater_worker():
        for i in range(200):
            kb.update_pattern("test_pattern", success=(i % 2 == 0))

            # wait a bit after flush starts to create race condition
            if i == 100:
                flush_complete.wait(timeout=0.5)

    def flusher_worker():
        import time
        time.sleep(0.1)  # let some updates happen first
        kb.flush()
        flush_complete.set()

    # run both workers
    updater = threading.Thread(target=updater_worker)
    flusher = threading.Thread(target=flusher_worker)

    updater.start()
    flusher.start()

    updater.join()
    flusher.join()
    final_pattern = kb.get_pattern("test_pattern")
    assert final_pattern.successful_exploits >= 0
    assert final_pattern.failed_attempts >= 0
    assert final_pattern.successful_exploits + final_pattern.failed_attempts == 200

    # final flush
    kb.flush()

    # reload and verify
    kb2 = KnowledgeBase(data_dir=temp_kb_dir)
    reloaded = kb2.get_pattern("test_pattern")
    assert reloaded.successful_exploits == final_pattern.successful_exploits

def test_atomic_file_write(temp_kb_dir):
    kb = KnowledgeBase(data_dir=temp_kb_dir)

    # add some patterns
    for i in range(10):
        pattern = VulnerabilityPattern(
            id=f"pattern_{i}",
            name=f"Pattern {i}",
            vuln_type="reentrancy",
            description=f"Pattern {i}",
            preconditions=[],
            attack_steps=[],
            indicators=[]
        )
        kb.add_pattern(pattern)

    # flush to disk
    kb.flush()
    temp_files = list(temp_kb_dir.glob("*.tmp"))
    assert len(temp_files) == 0, f"Temp files not cleaned up: {temp_files}"
    backup_files = list(temp_kb_dir.glob("*.bak"))
    # (May or may not exist on first write)
    kb2 = KnowledgeBase(data_dir=temp_kb_dir)
    assert len(kb2.patterns) == 10

if __name__ == "__main__":
    # run tests
    pytest.main([__file__, "-v"])
