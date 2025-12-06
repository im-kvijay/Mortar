"""common utilities for research layer"""

import re
from typing import List, Dict, Any


def extract_discoveries_standard(response: str, round_num: int) -> List[Dict[str, Any]]:
    """
    Standard discovery extraction (works for all specialists)

    Format:
        DISCOVERY: [type]
        Content: [description]
        Confidence: [0.0-1.0]
        Evidence: [references]
        ---
    """
    discoveries = []

    for block in response.split("DISCOVERY:")[1:]:
        lines = block.strip().split("\n")
        if len(lines) < 3:
            continue

        discovery = {
            "round_num": round_num,
            "discovery_type": lines[0].strip(),
            "content": "",
            "confidence": 0.8,
            "evidence": []
        }

        for line in lines[1:]:
            if line.startswith("Content:"):
                discovery["content"] = line.replace("Content:", "").strip()
            elif line.startswith("Confidence:"):
                try:
                    discovery["confidence"] = float(line.replace("Confidence:", "").strip())
                except ValueError:
                    # Invalid confidence value - keep default 0.0
                    pass
            elif line.startswith("Evidence:"):
                discovery["evidence"].append(line.replace("Evidence:", "").strip())
            elif line.startswith("---"):
                break

        if discovery["content"]:
            discoveries.append(discovery)

    return discoveries


def extract_decision_standard(response: str) -> tuple[str, str, float]:
    """
    Standard decision extraction

    Returns: (decision, reasoning, confidence)
    """
    decision_match = re.search(r"DECISION:\s*(continue|stop)", response, re.IGNORECASE)
    reasoning_match = re.search(r"REASONING:\s*([^\n]+)", response, re.IGNORECASE)
    # Match CONFIDENCE: (capital letters) to avoid matching "Confidence:" from discoveries
    confidence_match = re.search(r"CONFIDENCE:\s*([\d.]+)", response)

    decision = decision_match.group(1).lower() if decision_match else "continue"
    reasoning = reasoning_match.group(1) if reasoning_match else "No reasoning provided"
    confidence = float(confidence_match.group(1)) if confidence_match else 0.7

    return decision, reasoning, confidence


def should_continue_standard(
    round_num: int,
    response: str,
    discoveries,  # Can be List[Dict] or List[Discovery] or just int
    max_rounds: int
) -> tuple[bool, str, float]:
    """
    TRUE AGENTIC continuation logic - agent decides when to stop

    max_rounds is now a SAFETY LIMIT only (prevents runaway costs)
    Primary decision comes from the agent's Extended Thinking

    Returns: (should_continue, reasoning, confidence)
    """
    decision, reasoning, confidence = extract_decision_standard(response)

    # Handle different types of discoveries parameter
    if isinstance(discoveries, int):
        num_discoveries = discoveries
    elif isinstance(discoveries, list):
        num_discoveries = len(discoveries)
    else:
        num_discoveries = 0

    # PRIMARY: Agent explicitly decides to stop
    if decision == "stop":
        return False, f"Agent decided to stop: {reasoning}", confidence

    # SAFETY LIMIT: Prevent runaway costs (but agent can stop earlier)
    if max_rounds and round_num >= max_rounds:
        return False, f"Safety limit reached ({max_rounds} rounds)", confidence

    # NATURAL STOPPING: No progress for multiple rounds
    if round_num > 5 and num_discoveries == 0:
        return False, "No new discoveries after 5 rounds - analysis exhausted", confidence

    # CONTINUE: Agent wants to continue (default for "continue" decision)
    if decision == "continue":
        discovery_msg = f" ({num_discoveries} discoveries)" if num_discoveries > 0 else ""
        return True, f"Agent continuing analysis{discovery_msg}: {reasoning}", confidence

    # FALLBACK: If agent unclear, continue if still making discoveries
    if num_discoveries > 0:
        return True, f"Found {num_discoveries} discoveries, continuing", confidence

    # FALLBACK: Early rounds, keep going
    if round_num < 3:
        return True, "Early analysis phase, continuing", confidence

    # DEFAULT: Stop if no clear reason to continue
    return False, "Analysis complete - no new information", confidence


def extract_graph_nodes(response: str, round_num: int, patterns: Dict[str, tuple]) -> List[Dict]:
    """
    Extract graph nodes using patterns

    Args:
        patterns: {node_type: (regex_pattern, node_type_enum)}
    """
    updates = []

    for name, (pattern, node_type) in patterns.items():
        for match in re.finditer(pattern, response, re.IGNORECASE):
            item = match.group(1).strip()[:100]
            updates.append({
                "type": "node",
                "node_id": f"{name}_{hash(item) % 100000}",
                "node_type": node_type,
                "name": item,
                "data": {"discovered_in_round": round_num}
            })

    return updates
