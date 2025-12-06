# SPDX-License-Identifier: MIT
"""hypothesis selector with kb-aware scoring and exploration reserve"""

from __future__ import annotations

import random
from typing import Dict, List, Optional

from config import config
from kb.kb_store import KBStore
from kb.feature_utils import hypothesis_feature_keys


def _score_hypothesis(kb: KBStore, hypothesis, contract_info, use_priors: bool) -> float:
    features = hypothesis_feature_keys(hypothesis, contract_info)
    attack_key = getattr(hypothesis, "attack_type", "unknown")
    priors = kb.priors_for(attack_key) if use_priors else {}
    base = sum(priors.get(f, 0.5) for f in features) if use_priors else len(features) * 0.5
    novelty = 1.0 - max(0.0, min(1.0, getattr(hypothesis, "confidence", 0.5)))
    return base + 0.2 * novelty


def select_hypotheses(
    hypotheses: List,
    contract_info: Optional[Dict[str, any]],
    kb_mode: str,
    budget: int,
    exploration_fraction: float,
) -> List:
    if budget <= 0 or len(hypotheses) <= budget:
        return hypotheses

    kb = KBStore(config.KB_DIR)
    use_priors = kb_mode in ("rerank", "enrich")
    scored = [
        (max(0.0, _score_hypothesis(kb, hyp, contract_info, use_priors)), hyp)
        for hyp in hypotheses
    ]
    scored.sort(key=lambda item: item[0], reverse=True)

    exploration_fraction = max(0.0, min(0.5, exploration_fraction))
    reserve = max(1, int(budget * exploration_fraction)) if len(scored) > 1 else 0

    selected: List = []
    if reserve:
        bottom = [h for _, h in scored[len(scored) // 2 :]] or [h for _, h in scored]
        random.shuffle(bottom)
        selected.extend(bottom[:reserve])

    for _, hyp in scored:
        if len(selected) >= budget:
            break
        if hyp in selected:
            continue
        selected.append(hyp)

    return selected[:budget]
