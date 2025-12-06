# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .automanifest import synthesize_manifest
from .llm_fallback import render_with_fallback
from .poc_executor import compile_and_run
from .poc_generator import render_manifest_test, generate_llm_fallback
from .providers import CheapTemplateProvider, XAIProvider
from .target_ingest import load_target

ENGINE_VERSION = "immunefi/1.0.0"


def _default_accept(code: str) -> bool:
    stripped = code.lstrip()
    return stripped.startswith("// SPDX-") and "pragma solidity" in stripped


def run_immunefi(
    chain: str,
    address: str,
    *,
    fork_block: int,
    repo_root: str,
    use_llm_fallback: bool = True,
) -> Dict[str, Any]:
    target = load_target(chain, address)
    manifest = synthesize_manifest(target)
    manifest["fork_block"] = fork_block
    manifest["chain"] = chain

    deterministic_code = render_manifest_test(manifest)

    def _llm() -> Optional[str]:
        if not use_llm_fallback:
            return None

        try:
            return generate_llm_fallback(manifest)
        except Exception:
            xai_provider = XAIProvider()
            template_provider = CheapTemplateProvider(render_manifest_test)

            providers = []
            if xai_provider.is_available():
                providers.append((xai_provider, "grok-4.1-fast"))
            providers.append((template_provider, "rules-only"))

            return render_with_fallback(
                payload=manifest,
                engine_version=ENGINE_VERSION,
                model_chain=providers,
                render_prompt=lambda payload: "Return Solidity only.\n---MANIFEST_JSON---\n"
                + json.dumps(payload, sort_keys=True),
                accept=_default_accept,
            )

    fallback_callable = _llm if use_llm_fallback else None
    ok, report = compile_and_run(
        repo_root=repo_root,
        solidity_test=deterministic_code,
        test_filename=f"Immunefi_{address}.t.sol",
        match_contract=None,
        llm_fallback=fallback_callable,
    )

    return {
        "ok": ok,
        "report": report,
        "manifest": manifest,
        "target": target,
    }
