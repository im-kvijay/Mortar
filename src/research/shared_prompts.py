"""shared prompt components for research specialists."""

TOOL_USAGE_GUIDE = """
functional tools (analyze):
- trace_state_variable(var): track variable mutations
- analyze_function_symbolically(func): deep function analysis
- check_invariant(inv, evidence): verify invariant holds
- run_static_analysis(focus): security checks
- reflect_on_finding(finding, confidence): self-critique
- compare_with_pattern(pattern): match known vulns

recording tools (save results):
- record_discovery(type, content, confidence, evidence): save finding
- update_knowledge_graph(action, ...): add nodes/edges
- analysis_complete(): signal done

workflow:
1. query_knowledge_base() - check historical patterns first
2. analyze systematically: trace vars -> analyze funcs -> check invariants
3. record immediately when you find something (don't batch)
4. build graph relationships as you discover them
5. call analysis_complete() when exhausted all paths

recording rules:
- record each finding immediately, not at the end
- even low-confidence findings (0.3+) should be recorded
- graph edges capture relationships (func x modifies var y)

stopping criteria (all must be true):
- traced all critical state variables
- analyzed all public/external functions
- checked all invariants
- explored multi-step attack paths
- recorded findings (or confirmed none exist)
"""

ANALYSIS_STANDARDS = """
your job: find all vulnerabilities, not just obvious ones.
- exhaust every analysis path before stopping
- for each finding, ask "what else could break here?"
- cover every function, variable, and execution path
- don't stop at first finding - keep going

avoid:
- calling same tool repeatedly on same target
- using tools without recording discoveries
- stopping early (< 10 tool calls usually means incomplete)
"""

SPECIALIST_ENHANCEMENT = TOOL_USAGE_GUIDE + "\n" + ANALYSIS_STANDARDS
