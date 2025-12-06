"""functional analysis tools for smart contract auditing specialists"""

from typing import List, Dict, Any, Optional
import re
import subprocess
import json
from pathlib import Path
from kb.knowledge_graph import EdgeType, NodeType


class FunctionalAnalysisTools:
    """functional analysis tools for smart contract auditing"""

    def __init__(self, contract_source: str, contract_info: Dict[str, Any], knowledge_graph: Optional[Any] = None):
        """initialize functional tools"""
        self.contract_source = contract_source
        self.contract_info = contract_info
        self.knowledge_graph = knowledge_graph
        self.analysis_cache = {}

        # performance optimization: cache compiled regex patterns for o(1) reuse
        self._regex_cache: Dict[str, re.Pattern] = {}
        self._pattern_matches_cache: Dict[str, List[re.Match]] = {}

    def _get_compiled_pattern(self, pattern: str, flags: int = 0) -> re.Pattern:
        """get or compile regex pattern - o(1) lookup instead of re-compiling"""
        cache_key = f"{pattern}:{flags}"
        if cache_key not in self._regex_cache:
            self._regex_cache[cache_key] = re.compile(pattern, flags)
        return self._regex_cache[cache_key]

    def _find_all_matches(self, pattern: str, flags: int = 0) -> List[re.Match]:
        """find all matches with caching to avoid redundant searches"""
        cache_key = f"{pattern}:{flags}"
        if cache_key not in self._pattern_matches_cache:
            compiled_pattern = self._get_compiled_pattern(pattern, flags)
            self._pattern_matches_cache[cache_key] = list(compiled_pattern.finditer(self.contract_source))
        return self._pattern_matches_cache[cache_key]

    def trace_state_variable(self, var_name: str) -> Dict[str, Any]:
        """trace all mutations of a state variable"""
        mutations = []

        # find all assignments to this variable
        # pattern: var_name = ... or var_name += ... etc.
        # security: use non-greedy quantifiers and limit match length to prevent redos
        patterns = [
            rf'{re.escape(var_name)}\s*=\s*([^;]{{1,500}})',
            rf'{re.escape(var_name)}\s*\+=\s*([^;]{{1,500}})',
            rf'{re.escape(var_name)}\s*-=\s*([^;]{{1,500}})',
            rf'{re.escape(var_name)}\s*\*=\s*([^;]{{1,500}})',
            rf'{re.escape(var_name)}\s*/=\s*([^;]{{1,500}})',
            rf'{re.escape(var_name)}\s*\+\+',
            rf'{re.escape(var_name)}\s*--',
        ]

        # use cached pattern matching for performance
        for pattern in patterns:
            matches = self._find_all_matches(pattern)
            for match in matches:
                # find which function this is in
                func_match = self._find_containing_function(match.start())
                mutations.append({
                    'location': match.start(),
                    'operation': match.group(0),
                    'value': match.group(1) if match.groups() else None,
                    'function': func_match if func_match else 'unknown',
                    'line': self.contract_source[:match.start()].count('\n') + 1
                })

        # find all reads
        reads = []
        read_pattern = rf'\b{re.escape(var_name)}\b'
        # use cached pattern matching for performance
        for match in self._find_all_matches(read_pattern):
            # check if this is a read (not a declaration or write)
            before = self.contract_source[max(0, match.start()-20):match.start()]
            after = self.contract_source[match.end():min(len(self.contract_source), match.end()+20)]

            if not any(op in before + after for op in ['=', '+=', '-=', '*=', '/=']):
                func_match = self._find_containing_function(match.start())
                reads.append({
                    'location': match.start(),
                    'function': func_match if func_match else 'unknown',
                    'line': self.contract_source[:match.start()].count('\n') + 1
                })

        result = {
            'variable': var_name,
            'total_mutations': len(mutations),
            'total_reads': len(reads),
            'mutations': mutations[:10],  # first 10
            'reads': reads[:10],
            'mutating_functions': list(set(m['function'] for m in mutations)),
            'reading_functions': list(set(r['function'] for r in reads))
        }

        # enrich knowledge graph with basic edges if provided
        if self.knowledge_graph:
            for m in mutations:
                fn = m.get('function') or 'unknown'
                fn_node = f"fn::{fn}"
                var_node = f"state::{var_name}"
                if not self.knowledge_graph.get_node(fn_node):
                    self.knowledge_graph.add_node(
                        node_id=fn_node,
                        node_type=NodeType.FUNCTION,
                        name=fn,
                        data={},
                        discovered_by="functional_tools",
                        metadata={"component": "dependency"},
                    )
                if not self.knowledge_graph.get_node(var_node):
                    self.knowledge_graph.add_node(
                        node_id=var_node,
                        node_type=NodeType.STATE_VAR,
                        name=var_name,
                        data={},
                        discovered_by="functional_tools",
                        metadata={"component": "dependency"},
                    )
                self.knowledge_graph.add_edge(
                    source=fn_node,
                    target=var_node,
                    edge_type=EdgeType.MODIFIES,
                    data={"source": "trace_state_variable"},
                    discovered_by="functional_tools",
                    metadata={"component": "dependency"},
                )

        return result

    def analyze_function_symbolically(self, function_name: str) -> Dict[str, Any]:
        """perform basic symbolic execution on a function"""
        # extract function code
        # security: use re.escape for user input to prevent redos
        safe_name = re.escape(function_name)
        # find function header first using cached pattern
        func_header_pattern = rf'function\s+{safe_name}\s*\([^)]*?\)\s*(?:external|public|internal|private)?\s*(?:view|pure|payable)?\s*(?:returns\s*\([^)]*?\))?\s*\{{'
        compiled_pattern = self._get_compiled_pattern(func_header_pattern, re.DOTALL)
        match = compiled_pattern.search(self.contract_source)

        if not match:
            return {'error': f'Function {function_name} not found'}

        # extract function body by counting braces (safer than greedy regex)
        start_pos = match.start()
        brace_start = match.end() - 1  # position of opening brace
        brace_count = 1
        end_pos = brace_start + 1
        max_len = min(len(self.contract_source), brace_start + 50000)  # limit search
        while brace_count > 0 and end_pos < max_len:
            char = self.contract_source[end_pos]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            end_pos += 1
        func_code = self.contract_source[start_pos:end_pos]

        # extract parameters using cached pattern
        params_pattern = rf'function\s+{safe_name}\s*\(([^)]*?)\)'
        params_match = self._get_compiled_pattern(params_pattern).search(func_code)
        parameters = []
        if params_match and params_match.group(1).strip():
            param_str = params_match.group(1)
            for param in param_str.split(','):
                param = param.strip()
                if param:
                    parts = param.split()
                    if len(parts) >= 2:
                        parameters.append({
                            'type': parts[0],
                            'name': parts[-1]
                        })

        # find require statements (preconditions) using cached pattern
        requires = []
        require_pattern = r'require\s*\(([^;]{1,500})\)'
        for req_match in self._get_compiled_pattern(require_pattern).finditer(func_code):
            requires.append(req_match.group(1).strip())

        # find state mutations using cached patterns
        state_vars = self.contract_info.get('state_vars', [])
        mutations = []
        for var in state_vars:
            mutation_pattern = rf'\b{re.escape(var)}\s*[+\-*/]?='
            if self._get_compiled_pattern(mutation_pattern).search(func_code):
                mutations.append(var)

        # find external calls using cached pattern
        external_calls = []
        call_pattern = r'(\w+)\.(\w+)\s*\('
        for call_match in self._get_compiled_pattern(call_pattern).finditer(func_code):
            target_contract = call_match.group(1)
            target_function = call_match.group(2)
            external_calls.append({
                'contract': target_contract,
                'function': target_function
            })

            # cross-contract wiring: add external call edges to knowledge graph
            if self.knowledge_graph:
                source_fn_node = f"fn::{function_name}"
                target_fn_node = f"call::{target_contract}.{target_function}"

                # ensure source node exists
                if not self.knowledge_graph.get_node(source_fn_node):
                    self.knowledge_graph.add_node(
                        node_id=source_fn_node,
                        node_type=NodeType.FUNCTION,
                        name=function_name,
                        data={},
                        discovered_by="functional_tools",
                        metadata={"component": "dependency"},
                    )

                # add target call node
                if not self.knowledge_graph.get_node(target_fn_node):
                    self.knowledge_graph.add_node(
                        node_id=target_fn_node,
                        node_type=NodeType.FUNCTION,
                        name=f"{target_contract}.{target_function}",
                        data={"external": True, "target_contract": target_contract},
                        discovered_by="functional_tools",
                        metadata={"component": "dependency"},
                    )

                # add external call edge
                self.knowledge_graph.add_edge(
                    source=source_fn_node,
                    target=target_fn_node,
                    edge_type=EdgeType.CALLS,
                    data={"source": "analyze_function_symbolically", "external": True},
                    discovered_by="functional_tools",
                    metadata={"component": "dependency"},
                )

        # check for reentrancy vulnerability pattern
        reentrancy_risk = False
        if external_calls and mutations:
            # if there's an external call followed by state mutation, potential reentrancy
            for call in external_calls:
                call_pos = func_code.find(f"{call['contract']}.{call['function']}")
                for var in mutations:
                    mutation_positions = [m.start() for m in re.finditer(rf'\b{var}\s*[+\-*/]?=', func_code)]
                    if any(pos > call_pos for pos in mutation_positions):
                        reentrancy_risk = True
                        break

        # find return values using cached pattern
        returns = []
        return_pattern = r'return\s+([^;]+)'
        for ret_match in self._get_compiled_pattern(return_pattern).finditer(func_code):
            returns.append(ret_match.group(1).strip())

        return {
            'function': function_name,
            'parameters': parameters,
            'preconditions': requires,
            'state_mutations': mutations,
            'external_calls': external_calls,
            'return_values': returns,
            'reentrancy_risk': reentrancy_risk,
            'analysis': self._generate_symbolic_insights(
                function_name, parameters, requires, mutations, external_calls, reentrancy_risk
            )
        }

    def check_invariant(self, invariant_description: str, code_evidence: str) -> Dict[str, Any]:
        """check if an invariant holds"""
        # this is a heuristic checker - looks for evidence

        result = {
            'invariant': invariant_description,
            'evidence': code_evidence,
            'likely_holds': True,
            'concerns': []
        }

        # check for common invariant violations

        # 1. balance invariant: total = sum of parts
        if 'total' in invariant_description.lower() and '=' in invariant_description:
            # look for direct transfers that bypass accounting
            if 'transfer(' in self.contract_source and 'total' not in code_evidence:
                result['concerns'].append('Direct transfers may bypass total accounting')
                result['likely_holds'] = False

        # 2. monotonic invariant: always increasing/decreasing
        if any(word in invariant_description.lower() for word in ['never decrease', 'always increase', 'monotonic']):
            # look for decrements using cached pattern
            var_pattern = r'(\w+)'
            var_match = self._get_compiled_pattern(var_pattern).search(invariant_description)
            if var_match:
                var = var_match.group(1)
                if f'{var} -=' in self.contract_source or f'{var}--' in self.contract_source:
                    result['concerns'].append(f'{var} can decrease')
                    result['likely_holds'] = False

        # 3. access control: only x can do y
        if 'only' in invariant_description.lower():
            # look for require(msg.sender == ...)
            if 'require' not in code_evidence and 'onlyOwner' not in code_evidence:
                result['concerns'].append('No access control check found')
                result['likely_holds'] = False

        return result

    def run_static_analysis(self, focus: str = "all") -> Dict[str, Any]:
        """run static analysis (slither-style checks)"""
        findings = []

        # reentrancy checks
        if focus in ["reentrancy", "all"]:
            findings.extend(self._check_reentrancy())

        # integer overflow/underflow (pre-0.8.0)
        if focus in ["overflow", "all"]:
            findings.extend(self._check_overflow())

        # access control
        if focus in ["access", "all"]:
            findings.extend(self._check_access_control())

        # unchecked external calls
        if focus in ["calls", "all"]:
            findings.extend(self._check_external_calls())

        return {
            'total_findings': len(findings),
            'findings': findings,
            'focus': focus
        }

    def reflect_on_finding(self, finding: str, confidence: float) -> Dict[str, Any]:
        """self-critique mechanism - reflect on a finding"""
        reflection = {
            'original_finding': finding,
            'original_confidence': confidence,
            'reflection': [],
            'adjusted_confidence': confidence
        }

        # reflect on common false positives

        if 'reentrancy' in finding.lower():
            # check if reentrancyguard is present
            if 'ReentrancyGuard' in self.contract_source or 'nonReentrant' in self.contract_source:
                reflection['reflection'].append('Contract uses ReentrancyGuard - may be protected')
                reflection['adjusted_confidence'] = max(0.3, confidence - 0.3)

        if 'overflow' in finding.lower() or 'underflow' in finding.lower():
            # check solidity version using cached pattern
            version_pattern = r'pragma solidity\s+[\^>]?(\d+\.\d+)'
            version_match = self._get_compiled_pattern(version_pattern).search(self.contract_source)
            if version_match:
                version = float(version_match.group(1))
                if version >= 0.8:
                    reflection['reflection'].append('Solidity 0.8+ has built-in overflow protection')
                    reflection['adjusted_confidence'] = max(0.1, confidence - 0.5)

        if 'access control' in finding.lower():
            # check for openzeppelin ownable
            if 'Ownable' in self.contract_source or 'onlyOwner' in self.contract_source:
                reflection['reflection'].append('Contract uses standard access control patterns')
                reflection['adjusted_confidence'] = min(0.9, confidence + 0.1)

        # generic reflection
        if confidence > 0.9:
            reflection['reflection'].append('High confidence - but verify with PoC')
        elif confidence < 0.5:
            reflection['reflection'].append('Low confidence - may be false positive')

        return reflection

    def compare_with_pattern(self, pattern_name: str) -> Dict[str, Any]:
        """compare contract with known vulnerability pattern"""
        patterns = {
            'flash_loan_dos': {
                'description': 'DoS via flash loan invariant break',
                'indicators': ['flashLoan', 'totalAssets', 'balanceOf', 'require'],
                'vulnerability': 'Direct transfer breaks balance invariant'
            },
            'oracle_manipulation': {
                'description': 'Oracle price manipulation',
                'indicators': ['getPrice', 'UniswapV2', 'reserves', 'price'],
                'vulnerability': 'Uses manipulatable price oracle'
            },
            'reentrancy': {
                'description': 'Reentrancy attack',
                'indicators': ['.call{', 'external call', 'state change'],
                'vulnerability': 'State change after external call'
            }
        }

        if pattern_name not in patterns:
            return {'error': f'Unknown pattern: {pattern_name}'}

        pattern = patterns[pattern_name]
        matches = []

        for indicator in pattern['indicators']:
            if indicator in self.contract_source:
                # find locations using cached patterns
                escaped_pattern = re.escape(indicator)
                for match in self._find_all_matches(escaped_pattern):
                    matches.append({
                        'indicator': indicator,
                        'line': self.contract_source[:match.start()].count('\n') + 1
                    })

        match_score = len(set(m['indicator'] for m in matches)) / len(pattern['indicators'])

        return {
            'pattern': pattern_name,
            'description': pattern['description'],
            'match_score': match_score,
            'matches': matches,
            'vulnerable': match_score > 0.7,
            'vulnerability': pattern['vulnerability'] if match_score > 0.7 else None
        }

    # helper methods

    def _find_containing_function(self, position: int) -> Optional[str]:
        """find which function contains a given position"""
        before_pos = self.contract_source[:position]

        # find all function definitions before this position using cached pattern
        func_pattern = r'function\s+(\w+)\s*\('
        compiled_pattern = self._get_compiled_pattern(func_pattern)
        functions = list(compiled_pattern.finditer(before_pos))

        if not functions:
            return None

        # get the last function before this position
        last_func = functions[-1]
        func_name = last_func.group(1)

        # verify we're inside the function body (not after it closed)
        func_start = last_func.end()
        after_func = self.contract_source[func_start:position]

        # count braces
        open_braces = after_func.count('{')
        close_braces = after_func.count('}')

        if open_braces > close_braces:
            return func_name

        return None

    def _generate_symbolic_insights(self, func_name, params, requires, mutations, calls, reentrancy_risk):
        """generate insights from symbolic analysis"""
        insights = []

        if not requires:
            insights.append(f'{func_name} has no require statements - may lack input validation')

        if mutations and not requires:
            insights.append(f'{func_name} mutates state but lacks preconditions - potential vulnerability')

        if calls and mutations:
            insights.append(f'{func_name} makes external calls and mutates state - check order')

        if reentrancy_risk:
            insights.append(f'CRITICAL: {func_name} may be vulnerable to reentrancy (external call before state update)')

        if len(calls) > 3:
            insights.append(f'{func_name} makes many external calls ({len(calls)}) - complexity risk')

        return insights

    def _check_reentrancy(self) -> List[Dict[str, Any]]:
        """check for reentrancy vulnerabilities"""
        findings = []

        # find functions with external calls using cached pattern
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*[^{]*\{([^}]*)\}'
        for func_match in self._find_all_matches(func_pattern, re.DOTALL):
            func_name = func_match.group(1)
            func_body = func_match.group(2)

            # check for .call{
            if '.call{' in func_body or '.transfer(' in func_body:
                # check if state is modified after
                call_pos = func_body.find('.call{') if '.call{' in func_body else func_body.find('.transfer(')
                after_call = func_body[call_pos:]

                if '=' in after_call:
                    findings.append({
                        'type': 'reentrancy',
                        'severity': 'high',
                        'function': func_name,
                        'description': f'{func_name} modifies state after external call'
                    })

        return findings

    def _check_overflow(self) -> List[Dict[str, Any]]:
        """check for overflow/underflow"""
        findings = []

        # check solidity version using cached pattern
        version_pattern = r'pragma solidity\s+[\^>]?(\d+\.\d+)'
        version_match = self._get_compiled_pattern(version_pattern).search(self.contract_source)
        if version_match:
            version = float(version_match.group(1))
            if version < 0.8:
                findings.append({
                    'type': 'overflow',
                    'severity': 'medium',
                    'description': f'Solidity {version} lacks automatic overflow protection'
                })

        return findings

    def _check_access_control(self) -> List[Dict[str, Any]]:
        """check for missing access control"""
        findings = []

        # find external/public functions without access control using cached pattern
        access_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(external|public)\s*[^{]*\{([^}]*)\}'
        for func_match in self._find_all_matches(access_pattern, re.DOTALL):
            func_name = func_match.group(1)
            func_body = func_match.group(3)

            # skip view/pure functions
            if 'view' in func_match.group(0) or 'pure' in func_match.group(0):
                continue

            # check for access control
            has_control = any(keyword in func_body for keyword in ['require(msg.sender', 'onlyOwner', 'onlyAdmin'])

            if not has_control and '=' in func_body:
                findings.append({
                    'type': 'access_control',
                    'severity': 'medium',
                    'function': func_name,
                    'description': f'{func_name} is public but lacks access control'
                })

        return findings

    def _check_external_calls(self) -> List[Dict[str, Any]]:
        """check for unchecked external calls"""
        findings = []

        # find .call( without checking return value using cached pattern
        call_pattern = r'(\w+)\.call\([^)]*\)[^;]*;'
        for call_match in self._find_all_matches(call_pattern):
            call_str = call_match.group(0)

            # check if return value is checked
            if 'require(' not in call_str and 'success' not in call_str:
                findings.append({
                    'type': 'unchecked_call',
                    'severity': 'low',
                    'description': 'External call without checking return value'
                })

        return findings
    def get_relevant_code(self, query: str) -> Dict[str, Any]:
        """retrieve relevant code from the project context using semantic search"""
        project_context = self.contract_info.get("project_context")

        if not project_context or not hasattr(project_context, "get_relevant_code"):
            return {
                "error": "ProjectContext not available. Cannot perform semantic search."
            }

        # default budget of 2000 tokens
        snippets = project_context.get_relevant_code(query, budget=2000, structured=True)
        code = project_context.get_relevant_code(query, budget=2000)
        if isinstance(snippets, dict):
            snippets_payload = snippets.get("payload") or snippets.get("results") or []
        else:
            snippets_payload = snippets
        if isinstance(code, dict):
            code_payload = code.get("text") or code.get("payload") or code
        else:
            code_payload = code

        return {
            "query": query,
            "result": code_payload,
            "snippets": snippets_payload
        }

# tool definitions for grok api
def get_functional_tool_definitions() -> List[Dict[str, Any]]:
    """get functional tool definitions for grok api"""
    return [
        {
            "name": "trace_state_variable",
            "description": """Trace all mutations and reads of a state variable throughout the contract.

This tool performs active analysis - it finds:
- All locations where the variable is modified
- All functions that read or write it
- The order of operations
- Potential invariant violations

Use this when you want to understand how a state variable behaves.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "variable_name": {
                        "type": "string",
                        "description": "Name of the state variable to trace"
                    }
                },
                "required": ["variable_name"]
            }
        },
        {
            "name": "analyze_function_symbolically",
            "description": """Perform symbolic execution on a function to find vulnerabilities.

This tool analyzes:
- Input constraints (require statements)
- State mutations
- External calls
- Reentrancy risks
- Return value possibilities

Use this to deeply understand a function's behavior.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "Function to analyze"
                    }
                },
                "required": ["function_name"]
            }
        },
        {
            "name": "check_invariant",
            "description": """Verify if an invariant you discovered actually holds.

This tool checks if your invariant can be violated by:
- Looking for code patterns that break it
- Checking for bypass mechanisms
- Verifying access controls

Use this to validate invariants before recording them.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "invariant_description": {
                        "type": "string",
                        "description": "What should always be true"
                    },
                    "code_evidence": {
                        "type": "string",
                        "description": "Code snippet that supports this invariant"
                    }
                },
                "required": ["invariant_description", "code_evidence"]
            }
        },
        {
            "name": "run_static_analysis",
            "description": """Run static analysis checks (Slither-style) on the contract.

Checks for:
- Reentrancy vulnerabilities
- Integer overflow/underflow
- Missing access control
- Unchecked external calls

Use this to get a vulnerability scan.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "focus": {
                        "type": "string",
                        "enum": ["all", "reentrancy", "overflow", "access", "calls"],
                        "description": "What to focus on (default: all)"
                    }
                },
                "required": []
            }
        },
        {
            "name": "reflect_on_finding",
            "description": """SELF-CRITIQUE: Reflect on one of your findings to check if it's valid.

Agents that reflect on their own reasoning are more accurate.

This tool helps you:
- Identify false positives
- Adjust confidence levels
- Consider edge cases
- Validate your reasoning

Use this before recording high-confidence findings.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "finding": {
                        "type": "string",
                        "description": "The discovery you made"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Your initial confidence"
                    }
                },
                "required": ["finding", "confidence"]
            }
        },
        {
            "name": "compare_with_pattern",
            "description": """Compare the contract with a known vulnerability pattern.

Available patterns:
- flash_loan_dos: DoS via flash loan invariant break
- oracle_manipulation: Price oracle manipulation
- reentrancy: Reentrancy attack

Returns a match score and vulnerability assessment.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "pattern_name": {
                        "type": "string",
                        "enum": ["flash_loan_dos", "oracle_manipulation", "reentrancy"],
                        "description": "Pattern to check"
                    }
                },
                "required": ["pattern_name"]
            }
        },
        {
            "name": "get_relevant_code",
            "description": """Search the entire codebase for relevant logic using semantic search.
            
This tool allows you to find code without knowing the file name.
Examples:
- "where is the fee calculated?"
- "how is the exchange rate determined?"
- "show me the reentrancy guard implementation"

Use this when you need to explore outside the current contract.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Natural language query"
                    }
                },
                "required": ["query"]
            }
        }
    ]
