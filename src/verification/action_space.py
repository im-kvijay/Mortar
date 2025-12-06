"""action space - generate possible actions for mcts exploration"""

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import random

from utils.logging import ResearchLogger
from verification.mcts_node import Transaction, ContractState


@dataclass
class ActionTemplate:
    """
    Template for generating actions

    Attributes:
        function_name: Function to call
        parameter_generators: Functions to generate parameter values
        priority: Priority score (0.0-1.0, higher = more important)
        constraints: Constraints on when this action is valid
        description: Human-readable description
    """
    function_name: str
    parameter_generators: Dict[str, Callable[[], Any]]
    priority: float = 0.5
    constraints: Optional[Callable[[ContractState], bool]] = None
    description: str = ""


class ActionSpace:
    """
    Generates possible actions from contract state

    Used by MCTS to expand nodes.
    """

    def __init__(
        self,
        logger: ResearchLogger,
        contract_address: str,
        contract_abi: List[Dict[str, Any]],
        attacker_address: str,
        attack_type: Optional[str] = None
    ):
        """
        Initialize action space

        Args:
            logger: Logger instance
            contract_address: Target contract address
            contract_abi: Contract ABI
            attacker_address: Attacker's address
            attack_type: Type of attack (for prioritization)
        """
        self.logger = logger
        self.contract_address = contract_address
        self.contract_abi = contract_abi
        self.attacker_address = attacker_address
        self.attack_type = attack_type

        # Extract function info from ABI
        self.functions = self._extract_functions(contract_abi)

        # Build action templates
        self.action_templates = self._build_action_templates()

        self.logger.info(
            f"[ActionSpace] Initialized with {len(self.action_templates)} action templates"
        )

    def _extract_functions(self, abi: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract function information from ABI

        Returns:
            List of function definitions
        """
        functions = []
        for item in abi:
            if item.get('type') == 'function':
                # Skip view/pure functions (can't change state)
                state_mutability = item.get('stateMutability', 'nonpayable')
                if state_mutability in ['view', 'pure']:
                    continue

                functions.append({
                    'name': item.get('name'),
                    'inputs': item.get('inputs', []),
                    'stateMutability': state_mutability
                })

        return functions

    def _build_action_templates(self) -> List[ActionTemplate]:
        """
        Build action templates from contract functions

        Returns:
            List of ActionTemplate objects
        """
        templates = []

        for func in self.functions:
            # Generate parameter generators
            param_generators = {}
            for input_param in func['inputs']:
                param_name = input_param.get('name', f'param_{len(param_generators)}')
                param_type = input_param.get('type', 'uint256')
                param_generators[param_name] = self._make_parameter_generator(param_type)

            # Calculate priority based on function name and attack type
            priority = self._calculate_priority(func['name'], func)

            # Create template
            template = ActionTemplate(
                function_name=func['name'],
                parameter_generators=param_generators,
                priority=priority,
                description=f"Call {func['name']} on target contract"
            )
            templates.append(template)

        # Sort by priority (highest first)
        templates.sort(key=lambda t: t.priority, reverse=True)

        return templates

    def _make_parameter_generator(self, param_type: str) -> Callable[[], Any]:
        """
        Create a parameter value generator for a given type

        Returns:
            Function that generates random valid values
        """
        if param_type.startswith('uint'):
            # Extract bit size
            bits = 256
            if param_type != 'uint':
                bits = int(param_type.replace('uint', ''))

            max_value = (2 ** bits) - 1

            def uint_generator():
                # Smart sampling: boundary values + random
                choice = random.random()
                if choice < 0.2:
                    return 0  # Zero
                elif choice < 0.3:
                    return 1  # Minimum non-zero
                elif choice < 0.4:
                    return max_value  # Maximum
                elif choice < 0.5:
                    return max_value // 2  # Half max
                elif choice < 0.7:
                    # Large values (for flash loans, etc.)
                    return random.randint(10**18, 10**24)
                else:
                    # Random value
                    return random.randint(0, max_value)

            return uint_generator

        elif param_type.startswith('int'):
            # Signed integer
            bits = 256
            if param_type != 'int':
                bits = int(param_type.replace('int', ''))

            max_value = (2 ** (bits - 1)) - 1
            min_value = -(2 ** (bits - 1))

            def int_generator():
                choice = random.random()
                if choice < 0.2:
                    return 0
                elif choice < 0.3:
                    return min_value  # Minimum
                elif choice < 0.4:
                    return max_value  # Maximum
                else:
                    return random.randint(min_value, max_value)

            return int_generator

        elif param_type == 'address':
            # Generate addresses
            def address_generator():
                # Mix of known addresses + random
                choice = random.random()
                if choice < 0.3:
                    return self.attacker_address
                elif choice < 0.4:
                    return self.contract_address
                elif choice < 0.5:
                    return "0x0000000000000000000000000000000000000000"  # Zero address
                else:
                    # Random address
                    return f"0x{random.randint(0, 2**160 - 1):040x}"

            return address_generator

        elif param_type == 'bool':
            def bool_generator():
                return random.choice([True, False])

            return bool_generator

        elif param_type.startswith('bytes'):
            # Fixed or dynamic bytes
            if param_type == 'bytes':
                # Dynamic bytes
                def bytes_generator():
                    length = random.randint(0, 256)
                    return f"0x{random.randbytes(length).hex()}"
            else:
                # Fixed bytes (bytes1, bytes32, etc.)
                size = int(param_type.replace('bytes', ''))

                def bytes_generator():
                    return f"0x{random.randbytes(size).hex()}"

            return bytes_generator

        elif param_type == 'string':
            def string_generator():
                choices = [
                    "",
                    "test",
                    "a" * 1000,  # Long string
                    "exploit"
                ]
                return random.choice(choices)

            return string_generator

        else:
            # Default: return 0
            self.logger.warning(f"[ActionSpace] Unsupported parameter type: {param_type}")
            return lambda: 0

    def _calculate_priority(self, func_name: str, func_info: Dict[str, Any]) -> float:
        """
        Calculate priority for a function

        Higher priority = more likely to be part of an exploit

        Returns:
            Priority score (0.0-1.0)
        """
        priority = 0.5  # Default

        func_name_lower = func_name.lower()

        # High priority functions
        if any(keyword in func_name_lower for keyword in [
            'flash', 'loan', 'borrow', 'withdraw', 'deposit',
            'swap', 'trade', 'transfer', 'approve', 'mint', 'burn'
        ]):
            priority += 0.3

        # Medium priority
        if any(keyword in func_name_lower for keyword in [
            'claim', 'stake', 'unstake', 'redeem', 'liquidate'
        ]):
            priority += 0.2

        # Payable functions (can receive ETH)
        if func_info.get('stateMutability') == 'payable':
            priority += 0.1

        # Attack-type specific prioritization
        if self.attack_type:
            attack_type_lower = self.attack_type.lower()

            if 'flash' in attack_type_lower and 'flash' in func_name_lower:
                priority += 0.2
            elif 'oracle' in attack_type_lower and any(
                keyword in func_name_lower for keyword in ['price', 'oracle', 'update']
            ):
                priority += 0.2
            elif 'reentrancy' in attack_type_lower and 'withdraw' in func_name_lower:
                priority += 0.2

        # Clamp to [0.1, 1.0]
        return max(0.1, min(1.0, priority))

    def get_possible_actions(
        self,
        state: ContractState,
        max_actions: int = 10,
        diversify: bool = True
    ) -> List[Transaction]:
        """
        Generate possible actions from current state

        Args:
            state: Current contract state
            max_actions: Maximum number of actions to return
            diversify: If True, sample diverse actions (not just top priority)

        Returns:
            List of possible transactions
        """
        actions = []

        # Filter templates by constraints
        valid_templates = [
            t for t in self.action_templates
            if t.constraints is None or t.constraints(state)
        ]

        if not valid_templates:
            self.logger.warning("[ActionSpace] No valid action templates available")
            return []

        # Sample templates
        if diversify:
            # Weighted random sampling (higher priority = more likely)
            weights = [t.priority for t in valid_templates]
            sampled_templates = random.choices(
                valid_templates,
                weights=weights,
                k=min(max_actions, len(valid_templates))
            )
        else:
            # Just take top N by priority
            sampled_templates = valid_templates[:max_actions]

        # Generate actions from templates
        for template in sampled_templates:
            # Generate parameter values
            parameters = {}
            for param_name, param_generator in template.parameter_generators.items():
                parameters[param_name] = param_generator()

            # Heuristic ETH value for payable functions
            value = 0
            if self._is_payable(template.function_name):
                value = self._heuristic_value(template.function_name)

            # Create transaction
            action = Transaction(
                function_name=template.function_name,
                contract_address=self.contract_address,
                caller=self.attacker_address,
                parameters=parameters,
                value=value,
                description=template.description
            )
            actions.append(action)

        # Prune obviously invalid actions based on state
        actions = self.prune_invalid_actions(actions, state)
        if len(actions) == 0:
            self.logger.warning("[ActionSpace] All actions pruned for current state")
        else:
            self.logger.info(f"[ActionSpace] Returning {len(actions)} actions after pruning")
        return actions

    def get_action_by_name(
        self,
        function_name: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Optional[Transaction]:
        """
        Generate a specific action by function name

        Args:
            function_name: Function to call
            parameters: Parameter values (None = generate random)

        Returns:
            Transaction or None if function not found
        """
        # Find template
        template = None
        for t in self.action_templates:
            if t.function_name == function_name:
                template = t
                break

        if template is None:
            self.logger.warning(f"[ActionSpace] Function not found: {function_name}")
            return None

        # Generate or use provided parameters
        if parameters is None:
            parameters = {}
            for param_name, param_generator in template.parameter_generators.items():
                parameters[param_name] = param_generator()

        # Create transaction
        return Transaction(
            function_name=function_name,
            contract_address=self.contract_address,
            caller=self.attacker_address,
            parameters=parameters,
            value=0,
            description=template.description
        )

    def prune_invalid_actions(
        self,
        actions: List[Transaction],
        state: ContractState
    ) -> List[Transaction]:
        """
        Prune obviously invalid actions

        Args:
            actions: List of candidate actions
            state: Current state

        Returns:
            Filtered list of actions
        """
        valid_actions: List[Transaction] = []
        balances = state.balances or {}
        attacker_bal = int(balances.get(self.attacker_address, 0))

        for action in actions:
            # Payable guard: attacker must have enough ETH
            if action.value and attacker_bal < action.value:
                continue
            # transferFrom-style guard: require non-zero amount
            if action.function_name and action.function_name.lower().endswith("transferfrom"):
                amt = action.parameters.get("value") or action.parameters.get("amount") or 0
                if isinstance(amt, int) and amt <= 0:
                    continue
            valid_actions.append(action)

        return valid_actions

    def _is_payable(self, func_name: str) -> bool:
        for f in self.functions:
            if f.get('name') == func_name:
                return f.get('stateMutability') == 'payable'
        return False

    def _heuristic_value(self, func_name: str) -> int:
        n = (func_name or "").lower()
        if any(k in n for k in ["deposit", "mint", "bid", "stake"]):
            return 10**15  # 0.001 ETH
        if any(k in n for k in ["buy", "contribute"]):
            return 10**16  # 0.01 ETH
        return 1  # 1 wei default

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get action space statistics

        Returns:
            Statistics dictionary
        """
        return {
            'num_functions': len(self.functions),
            'num_templates': len(self.action_templates),
            'avg_priority': sum(t.priority for t in self.action_templates) / len(self.action_templates)
            if self.action_templates else 0.0,
            'top_functions': [
                {'name': t.function_name, 'priority': t.priority}
                for t in self.action_templates[:5]
            ]
        }
