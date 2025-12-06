"""mcts node structure for tree search"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from math import sqrt, log
import json


@dataclass
class Transaction:
    """transaction in attack sequence"""
    function_name: str
    contract_address: str
    caller: str
    parameters: Dict[str, Any]
    value: int = 0
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging"""
        return {
            'function': self.function_name,
            'contract': self.contract_address,
            'caller': self.caller,
            'params': self.parameters,
            'value': self.value,
            'description': self.description
        }

    def to_foundry_call(self) -> str:
        """convert to foundry test code"""
        # build parameter list
        params = ', '.join(str(v) for v in self.parameters.values())

        # add value if non-zero
        value_clause = f"{{value: {self.value}}}" if self.value > 0 else ""

        return f"{self.contract_address}.{self.function_name}{value_clause}({params})"


@dataclass
class ContractState:
    """contract state snapshot"""
    balances: Dict[str, int] = field(default_factory=dict)
    storage: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # contract → slot → value
    block_number: int = 0
    block_timestamp: int = 0

    def clone(self) -> 'ContractState':
        """deep copy"""
        return ContractState(
            balances=self.balances.copy(),
            storage={k: v.copy() for k, v in self.storage.items()},
            block_number=self.block_number,
            block_timestamp=self.block_timestamp
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging"""
        return {
            'balances': {addr: bal for addr, bal in self.balances.items()},
            'storage': self.storage,
            'block_number': self.block_number,
            'block_timestamp': self.block_timestamp
        }


class MCTSNode:
    """node in mcts tree"""

    def __init__(
        self,
        state: ContractState,
        action: Optional[Transaction] = None,
        parent: Optional['MCTSNode'] = None,
        depth: int = 0
    ):
        self.state = state
        self.action = action
        self.parent = parent
        self.depth = depth

        # tree structure
        self.children: List[MCTSNode] = []

        # mcts statistics
        self.visits = 0
        self.value = 0.0
        self.total_value = 0.0
        self.wins = 0

        # policy prior
        self.policy_prior = 0.5

        # state tracking
        self.is_terminal = False
        self.terminal_reward = 0.0
        self.fully_expanded = False

    def uct_value(self, exploration_constant: float = 1.41) -> float:
        """calculate uct value"""
        # unvisited nodes have infinite value
        if self.visits == 0:
            return float('inf')

        # root node - just use win rate
        if self.parent is None:
            return self.wins / self.visits

        # standard uct formula
        exploitation = self.wins / self.visits
        exploration = exploration_constant * sqrt(log(self.parent.visits) / self.visits)

        return exploitation + exploration

    def win_rate(self) -> float:
        """calculate win rate"""
        if self.visits == 0:
            return 0.0
        return self.wins / self.visits

    def add_child(self, action: Transaction, state: ContractState) -> 'MCTSNode':
        """add child node"""
        child = MCTSNode(
            state=state,
            action=action,
            parent=self,
            depth=self.depth + 1
        )
        self.children.append(child)
        return child

    def best_child(self, exploration_constant: float = 1.41) -> Optional['MCTSNode']:
        """select best child using uct"""
        if not self.children:
            return None

        return max(self.children, key=lambda c: c.uct_value(exploration_constant))

    def most_visited_child(self) -> Optional['MCTSNode']:
        """select most visited child"""
        if not self.children:
            return None

        return max(self.children, key=lambda c: c.visits)

    def update(self, reward: float) -> None:
        """update node statistics"""
        self.visits += 1
        self.value += reward

        # count as win if reward > 0.5 threshold
        if reward > 0.5:
            self.wins += 1

    def backpropagate(self, reward: float) -> None:
        """backpropagate reward up tree"""
        node = self
        while node is not None:
            node.update(reward)
            node = node.parent

    def get_path_from_root(self) -> List[Transaction]:
        """get action sequence from root"""
        path = []
        node = self
        while node.parent is not None:
            if node.action:
                path.append(node.action)
            node = node.parent

        # reverse to get root → leaf order
        return list(reversed(path))

    def to_dict(self) -> Dict[str, Any]:
        """convert to dict"""
        return {
            'depth': self.depth,
            'visits': self.visits,
            'wins': self.wins,
            'win_rate': self.win_rate(),
            'value': self.value,
            'is_terminal': self.is_terminal,
            'terminal_reward': self.terminal_reward,
            'num_children': len(self.children),
            'fully_expanded': self.fully_expanded,
            'action': self.action.to_dict() if self.action else None,
            'state': self.state.to_dict()
        }

    def tree_stats(self) -> Dict[str, Any]:
        """compute tree statistics"""
        total_nodes = 1
        max_depth = self.depth
        leaf_nodes = 0
        terminal_nodes = 0

        # bfs to count nodes
        queue = [self]
        while queue:
            node = queue.pop(0)

            if not node.children:
                leaf_nodes += 1
            if node.is_terminal:
                terminal_nodes += 1

            for child in node.children:
                total_nodes += 1
                max_depth = max(max_depth, child.depth)
                queue.append(child)

        return {
            'total_nodes': total_nodes,
            'max_depth': max_depth,
            'leaf_nodes': leaf_nodes,
            'terminal_nodes': terminal_nodes,
            'root_visits': self.visits,
            'root_win_rate': self.win_rate()
        }

    def __repr__(self) -> str:
        """string representation"""
        action_str = f"Action: {self.action.function_name}" if self.action else "Root"
        return (
            f"MCTSNode({action_str}, "
            f"depth={self.depth}, "
            f"visits={self.visits}, "
            f"wins={self.wins}, "
            f"win_rate={self.win_rate():.2f})"
        )
