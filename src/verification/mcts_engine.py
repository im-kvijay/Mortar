"""monte carlo tree search for poc generation"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import random
import time

from utils.logging import ResearchLogger
from agent.base_attacker import AttackHypothesis
from verification.mcts_node import MCTSNode, Transaction, ContractState
from verification.action_space import ActionSpace
from verification.foundry_executor import FoundryExecutor, ExecutionResult


@dataclass
class MCTSConfig:
    """mcts configuration parameters"""
    max_iterations: int = 1000
    max_depth: int = 10
    exploration_constant: float = 1.41  # sqrt(2)
    simulation_depth: int = 5
    early_stop_threshold: float = 0.9
    progressive_widening_c: float = 2.0
    enable_progressive_widening: bool = True


@dataclass
class MCTSResult:
    """result of mcts search"""
    success: bool
    exploit_path: List[Transaction]
    confidence: float
    iterations_used: int
    best_reward: float
    tree_stats: Dict[str, Any]
    execution_time: float


class MCTSEngine:
    """monte carlo tree search engine for poc generation"""

    def __init__(
        self,
        logger: ResearchLogger,
        foundry_executor: FoundryExecutor,
        action_space: ActionSpace,
        config: Optional[MCTSConfig] = None
    ):
        self.logger = logger
        self.executor = foundry_executor
        self.action_space = action_space
        self.config = config or MCTSConfig()
        self.total_searches = 0
        self.successful_searches = 0

        self.logger.info(
            f"[MCTSEngine] Initialized with max_iterations={self.config.max_iterations}, "
            f"max_depth={self.config.max_depth}"
        )

    def search(
        self,
        hypothesis: AttackHypothesis,
        initial_state: Optional[ContractState] = None,
        success_criteria: Optional[Dict[str, Any]] = None
    ) -> MCTSResult:
        self.logger.info(
            f"[MCTSEngine] Starting MCTS search for {hypothesis.hypothesis_id}"
        )

        start_time = time.time()
        self.total_searches += 1
        root = MCTSNode(
            state=initial_state or ContractState(),
            action=None,
            parent=None,
            depth=0
        )

        best_reward = 0.0
        best_node = root
        for iteration in range(self.config.max_iterations):
            node = self._select(root)
            if not node.is_terminal and not node.fully_expanded:
                node = self._expand(node)
            reward = self._simulate(node, success_criteria)
            if reward > best_reward:
                best_reward = reward
                best_node = node
            self._backpropagate(node, reward)
            if root.win_rate() >= self.config.early_stop_threshold:
                self.logger.info(
                    f"[MCTSEngine] Early stop at iteration {iteration+1} "
                    f"(win_rate={root.win_rate():.2f})"
                )
                break
            if (iteration + 1) % 100 == 0:
                self.logger.info(
                    f"[MCTSEngine] Iteration {iteration+1}/{self.config.max_iterations}: "
                    f"win_rate={root.win_rate():.2f}, "
                    f"best_reward={best_reward:.2f}, "
                    f"tree_size={root.tree_stats()['total_nodes']}"
                )
        exploit_path = self._extract_best_path(root, best_node)
        success = best_reward > 0.5
        confidence = best_reward
        execution_time = time.time() - start_time
        if success:
            self.successful_searches += 1

        self.logger.info(
            f"[MCTSEngine] Search completed in {execution_time:.2f}s: "
            f"{'SUCCESS' if success else 'FAILURE'} "
            f"(confidence={confidence:.2f}, path_length={len(exploit_path)})"
        )

        return MCTSResult(
            success=success,
            exploit_path=exploit_path,
            confidence=confidence,
            iterations_used=iteration + 1,
            best_reward=best_reward,
            tree_stats=root.tree_stats(),
            execution_time=execution_time
        )

    def _select(self, root: MCTSNode) -> MCTSNode:
        node = root
        while node.children and node.fully_expanded:
            node = node.best_child(self.config.exploration_constant)
        return node

    def _expand(self, node: MCTSNode) -> MCTSNode:
        if node.depth >= self.config.max_depth:
            node.fully_expanded = True
            return node
        if self.config.enable_progressive_widening:
            max_children = int(
                self.config.progressive_widening_c * (node.visits ** 0.5)
            )
            if len(node.children) >= max_children and node.visits > 0:
                return node
        possible_actions = self.action_space.get_possible_actions(
            state=node.state,
            max_actions=10,
            diversify=True
        )
        if not possible_actions:
            node.fully_expanded = True
            return node
        explored_functions = {child.action.function_name for child in node.children if child.action}
        new_actions = [
            action for action in possible_actions
            if action.function_name not in explored_functions
        ]
        if not new_actions:
            node.fully_expanded = True
            return node
        action = random.choice(new_actions)
        new_state = node.state.clone()
        child = node.add_child(action, new_state)
        return child

    def _simulate(
        self,
        node: MCTSNode,
        success_criteria: Optional[Dict[str, Any]]
    ) -> float:
        current_path = node.get_path_from_root()
        if node.depth >= self.config.max_depth:
            return self._execute_and_evaluate(current_path, success_criteria)
        simulation_path = current_path.copy()
        current_state = node.state.clone()
        current_depth = node.depth
        while current_depth < min(self.config.max_depth, node.depth + self.config.simulation_depth):
            possible_actions = self.action_space.get_possible_actions(
                state=current_state,
                max_actions=5,
                diversify=True
            )
            if not possible_actions:
                break
            action = random.choice(possible_actions)
            simulation_path.append(action)
            current_depth += 1
        return self._execute_and_evaluate(simulation_path, success_criteria)

    def _execute_and_evaluate(
        self,
        transaction_path: List[Transaction],
        success_criteria: Optional[Dict[str, Any]]
    ) -> float:
        if not transaction_path:
            return 0.0
        result = self.executor.execute_sequence(
            transactions=transaction_path,
            initial_state=None,
            success_criteria=success_criteria
        )
        if result.success:
            return 1.0
        else:
            if result.profit > 0:
                return 0.3
            else:
                return 0.0

    def _backpropagate(self, node: MCTSNode, reward: float) -> None:
        node.backpropagate(reward)

    def _extract_best_path(self, root: MCTSNode, best_node: MCTSNode) -> List[Transaction]:
        path = []
        node = root
        while node.children:
            best_child = node.most_visited_child()
            if best_child is None:
                break
            if best_child.action:
                path.append(best_child.action)
            node = best_child
            if node.is_terminal:
                break
        if len(path) < 2 and best_node != root:
            path = best_node.get_path_from_root()
        return path

    def get_statistics(self) -> Dict[str, Any]:
        success_rate = 0.0
        if self.total_searches > 0:
            success_rate = self.successful_searches / self.total_searches
        return {
            'total_searches': self.total_searches,
            'successful_searches': self.successful_searches,
            'success_rate': success_rate,
            'config': {
                'max_iterations': self.config.max_iterations,
                'max_depth': self.config.max_depth,
                'exploration_constant': self.config.exploration_constant
            }
        }
