"""dvd vulnerability patterns"""
from config import config
from kb.knowledge_base import VulnerabilityPattern, PatternStatus, KnowledgeBase


def get_dvd_patterns() -> list[VulnerabilityPattern]:
    """get all dvd vulnerability patterns"""
    patterns = []

    patterns.append(VulnerabilityPattern(
        id="dvd_flash_dos_balance_eq",
        name="Flash Loan DoS via Balance Equality Invariant",
        vuln_type="flash_loan_dos",
        description=(
            "Contract enforces strict equality between accounting variable and token balance. "
            "Direct token transfer breaks invariant, causing DoS on all operations."
        ),
        preconditions=[
            "Contract has accounting variable (e.g., totalAssets, totalDeposits)",
            "Strict equality check: require(accounting == token.balanceOf(address(this)))",
            "Check is in critical path (deposit, withdraw, flashLoan, etc)",
            "Anyone can send tokens directly to contract",
        ],
        attack_steps=[
            "Identify accounting variable and equality check",
            "Send 1 wei directly to contract (not through deposit)",
            "Accounting variable now != balanceOf",
            "All operations revert due to broken invariant",
            "Contract is DoS'd",
        ],
        indicators=[
            "require(totalAssets == token.balanceOf(address(this)))",
            "assert(accountingVar == token.balanceOf(...))",
            "if (var != balanceOf(...)) revert",
            "Strict == equality (not >=)",
        ],
        successful_exploits=1,  # DVD Unstoppable
        failed_attempts=0,
        confidence=0.90,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["UnstoppableVault"],
        discovered_by="dvd_analysis",
        source_contract="UnstoppableVault",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_flash_unvalidated_receiver",
        name="Unvalidated Flash Loan Receiver",
        vuln_type="flash_loan_dos",
        description=(
            "Flash loan pool doesn't validate receiver address. "
            "Attacker can drain all fees by flash loaning to arbitrary address that doesn't repay."
        ),
        preconditions=[
            "Flash loan pool charges fees",
            "Pool doesn't validate receiver address",
            "Pool calls receiver.onFlashLoan()",
            "Attacker can specify arbitrary receiver",
        ],
        attack_steps=[
            "Deploy malicious receiver that doesn't approve/repay",
            "Call flashLoan(maliciousReceiver, amount)",
            "Receiver gets tokens but never repays",
            "Attacker (msg.sender) doesn't lose funds",
            "Victim pays flash loan fee",
        ],
        indicators=[
            "flashLoan(address receiver, ...) with no validation on receiver",
            "No require(receiver == msg.sender)",
            "IERC3156FlashBorrower(receiver).onFlashLoan() without checks",
        ],
        successful_exploits=1,  # DVD Naive Receiver
        failed_attempts=0,
        confidence=0.90,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["NaiveReceiverLenderPool"],
        discovered_by="dvd_analysis",
        source_contract="NaiveReceiverLenderPool",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_flash_arbitrary_call",
        name="Flash Loan with Arbitrary Target Call",
        vuln_type="flash_loan_arbitrary_call",
        description=(
            "Flash loan pool allows borrower to specify target and data for arbitrary call. "
            "Attacker can approve tokens from pool to themselves."
        ),
        preconditions=[
            "Flash loan function takes (target, data) parameters",
            "Pool makes call: target.call(data)",
            "Pool holds valuable tokens",
            "No validation on target or data",
        ],
        attack_steps=[
            "Call flashLoan(token, 0, attacker, approveData)",
            "approveData = abi.encodeWithSignature('approve(address,uint256)', attacker, type(uint256).max)",
            "Pool calls token.approve(attacker, max) on behalf of itself",
            "Attacker now has approval to drain pool",
            "transferFrom(pool, attacker, balance)",
        ],
        indicators=[
            "target.functionCall(data)",
            "target.call(data)",
            "No whitelist on target",
            "No validation on data",
        ],
        successful_exploits=1,  # DVD Truster
        failed_attempts=0,
        confidence=0.90,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["TrusterLenderPool"],
        discovered_by="dvd_analysis",
        source_contract="TrusterLenderPool",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_flash_reentrancy_deposit",
        name="Flash Loan Reentrancy During Deposit",
        vuln_type="flash_loan_reentrancy",
        description=(
            "Flash loan callback allows reentrant call to deposit(). "
            "Deposit credits tokens that will be returned to pool, giving free balance."
        ),
        preconditions=[
            "Flash loan calls borrower before updating state",
            "Deposit function is not protected against reentrancy",
            "Pool tracks deposits with accounting variable",
            "Flash loan tokens are same as deposit tokens",
        ],
        attack_steps=[
            "Call flashLoan(amount)",
            "In callback: deposit(amount) back to pool",
            "Pool credits deposit to attacker",
            "Return from callback, tokens go back to pool",
            "Attacker has deposit credited without paying",
            "Withdraw to steal funds",
        ],
        indicators=[
            "execute() or onFlashLoan() callback before state update",
            "No nonReentrant on deposit()",
            "Deposit before flash loan repayment check",
        ],
        successful_exploits=1,  # DVD Side Entrance
        failed_attempts=0,
        confidence=0.90,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["SideEntranceLenderPool"],
        discovered_by="dvd_analysis",
        source_contract="SideEntranceLenderPool",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_flash_governance_snapshot",
        name="Flash Loan Governance Snapshot Attack",
        vuln_type="flash_loan_governance",
        description=(
            "Governance uses balanceOf for voting power. "
            "Flash loan → get tokens → snapshot/vote → return tokens."
        ),
        preconditions=[
            "Governance voting power = token balance at snapshot",
            "No delegation/staking requirement",
            "Token has flash loan capability",
            "Governance allows same-block proposal and execution",
        ],
        attack_steps=[
            "Flash loan governance tokens",
            "Queue action (snapshot taken)",
            "Execute action immediately",
            "Return flash loan",
            "Governance action executed with borrowed voting power",
        ],
        indicators=[
            "snapshot.balanceOf(voter)",
            "token.balanceOf(voter) for voting",
            "Same-block proposal/execution",
            "No time delay between proposal and vote",
        ],
        successful_exploits=1,  # DVD Selfie
        failed_attempts=0,
        confidence=0.85,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["SelfiePool"],
        discovered_by="dvd_analysis",
        source_contract="SelfiePool",
    ))


    patterns.append(VulnerabilityPattern(
        id="dvd_oracle_spot_price",
        name="Spot Price Oracle Manipulation",
        vuln_type="oracle_manipulation",
        description=(
            "Contract uses spot price from DEX reserves for critical decisions. "
            "Flash loan → manipulate reserves → trigger exploit → restore."
        ),
        preconditions=[
            "Contract reads reserves from Uniswap/DEX for price",
            "Price = reserve1 / reserve0 (spot price)",
            "No TWAP or other manipulation resistance",
            "Contract allows same-block price usage",
        ],
        attack_steps=[
            "Flash loan large amount of token0",
            "Swap token0 → token1 on DEX (manipulate reserves)",
            "Price now heavily skewed",
            "Trigger contract action that uses manipulated price",
            "Extract value (buy cheap, borrow more, etc)",
            "Swap back and return flash loan",
        ],
        indicators=[
            "uniswapPair.getReserves()",
            "reserve1 * 1e18 / reserve0",
            "No TWAP oracle",
            "No price staleness check",
        ],
        successful_exploits=2,  # DVD Puppet v1, v2
        failed_attempts=0,
        confidence=0.90,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["PuppetPool", "PuppetV2Pool"],
        discovered_by="dvd_analysis",
        source_contract="PuppetPool",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_oracle_twap_manipulation",
        name="TWAP Oracle Manipulation",
        vuln_type="oracle_manipulation",
        description=(
            "TWAP oracle vulnerable to manipulation over observation window. "
            "Attack requires sustained price manipulation across multiple blocks."
        ),
        preconditions=[
            "Contract uses TWAP oracle (Uniswap V3)",
            "TWAP window is short (< 10 minutes)",
            "Low liquidity allows cheap manipulation",
            "Attacker can control multiple blocks (MEV)",
        ],
        attack_steps=[
            "Identify TWAP observation window",
            "Calculate required manipulation per block",
            "Execute series of swaps across N blocks",
            "Each block pushes TWAP in desired direction",
            "After window, TWAP is manipulated",
            "Trigger exploit using manipulated TWAP",
        ],
        indicators=[
            "oracle.observe()",
            "OracleLibrary.consult()",
            "Short TWAP window (< 600 seconds)",
            "observe([window, 0])",
        ],
        successful_exploits=1,  # DVD Puppet V3
        failed_attempts=0,
        confidence=0.75,  # Harder to execute
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["PuppetV3Pool"],
        discovered_by="dvd_analysis",
        source_contract="PuppetV3Pool",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_oracle_private_key_leak",
        name="Oracle Private Key Compromise",
        vuln_type="oracle_manipulation",
        description=(
            "Oracle price submissions signed by private key. "
            "If key is leaked, attacker can submit arbitrary prices."
        ),
        preconditions=[
            "Off-chain oracle with signature verification",
            "Private key stored insecurely",
            "No additional validation on submitted prices",
            "Price can be used immediately",
        ],
        attack_steps=[
            "Obtain oracle private key (leak, weak entropy, etc)",
            "Sign malicious price data",
            "Submit crafted prices to contract",
            "Exploit using manipulated prices",
        ],
        indicators=[
            "ecrecover(hash, v, r, s) == oracle",
            "Off-chain price signing",
            "No sanity checks on price (deviation, staleness)",
        ],
        successful_exploits=1,  # DVD Compromised
        failed_attempts=0,
        confidence=0.80,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["TrustfulOracle"],
        discovered_by="dvd_analysis",
        source_contract="TrustfulOracle",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_oracle_readonly_reentrancy",
        name="Read-Only Reentrancy via Oracle",
        vuln_type="reentrancy_readonly",
        description=(
            "Contract reads oracle/pool state during callback. "
            "State is inconsistent mid-transaction, oracle returns wrong value."
        ),
        preconditions=[
            "Contract reads external state (oracle, pool reserves)",
            "Read happens during callback from external contract",
            "External state is temporarily inconsistent",
            "No reentrancy guard on view functions",
        ],
        attack_steps=[
            "Trigger callback from external contract (e.g., Curve pool)",
            "During callback, external state is inconsistent",
            "Call target contract's view function",
            "View function reads inconsistent state",
            "Returns wrong value (price, balance, etc)",
            "Use wrong value to extract value from target",
        ],
        indicators=[
            "Reading external contract state in view function",
            "No reentrancy protection on views",
            "Curve pool or similar with callbacks",
            "Uses pool.get_virtual_price() or similar",
        ],
        successful_exploits=1,  # DVD Curvy Puppet
        failed_attempts=0,
        confidence=0.70,  # Complex attack
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["CurvyPuppetLending"],
        discovered_by="dvd_analysis",
        source_contract="CurvyPuppetLending",
    ))


    patterns.append(VulnerabilityPattern(
        id="dvd_logic_payment_before_transfer",
        name="Payment Before Transfer Logic Bug",
        vuln_type="logic_error",
        description=(
            "Contract pays for NFT before receiving it. "
            "Attacker can take payment without transferring NFT."
        ),
        preconditions=[
            "Contract sends ETH/tokens before receiving asset",
            "No validation that asset was received",
            "Multiple assets in single transaction",
            "Payment amount based on batch size",
        ],
        attack_steps=[
            "Offer to sell N NFTs to contract",
            "Contract calculates payment = N * price",
            "Contract sends payment",
            "Transfer only M < N NFTs (or none)",
            "Keep payment for N NFTs",
        ],
        indicators=[
            "value.transfer() or .call{value:} before safeTransferFrom",
            "Payment before receive",
            "No validation of received amount",
        ],
        successful_exploits=1,  # DVD Free Rider
        failed_attempts=0,
        confidence=0.85,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["FreeRiderNFTMarketplace"],
        discovered_by="dvd_analysis",
        source_contract="FreeRiderNFTMarketplace",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_logic_unvalidated_initialization",
        name="Unvalidated Proxy Initialization",
        vuln_type="logic_error",
        description=(
            "Proxy wallet allows initialization by anyone. "
            "Attacker becomes owner by calling setup()."
        ),
        preconditions=[
            "Proxy contract (Gnosis Safe, etc)",
            "setup() or initialize() callable by anyone",
            "No validation on initialization",
            "Contract holds or will receive funds",
        ],
        attack_steps=[
            "Identify uninitialized proxy",
            "Call setup(attacker, ...) or initialize(attacker)",
            "Become owner/admin",
            "Drain funds or execute arbitrary calls",
        ],
        indicators=[
            "delegatecall to implementation.setup()",
            "No initialized check",
            "No access control on setup",
        ],
        successful_exploits=1,  # DVD Backdoor
        failed_attempts=0,
        confidence=0.85,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["WalletRegistry"],
        discovered_by="dvd_analysis",
        source_contract="WalletRegistry",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_logic_timelock_bypass",
        name="Timelock Logic Bypass",
        vuln_type="logic_error",
        description=(
            "Timelock allows scheduling and executing in same transaction. "
            "Attacker bypasses time delay by exploiting execution logic."
        ),
        preconditions=[
            "Timelock with schedule() and execute()",
            "execute() doesn't check if delay has passed",
            "Or can manipulate state to bypass check",
            "Critical functions behind timelock",
        ],
        attack_steps=[
            "Schedule malicious proposal",
            "Exploit logic bug to execute immediately",
            "Bypass time delay entirely",
            "Execute privileged action",
        ],
        indicators=[
            "schedule() and execute() in same contract",
            "Weak delay validation",
            "State manipulation possible",
        ],
        successful_exploits=1,  # DVD Climber
        failed_attempts=0,
        confidence=0.75,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["ClimberTimelock"],
        discovered_by="dvd_analysis",
        source_contract="ClimberTimelock",
    ))


    patterns.append(VulnerabilityPattern(
        id="dvd_reward_timing_manipulation",
        name="Reward Distribution Timing Attack",
        vuln_type="reward_manipulation",
        description=(
            "Rewards distributed based on snapshot at specific time. "
            "Flash loan → deposit → claim rewards → withdraw → return."
        ),
        preconditions=[
            "Rewards distributed periodically (daily, weekly)",
            "Snapshot taken at specific block/time",
            "No minimum stake duration",
            "Flash loan available for stake token",
        ],
        attack_steps=[
            "Flash loan stake tokens",
            "Deposit into reward contract",
            "Wait for reward snapshot",
            "Claim accumulated rewards",
            "Withdraw stake",
            "Return flash loan",
            "Keep rewards without real stake",
        ],
        indicators=[
            "snapshot() function at fixed interval",
            "Rewards based on balance at snapshot time",
            "No minimum stake duration",
            "isNewRewardsRound() or similar timing logic",
        ],
        successful_exploits=1,  # DVD The Rewarder
        failed_attempts=0,
        confidence=0.85,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["TheRewarderPool"],
        discovered_by="dvd_analysis",
        source_contract="TheRewarderPool",
    ))


    patterns.append(VulnerabilityPattern(
        id="dvd_create2_address_mining",
        name="CREATE2 Address Mining",
        vuln_type="address_manipulation",
        description=(
            "Contract trusts addresses based on predictable CREATE2. "
            "Attacker mines salt to create address with specific properties."
        ),
        preconditions=[
            "Contract uses CREATE2 for deployment",
            "Address properties used for access control",
            "Salt is controllable or predictable",
            "Mining is economically feasible",
        ],
        attack_steps=[
            "Calculate CREATE2 address formula",
            "Mine salt to get address with desired property",
            "Deploy contract at mined address",
            "Exploit access control based on address",
        ],
        indicators=[
            "CREATE2 deployment",
            "Access control based on address properties",
            "User-controllable salt",
        ],
        successful_exploits=1,  # DVD Wallet Mining
        failed_attempts=0,
        confidence=0.70,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["WalletDeployer"],
        discovered_by="dvd_analysis",
        source_contract="WalletDeployer",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_abi_smuggling",
        name="ABI Encoding Manipulation",
        vuln_type="encoding_manipulation",
        description=(
            "Contract decodes ABI-encoded data with multiple interpretations. "
            "Attacker crafts data that decodes differently based on context."
        ),
        preconditions=[
            "Contract decodes same data multiple times",
            "Different decoding contexts/offsets",
            "No validation of encoded structure",
            "Critical decision based on decoded values",
        ],
        attack_steps=[
            "Analyze ABI decoding logic",
            "Craft data with multiple valid interpretations",
            "First decode passes validation",
            "Second decode triggers exploit",
        ],
        indicators=[
            "Multiple abi.decode() on same data",
            "Manual offset manipulation",
            "Complex nested encoding",
        ],
        successful_exploits=1,  # DVD ABI Smuggling
        failed_attempts=0,
        confidence=0.65,  # Very complex
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["AuthorizedExecutor"],
        discovered_by="dvd_analysis",
        source_contract="AuthorizedExecutor",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_merkle_proof_replay",
        name="Merkle Proof Replay Attack",
        vuln_type="merkle_proof",
        description=(
            "Merkle tree allows claiming same leaf multiple times. "
            "Missing nullifier or claimed tracking."
        ),
        preconditions=[
            "Contract uses Merkle tree for claims/withdrawals",
            "No tracking of claimed leaves",
            "Proof verification only checks validity, not uniqueness",
            "Valuable claims available",
        ],
        attack_steps=[
            "Generate valid Merkle proof for claim",
            "Submit proof and claim",
            "Submit same proof again",
            "Claim multiple times with single proof",
        ],
        indicators=[
            "MerkleProof.verify() without claimed mapping",
            "No nullifier for leaf hash",
            "No storage of processed claims",
        ],
        successful_exploits=1,  # DVD Withdrawal
        failed_attempts=0,
        confidence=0.80,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["L1Gateway"],
        discovered_by="dvd_analysis",
        source_contract="L1Gateway",
    ))

    patterns.append(VulnerabilityPattern(
        id="dvd_nft_fractionalization",
        name="NFT Fractionalization Exploit",
        vuln_type="fractionalization",
        description=(
            "NFT fractionalization allows buying back original NFT for less than market value. "
            "Economic arbitrage through fraction mechanics."
        ),
        preconditions=[
            "NFT split into fungible fractions",
            "Buyback price based on fraction price",
            "Fraction price manipulable via DEX",
            "NFT worth more than buyback cost",
        ],
        attack_steps=[
            "Manipulate fraction token price downward",
            "Trigger buyback at low price",
            "Acquire valuable NFT cheaply",
            "Profit = NFT value - buyback cost",
        ],
        indicators=[
            "NFT fractionalization contract",
            "Buyback based on token price",
            "Price from DEX (manipulable)",
        ],
        successful_exploits=1,  # DVD Shards
        failed_attempts=0,
        confidence=0.75,
        status=PatternStatus.VALIDATED,
        contracts_vulnerable=["ShardsNFTMarketplace"],
        discovered_by="dvd_analysis",
        source_contract="ShardsNFTMarketplace",
    ))


    patterns.append(VulnerabilityPattern(
        id="comp_flash_oracle_reentrancy",
        name="Flash Loan + Oracle + Reentrancy Composition",
        vuln_type="compositional",
        description=(
            "Combine flash loan, oracle manipulation, and reentrancy for complex exploit. "
            "Each vector alone insufficient, but composition breaks contract."
        ),
        preconditions=[
            "Contract has reentrancy vulnerability (but not directly exploitable)",
            "Contract uses oracle for critical decision",
            "Flash loan available to manipulate oracle",
            "Reentrancy during oracle read possible",
        ],
        attack_steps=[
            "Flash loan tokens",
            "Manipulate oracle (swap to change price)",
            "Trigger reentrant call",
            "During reentrancy, oracle reads manipulated state",
            "Extract value based on wrong oracle price",
            "Restore state and return flash loan",
        ],
        indicators=[
            "Combination of: flash loans + spot price oracle + callbacks",
            "Multiple attack surfaces in one contract",
            "Complex state dependencies",
        ],
        successful_exploits=0,
        failed_attempts=0,
        confidence=0.60,  # Theoretical until proven
        status=PatternStatus.UNVALIDATED,
        discovered_by="system_synthesis",
    ))

    patterns.append(VulnerabilityPattern(
        id="comp_flash_governance_oracle",
        name="Flash Loan + Governance + Oracle Composition",
        vuln_type="compositional",
        description=(
            "Flash loan voting power to pass governance proposal that manipulates oracle. "
            "Then exploit using manipulated oracle."
        ),
        preconditions=[
            "Governance controlled by token balance",
            "Governance can update oracle or oracle parameters",
            "Same-block proposal/execution possible",
            "Flash loan for governance token available",
        ],
        attack_steps=[
            "Flash loan governance tokens",
            "Propose and execute oracle parameter change",
            "Manipulate oracle with new parameters",
            "Exploit contract using manipulated oracle",
            "Restore oracle (if profitable)",
            "Return flash loan",
        ],
        indicators=[
            "Token-based governance + oracle management",
            "Quick governance execution",
            "Flash loan capability",
        ],
        successful_exploits=0,
        failed_attempts=0,
        confidence=0.55,
        status=PatternStatus.UNVALIDATED,
        discovered_by="system_synthesis",
    ))

    return patterns


def seed_kb(kb: KnowledgeBase) -> int:
    """seed kb with dvd patterns"""
    patterns = get_dvd_patterns()

    count = 0
    for pattern in patterns:
        kb.add_pattern(pattern)
        count += 1

    # Save to disk
    kb.save()

    return count


if __name__ == "__main__":
    # Test seeding
    from kb.knowledge_base import KnowledgeBase

    print("Seeding Knowledge Base with DVD patterns...")
    kb = KnowledgeBase()
    count = seed_kb(kb)

    print(f"[PASS] Seeded {count} vulnerability patterns")
    print(f"  - Validated patterns: {sum(1 for p in kb.patterns.values() if p.status == PatternStatus.VALIDATED)}")
    print(f"  - Unvalidated patterns: {sum(1 for p in kb.patterns.values() if p.status == PatternStatus.UNVALIDATED)}")
    print(f"  - Average confidence: {sum(p.confidence for p in kb.patterns.values()) / len(kb.patterns):.2f}")
    print()
    print("Top patterns by confidence:")
    sorted_patterns = sorted(kb.patterns.values(), key=lambda p: p.confidence, reverse=True)
    for i, pattern in enumerate(sorted_patterns[:5], 1):
        print(f"  {i}. {pattern.name} ({pattern.confidence:.2f})")

    print()
    print(f"KB saved to: {config.KB_PATTERNS_FILE}")
