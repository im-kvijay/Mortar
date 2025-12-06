#!/bin/bash
set -e

echo "=========================================="
echo "mortar-c diagnostic report"
echo "generated: $(date)"
echo "=========================================="
echo ""

echo "=========================================="
echo "system information"
echo "=========================================="
echo "os: $(uname -s)"
echo "arch: $(uname -m)"
echo "kernel: $(uname -r)"
echo ""

echo "=========================================="
echo "python environment"
echo "=========================================="
echo "python version:"
python --version || echo "error: python not found"
echo ""
echo "python location:"
which python || echo "error: python not in path"
echo ""
echo "virtual environment:"
echo $VIRTUAL_ENV || echo "warning: no venv active"
echo ""
echo "pip version:"
pip --version || echo "error: pip not found"
echo ""

echo "=========================================="
echo "foundry toolchain"
echo "=========================================="
echo "forge version:"
forge --version 2>&1 | head -5 || echo "error: forge not found"
echo ""
echo "forge location:"
which forge || echo "error: forge not in path"
echo ""
echo "cast version:"
cast --version 2>&1 | head -1 || echo "error: cast not found"
echo ""
echo "anvil version:"
anvil --version 2>&1 | head -1 || echo "error: anvil not found"
echo ""

echo "=========================================="
echo "static analysis tools"
echo "=========================================="
echo "slither version:"
slither --version || echo "error: slither not found"
echo ""
echo "slither location:"
which slither || echo "error: slither not in path"
echo ""

echo "=========================================="
echo "python packages"
echo "=========================================="
echo "core packages:"
pip list | grep -E "anthropic|openai|xai-sdk|slither-analyzer|web3|z3-solver" || echo "warning: some packages missing"
echo ""

echo "=========================================="
echo "environment variables"
echo "=========================================="
echo "xai_api_key: ${XAI_API_KEY:+SET (hidden)}"
echo "openrouter_api_key: ${OPENROUTER_API_KEY:+SET (hidden)}"
echo "backend: ${BACKEND:-not set (defaults to openrouter)}"
echo "model: ${MODEL:-not set (defaults to x-ai/grok-4.1-fast)}"
echo "offline_mode: ${OFFLINE_MODE:-0}"
echo "fresh_analysis: ${FRESH_ANALYSIS:-0}"
echo "enable_context_compression: ${ENABLE_CONTEXT_COMPRESSION:-1}"
echo ""

echo "=========================================="
echo "project structure"
echo "=========================================="
echo "project root: $(pwd)"
echo ""
echo "key directories:"
[ -d "data" ] && echo "✓ data/" || echo "✗ data/"
[ -d "data/kb" ] && echo "✓ data/kb/" || echo "✗ data/kb/"
[ -d "data/logs" ] && echo "✓ data/logs/" || echo "✗ data/logs/"
[ -d "training/damn-vulnerable-defi" ] && echo "✓ training/damn-vulnerable-defi/" || echo "✗ training/damn-vulnerable-defi/"
[ -d "src" ] && echo "✓ src/" || echo "✗ src/"
echo ""

echo "=========================================="
echo "dvd fixtures"
echo "=========================================="
if [ -d "training/damn-vulnerable-defi" ]; then
    echo "dvd checkout: ok"
    echo "dvd foundry.toml:"
    grep -E "evm_version|solc_version" training/damn-vulnerable-defi/foundry.toml 2>/dev/null || echo "warning: no evm_version set"
    echo ""
    echo "dvd compilation check:"
    cd training/damn-vulnerable-defi
    if forge build --force 2>&1 | grep -q "Compiler run successful"; then
        echo "✓ dvd contracts compile"
    else
        echo "✗ dvd compilation failed (run: cd training/damn-vulnerable-defi && forge build)"
    fi
    cd - > /dev/null
else
    echo "error: dvd not cloned"
fi
echo ""

echo "=========================================="
echo "network connectivity"
echo "=========================================="
echo "api endpoints:"
curl -I -s -m 5 https://api.openrouter.ai 2>&1 | head -1 | grep -q "200" && echo "✓ openrouter api" || echo "✗ openrouter api"
curl -I -s -m 5 https://api.x.ai 2>&1 | head -1 | grep -q "200" && echo "✓ xai api" || echo "✗ xai api"
echo ""

echo "=========================================="
echo "mortar-c configuration"
echo "=========================================="
python -c "from config import config; print(config.summary())" 2>&1 || echo "error: config validation failed"
echo ""

echo "=========================================="
echo "knowledge base status"
echo "=========================================="
if [ -f "data/kb/index.json" ]; then
    python -c "
from kb.knowledge_base import KnowledgeBase
kb = KnowledgeBase()
try:
    kb.load()
    kb.print_stats()
except Exception as e:
    print(f'error: kb load failed: {e}')
" 2>&1
else
    echo "kb not initialized"
fi
echo ""

echo "=========================================="
echo "lock files"
echo "=========================================="
if ls data/kb/*.lock 1> /dev/null 2>&1; then
    echo "warning: lock files found (may indicate hung process):"
    ls -lh data/kb/*.lock
else
    echo "✓ no lock files"
fi
echo ""

echo "=========================================="
echo "resource usage"
echo "=========================================="
echo "disk space (data/):"
du -sh data/ 2>/dev/null || echo "n/a"
echo ""
echo "memory usage (python processes):"
ps aux | grep python | grep -v grep | awk '{print "pid: " $2 " memory: " $6 " kb"}' || echo "no python processes"
echo ""

echo "=========================================="
echo "recent errors (last 10)"
echo "=========================================="
if [ -d "data/logs" ]; then
    grep -h -i "error\|failed" data/logs/*.log 2>/dev/null | tail -10 || echo "no recent errors"
else
    echo "no logs directory"
fi
echo ""

echo "=========================================="
echo "recent runs"
echo "=========================================="
if [ -d "data/runs" ]; then
    echo "last 3 run profiles:"
    ls -lt data/runs/*.json 2>/dev/null | head -3 || echo "no run profiles"
else
    echo "no runs directory"
fi
echo ""

echo "=========================================="
echo "diagnostic complete"
echo "=========================================="
echo ""
echo "next steps:"
echo "1. check for error/warning messages above"
echo "2. consult docs/troubleshooting.md"
echo "3. minimal test: OFFLINE_MODE=1 python main.py --dvd 1 --no-sniper --no-jit --no-kb"
echo ""
