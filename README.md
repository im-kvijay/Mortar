# Mortar

Automated smart contract security auditor that discovers vulnerabilities and generates executable Foundry proof-of-concept exploits.

## What It Does

Mortar analyzes Solidity contracts through a multi-stage pipeline:

1. **Discovery** - Parses contracts, runs Slither static analysis, maps attack surfaces
2. **Research** - Parallel AI specialists analyze state flows, invariants, access control, economic risks
3. **Attack** - Specialized modules target flash loans, oracle manipulation, reentrancy, logic flaws
4. **PoC Generation** - Creates Foundry test files that demonstrate exploits
5. **Verification** - Z3 formal verification + multi-tool ensemble validates findings
6. **Learning** - Bayesian knowledge base improves accuracy over time

## Installation

```bash
# clone
git clone https://github.com/im-kvijay/Mortar.git
cd Mortar

# foundry (required)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# solidity dependencies
forge install

# python dependencies
pip install -r requirements.txt

# optional: damn vulnerable defi test suite
mkdir -p training && cd training
git clone https://github.com/theredguild/damn-vulnerable-defi.git
cd damn-vulnerable-defi && forge install && cd ../..
```

## Configuration

Set your API key:

```bash
export OPENROUTER_API_KEY=your-key
# or
export XAI_API_KEY=your-key
```

See `.env.example` for all options. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND` | `openrouter` | LLM provider: `openrouter`, `xai`, `anthropic` |
| `MODEL` | `x-ai/grok-4.1-fast` | Model to use |
| `OFFLINE_MODE` | `0` | Set to `1` for template-only mode (no LLM) |
| `VERIFICATION_WORKERS` | `1` | Parallel verification threads |
| `POC_GEN_MODE` | `ai` | PoC generation: `ai`, `template`, `hybrid` |

**Note on model selection**: The default `grok-4.1-fast` was chosen purely for low cost during development. For better audit quality, use stronger models like `anthropic/claude-sonnet-4` or `anthropic/claude-opus-4`.

## Usage

```bash
# audit a single contract
python main.py --contract path/to/Contract.sol

# audit a foundry project
python main.py --project path/to/project

# run damn vulnerable defi challenge (1-18)
python main.py --dvd 16

# use CLI with execution profiles
python scripts/mortar_cli.py --profile balanced dvd 16
python scripts/mortar_cli.py --profile thorough contract MyContract.sol

# offline mode (no API calls)
OFFLINE_MODE=1 python main.py --contract Contract.sol
```

## Output

Results are saved to `data/`:

```
data/
├── reports/          # markdown vulnerability reports
├── pocs/             # generated solidity exploit files
├── artifacts/        # reproducible sandbox archives
├── logs/             # execution logs and metrics
└── kb/               # learned patterns and knowledge
```

To reproduce a finding:

```bash
# extract and run the archived PoC
tar -xzf data/artifacts/poc_sbx_xxx.tar.gz -C /tmp/poc
cd /tmp/poc && forge test --match-test testExploit -vvv
```

## Project Structure

```
Mortar/
├── main.py              # entry point
├── src/
│   ├── cal/             # contract analysis layer
│   ├── research/        # ai specialist modules
│   ├── agent/           # attack orchestration
│   ├── verification/    # z3, fuzzing, ensemble
│   ├── kb/              # knowledge base
│   └── utils/           # logging, llm backends
├── tests/
│   ├── unit/            # unit tests
│   └── integration/     # integration tests
├── training/            # test fixtures (dvd)
└── data/                # runtime output
```

## Testing

```bash
# all unit tests
pytest tests/unit/

# specific test file
pytest tests/unit/test_knowledge_base.py

# with coverage
pytest tests/unit/ --cov=src
```

## How It Works

**Research Phase**: Six parallel specialists analyze the contract:
- StateFlow - tracks state variable mutations
- Invariant - identifies broken invariants
- BusinessLogic - spots logic flaws
- Economic - models profit extraction
- Dependency - traces cross-contract calls
- AccessControl - checks permission bypasses

**Attack Phase**: Specialists generate hypotheses ranked by:
- Confidence score from analysis
- Economic profit potential
- Historical pattern matches from KB

**Verification Phase**: Each hypothesis goes through:
- Z3 constraint solving for formal proofs
- Slither confirmation of static findings
- Foundry execution to validate exploits
- Ensemble voting across multiple tools

**Learning Phase**: Results feed back to improve future audits:
- Successful exploits strengthen patterns
- False positives create anti-patterns
- Specialist accuracy is tracked per vulnerability type

## Requirements

- Python 3.11+
- Foundry (forge, cast, anvil)
- Slither (optional, for static analysis)
- API key for OpenRouter, xAI, or Anthropic

## License

Proprietary.
