#!/usr/bin/env bash
set -euo pipefail

# setup-btca.sh — One-time per-device btca bootstrap.
#
# What this script does:
#   1. Verifies bun is installed (prompts to install if missing)
#   2. Installs btca globally via bun
#   3. Prompts for LLM provider authentication
#   4. Registers btca as a global MCP server for detected agents
#   5. Optionally runs btca's skill installer
#
# Per-project resources are defined in btca.config.jsonc (committed to repo).
# This script handles the per-device parts that can't be committed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== btca setup ==="
echo "Project: $PROJECT_DIR"
echo ""

# ── 1. Check for bun ────────────────────────────────────────────────
if ! command -v bun &>/dev/null; then
    echo "[!] bun is not installed."
    echo "    btca requires bun as its runtime."
    echo "    Official installer: https://bun.sh"
    echo ""
    read -rp "Install bun now? (installs to ~/.bun) [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        curl -fsSL https://bun.sh/install | bash
        export BUN_INSTALL="${BUN_INSTALL:-$HOME/.bun}"
        export PATH="$BUN_INSTALL/bin:$PATH"
    else
        echo "Aborting. Install bun manually, then re-run this script."
        exit 1
    fi
fi
echo "[ok] bun $(bun --version)"

# ── 2. Install btca ─────────────────────────────────────────────────
if ! command -v btca &>/dev/null; then
    echo "[..] Installing btca globally..."
    bun add -g btca
else
    echo "[ok] btca $(btca --version 2>/dev/null || echo 'installed')"
fi

# ── 3. Provider authentication ──────────────────────────────────────
echo ""
echo "btca needs an LLM provider to process search queries."
echo "Credentials are stored per-device (~/.local/share/opencode/auth.json)"
echo "and are never committed to git."
echo ""
echo "Supported providers:"
echo "  opencode        - API key (default)"
echo "  anthropic       - API key"
echo "  openai          - OAuth (browser sign-in, no key needed)"
echo "  github-copilot  - OAuth (device flow, no key needed)"
echo "  openrouter      - API key"
echo "  google          - API key or OAuth"
echo "  openai-compat   - Custom endpoint"
echo ""
read -rp "Run 'btca connect' to authenticate now? [Y/n] " auth_confirm
if [[ ! "$auth_confirm" =~ ^[Nn]$ ]]; then
    btca connect
fi

# ── 4. Register btca as global MCP server ────────────────────────────
echo ""
echo "=== Registering btca-local MCP server globally ==="
echo ""

# Claude Code
if command -v claude &>/dev/null; then
    if claude mcp list 2>/dev/null | grep -q btca-local; then
        echo "[ok] Claude Code: btca-local already registered"
    else
        claude mcp add --transport stdio btca-local --scope user -- bunx btca mcp 2>/dev/null \
            && echo "[ok] Claude Code: btca-local registered (user scope)" \
            || echo "[!!] Claude Code: failed to register btca-local"
    fi
fi

# Codex CLI
if command -v codex &>/dev/null; then
    if grep -q 'btca-local' ~/.codex/config.toml 2>/dev/null; then
        echo "[ok] Codex CLI: btca-local already in ~/.codex/config.toml"
    else
        cat >> ~/.codex/config.toml <<'TOML'

[mcp_servers.btca-local]
command = "bunx"
args = ["btca", "mcp"]
startup_timeout_sec = 15.0
TOML
        echo "[ok] Codex CLI: btca-local added to ~/.codex/config.toml"
    fi
fi

# OpenCode
if command -v opencode &>/dev/null; then
    OC_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/opencode/opencode.json"
    if [ -f "$OC_CONFIG" ] && grep -q 'btca-local' "$OC_CONFIG" 2>/dev/null; then
        echo "[ok] OpenCode: btca-local already in $OC_CONFIG"
    else
        echo "[!!] OpenCode: add btca-local manually to $OC_CONFIG"
        echo "     Add to the \"mcp\" object:"
        echo '     "btca-local": {'
        echo '       "type": "local",'
        echo '       "command": ["bunx", "btca", "mcp"],'
        echo '       "enabled": true,'
        echo '       "timeout": 15000'
        echo '     }'
    fi
fi

# Generic fallback
if ! command -v claude &>/dev/null && ! command -v codex &>/dev/null && ! command -v opencode &>/dev/null; then
    echo "[--] No supported agents detected."
    echo "     btca works standalone: btca ask -r svelte -q '...'"
    echo "     For any MCP-compatible agent, configure a stdio server:"
    echo "       command: bunx btca mcp"
fi

# ── 5. Optional: btca skill installer ───────────────────────────────
echo ""
read -rp "Run 'btca skill' installer (optional agent integrations)? [y/N] " skill_confirm
if [[ "$skill_confirm" =~ ^[Yy]$ ]]; then
    btca skill
fi

# ── Done ─────────────────────────────────────────────────────────────
echo ""
echo "=== Setup complete ==="
echo ""
echo "btca resources (from btca.config.jsonc):"
cd "$PROJECT_DIR" && btca resources 2>/dev/null || echo "  (run 'btca resources' to list)"
echo ""
echo "Quick start:"
echo "  btca                              # Interactive TUI"
echo "  btca ask -r svelte -q '...'       # One-shot query"
echo "  btca resources                    # List configured resources"
echo "  btca serve                        # Start local API server (port 8080)"
echo ""
echo "btca MCP tools (listResources, ask) are available globally"
echo "in all agent sessions. Per-project resources are loaded from"
echo "btca.config.jsonc when you work inside a project directory."
