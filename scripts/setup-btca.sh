#!/usr/bin/env bash
set -euo pipefail

# setup-btca.sh — One-time per-device btca bootstrap for the npw project.
#
# What this script does:
#   1. Verifies bun is installed (prompts to install if missing)
#   2. Installs btca globally via bun
#   3. Prompts for LLM provider authentication
#   4. Detects installed AI agents and reports MCP readiness
#
# Agent MCP configs are already committed to the repo:
#   - Claude Code:  .mcp.json
#   - Codex CLI:    .codex/config.toml
#   - OpenCode:     opencode.json
#
# btca resources are defined in btca.config.jsonc (also committed).
# This script handles the per-device parts that can't be committed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== btca setup for npw ==="
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
echo "Credentials are stored per-device in OpenCode's auth storage"
echo "(~/.local/share/opencode/auth.json) — never committed to git."
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

# ── 4. Detect agents and report MCP readiness ───────────────────────
echo ""
echo "=== Agent MCP status ==="
echo ""

agents_found=0

if command -v claude &>/dev/null; then
    agents_found=$((agents_found + 1))
    echo "[ok] Claude Code detected"
    echo "     MCP config: .mcp.json (committed)"
    echo "     On next session, approve 'btca-local' when prompted."
fi

if command -v codex &>/dev/null; then
    agents_found=$((agents_found + 1))
    echo "[ok] Codex CLI detected ($(codex --version 2>/dev/null || echo '?'))"
    echo "     MCP config: .codex/config.toml (committed)"
    echo "     Trust this project when Codex prompts on first run."
fi

if command -v opencode &>/dev/null; then
    agents_found=$((agents_found + 1))
    echo "[ok] OpenCode detected ($(opencode --version 2>/dev/null || echo '?'))"
    echo "     MCP config: opencode.json (committed)"
    echo "     btca-local MCP server will load automatically."
fi

if [ "$agents_found" -eq 0 ]; then
    echo "[--] No supported agents detected (Claude Code, Codex CLI, OpenCode)."
    echo "     btca still works standalone: btca ask -r svelte -q '...'"
    echo ""
    echo "     To add MCP support for another agent, configure a stdio"
    echo "     MCP server with command: bunx btca mcp"
fi

# ── 5. Optional: btca skill installer ───────────────────────────────
echo ""
echo "btca offers an optional skill installer (interactive)."
echo "This may add slash commands or integrations for supported agents."
echo ""
read -rp "Run 'btca skill' installer? [y/N] " skill_confirm
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
echo "In any supported agent session, btca MCP tools (listResources, ask)"
echo "are available automatically via the committed config files."
