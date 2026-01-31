# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HexStrike AI v6.0 is an AI-powered MCP (Model Context Protocol) cybersecurity automation platform. It integrates AI agents with 150+ penetration testing tools through a two-script architecture.

## Architecture

**Two-Script System:**
- `hexstrike_server.py` (~17K lines) - RESTful API server exposing security tools via Flask
- `hexstrike_mcp.py` (~5.5K lines) - MCP client that connects AI agents to the server

**Communication Flow:**
```
AI Agent (Claude/GPT/Copilot) <-> MCP Client <-> REST API Server <-> Security Tools
```

**Key Architectural Components:**
- `IntelligentDecisionEngine` - AI-powered tool selection and parameter optimization
- `BugBountyWorkflowManager` / `CTFWorkflowManager` - Automated security workflows
- `AIExploitGenerator` - Generates exploits (SQLi, XSS, RCE, buffer overflow, etc.)
- `BrowserAgent` - Headless Chrome automation with DOM analysis
- `IntelligentErrorHandler` / `FailureRecoverySystem` - Fault tolerance
- `AdvancedCache` - LRU caching with TTL for performance

## Commands

### Starting the Server
```bash
# Activate virtual environment first
source hexstrike-env/bin/activate  # Linux/Mac
# or
hexstrike-env\Scripts\activate     # Windows

# Start server (default port 8888)
python3 hexstrike_server.py

# With debug mode
python3 hexstrike_server.py --debug

# Custom port
python3 hexstrike_server.py --port 9999
```

### Starting the MCP Client
```bash
python3 hexstrike_mcp.py --server http://localhost:8888

# With options
python3 hexstrike_mcp.py --server http://localhost:8888 --timeout 300 --debug
```

### Verify Server Health
```bash
curl http://localhost:8888/health
```

### Environment Variables
- `HEXSTRIKE_PORT` - Override default API port (8888)
- `HEXSTRIKE_HOST` - Override default host (127.0.0.1)
- `DEBUG_MODE` - Enable verbose logging

## API Structure

**Core endpoints pattern:** `/api/<category>/<action>`

Key categories:
- `/api/tools/*` - Direct security tool execution (nmap, sqlmap, nuclei, etc.)
- `/api/intelligence/*` - AI decision engine (analyze-target, select-tools, create-attack-chain)
- `/api/bugbounty/*` - Automated workflows (reconnaissance, vulnerability-hunting, osint)
- `/api/processes/*` - Process management (list, status, terminate, pause, resume)
- `/api/files/*` - File operations (create, modify, delete, list)
- `/health` - Server health and tool availability check

## Code Patterns

**Tool endpoint pattern** (in hexstrike_server.py):
```python
@app.route('/api/tools/<toolname>', methods=['POST'])
def tool_endpoint():
    data = request.get_json()
    # Validate and execute tool
    # Return JSON response
```

**MCP tool pattern** (in hexstrike_mcp.py):
```python
@mcp.tool()
def tool_name(param: str) -> str:
    """Tool description"""
    response = requests.post(f"{MCP_SERVER}/api/tools/...", json={...})
    return response.json()
```

## Configuration

Default settings (in code):
- `COMMAND_TIMEOUT`: 300 seconds
- `CACHE_SIZE`: 1000 entries
- `CACHE_TTL`: 3600 seconds
- `CONNECTION_RETRIES`: 3

MCP client configuration template: `hexstrike-ai-mcp.json`

## Dependencies

Core: Flask, Requests, psutil, fastmcp
Web automation: BeautifulSoup4, Selenium, webdriver-manager
Binary analysis: pwntools, angr
See `requirements.txt` for complete list with versions.

## Security Notes

- This tool executes arbitrary system commands - use only in isolated/VM environments
- All testing requires proper authorization
- Designed for authorized penetration testing, bug bounty programs, and CTF competitions
