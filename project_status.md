# Project Status: MCP Attack Surface Detector

**Current Version:** 0.5.0 (Alpha)
**Build Status:** Stable / Feature Complete for Phase 2

## Development Phases

### Phase 1: Core Infrastructure (Completed)
*   **Transport:** SSE & WebSocket support.
*   **Discovery:** Auto-enumeration of Tools, Resources, Prompts.
*   **Bridging:** Synchronous Burp (Repeater/Intruder) <-> Asynchronous MCP Proxy.

### Phase 2: Automation & Authentication (Completed)
*   **Authentication:**
    *   Custom HTTP Headers (OAuth/API Keys).
    *   mTLS (Client Certificates).
    *   Initialization Parameter Injection.
*   **Automated Scanning:**
    *   Basic Active Scanner Engine.
    *   Checks: Type Confusion, Input Reflection, BOLA (Resources).
*   **Verification:** Verified against local `mcp_server.py`.

### Phase 3: Advanced Capabilities (Planned)
*   **Native Integration:** Report issues to Burp Target/Dashboard (`IScanIssue`).
*   **Deep Fuzzing:** Recursive JSON schema parsing for complex objects.
*   **Intelligent Payloads:** LLM-assisted or context-aware payload selection.