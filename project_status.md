# Project Status and Next Steps: MCP Attack Surface Detector (MCP-ASD)

## Phase 1 Status: COMPLETE ✅

**Key Accomplishments:**
*   **Architecture:** Modular Transport Layer (SSE + WebSocket) fully implemented.
*   **Core Engine:** `EnumerationEngine` successfully discovers Tools, Resources, and Prompts.
*   **Stitching:** `McpProxy` (Internal Server) successfully bridges Burp Intruder/Repeater to asynchronous MCP traffic with ID auto-generation.
*   **UI:** 3-Pane Dashboard, Status Indicators, and robust Connection Dialog with Auto-Detection.
*   **Reliability:** Fixed threading issues, DNS resolution bugs, and socket connection flaws.

## Phase 2: Automation & Authentication (IN PROGRESS)

### 1. Authentication Support
**Priority:** High
**Objective:** Connect to secured MCP servers.
*   [x] Update `ConnectionDialog` to accept custom HTTP Headers (Authorization).
*   [x] Propagate headers to `SseTransport` and `WebSocketTransport`.
*   [x] Implement mTLS support in `OkHttp` client for SSE and WebSocket.
*   [ ] Support Auth Payloads in JSON-RPC `initialize`.

### 2. Automated Vulnerability Scanning
**Priority:** High
**Objective:** Active audit of MCP Primitives.
*   [x] **Infrastructure:** Create `SecurityTester` module and link to UI.
*   [x] **Type Confusion:** Fuzz tool arguments with invalid types and check for crashes/leaks.
*   [x] **Injection:** Probe String arguments for injection markers and check for reflection.
*   [ ] **BOLA:** Iterate Resource URIs.

### 3. Test Environment
*   [x] Update `mcp_server.py` to support Authentication (Header check).
*   [x] Add vulnerable endpoints to `mcp_server.py` for scanner verification (`echo_input`, `crash_me`).


---
**Current Build:** Stable
**Version:** 2.0 (Phase 2 Initial)
