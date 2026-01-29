# MCP Attack Surface Detector (MCP-ASD)

MCP-ASD is a Burp Suite extension (Montoya API) designed to identify, map, and test the attack surface of Model Context Protocol (MCP) servers. 

It provides a bridge between Burp's synchronous testing tools (Repeater, Intruder, Scanner) and the asynchronous, persistent nature of MCP connections (SSE & WebSockets). This allows security professionals to audit MCP Tools, Resources, and Prompts using standard web testing workflows.

## Features

- **Multi-Protocol Support:** Full support for Server-Sent Events (SSE) and WebSockets (ws/wss).
- **Endpoint Auto-Discovery:** Automated detection of MCP endpoints, including detection of protected endpoints that require authentication.
- **Attack Surface Enumeration:** Automatically discovers and visualizes Tools, Resources, and Prompts, including schema extraction for arguments.
- **Synchronous Bridging:** Enables seamless use of Burp Repeater and Intruder by handling asynchronous ID correlation and session management.
- **Prototype Generation:** Automatically generates valid JSON-RPC payloads based on discovered tool schemas.
- **Security Scanning:** Initial support for Active Scanning, including Type Confusion (crash/leak detection) and Injection probing.
- **Authentication & mTLS:** Support for custom HTTP headers (OAuth Bearer tokens, API keys) and mTLS client certificates (PKCS#12).

## Installation

### Prerequisites
- Java JDK 17+
- Burp Suite Professional or Community (2023.12.1+)

### Building from Source
```bash
git clone https://github.com/your-repo/mcp-asd.git
cd mcp-asd
./gradlew shadowJar
```
The resulting JAR will be located at `build/libs/mcp-asd.jar`.

### Loading the Extension
1. Open Burp Suite.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Select **Java** and browse to the generated `mcp-asd.jar`.

## Usage

### 1. Connection Management
- Use the **New Connection** button in the MCP-ASD tab to connect to a server.
- The **Auto-Detect Endpoints** feature identifies common MCP paths.
- Connection settings (host, port, headers, certificates) are persisted for the duration of the session.

### 2. Authentication Visibility Note
**Important:** MCP-ASD manages authentication and transport-level security (mTLS) internally. When you configure headers or certificates in the connection dialog, they are injected into the real transport connection by the extension. **You will not see these headers in Repeater or Intruder requests**, as those requests are sent to the extension's internal virtual bridge.

### 3. Mapping and Enumeration
Upon connection, the extension populates the dashboard with identified primitives:
- **Tools:** Executable functions.
- **Resources:** Data sources or files.
- **Prompts:** Pre-defined templates.

### 4. Security Testing
- **Send to Repeater:** Manually test tool invocations. Repeater tabs are automatically named (e.g., `MCP: get_weather`) for easy identification.
- **Send to Intruder:** Perform concurrent fuzzing. The extension ensures thread-safe correlation of requests and responses.
- **Active Scan:** Right-click a tool in the dashboard to perform automated security checks. The extension currently supports Type Confusion and basic Injection probing.

## Development Test Server
A mock MCP server is included for testing the extension's features.

### Requirements
```bash
pip install fastapi uvicorn[standard] websockets sse-starlette
```

### Execution
```bash
python3 mcp_server.py
```
The server supports authentication (Bearer token: `bearer-token-123`) and includes vulnerable endpoints (`echo_input`, `crash_me`) for verifying scanner functionality.

## Architecture
MCP-ASD implements a transparent internal proxy to bridge asynchronous MCP traffic to Burp's synchronous model:
1. Burp sends a request to the extension's virtual endpoint.
2. The extension decorates the request with a unique JSON-RPC ID.
3. The request is dispatched over the active SSE or WebSocket transport.
4. The extension blocks the Burp thread and monitors the incoming event stream for a matching ID.
5. Once found, the result is packaged as an HTTP response and returned to Burp.

## Contact
Drew Kirkpatrick  
@hoodoer  
hoodoer @bitwisemunitions.dev  

You can find me over at TrustedSec.
