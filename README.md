# MCP Attack Surface Detector (MCP-ASD)
**Version: 1.2.0**

MCP-ASD is a Burp Suite extension (Montoya API) designed to identify, map, and test the attack surface of Model Context Protocol (MCP) servers. 

It provides a bridge between Burp's synchronous testing tools (Repeater, Intruder, Scanner) and the asynchronous, persistent nature of MCP connections (SSE & WebSockets). This allows security professionals to audit MCP Tools, Resources, and Prompts using standard web testing workflows.

## Features

- **Multi-Protocol Support:** Full support for Server-Sent Events (SSE), WebSockets (ws/wss), and HTTP POST-only transport (for servers that don't support GET/SSE).
- **Endpoint Auto-Discovery:** Automated detection of MCP endpoints, including detection of protected endpoints that require authentication.
- **Attack Surface Enumeration:** Automatically discovers and visualizes Tools, Resources, and Prompts, including schema extraction for arguments.
- **Synchronous Bridging:** Enables seamless use of Burp Repeater and Intruder by handling asynchronous ID correlation and session management.
- **Prototype Generation:** Automatically generates valid JSON-RPC payloads based on discovered tool schemas.
- **Authentication & mTLS:** Support for custom HTTP headers (OAuth Bearer tokens, API keys) and mTLS client certificates (PKCS#12).
- **Native Integration:** Reports discovered MCP servers directly to Burp's **Target** and **Dashboard**.
- **Advanced Detection:** Includes passive monitoring and active probing for MCP servers on discovered domains.
- **Auth Gateway Detection:** Detects MCP endpoints behind authentication gateways (Zscaler, OAuth, SAML, SSO) by recognizing redirect patterns to auth endpoints, including URL-encoded origurl parameters.

## Installation

### Prerequisites
- Java JDK 21+ (to build)
- Burp Suite Professional or Community (2025.6+)
  - MCP server **detection** (passive and active checks) runs through Burp Scanner and requires **Burp Suite Professional**. Everything else works in Community.

### Building from Source
_Note: There is a precompiled .jar at:_  
https://github.com/hoodoer/MCP-ASD/releases/tag/v1.0

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
- **Cancel Button:** If a connection attempt hangs or takes too long, use the **Cancel** button to abort the handshake and reset the interface.

<img width="1359" height="1078" alt="image" src="https://github.com/user-attachments/assets/db879ed2-8876-404f-be80-5dddb1ba2b04" />  

*Figure 1: Starting a new connection*  

<img width="629" height="998" alt="image" src="https://github.com/user-attachments/assets/02729173-f8dd-4f5f-9773-8701af21cbf7" />  

*Figure 2: Automatic discovery of endpoints*  

<img width="605" height="311" alt="image" src="https://github.com/user-attachments/assets/eb663760-a195-4ce6-955c-3c46fc7c232e" />  

*Figure 3: Authentication required detected*

<img width="631" height="931" alt="image" src="https://github.com/user-attachments/assets/858617b4-a7fa-4e36-b195-ec9abd67f463" />  

*Figure 4: Configure authentication*




### 2. Global Settings & Detection
Settings live in Burp's own settings window: **Settings → Extensions → MCP-ASD** (or search for "MCP"). Changes apply immediately.

*   **Internal Traffic Visibility:**
    *   **Proxy Handshake/Enumeration Traffic:** Route the extension's internal SSE/WebSocket traffic through Burp's local proxy listener (default: `127.0.0.1:8080`). This allows you to see the "invisible" handshake and enumeration requests in Burp's **Logger** and **Proxy History**. Proxied connections trust only Burp's CA certificate, and Burp applies its own upstream TLS settings. HTTP (POST only) connections and endpoint auto-detection always go through Burp's HTTP stack and appear in **Logger**.
    *   **Ignore TLS certificate errors on direct connections:** Off by default. Only applies to SSE/WebSocket connections when proxying is turned off; enable it to connect directly to servers with self-signed or otherwise invalid certificates.

*   **MCP Server Detection (Burp Suite Professional):**
    *   **Passive Checks:** Burp's passive scanning checks traffic for MCP indicators (e.g., `MCP-Protocol-Version` header, JSON-RPC bodies, auth gateway redirects) and raises an **Informational Issue** if detected. Can be switched off in the settings.
    *   **Active Detection:** Runs as part of Burp's active scans, once per host, probing common MCP endpoints (`/mcp`, `/sse`, `/ws`, etc.). Detects endpoints behind auth gateways (302/303 redirects to OAuth, SAML, SSO, Zscaler, etc.). Scope, scheduling and throttling follow your scan configuration.

<img width="1108" height="803" alt="image" src="https://github.com/user-attachments/assets/f598284b-a0d2-426f-8f95-8cd7793ecaed" />  


*Figure 5: MCP ASD settings*

<img width="682" height="742" alt="image" src="https://github.com/user-attachments/assets/7eb050cc-7cf3-4981-b1d2-aa53e0be9125" />  

*Figure 6: MCP server active detection alert*



### 3. Authentication
The connection dialog includes a dedicated "Authentication" tab supporting three strategies:

*   **HTTP Headers:** Add custom headers (e.g., `Authorization: Bearer <token>`, `X-API-Key: <key>`) to the transport connection.
*   **mTLS (Mutual TLS):** Provide a PKCS#12 (`.p12`) client certificate and password. This allows the extension to handshake with servers requiring client-side certificates.
    *   Burp presents client certificates itself for traffic it sends. For **HTTP (POST only)**, and for SSE/WebSocket while **Proxy Handshake/Enumeration Traffic** is on, configure the certificate in Burp under **Settings → Network → TLS → Client TLS certificates**. The certificate in the connection dialog is used for direct (non-proxied) SSE/WebSocket connections.
*   **Initialization Parameters:** Inject custom JSON fields into the MCP `initialize` handshake.
    *   *Usage:* Paste a JSON object (e.g., `{"apiKey": "secret", "env": "prod"}`) into the text area.
    *   *Effect:* These fields are merged into the `params` object of the `initialize` JSON-RPC message sent immediately after connection.

<img width="631" height="931" alt="image" src="https://github.com/user-attachments/assets/858617b4-a7fa-4e36-b195-ec9abd67f463" />  

*Figure 7: Configure authentication*

### 4. Authentication Visibility Note
**Important:** MCP-ASD manages authentication and transport-level security (mTLS) internally. When you configure headers or certificates in the connection dialog, they are injected into the real transport connection by the extension. **You will not see these headers in Repeater or Intruder requests**, as those requests are sent to the extension's internal virtual bridge.

### 5. Mapping and Enumeration
Upon connection, the extension populates the dashboard with identified primitives:
- **Tools:** Executable functions.
- **Resources:** Data sources or files.
- **Prompts:** Pre-defined templates.

<img width="1354" height="904" alt="image" src="https://github.com/user-attachments/assets/23ffe577-1a47-4a8a-931f-e19885488da7" />  

*Figure 8: MCP primatives enumerated*  

<img width="1259" height="840" alt="image" src="https://github.com/user-attachments/assets/401d56e8-6581-47d1-900a-49f8d054f710" />  

*Figure 9: Select primative to generate request prototype*



### 6. Security Testing
- **Send to Repeater:** Manually test tool invocations. Repeater tabs are automatically named (e.g., `MCP: get_weather`) for easy identification.
- **Send to Intruder:** Perform concurrent fuzzing. The extension ensures thread-safe correlation of requests and responses.

<img width="1346" height="632" alt="image" src="https://github.com/user-attachments/assets/1e697b53-db36-4970-8007-8547c31e5e41" />  

*Figure 10: Syncronous bridge allows request/response style Repeater and Intruder usage*


### 7. Server Information
- Click the **Server Info** button in the top header to view detailed metadata about the connected MCP server.
- This includes the server name, version, protocol version, supported capabilities, and the full System Instructions (prompts).

<img width="1322" height="816" alt="image" src="https://github.com/user-attachments/assets/ee8ae5d0-329e-4f80-926a-2edc812145bc" />  

*Figure 11: Server information provided by some MCP servers*

## How it Works (Architecture)

MCP-ASD solves a fundamental impedance mismatch between Burp Suite and the Model Context Protocol:
*   **Burp Suite** is optimized for synchronous, stateless HTTP (Request -> Response).
*   **MCP** relies on asynchronous, persistent connections (Server-Sent Events or WebSockets) where messages (JSON-RPC) can flow in any direction at any time, often without a 1:1 request/response correlation at the transport layer.

To bridge this gap, MCP-ASD implements a novel **"Virtual Proxy" Architecture**:

### 1. Asynchronous Transport Layer
For the persistent SSE and WebSocket connections, MCP-ASD uses a dedicated HTTP client (`OkHttp`); request/response traffic (HTTP POST-only transport, endpoint auto-detection, scanner probes) uses Burp's HTTP API.
*   **Justification:** Standard HTTP clients (including Burp's native API) block waiting for a response body to complete. For SSE (Server-Sent Events), the response body is an infinite stream that never completes. Attempting to read it with standard methods causes the thread to hang indefinitely.
*   **Solution:** The extension maintains a dedicated background thread that reads the infinite stream event-by-event, decoupled from the Burp UI.

### 2. The Synchronous Bridge
When you send a request from Burp Repeater or Intruder:
1.  **Virtual Endpoint:** You send a standard HTTP POST request to `http://mcp-asd.local/invoke`.
2.  **Interception:** The extension's `HttpHandler` intercepts this request before it leaves Burp.
3.  **Automatic ID Correlation:** The extension **automatically overwrites the `id` field** in your JSON with a unique UUID. This ensures that even in high-concurrency Intruder attacks, every request is perfectly correlated to its specific response. **You do not need to manually change the ID in Repeater.**
4.  **Injection:** It injects the message into the *active* persistent SSE/WebSocket connection.
5.  **Thread Blocking:** The extension pauses the Burp request thread and waits.
6.  **Stitching:** When the matching JSON-RPC response arrives from the server, the extension "stitches" it into a standard HTTP 200 OK response and returns it to Burp.

This allows you to fuzz MCP tools using Intruder's powerful payloads without breaking the persistent connection or needing to re-authenticate for every fuzzing attempt.

**Bridge security:** Burp can't answer a request without sending it somewhere, so the bridge is a small listener on a random `127.0.0.1` port. It only accepts requests that come through the extension's `HttpHandler` from Burp's Repeater, Intruder, Scanner or other extensions: the handler adds a secret token (regenerated on every load), and the listener rejects requests without it or without `Host: mcp-asd.local`. Browser traffic through the Proxy is never bridged, so web pages can't reach the MCP session.

## Development Test Server
A mock MCP server is included for testing the extension's features.

### Requirements
```bash
pip3 install -r requirements.txt
```

### Execution
```bash
python3 mcp_server.py
```
The server supports authentication (Bearer token: `bearer-token-123`).

## Contact
Drew Kirkpatrick  
@hoodoer  
hoodoer@bitwisemunitions.dev  

You can find me over at TrustedSec.
