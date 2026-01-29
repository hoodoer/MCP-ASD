# Future Development Roadmap (Phase 2 & 3)

## Phase 2: Refinement & Integration (Remaining Tasks)

### 1. Native Burp Issue Reporting
*   **Goal:** Integrate findings into Burp's "Target" and "Dashboard" tabs instead of just the Event Log.
*   **Action:** Implement `IScanIssue` and `IAuditIssue` interfaces from the Montoya API.
*   **Details:**
    *   Create a `McpScanIssue` class implementing `IScanIssue`.
    *   Update `SecurityTester` to call `api.siteMap().add(new McpScanIssue(...))` upon finding a vulnerability.

### 2. Deep Parameter Analysis (Schema Fuzzing)
*   **Goal:** Handle complex, nested JSON objects in Tool arguments.
*   **Action:** Upgrade the `EnumerationEngine` and `DashboardTab` prototype generator.
*   **Details:**
    *   Currently, the tool handles flat arguments well.
    *   Need a recursive parser for `oneOf`, `anyOf`, and nested `object` types in JSON Schemas.
    *   Generate fuzzing payloads that respect these constraints (e.g., generating valid nested JSON structures to test business logic deeper than just top-level fields).

## Phase 3: Advanced Capabilities

### 1. Automated "Intelligent" Fuzzing
*   **Goal:** Use LLM-assisted fuzzing or smarter heuristics.
*   **Action:** Instead of random types, analyze the `description` field of a tool (e.g., "Expects a SQL query") to inject context-aware payloads (e.g., `' OR 1=1 --`).

### 2. Session Management / Macros
*   **Goal:** Support complex workflows where Tool A must be called before Tool B.
*   **Action:** Allow users to define a "Login Tool" or "Setup Sequence" that runs automatically before every scan or manual request.

### 3. Standalone Mode
*   **Goal:** Run MCP-ASD as a CLI tool without Burp Suite (optional).
*   **Action:** Decouple the `EnumerationEngine` from the Montoya API to allow CI/CD integration.
