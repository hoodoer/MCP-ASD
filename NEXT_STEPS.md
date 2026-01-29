# Next Steps: Phase 3 & Beyond

With Phase 2 (Authentication & Basic Scanning) complete, the project focus shifts to **Deep Integration** and **Advanced Fuzzing**.

## Phase 3: Advanced Capabilities

### 1. Native Burp Issue Reporting (High Priority)
*   **Objective:** Move vulnerability reporting out of the "Event Log" and into the standard Burp "Target" and "Dashboard" tabs.
*   **Tasks:**
    *   Implement `burp.api.montoya.scanner.audit.issues.AuditIssue`.
    *   Update `SecurityTester` to register these issues via `api.siteMap().add()`.

### 2. Deep Parameter Analysis
*   **Objective:** Support complex, real-world Tool schemas.
*   **Tasks:**
    *   Update `EnumerationEngine` to parse nested JSON objects, `oneOf`, and `anyOf` definitions.
    *   Generate fuzzing payloads that validate structural correctness while fuzzing values.

### 3. Intelligent Fuzzing
*   **Objective:** Context-aware attacks.
*   **Tasks:**
    *   Parse `description` fields (e.g., "SQL query to execute") to select specific payload lists (SQLi vs XSS).

### 4. Standalone Mode (Optional)
*   **Objective:** Run without Burp Suite for CI/CD pipelines.
*   **Tasks:**
    *   Decouple `EnumerationEngine` from Montoya API.
    *   Create a CLI wrapper.
