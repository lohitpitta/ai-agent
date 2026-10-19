# Dependency Vulnerability Scanner

**An AI-assisted security tool for detecting known vulnerabilities in npm dependencies using deterministic analysis, multi-source verification, and intelligent decision-making.**

Dependency Vulnerability Scanner analyzes local JavaScript and Node.js projects to identify known vulnerabilities in their dependencies. It extracts resolved package versions from lockfiles, queries the Open Source Vulnerabilities (OSV) database, applies deterministic version matching, and uses an AI-powered decision layer to determine how findings should be handled.

The scanner combines reliable security checks with AI-assisted analysis while keeping vulnerability detection and version matching deterministic.

---

## Overview

Modern applications rely on third-party dependencies, which can introduce security risks when vulnerable package versions are used.

This project helps developers and security researchers identify known dependency vulnerabilities and understand which findings require additional verification or manual review.

### Key Highlights

* **Deterministic vulnerability analysis:** Package versions are evaluated using explicit version-matching rules rather than AI-generated guesses.
* **Multi-source verification:** OSV provides primary vulnerability data, with GitHub Advisory API verification when required.
* **AI-powered decision-making:** Strands Decider 2B and Amazon Bedrock support finding classification and explanation generation.
* **Evidence-based reporting:** Reports distinguish collected security facts from AI-generated interpretations.
* **Persistent scan history:** SQLite stores scan results for future reference.
* **HTML security reports:** Findings are presented in a readable report format.
* **Safer project analysis:** The scanner does not execute code from the projects it analyzes.

## Features

### 1. Dependency Discovery

* Recursively discovers `package.json` and `package-lock.json` files.
* Extracts dependency names and resolved versions.
* Supports npm lockfile versions 1, 2, and 3.
* Analyzes local project directories.

### 2. Vulnerability Detection

* Queries the OSV API for known vulnerabilities.
* Applies deterministic version-matching logic.
* Preserves advisory identifiers and references.
* Handles network errors and unsuccessful vulnerability lookups.
* Identifies incomplete scans instead of treating failed lookups as proof of safety.

### 3. AI Decision Layer

The scanner uses a decision orchestration layer to determine how vulnerability findings should be handled.

**Strands Decider 2B**

* Primary decision-making model.
* Runs locally through a supported CLI or HTTP interface.
* Helps route findings according to the configured decision policy.

**Amazon Bedrock**

* Fallback decision-making when the primary decision service is unavailable.
* Supports AI-generated explanations based on collected evidence, subject to the configured implementation.

**GitHub Advisory API**

* Provides additional vulnerability evidence when cross-source verification is required.
* Helps distinguish confirmed findings from findings that need further investigation.

### 4. Three-Way Decision Policy

Each finding can be assigned one of three outcomes:

| Decision                     | Meaning                                                    | Next Step                                      |
| ---------------------------- | ---------------------------------------------------------- | ---------------------------------------------- |
| `CONTINUE_TO_REPORT`         | Available evidence is sufficient for normal reporting.     | Include the finding in the report.             |
| `VERIFY_WITH_ANOTHER_SOURCE` | Additional evidence is needed.                             | Query another configured vulnerability source. |
| `FLAG_FOR_REVIEW`            | The finding remains ambiguous or requires human attention. | Highlight it for manual review.                |

These decisions guide the handling of findings. They do not replace deterministic vulnerability checks or guarantee that a finding is exploitable.

### 5. Reporting and Storage

* Generates HTML vulnerability reports.
* Stores scan results in SQLite.
* Separates database-derived facts from AI interpretation.
* Includes decision outcomes and verification evidence where available.
* Supports investigation of findings that require manual review.

---

## Architecture

The application follows a modular architecture that separates dependency discovery, vulnerability detection, AI decision-making, data storage, and reporting.

```text
                 Local npm Project
                         |
                         v
              Project Scanner
                         |
                         v
               Dependency Parser
                         |
                         v
                Resolved Versions
                         |
                         v
                  OSV API Query
                         |
                         v
             Deterministic Version
                    Matching
                         |
                         v
                Vulnerability Finding
                         |
                         v
                Decision Orchestrator
                         |
             +-----------+-----------+
             |           |           |
             v           v           v
          Strands     Amazon      Default /
          Decider     Bedrock     Review Path
             |           |
             +-----+-----+
                   |
                   v
             Decision Policy
                   |
          +--------+---------+
          |                  |
          v                  v
   GitHub Advisory API   Manual Review
   (when required)       (when flagged)
          |
          v
     Evidence Merging
          |
          v
      SQLite Storage
          |
          v
       HTML Report
```

The exact execution path depends on the configured services and the decision outcome.

### Design Principles

1. **Deterministic core:** Vulnerability version matching is performed by code, not an AI model.
2. **Separation of concerns:** Scanning, data retrieval, decision-making, and reporting are handled by separate modules.
3. **Evidence-based decisions:** AI decisions should use collected vulnerability evidence.
4. **Graceful failure handling:** Unavailable services should not automatically cause a finding to be treated as safe.
5. **Human oversight:** Ambiguous findings can be flagged for manual review.
6. **No execution of scanned project code:** Dependency analysis does not require running the target application's code.

---

## Technology Stack

| Component                      | Technology          |
| ------------------------------ | ------------------- |
| Programming Language           | Python              |
| Dependency Ecosystem           | npm                 |
| Primary Vulnerability Database | OSV API             |
| Secondary Verification         | GitHub Advisory API |
| AI Decision Model              | Strands Decider 2B  |
| AI Fallback                    | Amazon Bedrock      |
| Database                       | SQLite              |
| Reports                        | HTML                |
| Testing                        | pytest              |

---

## Project Structure

```text
AI AGENT/
│
├── ai/
│   ├── bedrock_client.py
│   ├── decider_client.py
│   └── decision_orchestrator.py
│
├── database/
│   └── db.py
│
├── vulnerability/
│   ├── osv_client.py
│   ├── nvd_client.py
│   └── version_matcher.py
│
├── tests/
│   └── test_ai_decision.py
│
├── reports/
│   └── Generated HTML reports
│
├── app.py
├── ui.py
├── requirements.txt
├── .env.example
└── README.md
```

*Note: The structure above highlights the main application modules. Additional files may exist in the repository.*

---

## Prerequisites

Before running the scanner, ensure you have:

* Python installed.
* Git installed if cloning the repository.
* An internet connection for vulnerability database queries.
* npm project files for the target project.
* A configured Strands Decider 2B service for the primary decision path.
* AWS credentials and appropriate Amazon Bedrock access if using the Bedrock integration.
* A GitHub personal access token if required by your GitHub Advisory API configuration.

**Important:** Strands Decider 2B runs locally through its supported interface; it is not itself a model hosted through Amazon Bedrock.

---

## Installation

### 1. Clone the repository

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Replace the placeholders with your actual GitHub repository URL and directory name.

### 2. Create a virtual environment

**Windows PowerShell**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy `.env.example` to `.env` and fill in the values required by your implementation.

For example, on Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Configure the required settings for:

* AWS credentials and Amazon Bedrock access.
* Strands Decider 2B service configuration.
* GitHub Advisory API authentication, if required.
* Other application-specific settings.

Use the variable names defined in your actual `.env.example` file.

**Security:** Never commit `.env`, AWS secret access keys, GitHub tokens, or other credentials to GitHub.

### 5. Start the required services

If the primary decision model uses an HTTP server, start Strands Decider 2B using its supported setup instructions.

Configure the application to use the correct service endpoint.

If you intend to use Amazon Bedrock as a fallback, ensure your AWS identity has permission to invoke the selected model and that the model is available in your configured AWS Region.

---

## Usage

### Scan a local npm project

Run:

```bash
python app.py scan <path-to-project>
```

Replace `<path-to-project>` with the directory containing the npm project you want to analyze.

Example:

```bash
python app.py scan ./test-project
```

Use a real project directory that contains the required npm manifest and lockfile files.

### Scan Workflow

A typical scan performs the following steps:

1. Discovers npm project manifests and lockfiles.
2. Parses supported `package-lock.json` formats.
3. Extracts dependency names and resolved versions.
4. Queries OSV for vulnerability information.
5. Applies deterministic version-matching rules.
6. Sends eligible findings through the configured AI decision layer.
7. Requests additional vulnerability evidence when required by the decision policy.
8. Stores scan results in SQLite.
9. Generates an HTML report in the configured reports directory.

The exact behavior depends on the configured integrations and available services.

### View Reports

After a successful scan, open the generated HTML report in a web browser.

Reports are designed to distinguish:

**Database Facts**

* Dependency names and resolved versions.
* Vulnerability identifiers.
* Collected advisory information.
* Matching and verification evidence.

**AI Interpretation**

* Decision outcomes.
* Explanations based on available evidence.
* Findings requiring additional verification.
* Recommendations for manual review.

AI-generated explanations are supplementary information and should not be treated as independent proof of exploitability.

---

## Tool Selection Policy

The scanner uses a three-way policy to decide how findings should proceed.

### `CONTINUE_TO_REPORT`

Used when the available evidence is sufficient for normal reporting.

The finding proceeds to the report with its collected vulnerability information.

### `VERIFY_WITH_ANOTHER_SOURCE`

Used when additional evidence is needed.

The scanner attempts cross-source verification through the configured GitHub Advisory API integration and incorporates the resulting evidence when available.

A missing match from a secondary database does not, by itself, prove that a vulnerability is invalid.

### `FLAG_FOR_REVIEW`

Used when the finding is ambiguous or requires human assessment.

The report highlights the finding for manual review instead of assuming that the automated decision is conclusive.

### Decision Flow

```text
Vulnerability Finding
          |
          v
  Strands Decider 2B
          |
     Available?
       /     \
     Yes      No
      |        |
      |        v
      |   Bedrock Fallback
      |        |
      +----+---+
           |
           v
     Apply Decision Policy
           |
    +------+------+ 
    |      |      |
    v      v      v
 Continue Verify  Flag
    |      |      |
    |      v      |
    |  Secondary  |
    |  Verification
    |      |      |
    +------+------+
           |
           v
       Final Report
```

If the decision services are unavailable, the application should follow its configured safe fallback behavior rather than silently treating the finding as secure.

---

## Security Considerations

This project is designed to support safer dependency analysis.

* **No target code execution:** The scanner analyzes project metadata instead of running the scanned application's code.
* **Deterministic matching:** AI is not responsible for deciding whether a package version falls within a vulnerability's affected range.
* **Untrusted external data:** Repository metadata and advisory text should be treated as untrusted input.
* **Credential protection:** API tokens and AWS credentials should be supplied through secure configuration mechanisms.
* **Failure visibility:** Failed vulnerability lookups should be distinguishable from successful lookups with no known vulnerabilities.
* **Human review:** Ambiguous findings should remain visible for further investigation.
* **Evidence separation:** AI explanations should remain distinguishable from authoritative vulnerability data.

No scanner can guarantee that a project is completely secure merely because a scan reports no known vulnerabilities.

---

## Assumptions

1. The initial implementation focuses on npm dependencies.
2. `package-lock.json` files are expected to contain valid JSON.
3. Malformed files should be reported as parsing errors where supported.
4. Version matching follows the rules implemented by the project's version matcher and supported advisory range formats.
5. Network failures should be recorded as failed or incomplete lookups rather than interpreted as evidence that a package is safe.
6. Strands Decider 2B must be available through its supported local interface for the primary decision path.
7. Amazon Bedrock requires valid AWS authentication, permissions, and model access.
8. GitHub Advisory API requests may be subject to rate limits.
9. AI explanations are grounded in collected evidence to the extent enforced by the application's implementation.
10. AI-generated decisions are advisory and should not override deterministic scan evidence.

---

## Testing

Run the test suite with:

```bash
pytest
```

To run a specific test file:

```bash
pytest tests/test_ai_decision.py
```

Additional integration tests may require a running Decider service, AWS credentials, model access, or network connectivity.

Tests that use external services should be configured appropriately for the local environment.

---

## Limitations

* Currently focused on npm dependency analysis.
* Does not provide complete software composition analysis for every ecosystem.
* Does not execute the scanned application's code.
* Does not use AI for deterministic version matching.
* Depends on the quality and availability of external vulnerability databases.
* Network failures can result in partial scans.
* AI-generated explanations may be incomplete or incorrect.
* A finding flagged for review requires further human assessment.
* Detection of known vulnerabilities does not establish whether a package is exploitable in a particular application.
* Does not guarantee detection of unknown or undisclosed vulnerabilities.

---

## Future Improvements

Potential future enhancements include:

* Support for Python, Go, and Rust dependency ecosystems.
* Additional vulnerability intelligence sources.
* Improved scan history and comparison between scans.
* Enhanced severity-based prioritization.
* More detailed remediation guidance.
* Continuous integration support.
* Automated regression testing for decision policies.
* Exportable reports for security review workflows.

---

## Responsible Use

Use this tool to assess projects you own or have permission to analyze.

The scanner is intended to support dependency security assessment, vulnerability triage, and developer remediation workflows.

---

## License

Add the appropriate open-source license before distributing this project. Until a license is included, do not assume that others have permission to reuse, modify, or redistribute the code.
