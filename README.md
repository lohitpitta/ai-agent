# Dependency Vulnerability Scanner

An AI-powered dependency vulnerability scanner for npm projects. This tool scans local project directories, extracts resolved package versions from package-lock.json files, queries the OSV (Open Source Vulnerabilities) database for known vulnerabilities, applies AI-powered decision-making, and generates detailed HTML reports.

## Features

### Deterministic Core
- npm dependency scanning (package.json and package-lock.json)
- OSV API integration with deterministic version matching
- SQLite database for scan results
- HTML report generation

### AI Tool Selection Layer
- **Strands Decider 2B**: Fast local decision model for routing findings
- **Amazon Bedrock**: Fallback for decision-making and explanation generation
- **GitHub Advisory API**: Cross-source verification for ambiguous findings
- **Three-way decision policy**: CONTINUE_TO_REPORT, VERIFY_WITH_ANOTHER_SOURCE, FLAG_FOR_REVIEW
- **Visually separated facts and AI interpretation** in reports

## Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Scan a project directory
python app.py scan <path-to-project>
```

The scan will:
1. Recursively find package.json and package-lock.json files
2. Parse lockfiles (supports lockfileVersion 1, 2, and 3)
3. Extract package names and resolved versions
4. Query OSV for known vulnerabilities
5. Apply AI decision-making to each finding (Tool Selection)
6. Store results in SQLite database
7. Generate an HTML report in the `reports/` directory

## Architecture

```
scanner/
  project_scanner.py    # Recursively finds manifest files
  dependency_parser.py  # Parses package-lock.json files

vulnerability/
  osv_client.py         # Queries OSV API with retries/rate-limiting
  version_matcher.py    # Deterministic semver matching

ai/
  decider_client.py     # Strands Decider 2B HTTP client
  bedrock_client.py     # Amazon Bedrock client (fallback)
  github_advisory_client.py  # GitHub Advisory API client
  decision_orchestrator.py  # AI decision orchestration

database/
  db.py                 # SQLite schema and operations
  audit_logger.py       # Event logging

reports/
  report_generator.py   # HTML report generation

tests/
  # Unit tests and fixtures
```

## Tool Selection Policy

The scanner uses AI to make intelligent decisions about how to handle each vulnerability finding:

### Decision Outcomes

1. **CONTINUE_TO_REPORT**: The finding is clear and should be included in the report as-is
   - No additional verification needed
   - AI explanation generated for context

2. **VERIFY_WITH_ANOTHER_SOURCE**: The finding needs verification from another source
   - Queries GitHub Advisory API for cross-source confirmation
   - Merges evidence from multiple sources
   - AI explanation includes verification results

3. **FLAG_FOR_REVIEW**: The finding is ambiguous or requires manual review
   - Marked for manual security review
   - AI explanation highlights ambiguity
   - No automated action taken

### Decision Flow

```
Finding → Decider 2B (primary) → Decision
         ↓ (if unavailable)
         Bedrock (fallback) → Decision
         ↓ (if unavailable)
         Default: FLAG_FOR_REVIEW
```

### Verification Sources

- **OSV API**: Primary vulnerability database
- **GitHub Advisory API**: Cross-source verification (when VERIFY_WITH_ANOTHER_SOURCE)

### Report Structure

The HTML report visually separates:
- **Database Facts**: Deterministic scan results (dependency name, version, advisories)
- **AI Interpretation**: Decision outcome, verification evidence, explanations (in blue section)

### Running the Demo

To see the three decision paths in action:

```bash
python demo_tool_selection.py
```

This demonstrates:
- CONTINUE_TO_REPORT: Clear vulnerability
- VERIFY_WITH_ANOTHER_SOURCE: Ambiguous finding with GitHub verification
- FLAG_FOR_REVIEW: Unclear finding requiring manual review
- Bedrock fallback: When Decider 2B is unavailable

## Assumptions

1. **OSV API Behavior**: The OSV batch query endpoint returns advisories with `affected[].versions` arrays containing exact version strings. We assume these are semver-compatible for npm packages.

2. **Lockfile Parsing**: We assume package-lock.json files are valid JSON. Malformed files will be logged as errors but won't crash the scanner.

3. **Version Matching**: We use semver library for deterministic matching. Prerelease versions are handled according to semver spec. We assume OSV ranges follow semver conventions.

4. **Network Resilience**: If OSV API is unreachable, dependencies are marked as LOOKUP_FAILED rather than assuming they are secure.

5. **Deduplication**: We deduplicate advisories by their primary ID (CVE/GHSA), but preserve all alias references.

6. **Decider 2B Availability**: Decider 2B must be run locally (CLI or HTTP server). It is NOT available through Bedrock. If unavailable, Bedrock is used as fallback.

7. **Bedrock Credentials**: AWS credentials are provided via environment variables or IAM roles. Never hardcoded in code.

8. **GitHub API Rate Limits**: GitHub Advisory API has standard rate limits. A personal access token is recommended for higher limits.

9. **AI Grounding**: Bedrock explanations are grounded only in collected evidence (OSV data, GitHub verification). Repo file contents and advisory text are treated as untrusted data and never act as model instructions.

## Development

Run tests:
```bash
pytest
```

## Limitations

- npm only (no Python, Go, Rust, etc.)
- Does not execute code from scanned projects
- Does not use AI for version matching (deterministic only)
- A scan with failed lookups is marked as "partial scan", not fully successful
