# Integration Notes: Strands Agents SDK, Strands Decider 2B, and Amazon Bedrock

## Verified Facts

### Strands Agents SDK
- **Package**: `strands-agents` (Python)
- **Tools**: Functions decorated with `@tool` become callable by the agent
- **Model Providers**: Supports Bedrock, Anthropic, OpenAI, Ollama, and custom providers
- **Deployment**: Can deploy to Lambda, Fargate, EKS, Bedrock AgentCore
- **Agent Loop**: Built-in loop with hooks, interventions, cancellation, retry strategies
- **Credentials**: Environment variables or AWS IAM roles

### Strands Decider 2B
- **Package**: `strands-decider` (Python)
- **Model Size**: 1.9 billion parameters (2B class)
- **Architecture**: Qwen3.5-2B-Base torso with pointer head (no text generation)
- **Hardware Requirements**:
  - GPU: RTX 3090 (median 115ms latency)
  - CPU: Supported (slower)
  - Apple Silicon: Supported
- **Availability**: Local model only, NOT available through Amazon Bedrock
- **Model Names**:
  - `StrandsAgents/strands-decider-2B-qwen3.5-v1-2610` (latest)
  - `StrandsAgents/strands-decider-2B-hobson-v19` (older)
- **Input Format**:
  - CLI: `--state <text>` + `--choice <question=options>` / `--noul <yes/no question>` / `--score <question=scale>`
  - HTTP Server: POST to `/v1/systemone` with JSON body
  ```json
  {
    "state": "context text",
    "questions": {
      "question_name": {
        "type": "choice|noul|score",
        "instructions": "question text"
      }
    }
  }
  ```
- **Output Format**:
  ```json
  {
    "model": "strands-decider-2b-...",
    "answers": {
      "question_name": {
        "type": "choice|noul|score",
        "choice": "selected_option",  // for choice type
        "noul": 0.858,  // for yes/no (0-1, closer to 1 = yes)
        "score": 1.03,  // for score type
        "confidence": 0.659
      }
    },
    "usage": {
      "input_tokens": 86,
      "output_tokens": 1
    },
    "latency_ms": 140.03
  }
  ```
- **Server Mode**: `strands-decider serve <model_name> --port 8000`
- **Question Types**:
  - `choice`: Select from multiple options
  - `noul`: Yes/no question (numeric 0-1)
  - `score`: Rate on a scale

### Amazon Bedrock
- **Endpoints**:
  - `bedrock-runtime`: Control plane for model management
  - `bedrock-runtime`: Data plane for inference (recommended)
  - `bedrock-mantle`: Data plane with server-side tools
- **APIs**:
  - Converse: Unified interface for all models
  - Invoke: Direct access with more control
  - Responses: OpenAI-compatible, stateful
  - Chat Completions: OpenAI-compatible, stateless
  - Messages: Anthropic-native interface
- **Credentials**:
  - AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
  - IAM roles (on AWS services)
  - Bedrock API keys (AWS_BEARER_TOKEN_BEDROCK)
- **Python SDK**: boto3
- **Models**: Anthropic Claude, Amazon Titan, Meta Llama, Mistral, etc.
- **Custom Models**: Decider 2B is NOT hosted on Bedrock; it's a local model

## Assumptions

1. **Decider 2B Integration**: Decider 2B must be run locally (CLI or HTTP server). It cannot be called through Bedrock. Integration requires either:
   - Running the HTTP server and making HTTP requests
   - Using the Python package directly (if a programmatic API exists)

2. **Strands SDK Integration**: The deterministic scanner components can be wrapped as Strands tools using the `@tool` decorator. The agent loop can then orchestrate calls to these tools.

3. **Bedrock Fallback**: If Decider 2B is unavailable, Bedrock models (e.g., Claude) can be used for decision-making by requesting structured JSON output with the three decision options.

4. **GitHub Advisory API**: Assumed to be a REST API that can be queried for vulnerability information. Need to verify the actual API documentation.

5. **Hardware**: For Decider 2B, a GPU (RTX 3090 or similar) is recommended for acceptable latency, but CPU execution is possible (slower).

## Can Decider 2B Be Integrated Cleanly?

**Yes, with caveats:**

- **Clean Integration Path**: Decider 2B can be integrated cleanly by running it as an HTTP server (`strands-decider serve`) and making HTTP requests from the vulnerability scanner. The input/output format is well-defined JSON.

- **Limitation**: Decider 2B is NOT available through Bedrock. It must be run locally. This means:
  - The scanner needs to either:
    a) Depend on the local HTTP server being running, or
    b) Include `strands-decider` as a dependency and use it programmatically (need to verify if a Python API exists beyond CLI)
  - Hardware requirements (GPU recommended) may not be available in all deployment environments

- **Fallback Strategy**: The Bedrock fallback is viable for production environments where running Decider 2B locally is not feasible. Bedrock models can produce structured JSON decisions.

## Integration Approach

1. **Primary Path**: Use Strands Decider 2B (local HTTP server) for decision-making
2. **Fallback Path**: Use Amazon Bedrock (Claude via Converse API) with structured JSON output
3. **Tool Wrapping**: Wrap scanner/OSV/version matcher as Strands tools
4. **Decision Logic**: Three-way decision (CONTINUE_TO_REPORT, VERIFY_WITH_ANOTHER_SOURCE, FLAG_FOR_REVIEW)
5. **Verification Source**: GitHub Advisory API (need to research actual API)
6. **Explanations**: Use Bedrock for remediation text grounded in evidence

### GitHub Advisory API
- **Endpoint**: `https://api.github.com/advisories` (global advisories)
- **Authentication**: `Authorization: Bearer <token>` (GitHub personal access token)
- **Headers**:
  - `Accept: application/vnd.github+json`
  - `X-GitHub-Api-Version: 2026-03-10`
- **Query Parameters**:
  - `ghsa_id`: Filter by GHSA ID
  - `cve_id`: Filter by CVE ID
  - `ecosystem`: Filter by ecosystem (e.g., "npm")
  - `affects`: Filter by package or package@version (max 1000 packages)
  - `severity`: Filter by severity
  - `type`: "reviewed" (default), "malware", "unreviewed"
- **Example**: `GET /advisories?ecosystem=npm&affects=lodash@4.17.15`
- **Rate Limit**: Standard GitHub API rate limits apply
- **Response**: JSON with advisory details including severity, CVSS, CWEs, vulnerabilities

## Next Steps

1. Check if `strands-decider` has a programmatic Python API (beyond CLI)
2. Implement Strands tool wrappers
3. Implement decision logic with Decider 2B HTTP client
4. Implement Bedrock fallback
5. Implement GitHub Advisory API client
6. Update report generator to separate facts from AI interpretation
