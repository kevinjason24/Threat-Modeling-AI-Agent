# Threat Modeling AI Agent

AI-powered Threat Modeling Agent - A multi-step planner-executor system that automates security threat analysis using STRIDE methodology.

## Features

- 🤖 **Agentic Pipeline**: Specialized sub-agents (Planner → Extractor → DFD Builder → STRIDE Analyst → Abuse Case Writer → Checklist Writer → QA Checker)
- 📊 **Structured Output**: All outputs validated with Pydantic schemas
- 📝 **Multiple Formats**: Markdown report + JSON output
- 🔒 **Secret Redaction**: Optional redaction of sensitive data before LLM processing
- 🎯 **STRIDE Analysis**: Systematic threat identification with severity scoring
- ✅ **Quality Assurance**: Automated completeness and consistency checking
- 🌐 **Flexible Deployment**: CLI + FastAPI server

## Installation

### Prerequisites

- Python 3.11+
- Groq API key (free at https://console.groq.com/keys)

### Setup

```bash
# Clone the repository
cd threat-model-copilot

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

## Usage

### CLI

```bash
# Analyze a design document
threat-model --input design.md --out report.md --json report.json

# With secret redaction
threat-model -i design.md -o report.md --redact

# Read from stdin
cat design.md | threat-model --out report.md

# Verbose output
threat-model -i design.md -o report.md --verbose

# Validate existing threat model
threat-model validate report.json
```

### FastAPI Server

```bash
# Start the server
uvicorn app.server:app --reload

# The API will be available at http://localhost:8000
# Interactive docs at http://localhost:8000/docs
```

#### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/analyze` | POST | Synchronous analysis |
| `/analyze/async` | POST | Async analysis (returns job ID) |
| `/jobs/{job_id}` | GET | Check async job status |
| `/render/markdown` | POST | Render JSON to Markdown |

### Python API

```python
from app.pipeline import ThreatModelPipeline
from app.render_markdown import render_markdown_report

# Create pipeline
pipeline = ThreatModelPipeline()

# Run analysis
with open("design.md") as f:
    document = f.read()

report = pipeline.run(document, redact=True)

# Generate markdown
markdown = render_markdown_report(report)
print(markdown)

# Access structured data
for threat in report.stride_analysis.threats:
    print(f"{threat.id}: {threat.title} ({threat.severity_label.value})")
```

## Output Structure

The threat model report includes these sections:

1. **Overview** - Executive summary of the system and findings
2. **Assumptions & Unknowns** - Explicit documentation of assumptions
3. **System Inventory** - Actors, components, data stores, entry points
4. **Data-Flow Diagram Notes** - DFD observations and caveats
5. **Mermaid DFD** - Visual data flow diagram
6. **STRIDE Threat Analysis** - Detailed threat breakdown by category
7. **Abuse Cases** - Attack scenarios with steps
8. **Engineering Checklist** - Actionable security checklist
9. **Top Risks & Mitigations** - Prioritized risk summary
10. **Next Steps** - Recommended actions

### Severity Scoring

Threats are scored using Likelihood × Impact:

| Likelihood | Impact | Severity |
|------------|--------|----------|
| 1-5 | 1-5 | 1-25 |

| Score Range | Label |
|-------------|-------|
| 1-6 | 🟢 Low |
| 7-14 | 🟡 Medium |
| 15-25 | 🔴 High |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key | Required |
| `GROQ_MODEL` | Model to use | `llama-3.3-70b-versatile` |
| `LLM_TEMPERATURE` | Temperature setting | `0.1` |
| `LLM_MAX_TOKENS` | Max tokens per request | `8192` |

### Available Groq Models

- `llama-3.3-70b-versatile` (default) - Best quality
- `llama-3.1-8b-instant` - Faster, lighter
- `mixtral-8x7b-32768` - Good for long context
- `gemma2-9b-it` - Google's Gemma 2

## Pipeline Architecture

```
┌─────────────────┐
│  Design Doc     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Planner Agent  │  → Plan + Unknowns
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Extractor Agent │  → System Inventory
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ DFD Builder     │  → Data Flow Diagram
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ STRIDE Analyst  │  → Threats + Scoring
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Abuse Writer    │  → Attack Scenarios
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│Checklist Writer │  → Security Checklist
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ QA Checker      │  → Validation + Scores
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Report Assembly │  → Final Output
└─────────────────┘
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_scoring.py

# Run with verbose output
pytest -v
```

## Examples

See the `examples/` directory for sample design documents:

- `auth_feature.md` - Authentication system design
- `payments_webhook.md` - Payment webhook integration

Run an example:

```bash
threat-model -i examples/auth_feature.md -o out/auth_report.md -j out/auth_report.json
```

## Design Principles

1. **No Questions Asked**: The system makes explicit assumptions rather than asking for clarification
2. **Unknowns Documented**: Missing information is clearly labeled, not invented
3. **Deterministic Structure**: Same headings and JSON keys every time
4. **Engineer-Friendly**: Technical language without GRC fluff
5. **Actionable Output**: Every mitigation and checklist item is testable

## Limitations

- Requires a Groq API key (free tier available)
- Quality depends on input document detail
- Not a replacement for human security review
- May miss context-specific vulnerabilities

## License

MIT

## Contributing

Contributions welcome! Please read the contributing guidelines before submitting PRs.

