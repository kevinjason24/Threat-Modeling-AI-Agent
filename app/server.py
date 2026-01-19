"""FastAPI server for Threat Model Copilot."""

import logging
from datetime import datetime
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .pipeline import ThreatModelPipeline
from .render_markdown import render_markdown_report
from .schemas import ThreatModelReport

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Threat Modeling Agent API",
    description="AI-powered security threat analysis API",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response models
class AnalyzeRequest(BaseModel):
    """Request body for threat model analysis."""

    document: str = Field(..., description="Design document text to analyze")
    document_name: Optional[str] = Field(None, description="Optional document name/path")
    redact_secrets: bool = Field(False, description="Redact secrets before LLM processing")
    output_format: str = Field("json", description="Output format: 'json' or 'markdown'")


class AnalyzeResponse(BaseModel):
    """Response body for threat model analysis."""

    success: bool
    message: str
    report: Optional[ThreatModelReport] = None
    markdown: Optional[str] = None
    processing_time_seconds: float


class JobStatus(BaseModel):
    """Status of an async analysis job."""

    job_id: str
    status: str  # pending, running, completed, failed
    created_at: str
    completed_at: Optional[str] = None
    current_stage: Optional[str] = None
    error: Optional[str] = None
    result: Optional[ThreatModelReport] = None


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    timestamp: str


# In-memory job storage (use Redis/DB in production)
jobs: dict[str, JobStatus] = {}


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    from . import __version__

    return HealthResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.now().isoformat(),
    )


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_sync(request: AnalyzeRequest) -> AnalyzeResponse:
    """Synchronous threat model analysis.

    Analyzes the provided document and returns the complete threat model.
    This is a blocking operation that may take 30-60 seconds.
    """
    import time
    start_time = time.time()

    try:
        # Validate input
        if not request.document.strip():
            raise HTTPException(status_code=400, detail="Document cannot be empty")

        if len(request.document) > 500_000:  # ~500KB limit
            raise HTTPException(status_code=400, detail="Document too large (max 500KB)")

        # Run pipeline
        pipeline = ThreatModelPipeline()
        report = pipeline.run(
            input_text=request.document,
            input_path=request.document_name,
            redact=request.redact_secrets,
        )

        processing_time = time.time() - start_time

        # Generate markdown if requested
        markdown = None
        if request.output_format == "markdown":
            markdown = render_markdown_report(report)

        return AnalyzeResponse(
            success=True,
            message="Threat model generated successfully",
            report=report if request.output_format == "json" else None,
            markdown=markdown,
            processing_time_seconds=round(processing_time, 2),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Analysis failed")
        processing_time = time.time() - start_time
        return AnalyzeResponse(
            success=False,
            message=f"Analysis failed: {str(e)}",
            processing_time_seconds=round(processing_time, 2),
        )


@app.post("/analyze/async")
async def analyze_async(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    """Asynchronous threat model analysis.

    Starts analysis in background and returns a job ID.
    Poll /jobs/{job_id} to check status.
    """
    import uuid

    # Validate input
    if not request.document.strip():
        raise HTTPException(status_code=400, detail="Document cannot be empty")

    # Create job
    job_id = str(uuid.uuid4())
    job = JobStatus(
        job_id=job_id,
        status="pending",
        created_at=datetime.now().isoformat(),
    )
    jobs[job_id] = job

    # Start background task
    background_tasks.add_task(
        run_analysis_job,
        job_id,
        request.document,
        request.document_name,
        request.redact_secrets,
    )

    return {
        "job_id": job_id,
        "status": "pending",
        "poll_url": f"/jobs/{job_id}",
    }


def run_analysis_job(
    job_id: str,
    document: str,
    document_name: Optional[str],
    redact: bool,
) -> None:
    """Background job for async analysis."""
    job = jobs.get(job_id)
    if not job:
        return

    job.status = "running"

    def on_stage_complete(stage: str, status: str) -> None:
        if status == "running":
            job.current_stage = stage

    try:
        pipeline = ThreatModelPipeline(on_stage_complete=on_stage_complete)
        report = pipeline.run(document, document_name, redact)

        job.status = "completed"
        job.completed_at = datetime.now().isoformat()
        job.result = report

    except Exception as e:
        logger.exception(f"Job {job_id} failed")
        job.status = "failed"
        job.error = str(e)
        job.completed_at = datetime.now().isoformat()


@app.get("/jobs/{job_id}", response_model=JobStatus)
async def get_job_status(job_id: str) -> JobStatus:
    """Get status of an async analysis job."""
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.delete("/jobs/{job_id}")
async def delete_job(job_id: str) -> dict:
    """Delete a completed job."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    del jobs[job_id]
    return {"message": "Job deleted"}


@app.get("/jobs")
async def list_jobs() -> dict:
    """List all jobs."""
    return {
        "jobs": [
            {
                "job_id": job.job_id,
                "status": job.status,
                "created_at": job.created_at,
            }
            for job in jobs.values()
        ]
    }


# Convenience endpoint for markdown rendering
@app.post("/render/markdown")
async def render_to_markdown(report: ThreatModelReport) -> dict:
    """Render a threat model report to Markdown."""
    try:
        markdown = render_markdown_report(report)
        return {"markdown": markdown}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Rendering failed: {e}")


# Run with: uvicorn app.server:app --reload
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)



