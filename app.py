"""
app.py
------
FastAPI service for the Malicious URL Detection pipeline.

Endpoints
---------
POST /predict            — classify a URL; returns probability, verdict, SHAP explanation
POST /feedback           — log a ground-truth label for future retraining
GET  /feedback/stats     — summary of collected feedback (counts, label distribution)
POST /feedback/retrain   — trigger an async model retrain from feedback.csv
GET  /health             — liveness probe

Run
---
    uvicorn app:app --host 0.0.0.0 --port 8000 --workers 1

Note: use --workers 1 during retraining to avoid concurrent model reloads.
Set FEEDBACK_CSV env var to override the default feedback file path.
"""

from __future__ import annotations

import asyncio
import csv
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from ai.predict import (
    FeatureContribution,
    PredictionResult,
    load_model,
    predict_url,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("app")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).parent
_FEEDBACK_PATH = Path(os.getenv("FEEDBACK_CSV", _BASE_DIR / "ai" / "feedback.csv"))
_FEEDBACK_FIELDNAMES = ["timestamp", "url", "label"]

# Lock to prevent concurrent retrains
_retrain_lock = asyncio.Lock()
_retrain_running: bool = False


# ---------------------------------------------------------------------------
# Feedback I/O
# ---------------------------------------------------------------------------
def _append_feedback(url: str, label: int) -> None:
    """Append one labelled row to feedback.csv (thread-safe for single-worker deployments)."""
    _FEEDBACK_PATH.parent.mkdir(parents=True, exist_ok=True)
    write_header = not _FEEDBACK_PATH.exists() or _FEEDBACK_PATH.stat().st_size == 0

    with _FEEDBACK_PATH.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FEEDBACK_FIELDNAMES)
        if write_header:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "url": url,
                "label": label,
            }
        )


def _read_feedback_stats() -> dict:
    """Return row counts and label distribution from feedback.csv."""
    if not _FEEDBACK_PATH.exists() or _FEEDBACK_PATH.stat().st_size == 0:
        return {"total_rows": 0, "benign": 0, "malicious": 0, "feedback_file": str(_FEEDBACK_PATH)}

    try:
        df = pd.read_csv(_FEEDBACK_PATH)
        total = len(df)
        benign = int((df["label"] == 0).sum())
        malicious = int((df["label"] == 1).sum())
    except Exception as exc:
        logger.warning("Could not parse feedback CSV: %s", exc)
        return {"total_rows": -1, "error": str(exc), "feedback_file": str(_FEEDBACK_PATH)}

    return {
        "total_rows": total,
        "benign": benign,
        "malicious": malicious,
        "feedback_file": str(_FEEDBACK_PATH),
    }


async def _run_retrain(with_page: bool) -> None:
    """
    Spawn train.py as a subprocess so it doesn't block the event loop.
    Uses --feedback flag so the new training run merges feedback.csv.
    Reloads the model singleton once training finishes successfully.
    """
    global _retrain_running
    cmd = [
        sys.executable, "-m", "ai.train",
        "--feedback",
        "--feedback-path", str(_FEEDBACK_PATH),
    ]
    if with_page:
        cmd.append("--with-page")

    logger.info("Retrain started: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(_BASE_DIR),
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors="replace") if stdout else ""

        if proc.returncode == 0:
            logger.info("Retrain completed successfully.\n%s", output[-2000:])
            # Invalidate the in-memory model so the next request reloads from disk
            import ai.predict as _pred_module
            _pred_module._MODEL = None
            _pred_module._EXPLAINER = None
            _pred_module._FEATURE_NAMES = []
            _pred_module._META = {}
            # Eagerly reload
            load_model()
            logger.info("Model reloaded after retrain.")
        else:
            logger.error("Retrain process exited with code %d.\n%s", proc.returncode, output[-3000:])
    except Exception as exc:
        logger.error("Retrain subprocess failed: %s", exc, exc_info=True)
    finally:
        _retrain_running = False


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class PredictRequest(BaseModel):
    url: str
    include_page: bool = False
    threshold: Optional[float] = None
    top_n: int = 3

    @field_validator("url")
    @classmethod
    def url_must_have_scheme(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("url must start with http:// or https://")
        return v

    @field_validator("threshold")
    @classmethod
    def threshold_in_range(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError("threshold must be between 0.0 and 1.0")
        return v

    @field_validator("top_n")
    @classmethod
    def top_n_in_range(cls, v: int) -> int:
        if not (1 <= v <= 20):
            raise ValueError("top_n must be between 1 and 20")
        return v


class FeatureContributionSchema(BaseModel):
    feature: str
    value: float
    shap_value: float

    model_config = {"from_attributes": True}


class PredictResponse(BaseModel):
    url: str
    probability: float
    is_malicious: bool
    threshold: float
    explanation: list[FeatureContributionSchema]


class FeedbackRequest(BaseModel):
    url: str
    label: int      # 0 = benign, 1 = malicious
    source: str = "user"  # free-text tag: "user", "analyst", "automated", etc.

    @field_validator("url")
    @classmethod
    def url_non_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        return v

    @field_validator("label")
    @classmethod
    def label_must_be_binary(cls, v: int) -> int:
        if v not in (0, 1):
            raise ValueError("label must be 0 (benign) or 1 (malicious)")
        return v


class FeedbackResponse(BaseModel):
    status: str
    url: str
    label: int
    source: str
    total_feedback_rows: int
    feedback_file: str


class FeedbackStatsResponse(BaseModel):
    total_rows: int
    benign: int
    malicious: int
    feedback_file: str


class RetrainRequest(BaseModel):
    with_page: bool = False     # mirror train.py --with-page flag


class RetrainResponse(BaseModel):
    status: str
    message: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_type: str             # "lgbm", "logistic_regression", or "unknown"
    feedback_rows: int
    retrain_running: bool


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Malicious URL Detector API",
    description=(
        "Classify URLs as malicious or benign using a LightGBM pipeline. "
        "Includes SHAP-based explanations and a continuous feedback/retraining loop."
    ),
    version="3.0.0",
)


@app.on_event("startup")
async def _startup() -> None:
    """Pre-load model at startup so the first request isn't slow."""
    try:
        load_model()
        logger.info("Model loaded successfully at startup.")
    except Exception as exc:
        logger.error("Failed to load model at startup: %s", exc)


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled error on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error. Check server logs for details."},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health() -> HealthResponse:
    """
    Liveness probe.

    Reports: model load state, model type (lgbm / logistic_regression),
    feedback row count, and whether a retrain is currently running.
    """
    import ai.predict as _pred_module

    model_loaded = _pred_module._MODEL is not None
    model_type = _pred_module._META.get("model_type", "unknown") if model_loaded else "unknown"

    stats = _read_feedback_stats()
    feedback_rows = stats.get("total_rows", 0)

    return HealthResponse(
        status="ok",
        model_loaded=model_loaded,
        model_type=model_type,
        feedback_rows=feedback_rows,
        retrain_running=_retrain_running,
    )


@app.post("/predict", response_model=PredictResponse, tags=["inference"])
async def predict(body: PredictRequest) -> PredictResponse:
    """
    Classify a URL as malicious or benign.

    Returns probability, binary verdict, the threshold used, and a ranked
    list of SHAP feature contributions explaining the decision.
    """
    try:
        result: PredictionResult = predict_url(
            url=body.url,
            threshold=body.threshold,
            include_page=body.include_page,
            top_n=body.top_n,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except Exception as exc:
        logger.error("Prediction error for '%s': %s", body.url, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction failed. Check server logs.",
        )

    logger.info(
        "predict url=%s prob=%.4f malicious=%s",
        body.url, result.probability, result.is_malicious,
    )

    return PredictResponse(
        url=body.url,
        probability=result.probability,
        is_malicious=result.is_malicious,
        threshold=result.threshold,
        explanation=[
            FeatureContributionSchema(
                feature=fc.feature,
                value=fc.value,
                shap_value=fc.shap_value,
            )
            for fc in result.top_features
        ],
    )


@app.post("/feedback", response_model=FeedbackResponse, tags=["retraining"])
async def feedback(body: FeedbackRequest) -> FeedbackResponse:
    """
    Submit a ground-truth label for a URL.

    The entry is appended to ``feedback.csv`` with a UTC timestamp.
    Call ``POST /feedback/retrain`` (or run ``train.py --feedback``) to
    incorporate collected labels into the next model version.

    Labels:  ``0`` = benign  |  ``1`` = malicious
    """
    try:
        _append_feedback(url=body.url, label=body.label)
    except OSError as exc:
        logger.error("Failed to write feedback: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not persist feedback. Check disk permissions.",
        )

    stats = _read_feedback_stats()
    logger.info("feedback url=%s label=%d source=%s", body.url, body.label, body.source)

    return FeedbackResponse(
        status="accepted",
        url=body.url,
        label=body.label,
        source=body.source,
        total_feedback_rows=stats.get("total_rows", -1),
        feedback_file=str(_FEEDBACK_PATH),
    )


@app.get("/feedback/stats", response_model=FeedbackStatsResponse, tags=["retraining"])
async def feedback_stats() -> FeedbackStatsResponse:
    """
    Return a summary of collected feedback labels.

    Useful for deciding when there is enough new data to warrant retraining
    (e.g. once total_rows > 500 or malicious / benign ratio shifts significantly).
    """
    stats = _read_feedback_stats()
    return FeedbackStatsResponse(
        total_rows=stats.get("total_rows", 0),
        benign=stats.get("benign", 0),
        malicious=stats.get("malicious", 0),
        feedback_file=str(_FEEDBACK_PATH),
    )


@app.post("/feedback/retrain", response_model=RetrainResponse, tags=["retraining"])
async def retrain(body: RetrainRequest) -> RetrainResponse:
    """
    Trigger an asynchronous model retrain using the original dataset
    **merged with all collected feedback labels**.

    The retrain runs in the background via ``ai.train`` (LightGBM pipeline).
    When it completes, the in-memory model singleton is automatically reloaded
    so subsequent ``/predict`` calls use the new model without a server restart.

    Only one retrain can run at a time; concurrent requests return HTTP 409.

    Recommended trigger: when ``/feedback/stats`` reports enough new labels
    (e.g. > 200 new rows, or a shift in label distribution).
    """
    global _retrain_running

    if _retrain_running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A retrain is already running. Check /health for status.",
        )

    if not _FEEDBACK_PATH.exists() or _FEEDBACK_PATH.stat().st_size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No feedback data found. Submit labels via POST /feedback first.",
        )

    stats = _read_feedback_stats()
    if stats.get("total_rows", 0) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Only {stats['total_rows']} feedback rows collected. "
                   "Retrain requires at least 10 labelled samples.",
        )

    _retrain_running = True
    # Fire-and-forget: schedule the coroutine without awaiting it
    asyncio.create_task(_run_retrain(with_page=body.with_page))

    logger.info("Retrain task scheduled (with_page=%s).", body.with_page)
    return RetrainResponse(
        status="accepted",
        message=(
            f"Retrain started with {stats['total_rows']} feedback rows "
            f"(benign={stats['benign']}, malicious={stats['malicious']}). "
            "Poll GET /health for completion — retrain_running will become false "
            "and model_type will reflect the new model."
        ),
    )