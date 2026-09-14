"""
SatyaAI 3.0 — FastAPI Backend
Multimodal AI Cyber Fraud & Deepfake Intelligence Platform

Run with:
    ./venv311/bin/python -m uvicorn backend.main:app --reload
"""

import os
import re
import uuid
import time
import logging
from pathlib import Path

# ─── Database imports ─────────────────────────────────────────────────────────
try:
    from backend.database.database import init_db, get_db
    from backend.services.database_service import (
        save_analysis_safely,
        get_analyses,
        get_analysis_by_id,
    )
    _DB_AVAILABLE = True
except Exception as _db_import_err:
    _DB_AVAILABLE = False
    _db_import_err_msg = str(_db_import_err)

from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, field_validator

# ─── Configure logging ───────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("satyaai")

# ─── Directory setup ─────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "backend" / "uploads"
FRONTEND_DIR = BASE_DIR / "frontend"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff"}
ALLOWED_AUDIO_EXTS = {".mp3", ".wav", ".m4a", ".ogg", ".flac", ".aac", ".webm"}
ALLOWED_VIDEO_EXTS = {".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv"}
ALLOWED_EMAIL_EXTS = {".eml", ".msg", ".txt"}
ALLOWED_CALL_EXTS = {".mp3", ".wav", ".m4a", ".ogg", ".webm", ".flac", ".aac"}

# ─── FastAPI app ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="SatyaAI 3.0",
    description="Multimodal AI Cyber Fraud & Deepfake Intelligence Platform",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.on_event("startup")
async def startup_event():
    """Initialize DB schema on startup — non-blocking if PostgreSQL is unavailable."""
    if _DB_AVAILABLE:
        try:
            init_db()
            logger.info("PostgreSQL schema initialized (satyaai_db).")
        except Exception as exc:
            logger.warning(f"DB startup init skipped: {exc}")
    else:
        logger.warning(f"DB module unavailable at startup — persistence disabled. Reason: {_db_import_err_msg if not _DB_AVAILABLE else ''}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Static frontend ─────────────────────────────────────────────────────────

if FRONTEND_DIR.exists() and (FRONTEND_DIR / "index.html").exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.api_route("/style.css", methods=["GET", "HEAD"], include_in_schema=False)
def get_css():
    return FileResponse(FRONTEND_DIR / "style.css", media_type="text/css")


@app.api_route("/app.js", methods=["GET", "HEAD"], include_in_schema=False)
def get_js():
    return FileResponse(FRONTEND_DIR / "app.js", media_type="application/javascript")


@app.api_route("/i18n.js", methods=["GET", "HEAD"], include_in_schema=False)
def get_i18n():
    return FileResponse(FRONTEND_DIR / "i18n.js", media_type="application/javascript")


@app.api_route("/app", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/ui", methods=["GET", "HEAD"], include_in_schema=False)
def get_ui():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.api_route("/logo.png", methods=["GET", "HEAD"], include_in_schema=False)
def get_logo():
    return FileResponse(FRONTEND_DIR / "logo.png", media_type="image/png")


@app.api_route("/logo-brain.png", methods=["GET", "HEAD"], include_in_schema=False)
def get_logo_brain():
    return FileResponse(FRONTEND_DIR / "logo-brain.png", media_type="image/png")


@app.api_route("/satya_emblem.png", methods=["GET", "HEAD"], include_in_schema=False)
def get_satya_emblem():
    return FileResponse(FRONTEND_DIR / "satya_emblem.png", media_type="image/png")


@app.api_route("/satya_logo.png", methods=["GET", "HEAD"], include_in_schema=False)
def get_satya_logo():
    return FileResponse(FRONTEND_DIR / "satya_logo.png", media_type="image/png")


@app.api_route("/reference_dashboard.png", methods=["GET", "HEAD"], include_in_schema=False)
def get_reference_dashboard():
    return FileResponse(FRONTEND_DIR / "reference_dashboard.png", media_type="image/png")


@app.api_route("/components.js", methods=["GET", "HEAD"], include_in_schema=False)
def get_components():
    return FileResponse(FRONTEND_DIR / "components.js", media_type="application/javascript")


@app.api_route("/services/{file_path:path}", methods=["GET", "HEAD"], include_in_schema=False)
def get_frontend_services(file_path: str):
    target = FRONTEND_DIR / "services" / file_path
    if target.exists() and target.is_file():
        return FileResponse(target, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="File not found")


@app.api_route("/favicon.png", methods=["GET", "HEAD"], include_in_schema=False)
def get_favicon():
    return FileResponse(FRONTEND_DIR / "favicon.png", media_type="image/png")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _safe_filename(original: str) -> str:
    """Sanitize uploaded filename to prevent path traversal."""
    name = Path(original).name
    name = re.sub(r"[^\w.\-]", "_", name)
    return f"{uuid.uuid4().hex}_{name}"


def _save_upload(file: UploadFile, allowed_exts: set[str]) -> Path:
    """Validate extension and save uploaded file. Returns saved path."""
    ext = Path(file.filename or "").suffix.lower()
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {sorted(allowed_exts)}"
        )
    safe_name = _safe_filename(file.filename or "upload")
    dest = UPLOAD_DIR / safe_name
    return dest


async def _write_upload(file: UploadFile, dest: Path) -> None:
    content = await file.read()
    with open(dest, "wb") as f:
        f.write(content)


# ─── Request schemas ─────────────────────────────────────────────────────────

class MessageRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def text_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("text must not be empty")
        return v.strip()


class URLRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("url must not be empty")
        return v.strip()


class EmailTextRequest(BaseModel):
    subject: Optional[str] = ""
    body: str
    sender: Optional[str] = ""

    @field_validator("body")
    @classmethod
    def body_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Email body must not be empty")
        return v.strip()


class CallTextRequest(BaseModel):
    transcript: str

    @field_validator("transcript")
    @classmethod
    def transcript_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Call transcript must not be empty")
        return v.strip()


# ─── Global exception handler ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error. Please try again.", "detail": str(exc)},
    )


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.api_route("/", methods=["GET", "HEAD"], tags=["Status"])
def root(request: Request):
    accept = request.headers.get("accept", "")
    user_agent = request.headers.get("user-agent", "").lower()
    if "text/html" in accept and "testclient" not in user_agent and (FRONTEND_DIR / "index.html").exists():
        return FileResponse(FRONTEND_DIR / "index.html")
    return {
        "name": "SatyaAI 3.0",
        "description": "Multimodal AI Cyber Fraud & Deepfake Intelligence Platform",
        "version": "3.0.0",
        "status": "running",
        "endpoints": [
            "GET  /health",
            "POST /api/analyze/message",
            "POST /api/analyze/url",
            "POST /api/analyze/image",
            "POST /api/analyze/audio",
            "POST /api/analyze/video",
            "POST /api/analyze/multimodal",
        ],
    }


@app.api_route("/health", methods=["GET", "HEAD"], tags=["Status"])
def health():
    from backend.services.message_service import MODEL_PATH as MSG_MODEL
    from backend.services.url_service import MODEL_PATH as URL_MODEL
    email_model_exists = (BASE_DIR / "models" / "email_threat_model.pkl").exists()
    call_model_exists = (BASE_DIR / "models" / "call_threat_model.pkl").exists()
    video_model_exists = (BASE_DIR / "models" / "face_detection_yunet_2023mar.onnx").exists()

    return {
        "status": "healthy",
        "models": {
            "message": MSG_MODEL.exists(),
            "url": URL_MODEL.exists(),
            "email": email_model_exists,
            "call": call_model_exists,
            "video": video_model_exists,
        },
        "message_model": str(MSG_MODEL.exists()),
        "url_model": str(URL_MODEL.exists()),
        "email_model": str(email_model_exists),
        "call_model": str(call_model_exists),
        "upload_dir": str(UPLOAD_DIR),
    }


def _register_analysis_context(
    input_type: str,
    risk: dict,
    extracted_text: str = "",
    detected_urls: list = None,
    indicators: list = None,
    ml_preds: dict = None,
    filename: str = None,
    deepfake_status: str = "NOT_APPLICABLE",
    processing_time_ms: float = 0.0,
) -> str:
    try:
        from backend.services.analysis_context import get_context_store
        score = int(risk.get("final_score", risk.get("score", 0)) or 0)
        level = str(risk.get("risk_level", risk.get("level", "LOW")) or "LOW")
        rec = str(risk.get("recommendation", "") or "")
        analysis_id = get_context_store().create_context(
            input_type=input_type,
            original_filename=filename,
            extracted_text=extracted_text,
            detected_urls=detected_urls or [],
            ml_predictions=ml_preds or {},
            risk_score=score,
            risk_level=level,
            indicators=indicators or [],
            recommendation=rec,
            deepfake_status=deepfake_status,
        )
        return analysis_id
    except Exception as exc:
        logger.warning(f"Could not register analysis context: {exc}")
        return ""


# ── 1. Message analysis ──────────────────────────────────────────────────────

@app.post("/api/analyze/message", tags=["Analysis"])
async def analyze_message_endpoint(request: MessageRequest):
    """Analyze a text message for scam/fraud indicators."""
    t0 = time.time()
    try:
        from backend.services.message_service import analyze_message
        result = analyze_message(request.text)

        from backend.services.risk_engine import compute_risk
        risk = compute_risk(
            message_score=result.get("probability", 0),
            all_indicators=result.get("indicators", []),
            all_modalities=["message"],
        )

        proc_time = round((time.time() - t0) * 1000, 1)
        analysis_id = _register_analysis_context(
            input_type="message",
            risk=risk,
            extracted_text=request.text,
            detected_urls=result.get("extracted_urls", []),
            indicators=result.get("indicators", []),
            ml_preds={"message": result},
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "message",
            "risk_assessment": risk,
            "analysis": result,
        })

        response = {
            "analysis_id": analysis_id,
            "modality": "message",
            "analysis": result,
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            save_analysis_safely(response, input_type="message", input_data=request.text, custom_id=analysis_id or None)
        return response
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Message analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Message analysis failed: {exc}")


# ── 2. URL analysis ──────────────────────────────────────────────────────────

@app.post("/api/analyze/url", tags=["Analysis"])
async def analyze_url_endpoint(request: URLRequest):
    """Analyze a URL for phishing indicators."""
    t0 = time.time()
    try:
        from backend.services.url_service import analyze_url
        result = analyze_url(request.url)

        from backend.services.risk_engine import compute_risk
        risk = compute_risk(
            url_score=result.get("probability", 0),
            all_indicators=result.get("indicators", []),
            all_modalities=["url"],
        )

        proc_time = round((time.time() - t0) * 1000, 1)
        analysis_id = _register_analysis_context(
            input_type="url",
            risk=risk,
            detected_urls=[request.url],
            indicators=result.get("indicators", []),
            ml_preds={"url": result},
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "url",
            "risk_assessment": risk,
            "analysis": result,
        })

        response = {
            "analysis_id": analysis_id,
            "modality": "url",
            "analysis": result,
            "threat_origin": result.get("threat_origin"),
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            save_analysis_safely(response, input_type="url", input_data=request.url, custom_id=analysis_id or None)
        return response
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"URL analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {exc}")


# ── 3. Image / OCR analysis ──────────────────────────────────────────────────

@app.post("/api/analyze/image", tags=["Analysis"])
async def analyze_image_endpoint(file: UploadFile = File(...)):
    """Extract text from screenshot/image and analyze for scam content."""
    t0 = time.time()
    dest = _save_upload(file, ALLOWED_IMAGE_EXTS)
    await _write_upload(file, dest)

    try:
        from backend.services.ocr_service import analyze_image
        result = analyze_image(str(dest))

        msg_score = None
        if result.get("message_analysis"):
            msg_score = result["message_analysis"].get("probability")

        url_scores = [
            u.get("probability", 0)
            for u in result.get("url_analyses", [])
            if u.get("prediction") == "PHISHING"
        ]
        url_score = max(url_scores) if url_scores else None

        from backend.services.risk_engine import compute_risk
        risk = compute_risk(
            message_score=msg_score,
            url_score=url_score,
            image_score=msg_score,
            all_indicators=result.get("indicators", []),
            all_modalities=["image"],
        )

        proc_time = round((time.time() - t0) * 1000, 1)
        analysis_id = _register_analysis_context(
            input_type="image",
            filename=file.filename,
            risk=risk,
            extracted_text=result.get("extracted_text", ""),
            detected_urls=result.get("extracted_urls", []),
            indicators=result.get("indicators", []),
            ml_preds={"ocr": result},
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "image",
            "risk_assessment": risk,
            "analysis": result,
        })

        response = {
            "analysis_id": analysis_id,
            "modality": "image",
            "filename": file.filename,
            "analysis": result,
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            save_analysis_safely(response, input_type="image", input_data=file.filename, custom_id=analysis_id or None)
        return response
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Image analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Image analysis failed: {exc}")
    finally:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass


# ── 4. Audio analysis ────────────────────────────────────────────────────────

@app.post("/api/analyze/audio", tags=["Analysis"])
async def analyze_audio_endpoint(file: UploadFile = File(...)):
    """Transcribe audio and analyze transcript for scam content."""
    t0 = time.time()
    dest = _save_upload(file, ALLOWED_AUDIO_EXTS)
    await _write_upload(file, dest)

    try:
        from backend.services.audio_service import analyze_audio
        result = analyze_audio(str(dest))

        from backend.services.risk_engine import compute_risk
        risk = compute_risk(
            audio_score=result.get("scam_probability", 0),
            all_indicators=result.get("indicators", []),
            all_modalities=["audio"],
        )

        proc_time = round((time.time() - t0) * 1000, 1)
        analysis_id = _register_analysis_context(
            input_type="audio",
            filename=file.filename,
            risk=risk,
            extracted_text=result.get("transcript", ""),
            indicators=result.get("indicators", []),
            ml_preds={"audio": result},
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "audio",
            "risk_assessment": risk,
            "analysis": result,
        })

        response = {
            "analysis_id": analysis_id,
            "modality": "audio",
            "filename": file.filename,
            "analysis": result,
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            save_analysis_safely(response, input_type="audio", input_data=file.filename, custom_id=analysis_id or None)
        return response
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Audio analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Audio analysis failed: {exc}")
    finally:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass


# ── 5. Video / Deepfake analysis ─────────────────────────────────────────────

@app.post("/api/analyze/video", tags=["Analysis"])
async def analyze_video_endpoint(file: UploadFile = File(...)):
    """Extract frames from video and analyze for deepfakes."""
    t0 = time.time()
    dest = _save_upload(file, ALLOWED_VIDEO_EXTS)
    await _write_upload(file, dest)

    try:
        from backend.services.deepfake_service import analyze_video
        result = analyze_video(str(dest))

        video_score = result.get("video_score")
        risk_input_score = int(round(video_score * 100)) if video_score is not None else 0

        from backend.services.risk_engine import compute_risk
        risk = compute_risk(
            video_score=risk_input_score,
            all_indicators=result.get("indicators", []),
            all_modalities=["video"],
        )

        proc_time = round((time.time() - t0) * 1000, 1)
        analysis_id = _register_analysis_context(
            input_type="video",
            filename=file.filename,
            risk=risk,
            indicators=result.get("indicators", []),
            ml_preds={"video": result},
            deepfake_status=result.get("deepfake_status", "NOT_DETECTED"),
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "video",
            "risk_assessment": risk,
            "analysis": result,
        })

        response = {
            "analysis_id": analysis_id,
            "modality": "video",
            "filename": file.filename,
            "status": result.get("status", "success"),
            "frames_processed": result.get("frames_processed", 0),
            "frames_with_faces": result.get("frames_with_faces", 0),
            "total_faces_detected": result.get("total_faces_detected", 0),
            "primary_face_frames": result.get("primary_face_frames", 0),
            "face_detection_rate": result.get("face_detection_rate", 0.0),
            "deepfake_model_loaded": result.get("deepfake_model_loaded", False),
            "frame_scores_available": result.get("frame_scores_available", False),
            "video_score": result.get("video_score"),
            "risk_score": result.get("risk_score"),
            "risk_level": result.get("risk_level", "LOW"),
            "message": result.get("message", "Video analysis completed"),
            "analysis": result,
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            save_analysis_safely(response, input_type="video", input_data=file.filename, custom_id=analysis_id or None)
        return response
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Video analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Video analysis failed: {exc}")
    finally:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass


# ── 6. Email Threat Analysis ──────────────────────────────────────────────────

@app.post("/api/analyze/email", tags=["Email"])
async def analyze_email_endpoint(request: EmailTextRequest):
    """Analyze email subject and body for phishing, credential harvesting, and scam markers."""
    t0 = time.time()
    try:
        from backend.services.email_service import analyze_email
        result = analyze_email(
            subject=request.subject or "",
            body=request.body,
            sender=request.sender or "",
        )

        analysis = result.get("analysis", {})
        risk = analysis.get("risk", {})
        proc_time = round((time.time() - t0) * 1000, 1)

        analysis_id = _register_analysis_context(
            input_type="email",
            risk=risk,
            extracted_text=f"{request.subject}\n{request.body}".strip(),
            detected_urls=[u.get("url") for u in analysis.get("urls", [])],
            indicators=analysis.get("evidence", []),
            ml_preds={"email": analysis.get("ml", {})},
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "email",
            "risk_assessment": risk,
            "analysis": analysis,
        })

        response = {
            "status": "success",
            "type": "email",
            "analysis_id": analysis_id,
            "analysis": analysis,
            "threat_origin": result.get("threat_origin") or analysis.get("threat_origin"),
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            email_input = f"{request.subject} | {request.body[:200]}".strip(" |")
            save_analysis_safely(response, input_type="email", input_data=email_input, custom_id=analysis_id or None)
        return response
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=f"Email threat detection model unavailable: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Email analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Email analysis failed: {exc}")


@app.post("/api/analyze/email/file", tags=["Email"])
async def analyze_email_file_endpoint(file: UploadFile = File(...)):
    """Upload and parse an .eml email file for header spoofing, SPF/DKIM/DMARC status, and URLs."""
    t0 = time.time()
    dest = _save_upload(file, ALLOWED_EMAIL_EXTS)
    await _write_upload(file, dest)

    try:
        with open(dest, "rb") as f:
            eml_bytes = f.read()

        from backend.services.email_parser import parse_eml_bytes
        try:
            parsed = parse_eml_bytes(eml_bytes)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Corrupted or invalid EML file: {e}")

        from backend.services.email_service import analyze_email
        result = analyze_email(
            subject=parsed.get("subject", ""),
            body=parsed.get("body_text", ""),
            sender=parsed.get("from", {}).get("email", ""),
            headers_data=parsed,
        )

        analysis = result.get("analysis", {})
        risk = analysis.get("risk", {})
        proc_time = round((time.time() - t0) * 1000, 1)

        analysis_id = _register_analysis_context(
            input_type="email",
            filename=file.filename,
            risk=risk,
            extracted_text=f"{parsed.get('subject', '')}\n{parsed.get('body_text', '')}".strip(),
            detected_urls=[u.get("url") for u in analysis.get("urls", [])],
            indicators=analysis.get("evidence", []),
            ml_preds={"email": analysis.get("ml", {})},
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "email",
            "risk_assessment": risk,
            "analysis": analysis,
        })

        response = {
            "status": "success",
            "type": "email",
            "filename": file.filename,
            "analysis_id": analysis_id,
            "analysis": analysis,
            "threat_origin": result.get("threat_origin") or analysis.get("threat_origin"),
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            save_analysis_safely(response, input_type="email", input_data=file.filename, custom_id=analysis_id or None)
        return response
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=f"Email threat detection model unavailable: {exc}")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Email file analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Email file analysis failed: {exc}")
    finally:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass


# ── 7. Call Threat Analysis ───────────────────────────────────────────────────

@app.post("/api/analyze/call/text", tags=["Call"])
async def analyze_call_text_endpoint(request: CallTextRequest):
    """Analyze call transcript text for vishing, OTP extortion, and social engineering."""
    t0 = time.time()
    try:
        from backend.services.call_service import analyze_call_transcript
        result = analyze_call_transcript(request.transcript)

        analysis = result.get("analysis", {})
        risk = analysis.get("risk", {})
        proc_time = round((time.time() - t0) * 1000, 1)

        analysis_id = _register_analysis_context(
            input_type="call",
            risk=risk,
            extracted_text=request.transcript,
            detected_urls=[u.get("url") for u in analysis.get("urls", [])],
            indicators=analysis.get("evidence", []),
            ml_preds={"call": analysis.get("ml", {})},
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "call",
            "risk_assessment": risk,
            "analysis": analysis,
        })

        response = {
            "status": "success",
            "type": "call",
            "analysis_id": analysis_id,
            "analysis": analysis,
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            save_analysis_safely(response, input_type="call", input_data=request.transcript[:200], custom_id=analysis_id or None)
        return response
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=f"Call threat detection model unavailable: {exc}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Call text analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Call analysis failed: {exc}")


@app.post("/api/analyze/call", tags=["Call"])
async def analyze_call_audio_endpoint(file: UploadFile = File(...)):
    """Upload audio call recording (.mp3, .wav, .m4a, .ogg, .webm) -> Whisper -> Call Threat Detection."""
    t0 = time.time()
    dest = _save_upload(file, ALLOWED_CALL_EXTS)
    await _write_upload(file, dest)

    try:
        from backend.services.call_service import analyze_call_audio
        result = analyze_call_audio(str(dest))

        analysis = result.get("analysis", {})
        risk = analysis.get("risk", {})
        proc_time = round((time.time() - t0) * 1000, 1)

        analysis_id = _register_analysis_context(
            input_type="call",
            filename=file.filename,
            risk=risk,
            extracted_text=analysis.get("transcript", ""),
            detected_urls=[u.get("url") for u in analysis.get("urls", [])],
            indicators=analysis.get("evidence", []),
            ml_preds={"call": analysis.get("ml", {})},
            processing_time_ms=proc_time,
        )

        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis({
            "modality": "call",
            "risk_assessment": risk,
            "analysis": analysis,
        })

        response = {
            "status": "success",
            "type": "call",
            "filename": file.filename,
            "analysis_id": analysis_id,
            "analysis": analysis,
            "risk_assessment": risk,
            "final_analysis": final_analysis,
            "processing_time_ms": proc_time,
        }
        if _DB_AVAILABLE:
            save_analysis_safely(response, input_type="call", input_data=file.filename, custom_id=analysis_id or None)
        return response
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=f"Model or file error: {exc}")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Call audio analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Call audio analysis failed: {exc}")
    finally:
        try:
            dest.unlink(missing_ok=True)
        except Exception:
            pass


# ── 8. Multimodal combined analysis ──────────────────────────────────────────

@app.post("/api/analyze/multimodal", tags=["Analysis"])
async def analyze_multimodal_endpoint(
    message: str = None,
    url: str = None,
    image: UploadFile = File(default=None),
    audio: UploadFile = File(default=None),
    video: UploadFile = File(default=None),
):
    """
    Combined multimodal analysis — provide any combination of
    message text, URL, image, audio, video.
    """
    t0 = time.time()
    all_indicators: list[str] = []
    all_modalities: list[str] = []
    results: dict = {}

    msg_score = url_score = audio_score = image_score = video_score = None

    # Message
    if message and message.strip():
        from backend.services.message_service import analyze_message
        r = analyze_message(message)
        results["message"] = r
        msg_score = r.get("probability")
        all_indicators.extend(r.get("indicators", []))
        all_modalities.append("message")

    # URL
    if url and url.strip():
        from backend.services.url_service import analyze_url
        r = analyze_url(url)
        results["url"] = r
        url_score = r.get("probability")
        all_indicators.extend(r.get("indicators", []))
        all_modalities.append("url")

    # Image
    if image and image.filename:
        dest = _save_upload(image, ALLOWED_IMAGE_EXTS)
        await _write_upload(image, dest)
        try:
            from backend.services.ocr_service import analyze_image
            r = analyze_image(str(dest))
            results["image"] = r
            if r.get("message_analysis"):
                image_score = r["message_analysis"].get("probability")
            all_indicators.extend(r.get("indicators", []))
            all_modalities.append("image")
        finally:
            dest.unlink(missing_ok=True)

    # Audio
    if audio and audio.filename:
        dest = _save_upload(audio, ALLOWED_AUDIO_EXTS)
        await _write_upload(audio, dest)
        try:
            from backend.services.audio_service import analyze_audio
            r = analyze_audio(str(dest))
            results["audio"] = r
            audio_score = r.get("scam_probability")
            all_indicators.extend(r.get("indicators", []))
            all_modalities.append("audio")
        finally:
            dest.unlink(missing_ok=True)

    # Video
    if video and video.filename:
        dest = _save_upload(video, ALLOWED_VIDEO_EXTS)
        await _write_upload(video, dest)
        try:
            from backend.services.deepfake_service import analyze_video
            r = analyze_video(str(dest))
            results["video"] = r
            p = r.get("deepfake_probability")
            video_score = int(p) if p is not None else None
            all_indicators.extend(r.get("indicators", []))
            all_modalities.append("video")
        finally:
            dest.unlink(missing_ok=True)

    if not all_modalities:
        raise HTTPException(
            status_code=400,
            detail="At least one input (message, url, image, audio, or video) is required."
        )

    from backend.services.risk_engine import compute_risk
    risk = compute_risk(
        message_score=msg_score,
        url_score=url_score,
        audio_score=audio_score,
        image_score=image_score,
        video_score=video_score,
        all_indicators=list(dict.fromkeys(all_indicators)),
        all_modalities=all_modalities,
    )

    from backend.services.analysis_response_service import build_final_analysis
    final_analysis = build_final_analysis({
        "modality": "multimodal",
        "risk_assessment": risk,
        "analysis": {"indicators": all_indicators},
    })

    return {
        "modality": "multimodal",
        "modalities_analyzed": all_modalities,
        "individual_results": results,
        "risk_assessment": risk,
        "final_analysis": final_analysis,
        "processing_time_ms": round((time.time() - t0) * 1000, 1),
    }


# ── 7. Explainable Analysis Endpoint ─────────────────────────────────────────

@app.post("/api/analyze/explanation", tags=["Analysis"])
async def analyze_explanation_endpoint(payload: dict = Body(...)):
    """
    Accepts an existing analysis result or raw signals and returns an
    explainable breakdown (why suspicious, evidence, attacker goal, actions, avoid, verification).
    """
    try:
        from backend.services.analysis_response_service import build_final_analysis
        final_analysis = build_final_analysis(payload)
        return {
            "success": True,
            "analysis": final_analysis,
        }
    except Exception as exc:
        logger.error(f"Explanation analysis error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Explanation analysis failed: {exc}")


# ── 7. Fraud Investigation Copilot Endpoints ─────────────────────────────────

class ChatMessageRequest(BaseModel):
    message: str
    analysis_id: str | None = None


@app.post("/api/chat/upload", tags=["Copilot"])
async def copilot_upload_endpoint(
    text: str | None = Form(None),
    url: str | None = Form(None),
    file: UploadFile | None = File(None),
):
    """
    Accepts multimodal evidence (text, URL, screenshot, audio, or video) for Copilot investigation.
    Executes SatyaAI detection models, stores context in memory, and returns analysis_id.
    """
    from backend.services.analysis_context import get_context_store
    from backend.services.risk_engine import compute_risk

    context_store = get_context_store()
    input_type = "text"
    filename = None
    extracted_text = ""
    detected_urls = []
    ml_preds = {}
    indicators = []
    deepfake_status = "NOT_APPLICABLE"

    # 1. Text input
    if text and text.strip():
        input_type = "text"
        extracted_text = text.strip()
        from backend.services.message_service import analyze_message
        r = analyze_message(extracted_text)
        ml_preds["message"] = r
        indicators.extend(r.get("indicators", []))
        detected_urls.extend(r.get("extracted_urls", []))

    # 2. URL input
    elif url and url.strip():
        input_type = "url"
        target_url = url.strip()
        detected_urls.append(target_url)
        from backend.services.url_service import analyze_url
        r = analyze_url(target_url)
        ml_preds["url"] = r
        indicators.extend(r.get("indicators", []))

    # 3. File upload (Image, Audio, or Video)
    elif file and file.filename:
        filename = file.filename
        ext = Path(filename).suffix.lower()

        if ext in ALLOWED_IMAGE_EXTS:
            input_type = "image"
            dest = _save_upload(file, ALLOWED_IMAGE_EXTS)
            await _write_upload(file, dest)
            try:
                from backend.services.ocr_service import analyze_image
                r = analyze_image(str(dest))
                ml_preds["image"] = r
                extracted_text = r.get("ocr_text", "")
                indicators.extend(r.get("indicators", []))
                if r.get("message_analysis"):
                    ml_preds["message"] = r["message_analysis"]
                if r.get("url_analysis"):
                    ml_preds["url"] = r["url_analysis"]
                    detected_urls.extend(r["url_analysis"].keys())
            finally:
                dest.unlink(missing_ok=True)

        elif ext in ALLOWED_AUDIO_EXTS:
            input_type = "audio"
            dest = _save_upload(file, ALLOWED_AUDIO_EXTS)
            await _write_upload(file, dest)
            try:
                from backend.services.audio_service import analyze_audio
                r = analyze_audio(str(dest))
                ml_preds["audio"] = r
                extracted_text = r.get("transcript", "")
                indicators.extend(r.get("indicators", []))
                if r.get("message_analysis"):
                    ml_preds["message"] = r["message_analysis"]
            finally:
                dest.unlink(missing_ok=True)

        elif ext in ALLOWED_VIDEO_EXTS:
            input_type = "video"
            dest = _save_upload(file, ALLOWED_VIDEO_EXTS)
            await _write_upload(file, dest)
            try:
                from backend.services.deepfake_service import analyze_video
                r = analyze_video(str(dest))
                ml_preds["video"] = r
                indicators.extend(r.get("indicators", []))
                deepfake_status = r.get("deepfake_status", "analyzed")
            finally:
                dest.unlink(missing_ok=True)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file format: {ext}. Upload image, audio, or video."
            )
    else:
        raise HTTPException(
            status_code=400,
            detail="Please provide text, a URL, or an evidence file (image/audio/video)."
        )

    # Compute unified risk
    msg_score = ml_preds["message"].get("probability") if "message" in ml_preds else None
    url_score = ml_preds["url"].get("probability") if "url" in ml_preds else None
    audio_score = ml_preds["audio"].get("scam_probability") if "audio" in ml_preds else None
    video_score = ml_preds["video"].get("deepfake_probability") if "video" in ml_preds else None

    modalities = []
    if msg_score is not None: modalities.append("message")
    if url_score is not None: modalities.append("url")
    if audio_score is not None: modalities.append("audio")
    if video_score is not None: modalities.append("video")
    if not modalities: modalities.append(input_type)

    risk = compute_risk(
        message_score=msg_score,
        url_score=url_score,
        audio_score=audio_score,
        video_score=video_score,
        all_indicators=list(dict.fromkeys(indicators)),
        all_modalities=modalities,
    )

    # Persist in context memory
    analysis_id = context_store.create_context(
        input_type=input_type,
        original_filename=filename,
        extracted_text=extracted_text,
        detected_urls=detected_urls,
        ml_predictions=ml_preds,
        risk_level=risk["risk_level"],
        risk_score=risk["final_score"],
        indicators=risk["evidence"],
        recommendation=risk["recommendation"],
        deepfake_status=deepfake_status,
        raw_analysis=ml_preds,
    )

    return {
        "analysis_id": analysis_id,
        "input_type": input_type,
        "filename": filename,
        "risk_level": risk["risk_level"],
        "risk_score": risk["final_score"],
        "indicators": risk["evidence"],
        "extracted_text": extracted_text,
        "detected_urls": detected_urls,
        "recommendation": risk["recommendation"],
        "deepfake_status": deepfake_status,
        "ml_predictions": ml_preds,
    }


@app.post("/api/chat", tags=["Copilot"])
async def chat_endpoint(req: ChatMessageRequest):
    """
    NLP + RAG AI Fraud Investigation Copilot query endpoint.
    Answers questions grounded on uploaded evidence and threat intelligence.
    """
    from backend.services.chat_service import get_chat_service
    chat_svc = get_chat_service()
    result = chat_svc.process_chat(
        message=req.message,
        analysis_id=req.analysis_id,
    )
    return result


@app.get("/api/chat/context/{analysis_id}", tags=["Copilot"])
async def get_chat_context_endpoint(analysis_id: str):
    """Retrieve active analysis context by analysis_id."""
    from backend.services.analysis_context import get_context_store
    ctx = get_context_store().get_context(analysis_id)
    if not ctx:
        raise HTTPException(status_code=404, detail=f"Context {analysis_id} not found.")
    return ctx


# ─── PostgreSQL Analyses CRUD Endpoints ───────────────────────────────────────

@app.get("/api/analyses", tags=["Database"])
def list_analyses_endpoint(skip: int = 0, limit: int = 50):
    """
    Retrieve stored analysis records from PostgreSQL, ordered by newest first.
    Returns up to `limit` results, offset by `skip`.
    """
    if not _DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database unavailable.")
    db_gen = get_db()
    db = next(db_gen)
    try:
        records = get_analyses(db, skip=skip, limit=limit)
        return {"count": len(records), "analyses": [r.to_dict() for r in records]}
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass


@app.get("/api/analyses/stats/summary", tags=["Database"])
def analyses_stats_endpoint():
    """
    Returns aggregate statistics: total count, counts per input_type and threat_level.
    """
    if not _DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database unavailable.")
    db_gen = get_db()
    db = next(db_gen)
    try:
        from backend.database.models import Analysis
        from sqlalchemy import func
        total = db.query(func.count(Analysis.id)).scalar()
        by_type = db.query(Analysis.input_type, func.count(Analysis.id)).group_by(Analysis.input_type).all()
        by_level = db.query(Analysis.threat_level, func.count(Analysis.id)).group_by(Analysis.threat_level).all()
        return {
            "total": total,
            "by_input_type": {t: c for t, c in by_type if t},
            "by_threat_level": {lvl: c for lvl, c in by_level if lvl},
        }
    except Exception as exc:
        logger.error(f"Stats query error: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Stats query failed: {exc}")
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass


@app.get("/api/analyses/{analysis_id}", tags=["Database"])
def get_analysis_endpoint(analysis_id: str):
    """
    Retrieve a single analysis record by its ID from PostgreSQL.
    """
    if not _DB_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database unavailable.")
    db_gen = get_db()
    db = next(db_gen)
    try:
        record = get_analysis_by_id(db, analysis_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
        return record.to_dict()
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass