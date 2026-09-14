#!/usr/bin/env python3
"""
SatyaAI 3.0 — Comprehensive System Diagnostic Tool
Tests all critical components, dependencies, system binaries, and ML models.
"""

import sys
import os
import shutil
import os
import sys
import warnings
from pathlib import Path

# Suppress benign feature name warnings from scikit-learn models
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"

results = {}
errors = []


def record_result(component: str, passed: bool, error_msg: str = None, cause: str = None, fix: str = None):
    results[component] = "PASS" if passed else "FAIL"
    if not passed and error_msg:
        errors.append({
            "component": component,
            "error": error_msg,
            "cause": cause or "Unknown cause",
            "fix": fix or "Check environment documentation"
        })


def check_python():
    v = sys.version_info
    py_str = f"Python {v.major}.{v.minor}.{v.micro}"
    if v.major == 3 and v.minor == 11:
        record_result("Python", True)
    elif v.major == 3 and v.minor in (10, 11, 12):
        record_result("Python", True)
    else:
        record_result(
            "Python", False,
            error_msg=f"Unsupported Python version: {py_str}",
            cause="ML stack requires Python 3.11 for scikit-learn 1.6.1 and PyTorch/Whisper compatibility.",
            fix="Activate venv311: source venv311/bin/activate"
        )


def check_fastapi():
    try:
        import fastapi
        import uvicorn
        record_result("FastAPI", True)
    except Exception as e:
        record_result(
            "FastAPI", False,
            error_msg=str(e),
            cause="FastAPI or Uvicorn is not installed in the active environment.",
            fix="pip install fastapi 'uvicorn[standard]'"
        )


def check_opencv():
    try:
        import cv2
        _ = cv2.__version__
        record_result("OpenCV", True)
    except Exception as e:
        record_result(
            "OpenCV", False,
            error_msg=str(e),
            cause="opencv-python is missing or corrupt.",
            fix="pip install opencv-python"
        )


def check_numpy():
    try:
        import numpy as np
        _ = np.__version__
        record_result("NumPy", True)
    except Exception as e:
        record_result(
            "NumPy", False,
            error_msg=str(e),
            cause="NumPy is missing or incompatible.",
            fix="pip install 'numpy>=1.26.0,<2.5.0'"
        )


def check_pillow():
    try:
        import PIL
        from PIL import Image
        record_result("Pillow", True)
    except Exception as e:
        record_result(
            "Pillow", False,
            error_msg=str(e),
            cause="Pillow is missing.",
            fix="pip install Pillow"
        )


def check_tesseract():
    tess_path = shutil.which("tesseract")
    brew_tess = Path("/opt/homebrew/bin/tesseract")
    usr_tess = Path("/usr/local/bin/tesseract")
    
    found = tess_path or (brew_tess.exists() and str(brew_tess)) or (usr_tess.exists() and str(usr_tess))
    
    try:
        import pytesseract
        if found:
            pytesseract.pytesseract.tesseract_cmd = str(found)
        record_result("Tesseract", bool(found))
        if not found:
            errors.append({
                "component": "Tesseract",
                "error": "Tesseract binary not found in PATH or standard locations.",
                "cause": "Tesseract OCR engine is not installed on the system.",
                "fix": "macOS: brew install tesseract | Linux: sudo apt install tesseract-ocr"
            })
    except Exception as e:
        record_result(
            "Tesseract", False,
            error_msg=str(e),
            cause="pytesseract Python package is missing.",
            fix="pip install pytesseract"
        )


def check_sklearn():
    try:
        import sklearn
        import joblib
        record_result("Scikit-learn", True)
    except Exception as e:
        record_result(
            "Scikit-learn", False,
            error_msg=str(e),
            cause="scikit-learn or joblib is missing.",
            fix="pip install scikit-learn==1.6.1 joblib"
        )


def check_message_model():
    model_path = MODELS_DIR / "message_model.pkl"
    if not model_path.exists():
        record_result(
            "Message Model", False,
            error_msg=f"File not found: {model_path}",
            cause="Model file is missing from models/ directory.",
            fix="Ensure models/message_model.pkl exists."
        )
        return

    try:
        import joblib
        model = joblib.load(model_path)
        # Test inference with sample text
        pred = model.predict(["Test verification scam message"])
        _ = model.predict_proba(["Test verification scam message"])
        record_result("Message Model", True)
    except Exception as e:
        record_result(
            "Message Model", False,
            error_msg=str(e),
            cause=f"Failed to load or execute models/message_model.pkl: {e}",
            fix="Ensure scikit-learn 1.6.1 is installed in Python 3.11 environment."
        )


def check_url_model():
    phishing_path = MODELS_DIR / "url_phishing_model.pkl"
    fallback_path = MODELS_DIR / "url_model.pkl"
    model_path = phishing_path if phishing_path.exists() else fallback_path
    features_path = MODELS_DIR / "url_features.pkl"
    
    if not model_path.exists() or not features_path.exists():
        record_result(
            "URL Model", False,
            error_msg="URL model or features file missing.",
            cause=f"Checked: {model_path.exists()} for model ({model_path.name}), {features_path.exists()} for features.",
            fix="Ensure models/url_phishing_model.pkl (or url_model.pkl) and models/url_features.pkl exist."
        )
        return

    try:
        import joblib
        import numpy as np
        model = joblib.load(model_path)
        features = joblib.load(features_path)
        # Verify feature vector of length 12
        sample_vec = np.zeros((1, len(features)))
        _ = model.predict(sample_vec)
        _ = model.predict_proba(sample_vec)
        record_result("URL Model", True)
    except Exception as e:
        record_result(
            "URL Model", False,
            error_msg=str(e),
            cause=f"Failed to load or execute {model_path.name}: {e}",
            fix="Check scikit-learn compatibility and feature length."
        )


def check_pytorch():
    try:
        import torch
        _ = torch.__version__
        record_result("PyTorch", True)
    except Exception as e:
        record_result(
            "PyTorch", False,
            error_msg=str(e),
            cause="PyTorch is missing.",
            fix="pip install torch torchvision"
        )


def check_whisper():
    try:
        import whisper
        record_result("Whisper", True)
    except Exception as e:
        record_result(
            "Whisper", False,
            error_msg=str(e),
            cause="openai-whisper package is missing.",
            fix="pip install openai-whisper"
        )


def check_ffmpeg():
    ffmpeg_path = shutil.which("ffmpeg")
    brew_ffmpeg = Path("/opt/homebrew/bin/ffmpeg")
    usr_ffmpeg = Path("/usr/local/bin/ffmpeg")
    found = ffmpeg_path or (brew_ffmpeg.exists() and str(brew_ffmpeg)) or (usr_ffmpeg.exists() and str(usr_ffmpeg))
    
    if found:
        record_result("FFmpeg", True)
    else:
        record_result(
            "FFmpeg", False,
            error_msg="FFmpeg binary not found in PATH.",
            cause="FFmpeg is needed by Whisper and OpenCV for audio/video decoding.",
            fix="macOS: brew install ffmpeg | Linux: sudo apt install ffmpeg"
        )


def main():
    print("=============================")
    print("SATYAAI SYSTEM DIAGNOSTIC")
    print("=============================")
    print()

    check_python()
    check_fastapi()
    check_opencv()
    check_numpy()
    check_pillow()
    check_tesseract()
    check_sklearn()
    check_message_model()
    check_url_model()
    check_pytorch()
    check_whisper()
    check_ffmpeg()

    for comp, res in results.items():
        print(f"{comp}: {res}")

    print()
    print("=============================")
    all_passed = all(v == "PASS" for v in results.values())
    if all_passed:
        print("FINAL STATUS: READY")
    else:
        print("FINAL STATUS: ISSUES DETECTED")
        print("=============================")
        print()
        for err in errors:
            print(f"ERROR [{err['component']}]: {err['error']}")
            print(f"CAUSE: {err['cause']}")
            print(f"FIX: {err['fix']}")
            print("-" * 30)
    print("=============================")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
