"""
SatyaAI 3.0 — Face Detection & Deepfake Modeling Service
Implements a multi-strategy face detector (OpenCV DNN YuNet + CLAHE-enhanced Haar fallback),
extracts and preprocesses face crops, executes deepfake analysis with temporal aggregation,
and honestly reports model status without inventing artificial AI scores.
"""

import os
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

import cv2
import numpy as np

# Model weights path configuration
MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
YUNET_MODEL_PATH = MODELS_DIR / "face_detection_yunet_2023mar.onnx"
DEEPFAKE_MODEL_PATH = MODELS_DIR / "deepfake_model.pth"


# ─── 1. Multi-Strategy Face Detector ─────────────────────────────────────────

class MultiStrategyFaceDetector:
    """
    Robust Face Detector employing a tiered strategy:
    - Tier 1: OpenCV DNN FaceDetectorYN (YuNet ONNX) — high accuracy, fast CPU inference.
    - Tier 2: CLAHE-boosted Haar Cascade fallback (frontal + profile) for low-contrast/stylized faces.
    """

    def __init__(self, score_threshold: float = 0.45, nms_threshold: float = 0.3):
        self.score_threshold = score_threshold
        self.nms_threshold = nms_threshold
        self._yunet = None
        self._yunet_loaded = False
        self._haar_cascades = []
        self._clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        self._lock = threading.Lock()
        self._init_detectors()

    def _init_detectors(self) -> None:
        """Initialize YuNet DNN detector and Haar cascade fallbacks."""
        # 1. Initialize YuNet if ONNX weights exist
        if YUNET_MODEL_PATH.exists() and hasattr(cv2, "FaceDetectorYN"):
            try:
                self._yunet = cv2.FaceDetectorYN.create(
                    model=str(YUNET_MODEL_PATH),
                    config="",
                    input_size=(320, 320),
                    score_threshold=self.score_threshold,
                    nms_threshold=self.nms_threshold,
                    top_k=5000,
                )
                self._yunet_loaded = True
            except Exception:
                self._yunet_loaded = False

        # 2. Initialize Haar cascades as robust fallback
        try:
            cascade_paths = [
                ("frontal", cv2.data.haarcascades + "haarcascade_frontalface_default.xml"),
                ("profile", cv2.data.haarcascades + "haarcascade_profileface.xml"),
                ("frontal_alt", cv2.data.haarcascades + "haarcascade_frontalface_alt2.xml"),
            ]
            for name, path in cascade_paths:
                if os.path.exists(path):
                    c = cv2.CascadeClassifier(path)
                    if not c.empty():
                        self._haar_cascades.append((name, c))
        except Exception:
            pass

    def detect_faces(self, frame: np.ndarray) -> List[Dict[str, Any]]:
        """
        Detect faces in a single video frame.

        Returns list of bounding boxes in format:
        [
            {
                "x": int,
                "y": int,
                "width": int,
                "height": int,
                "confidence": float,
                "detector": "yunet" | "haar_clahe"
            },
            ...
        ]
        """
        if frame is None or frame.size == 0:
            return []

        h, w = frame.shape[:2]
        detected_faces: List[Dict[str, Any]] = []

        # Strategy 1: OpenCV DNN FaceDetectorYN
        if self._yunet_loaded and self._yunet is not None:
            try:
                with self._lock:
                    self._yunet.setInputSize((w, h))
                    _, raw_faces = self._yunet.detect(frame)

                if raw_faces is not None and len(raw_faces) > 0:
                    for f in raw_faces:
                        fx = int(f[0])
                        fy = int(f[1])
                        fw = int(f[2])
                        fh = int(f[3])
                        conf = float(f[-1])

                        # Boundary clipping
                        cx = max(0, min(w - 1, fx))
                        cy = max(0, min(h - 1, fy))
                        cw = max(1, min(w - cx, fw))
                        ch = max(1, min(h - cy, fh))

                        if cw >= 20 and ch >= 20:
                            detected_faces.append({
                                "x": cx,
                                "y": cy,
                                "width": cw,
                                "height": ch,
                                "confidence": round(conf, 3),
                                "detector": "yunet",
                            })
            except Exception:
                pass

        # If YuNet detected faces, return them
        if detected_faces:
            return detected_faces

        # Strategy 2: CLAHE-boosted Haar Cascade Fallback
        if self._haar_cascades:
            try:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                enhanced_gray = self._clahe.apply(gray)

                # Try on enhanced gray first, then standard gray if empty
                for gray_input, factor in [(enhanced_gray, 1.05), (gray, 1.1)]:
                    for name, cascade in self._haar_cascades:
                        boxes = cascade.detectMultiScale(
                            gray_input,
                            scaleFactor=factor,
                            minNeighbors=3,
                            minSize=(30, 30),
                        )
                        if len(boxes) > 0:
                            for (bx, by, bw, bh) in boxes:
                                cx = max(0, min(w - 1, int(bx)))
                                cy = max(0, min(h - 1, int(by)))
                                cw = max(1, min(w - cx, int(bw)))
                                ch = max(1, min(h - cy, int(bh)))

                                # Avoid duplicate boxes
                                duplicate = False
                                for ex in detected_faces:
                                    if abs(ex["x"] - cx) < 20 and abs(ex["y"] - cy) < 20:
                                        duplicate = True
                                        break

                                if not duplicate and cw >= 24 and ch >= 24:
                                    detected_faces.append({
                                        "x": cx,
                                        "y": cy,
                                        "width": cw,
                                        "height": ch,
                                        "confidence": 0.75 if name == "frontal" else 0.65,
                                        "detector": "haar_clahe",
                                    })
                    if detected_faces:
                        break
            except Exception:
                pass

        return detected_faces


# Global Face Detector Singleton
_global_face_detector = None
_face_detector_lock = threading.Lock()


def get_face_detector() -> MultiStrategyFaceDetector:
    """Return singleton MultiStrategyFaceDetector instance."""
    global _global_face_detector
    if _global_face_detector is not None:
        return _global_face_detector

    with _face_detector_lock:
        if _global_face_detector is None:
            _global_face_detector = MultiStrategyFaceDetector()
    return _global_face_detector


# ─── 2. Deepfake Analysis & Temporal Aggregation ─────────────────────────────

class DeepfakeDetector:
    """
    Manages deepfake neural model evaluation and forensic telemetry.
    Honestly distinguishes between loaded neural models and unavailable weights.
    """

    def __init__(self):
        self._model = None
        self._deepfake_model_loaded = False
        self._face_detector = get_face_detector()
        self.load_model()

    def load_model(self) -> None:
        """Load trained neural deepfake weights if available."""
        if DEEPFAKE_MODEL_PATH.exists():
            try:
                import torch
                self._model = torch.load(str(DEEPFAKE_MODEL_PATH), map_location="cpu")
                if hasattr(self._model, "eval"):
                    self._model.eval()
                self._deepfake_model_loaded = True
            except Exception:
                self._deepfake_model_loaded = False
        else:
            self._deepfake_model_loaded = False

    @property
    def is_model_loaded(self) -> bool:
        return self._deepfake_model_loaded

    def analyze_face_forensics(self, face_bgr: np.ndarray) -> Dict[str, Any]:
        """
        Mathematical forensic telemetry:
        1. 2D FFT High-Frequency Energy Ratio (detects GAN upsampling artifacts).
        2. Boundary Laplacian Gradient Variance (detects blending feathering).
        """
        if face_bgr is None or face_bgr.shape[0] < 20 or face_bgr.shape[1] < 20:
            return {"score": 10, "anomalies": []}

        h, w = face_bgr.shape[:2]
        gray = cv2.cvtColor(face_bgr, cv2.COLOR_BGR2GRAY)
        anomalies = []
        anomaly_score = 10

        # FFT High-Frequency Energy Ratio
        try:
            f = np.fft.fft2(gray)
            fshift = np.fft.fftshift(f)
            mag = np.abs(fshift)
            cy, cx = h // 2, w // 2
            y, x = np.ogrid[:h, :w]
            dist = np.sqrt((x - cx) ** 2 + (y - cy) ** 2)
            high_mask = dist > (min(h, w) * 0.38)
            total_energy = np.sum(mag) + 1e-6
            high_energy = np.sum(mag[high_mask])
            ratio = high_energy / total_energy

            if ratio > 0.68:
                anomalies.append("High-frequency spectral anomaly detected (possible GAN artifact)")
                anomaly_score += 30
            elif ratio < 0.08:
                anomalies.append("Abnormal facial over-smoothing / low texture frequency")
                anomaly_score += 20
        except Exception:
            pass

        # Boundary Blending Discontinuity
        try:
            pad_h = max(2, int(h * 0.12))
            pad_w = max(2, int(w * 0.12))
            lap_total = cv2.Laplacian(gray, cv2.CV_64F).var()
            inner = gray[pad_h:h - pad_h, pad_w:w - pad_w]
            if inner.size > 0:
                inner_var = cv2.Laplacian(inner, cv2.CV_64F).var()
                border_diff = abs(lap_total - inner_var) / (inner_var + 1e-6)
                if border_diff > 3.0:
                    anomalies.append("Boundary gradient discrepancy (feathering/blending artifact)")
                    anomaly_score += 25
        except Exception:
            pass

        return {
            "score": min(90, anomaly_score),
            "anomalies": anomalies,
        }

    def predict_face_crop(self, face_rgb: np.ndarray) -> Optional[float]:
        """
        Predict deepfake manipulation probability for a preprocessed face crop.
        Returns float probability in [0.0, 1.0], or None if no deepfake model is loaded.
        """
        if not self._deepfake_model_loaded or self._model is None:
            return None

        try:
            import torch
            # Convert HWC uint8 [0, 255] to CHW float tensor [0.0, 1.0]
            tensor = torch.from_numpy(face_rgb).permute(2, 0, 1).unsqueeze(0).float() / 255.0
            with torch.no_grad():
                out = self._model(tensor)
                if isinstance(out, torch.Tensor):
                    prob = torch.sigmoid(out).item() if out.shape[-1] == 1 else torch.softmax(out, dim=-1)[0, 1].item()
                    return float(np.clip(prob, 0.0, 1.0))
        except Exception:
            pass

        return None

    def aggregate_predictions(self, frame_scores: List[float]) -> Dict[str, Any]:
        """
        Aggregate frame-level predictions into a video-level verdict using median score.
        """
        if not frame_scores:
            return {
                "frame_scores_available": False,
                "video_score": None,
                "risk_score": None,
                "mean_score": None,
                "median_score": None,
                "max_score": None,
                "risk_level": "LOW",
            }

        scores_arr = np.array(frame_scores)
        mean_s = float(np.mean(scores_arr))
        median_s = float(np.median(scores_arr))
        max_s = float(np.max(scores_arr))

        # Primary video score is median to prevent single-frame false-alarm skew
        video_score = round(median_s, 3)
        risk_score = int(round(video_score * 100))

        if risk_score >= 75:
            risk_level = "HIGH"
        elif risk_score >= 45:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "frame_scores_available": True,
            "video_score": video_score,
            "risk_score": risk_score,
            "mean_score": round(mean_s, 3),
            "median_score": round(median_s, 3),
            "max_score": round(max_s, 3),
            "risk_level": risk_level,
        }


# Global Deepfake Detector Singleton
_global_deepfake_detector = None
_deepfake_detector_lock = threading.Lock()


def get_detector() -> DeepfakeDetector:
    """Return singleton DeepfakeDetector instance."""
    global _global_deepfake_detector
    if _global_deepfake_detector is not None:
        return _global_deepfake_detector

    with _deepfake_detector_lock:
        if _global_deepfake_detector is None:
            _global_deepfake_detector = DeepfakeDetector()
    return _global_deepfake_detector
