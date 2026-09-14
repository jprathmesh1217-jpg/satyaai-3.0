"""
SatyaAI 3.0 — Video Frame Extraction & Face Tracking Pipeline
Extracts representative video frames, tracks faces across temporal sequences,
extracts and preprocesses standardized face crops, and coordinates deepfake analysis.
"""

import os
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

import cv2
import numpy as np

from backend.services.deepfake_model import get_face_detector, get_detector

# Configuration Constants
MAX_FILE_SIZE_MB = 500
MAX_FRAMES = 32
DEBUG_FACE_DETECTION = True
DEBUG_DIR = Path(__file__).resolve().parent.parent / "uploads" / "debug"
PRIMARY_FACE_STRATEGY = "largest"  # "largest" or "highest_confidence"
FACE_MARGIN_RATIO = 0.2
MIN_FACE_SIZE = 30


# ─── 1. Validation & Preprocessing Helpers ────────────────────────────────────

def _validate_video(video_path: str) -> None:
    """Validate video file existence, non-emptiness, and size limits."""
    path = Path(video_path)
    if not path.exists():
        raise FileNotFoundError(f"Video not found: {video_path}")

    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise ValueError(
            f"Video file too large: {size_mb:.1f} MB. Maximum allowed: {MAX_FILE_SIZE_MB} MB."
        )

    if path.stat().st_size == 0:
        raise ValueError("Video file is empty.")


def extract_face(
    frame: np.ndarray,
    bbox: Dict[str, Any],
    margin_ratio: float = FACE_MARGIN_RATIO,
    margin: Optional[float] = None,
    min_size: int = MIN_FACE_SIZE,
    target_size: Tuple[int, int] = (224, 224),
    to_rgb: bool = True,
) -> Optional[np.ndarray]:
    """
    Validate, add margin, clip boundaries, crop, and normalize a face region.

    Args:
        frame: BGR numpy image array.
        bbox: Dictionary with {"x": int, "y": int, "width": int, "height": int}.
        margin_ratio: Margin to expand bounding box by (0.2 = 20%).
        margin: Optional alias for margin_ratio.
        min_size: Minimum pixel dimension allowed for valid face crop.
        target_size: Output (width, height) to resize face crop to.
        to_rgb: Whether to convert BGR to RGB color space.

    Returns:
        Standardized face crop numpy array, or None if invalid.
    """
    if margin is not None:
        margin_ratio = margin
    if frame is None or frame.size == 0 or not bbox:
        return None

    frame_h, frame_w = frame.shape[:2]
    x = int(bbox.get("x", 0))
    y = int(bbox.get("y", 0))
    w = int(bbox.get("width", 0))
    h = int(bbox.get("height", 0))

    if w < min_size or h < min_size:
        return None

    # Calculate proportional expansion margin
    pad_x = int(w * margin_ratio)
    pad_y = int(h * margin_ratio)

    # Apply margin with strict image boundary clipping
    x1 = max(0, x - pad_x)
    y1 = max(0, y - pad_y)
    x2 = min(frame_w, x + w + pad_x)
    y2 = min(frame_h, y + h + pad_y)

    crop_w = x2 - x1
    crop_h = y2 - y1

    if crop_w < min_size or crop_h < min_size:
        return None

    crop = frame[y1:y2, x1:x2]
    if crop.size == 0:
        return None

    # Color space conversion
    if to_rgb:
        crop = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB)

    # Standardized resizing
    if target_size and (crop.shape[1] != target_size[0] or crop.shape[0] != target_size[1]):
        crop = cv2.resize(crop, target_size, interpolation=cv2.INTER_AREA)

    return crop


# ─── 2. Temporal Face Tracker (IoU + Centroid) ────────────────────────────────

class CentroidIoUTracker:
    """
    Lightweight, dependency-free face tracker using IoU and centroid distance
    to maintain consistent face identities across temporal video frames.
    """

    def __init__(self, iou_threshold: float = 0.25, max_distance: float = 120.0):
        self.iou_threshold = iou_threshold
        self.max_distance = max_distance
        self.next_track_id = 1
        self.active_tracks: Dict[int, Dict[str, Any]] = {}  # track_id -> {"bbox": ..., "lost": ...}

    def _compute_iou(self, boxA: Dict[str, int], boxB: Dict[str, int]) -> float:
        xA = max(boxA["x"], boxB["x"])
        yA = max(boxA["y"], boxB["y"])
        xB = min(boxA["x"] + boxA["width"], boxB["x"] + boxB["width"])
        yB = min(boxA["y"] + boxA["height"], boxB["y"] + boxB["height"])

        interArea = max(0, xB - xA) * max(0, yB - yA)
        boxAArea = boxA["width"] * boxA["height"]
        boxBArea = boxB["width"] * boxB["height"]
        unionArea = boxAArea + boxBArea - interArea

        return interArea / unionArea if unionArea > 0 else 0.0

    def update(self, detected_faces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Update tracked faces with newly detected bounding boxes.
        Appends 'track_id' to each detected face dictionary.
        """
        if not detected_faces:
            # Mark all active tracks as aged
            for tid in list(self.active_tracks.keys()):
                self.active_tracks[tid]["lost"] += 1
                if self.active_tracks[tid]["lost"] > 5:
                    del self.active_tracks[tid]
            return []

        matched_detections = set()
        matched_tracks = set()
        updated_faces = []

        # Try to match detections with existing active tracks
        for tid, track_info in self.active_tracks.items():
            best_iou = 0.0
            best_det_idx = -1
            prev_bbox = track_info["bbox"]

            for idx, det in enumerate(detected_faces):
                if idx in matched_detections:
                    continue
                iou = self._compute_iou(prev_bbox, det)
                if iou > best_iou:
                    best_iou = iou
                    best_det_idx = idx

            if best_iou >= self.iou_threshold and best_det_idx != -1:
                matched_detections.add(best_det_idx)
                matched_tracks.add(tid)
                det = detected_faces[best_det_idx].copy()
                det["track_id"] = tid
                self.active_tracks[tid] = {"bbox": det, "lost": 0}
                updated_faces.append(det)

        # Create new tracks for unmatched detections
        for idx, det in enumerate(detected_faces):
            if idx not in matched_detections:
                tid = self.next_track_id
                self.next_track_id += 1
                det_copy = det.copy()
                det_copy["track_id"] = tid
                self.active_tracks[tid] = {"bbox": det_copy, "lost": 0}
                updated_faces.append(det_copy)

        # Clean aged tracks
        for tid in list(self.active_tracks.keys()):
            if tid not in matched_tracks:
                self.active_tracks[tid]["lost"] += 1
                if self.active_tracks[tid]["lost"] > 5:
                    del self.active_tracks[tid]

        return updated_faces


# ─── 3. Frame Extraction Service ─────────────────────────────────────────────

def extract_frames(video_path: str, max_frames: int = MAX_FRAMES) -> List[np.ndarray]:
    """
    Extract up to max_frames representative frames using sequential reading.
    Avoids random seeking jitter while preserving high resolution (caps at 1280px).
    """
    _validate_video(video_path)

    cap = cv2.VideoCapture(str(video_path))
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")

    frames: List[np.ndarray] = []
    try:
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if total_frames <= 0:
            # Try reading until EOF
            count = 0
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                count += 1
            total_frames = count
            cap.set(cv2.CAP_PROP_POS_FRAMES, 0)

        if total_frames <= 0:
            return []

        step = max(1, total_frames // max_frames)
        frame_idx = 0

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            if frame_idx % step == 0:
                h, w = frame.shape[:2]
                # High-fidelity cap at 1280px (never downscale to 640px)
                if w > 1280:
                    scale = 1280 / w
                    frame = cv2.resize(frame, (1280, int(h * scale)), interpolation=cv2.INTER_AREA)
                frames.append(frame)

                if len(frames) >= max_frames:
                    break

            frame_idx += 1

        return frames

    finally:
        cap.release()


# ─── 4. Full Video Deepfake Pipeline ─────────────────────────────────────────

def analyze_video(video_path: str, max_frames: int = MAX_FRAMES) -> Dict[str, Any]:
    """
    Complete video analysis pipeline:
    1. Validate and open video
    2. Sequentially extract representative frames
    3. Multi-strategy face detection on each frame
    4. Centroid/IoU face tracking across frames
    5. Primary face extraction and preprocessing
    6. Deepfake model evaluation (or honest not-loaded reporting)
    7. Temporal score aggregation
    8. Debug frame export when enabled
    """
    filename = Path(video_path).name
    result: Dict[str, Any] = {
        "filename": filename,
        "status": "success",
        "frames_processed": 0,
        "frames_extracted": 0,  # Backward compatibility
        "frames_with_faces": 0,
        "total_faces_detected": 0,
        "primary_face_frames": 0,
        "face_detection_rate": 0.0,
        "deepfake_model_loaded": False,
        "frame_scores_available": False,
        "video_score": None,
        "risk_score": None,
        "risk_level": "LOW",
        "deepfake_status": "not_analyzed",
        "deepfake_probability": None,  # Backward compatibility
        "duration_seconds": 0.0,
        "faces_detected": 0,  # Backward compatibility
        "indicators": [],
        "debug_frames_saved": 0,
        "message": "Analysis completed",
        "error": None,
    }

    try:
        _validate_video(video_path)

        # Video metadata
        cap = cv2.VideoCapture(str(video_path))
        if not cap.isOpened():
            raise ValueError(f"Cannot open video: {video_path}")
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        cap.release()

        result["duration_seconds"] = round(total_frames / fps, 2) if total_frames > 0 else 0.0

        # Frame extraction
        frames = extract_frames(video_path, max_frames)
        result["frames_processed"] = len(frames)
        result["frames_extracted"] = len(frames)

        if not frames:
            result["status"] = "error"
            result["message"] = "No frames could be extracted from video"
            result["indicators"].append("No frames could be extracted from video")
            return result

        # Initialize detector & tracker
        face_detector = get_face_detector()
        deepfake_detector = get_detector()
        tracker = CentroidIoUTracker()

        result["deepfake_model_loaded"] = deepfake_detector.is_model_loaded

        # Prepare debug export directory if enabled
        if DEBUG_FACE_DETECTION:
            DEBUG_DIR.mkdir(parents=True, exist_ok=True)

        frames_with_faces = 0
        total_faces = 0
        primary_crops: List[np.ndarray] = []
        frame_deepfake_scores: List[float] = []
        all_anomalies: List[str] = []
        debug_count = 0

        # Process each sampled frame
        for frame_idx, frame in enumerate(frames):
            detected_faces = face_detector.detect_faces(frame)
            tracked_faces = tracker.update(detected_faces)

            if tracked_faces:
                frames_with_faces += 1
                total_faces += len(tracked_faces)

                # Select primary face according to strategy
                if PRIMARY_FACE_STRATEGY == "highest_confidence":
                    primary_face = max(tracked_faces, key=lambda f: f.get("confidence", 0.0))
                else:  # "largest"
                    primary_face = max(tracked_faces, key=lambda f: f["width"] * f["height"])

                # Extract standardized face crop
                crop = extract_face(frame, primary_face, margin_ratio=FACE_MARGIN_RATIO, to_rgb=True)
                if crop is not None:
                    primary_crops.append(crop)

                    # Run deepfake neural prediction if weights are loaded
                    pred_score = deepfake_detector.predict_face_crop(crop)
                    if pred_score is not None:
                        frame_deepfake_scores.append(pred_score)

                    # Mathematical forensic telemetry
                    bgr_crop = cv2.cvtColor(crop, cv2.COLOR_RGB2BGR)
                    forensics = deepfake_detector.analyze_face_forensics(bgr_crop)
                    if forensics.get("anomalies"):
                        all_anomalies.extend(forensics["anomalies"])

                # Save debug annotated frame
                if DEBUG_FACE_DETECTION and debug_count < 10:
                    dbg_frame = frame.copy()
                    for idx, tf in enumerate(tracked_faces):
                        x, y, w, h = tf["x"], tf["y"], tf["width"], tf["height"]
                        conf = tf.get("confidence", 0.0)
                        tid = tf.get("track_id", idx + 1)
                        det_type = tf.get("detector", "det")

                        # Draw bounding box (cyan for primary, magenta for others)
                        color = (255, 245, 0) if tf is primary_face else (255, 0, 180)
                        cv2.rectangle(dbg_frame, (x, y), (x + w, y + h), color, 2)

                        label = f"FACE {idx + 1} [ID:{tid}] {conf:.2f} ({det_type})"
                        cv2.putText(
                            dbg_frame,
                            label,
                            (x, max(15, y - 8)),
                            cv2.FONT_HERSHEY_SIMPLEX,
                            0.5,
                            color,
                            1,
                            cv2.LINE_AA,
                        )

                    out_path = DEBUG_DIR / f"frame_{frame_idx + 1:03d}.jpg"
                    cv2.imwrite(str(out_path), dbg_frame)

                    if crop is not None:
                        crop_out = DEBUG_DIR / f"face_{frame_idx + 1:03d}.jpg"
                        cv2.imwrite(str(crop_out), cv2.cvtColor(crop, cv2.COLOR_RGB2BGR))

                    debug_count += 1

        result["frames_with_faces"] = frames_with_faces
        result["total_faces_detected"] = total_faces
        result["faces_detected"] = total_faces  # Backward compatibility
        result["primary_face_frames"] = len(primary_crops)
        result["debug_frames_saved"] = debug_count
        result["face_detection_rate"] = round(frames_with_faces / len(frames), 3) if frames else 0.0

        # Handle No-Face Scenario
        if frames_with_faces == 0:
            result["status"] = "no_face_detected"
            result["deepfake_status"] = "no_face_detected"
            result["video_score"] = None
            result["risk_score"] = 0
            result["deepfake_probability"] = 0
            result["risk_level"] = "LOW"
            result["message"] = "No reliable face detected in the sampled video frames"
            result["indicators"].append("No reliable human or stylized face detected in video")
            return result

        # Handle Detected Faces Scenario
        result["status"] = "success"
        result["indicators"].append(
            f"Detected {total_faces} face instance(s) across {frames_with_faces}/{len(frames)} frames "
            f"({result['face_detection_rate'] * 100:.1f}% detection rate)"
        )

        # Deepfake Analysis Reporting
        if result["deepfake_model_loaded"] and frame_deepfake_scores:
            agg = deepfake_detector.aggregate_predictions(frame_deepfake_scores)
            result["frame_scores_available"] = True
            result["video_score"] = agg["video_score"]
            result["risk_score"] = agg["risk_score"]
            result["deepfake_probability"] = agg["risk_score"]
            result["risk_level"] = agg["risk_level"]
            result["deepfake_status"] = "analyzed"
            result["message"] = f"Video deepfake analysis complete: {agg['risk_level']} risk ({agg['risk_score']}/100)"
        else:
            # Model not loaded: honest reporting per instructions
            result["frame_scores_available"] = False
            result["video_score"] = None
            result["risk_score"] = None
            result["deepfake_probability"] = None
            result["risk_level"] = "LOW"
            result["deepfake_status"] = "deepfake_model_not_loaded"
            result["message"] = "Face detection & tracking succeeded. Deepfake neural model weights not loaded."
            result["indicators"].append("Deepfake neural model weights not loaded (models/deepfake_model.pth)")

        # Include forensic telemetry in indicators if anomalies detected
        if all_anomalies:
            unique_anomalies = list(dict.fromkeys(all_anomalies))
            result["indicators"].extend(unique_anomalies)

    except (FileNotFoundError, ValueError) as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        result["message"] = str(exc)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"Video analysis failed: {exc}"
        result["message"] = f"Video analysis failed: {exc}"

    return result