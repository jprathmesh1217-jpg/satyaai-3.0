"""
QR Code Detection Service for SatyaAI 3.0.
Detects and decodes one or multiple QR codes from image bytes using OpenCV QRCodeDetector.
Does NOT perform scam classification or modify any existing ML models.
"""

import logging
from typing import Any, Dict, List
import cv2
import numpy as np

logger = logging.getLogger("satyaai.qr_detector")


def _format_points(pts: Any) -> List[List[float]]:
    """Format OpenCV polygon points into a clean JSON-serializable list of [x, y] coordinates."""
    if pts is None:
        return []
    try:
        if hasattr(pts, "tolist"):
            raw_list = pts.tolist()
        else:
            raw_list = list(pts)

        # In case pts is 3D e.g. shape (1, 4, 2)
        if len(raw_list) == 1 and isinstance(raw_list[0], list) and len(raw_list[0]) == 4:
            raw_list = raw_list[0]

        formatted = []
        for point in raw_list:
            if isinstance(point, (list, tuple)) and len(point) >= 2:
                formatted.append([round(float(point[0]), 2), round(float(point[1]), 2)])
        return formatted
    except Exception as exc:
        logger.debug(f"Error formatting points: {exc}")
        return []


def detect_qr_codes(image_bytes: bytes) -> Dict[str, Any]:
    """
    Detects and decodes QR codes from image bytes.

    Args:
        image_bytes: Raw binary image bytes.

    Returns:
        Dict with keys:
            qr_detected (bool): True if at least one QR code was detected.
            count (int): Number of detected QR codes.
            codes (list): List of detected QR items:
                [
                    {
                        "data": "decoded QR content or empty string",
                        "points": [[x1, y1], [x2, y2], [x3, y3], [x4, y4]]
                    }
                ]
    """
    empty_result: Dict[str, Any] = {
        "qr_detected": False,
        "count": 0,
        "codes": []
    }

    if not image_bytes:
        return empty_result

    # 1. Convert uploaded image bytes into an OpenCV image
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            logger.warning("cv2.imdecode returned None; invalid image format or corrupt bytes.")
            return empty_result
    except Exception as exc:
        logger.warning(f"Failed to decode image bytes: {exc}")
        return empty_result

    detector = cv2.QRCodeDetector()
    codes: List[Dict[str, Any]] = []

    # 2. Detect multiple QR codes if possible
    try:
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
        if points is not None and len(points) > 0:
            for idx in range(len(points)):
                pts_formatted = _format_points(points[idx])
                text = ""
                if decoded_info is not None and idx < len(decoded_info):
                    text = str(decoded_info[idx]) if decoded_info[idx] is not None else ""
                codes.append({
                    "data": text,
                    "points": pts_formatted
                })
    except Exception as exc:
        logger.debug(f"detectAndDecodeMulti failed or threw error: {exc}")

    # 3. Fall back to single QR detection if multi-detection produced no codes
    if not codes:
        try:
            retval, points, _ = detector.detectAndDecode(img)
            decoded_text = str(retval) if retval else ""
            if points is not None and len(points) > 0:
                pts_formatted = _format_points(points)
                codes.append({
                    "data": decoded_text,
                    "points": pts_formatted
                })
            elif decoded_text:
                codes.append({
                    "data": decoded_text,
                    "points": []
                })
        except Exception as exc:
            logger.debug(f"Single detectAndDecode fallback failed: {exc}")

    # 4. Fall back to detect-only (multi or single) if detection succeeded but decoding failed
    if not codes:
        try:
            has_qr, det_points = detector.detectMulti(img)
            if has_qr and det_points is not None and len(det_points) > 0:
                for idx in range(len(det_points)):
                    codes.append({
                        "data": "",
                        "points": _format_points(det_points[idx])
                    })
            else:
                has_single, s_points = detector.detect(img)
                if has_single and s_points is not None and len(s_points) > 0:
                    codes.append({
                        "data": "",
                        "points": _format_points(s_points)
                    })
        except Exception as exc:
            logger.debug(f"detect-only fallback failed: {exc}")

    count = len(codes)
    qr_detected = count > 0

    return {
        "qr_detected": qr_detected,
        "count": count,
        "codes": codes
    }
