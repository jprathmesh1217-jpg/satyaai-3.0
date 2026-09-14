"""Tests for deepfake_service.py — video frame extraction."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.deepfake_service import extract_frames, analyze_video


def test_extract_frames_missing_file():
    try:
        extract_frames("/nonexistent/video.mp4")
        assert False, "Should have raised an exception"
    except (FileNotFoundError, ValueError):
        pass


def test_analyze_video_missing_file():
    result = analyze_video("/nonexistent/video.mp4")
    assert result["error"] is not None
    assert "not found" in result["error"].lower() or "Video" in result["error"]


def test_analyze_video_result_keys():
    result = analyze_video("/nonexistent/video.mp4")
    assert "filename" in result
    assert "frames_extracted" in result
    assert "faces_detected" in result
    assert "deepfake_probability" in result
    assert "deepfake_status" in result
    assert "indicators" in result
    assert "risk_level" in result
    assert "error" in result


def test_analyze_existing_video():
    """Test with an existing test video if available."""
    test_video = os.path.join(os.path.dirname(__file__), "..", "backend", "uploads", "test.mp4")
    if not os.path.exists(test_video):
        return  # Skip if test video doesn't exist

    result = analyze_video(test_video)
    assert isinstance(result["frames_extracted"], int)
    assert result["frames_extracted"] >= 0
    assert result["deepfake_status"] in (
        "analyzed", "deepfake_model_not_loaded", "no_frames", "not_analyzed"
    )


def test_deepfake_status_is_not_loaded():
    """Verify that the deepfake status is honest when no model weights are loaded."""
    test_video = os.path.join(os.path.dirname(__file__), "..", "backend", "uploads", "test.mp4")
    if not os.path.exists(test_video):
        return

    result = analyze_video(test_video)
    # Must not claim to be analyzed if model is not loaded
    if result.get("deepfake_probability") is None:
        assert result["deepfake_status"] == "deepfake_model_not_loaded"


def test_empty_video_path():
    result = analyze_video("")
    assert result["error"] is not None


def test_extract_face_and_clipping():
    import numpy as np
    from backend.services.deepfake_service import extract_face

    # Dummy image 200x200
    frame = np.ones((200, 200, 3), dtype=np.uint8) * 128
    # Boundary-overflowing bbox
    bbox = {"x": 180, "y": 180, "width": 50, "height": 50, "confidence": 0.9}
    crop = extract_face(frame, bbox, margin=0.2, target_size=(224, 224))
    assert crop is not None
    assert crop.shape == (224, 224, 3)
    assert crop.dtype == np.uint8


def test_multi_strategy_detector_synthetic():
    import numpy as np
    from backend.services.deepfake_model import get_face_detector

    detector = get_face_detector()
    assert detector is not None
    # Test on blank image -> 0 faces, valid list
    blank = np.zeros((300, 300, 3), dtype=np.uint8)
    faces = detector.detect_faces(blank)
    assert isinstance(faces, list)
    assert len(faces) == 0


def test_analyze_video_telemetry_keys():
    test_video = os.path.join(os.path.dirname(__file__), "..", "backend", "uploads", "test.mp4")
    if not os.path.exists(test_video):
        return

    result = analyze_video(test_video)
    assert "frames_processed" in result
    assert "frames_with_faces" in result
    assert "total_faces_detected" in result
    assert "face_detection_rate" in result
    assert "deepfake_model_loaded" in result
    assert isinstance(result["face_detection_rate"], float)

