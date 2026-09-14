"""
SatyaAI 3.0 — Face Detection & Tracking Verification Script
Loads backend/uploads/test.mp4, runs multi-strategy face detection and tracking,
saves debug frames with bounding boxes, tests extract_face(), and displays telemetry.
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cv2
import numpy as np

from backend.services.deepfake_service import (
    extract_frames,
    extract_face,
    analyze_video,
    CentroidIoUTracker,
    DEBUG_DIR,
)
from backend.services.deepfake_model import get_face_detector


def test_extract_face_unit():
    """Unit test for extract_face() preprocessing function."""
    print("Testing extract_face() function...")
    dummy_frame = np.zeros((400, 600, 3), dtype=np.uint8)
    dummy_frame[100:200, 150:250] = 200  # Draw bright square (simulated face)

    valid_bbox = {"x": 150, "y": 100, "width": 100, "height": 100, "confidence": 0.9}
    crop = extract_face(dummy_frame, valid_bbox, margin_ratio=0.2, min_size=30, target_size=(224, 224), to_rgb=True)
    assert crop is not None, "Failed to extract valid face crop"
    assert crop.shape == (224, 224, 3), f"Unexpected crop shape: {crop.shape}"

    # Test boundary clipping (face near edge)
    edge_bbox = {"x": 550, "y": 350, "width": 80, "height": 80}
    crop_edge = extract_face(dummy_frame, edge_bbox, margin_ratio=0.3, min_size=30, target_size=(224, 224))
    assert crop_edge is not None, "Failed to extract edge face crop with boundary clipping"

    # Test tiny face rejection
    tiny_bbox = {"x": 50, "y": 50, "width": 15, "height": 15}
    crop_tiny = extract_face(dummy_frame, tiny_bbox, min_size=30)
    assert crop_tiny is None, "Should have rejected tiny face crop"

    # Test invalid / empty frame
    empty_crop = extract_face(np.zeros((0, 0, 3), dtype=np.uint8), valid_bbox)
    assert empty_crop is None, "Should return None for empty frame"

    print("✓ extract_face() unit tests passed successfully!\n")


def run_face_detection_test(video_path: str = "backend/uploads/test.mp4"):
    """Execute full face detection and tracking test on video."""
    vpath = Path(video_path)
    if not vpath.exists():
        print(f"Error: Video file not found: {video_path}")
        return

    # Run extract_face unit test first
    test_extract_face_unit()

    # 1. Extract frames
    frames = extract_frames(str(vpath), max_frames=32)
    frames_processed = len(frames)
    if frames_processed == 0:
        print(f"Error: Could not extract frames from {video_path}")
        return

    # 2. Run detector & tracker
    detector = get_face_detector()
    tracker = CentroidIoUTracker()
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)

    frames_with_faces = 0
    total_faces = 0
    max_confidence = 0.0
    debug_saved = 0

    for idx, frame in enumerate(frames):
        faces = detector.detect_faces(frame)
        tracked = tracker.update(faces)

        if tracked:
            frames_with_faces += 1
            total_faces += len(tracked)
            for f in tracked:
                conf = f.get("confidence", 0.0)
                if conf > max_confidence:
                    max_confidence = conf

            # Save sample debug frames
            if debug_saved < 10:
                dbg = frame.copy()
                for fidx, tf in enumerate(tracked):
                    x, y, w, h = tf["x"], tf["y"], tf["width"], tf["height"]
                    conf = tf.get("confidence", 0.0)
                    tid = tf.get("track_id", fidx + 1)
                    det = tf.get("detector", "det")

                    cv2.rectangle(dbg, (x, y), (x + w, y + h), (0, 245, 255), 2)
                    label = f"FACE {fidx + 1} [ID:{tid}] {conf:.2f} ({det})"
                    cv2.putText(
                        dbg,
                        label,
                        (x, max(15, y - 8)),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.55,
                        (0, 245, 255),
                        1,
                        cv2.LINE_AA,
                    )

                out_file = DEBUG_DIR / f"test_debug_frame_{idx + 1:03d}.jpg"
                cv2.imwrite(str(out_file), dbg)
                debug_saved += 1

    detection_rate = round(frames_with_faces / frames_processed, 3) if frames_processed > 0 else 0.0

    # 3. Print formatted test output per requirement
    print("================================")
    print("SATYAAI FACE DETECTION TEST")
    print("================================")
    print(f"Video: {video_path}")
    print(f"Frames processed: {frames_processed}")
    print(f"Frames containing faces: {frames_with_faces}")
    print(f"Total faces: {total_faces}")
    print(f"Largest face confidence: {max_confidence:.2f}")
    print(f"Face detection rate: {detection_rate:.1%}")
    print(f"Debug frames saved to: {DEBUG_DIR}")
    print("================================\n")

    # 4. Test analyze_video pipeline
    print("Testing analyze_video() pipeline integration...")
    full_result = analyze_video(str(vpath), max_frames=32)
    print(f"Pipeline status: {full_result['status']}")
    print(f"Deepfake model loaded: {full_result['deepfake_model_loaded']}")
    print(f"Message: {full_result['message']}")
    print("✓ Full video pipeline test completed.")


if __name__ == "__main__":
    test_video_path = sys.argv[1] if len(sys.argv) > 1 else "backend/uploads/test.mp4"
    run_face_detection_test(test_video_path)
