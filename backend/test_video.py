from services.deepfake_service import extract_frames

video_path = "backend/uploads/test.mp4"

try:
    frames = extract_frames(video_path, max_frames=32)

    print("================================")
    print("SATYAAI VIDEO TEST")
    print("================================")
    print("Frames extracted:", len(frames))

    if len(frames) > 0:
        print("Video processing: SUCCESS")
    else:
        print("Video processing: FAILED")

except Exception as e:
    print("VIDEO ERROR:", e)