try:
    from backend.services.audio_service import transcribe_audio
except ImportError:
    from services.audio_service import transcribe_audio


audio_path = "backend/uploads/test.mp3"

try:

    text = transcribe_audio(audio_path)

    print("================================")
    print("SATYAAI AUDIO TEST")
    print("================================")

    print("Transcript:")
    print(text)

except Exception as e:

    print("AUDIO ERROR:", e) 