import pytesseract
import cv2
import re


def extract_text(image_path: str) -> str:

    image = cv2.imread(image_path)

    if image is None:
        raise FileNotFoundError(f"Image not found or unreadable: {image_path}")

    gray = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2GRAY
    )

    gray = cv2.threshold(
        gray,
        0,
        255,
        cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )[1]

    text = pytesseract.image_to_string(gray)

    return text.strip()


def extract_urls(text: str):

    pattern = r'https?://[^\s]+|www\.[^\s]+'

    urls = re.findall(pattern, text)

    return list(dict.fromkeys(urls))


def analyze_image(image_path: str):
    """Perform OCR and analyze extracted text & embedded URLs for scams."""
    try:
        text = extract_text(image_path)
    except Exception as exc:
        return {
            "extracted_text": "",
            "ocr_text": "",
            "extracted_urls": [],
            "message_analysis": None,
            "url_analyses": [],
            "indicators": [],
            "scam_probability": 0,
            "error": str(exc),
        }

    urls = extract_urls(text)

    from backend.services.message_service import analyze_message
    from backend.services.url_service import analyze_url

    msg_analysis = analyze_message(text) if text else None
    url_analyses = [analyze_url(u) for u in urls]

    indicators = []
    if msg_analysis:
        indicators.extend(msg_analysis.get("indicators", []))
    for ua in url_analyses:
        indicators.extend(ua.get("indicators", []))
    indicators = list(dict.fromkeys(indicators))

    score = 0
    if msg_analysis:
        score = msg_analysis.get("scam_probability", 0)
    if url_analyses:
        url_scores = [u.get("probability", 0) for u in url_analyses]
        if url_scores:
            score = max(score, max(url_scores))

    return {
        "extracted_text": text,
        "ocr_text": text,
        "extracted_urls": urls,
        "message_analysis": msg_analysis,
        "url_analyses": url_analyses,
        "indicators": indicators,
        "scam_probability": score,
        "error": None,
    }