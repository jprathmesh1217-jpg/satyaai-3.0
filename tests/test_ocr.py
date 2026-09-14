"""Tests for ocr_service.py"""
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.ocr_service import extract_urls


def _create_test_image_with_text(text: str) -> str:
    """Create a simple white image with black text using Pillow, return path."""
    try:
        from PIL import Image, ImageDraw, ImageFont
        img = Image.new("RGB", (600, 200), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)
        try:
            # Try system font
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 24)
        except Exception:
            font = ImageFont.load_default()
        draw.text((20, 80), text, fill=(0, 0, 0), font=font)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name)
        return tmp.name
    except ImportError:
        return None


def test_extract_urls_from_text():
    text = "Click here to verify: http://bit.ly/scam123 or visit www.phishing.com for details"
    urls = extract_urls(text)
    assert len(urls) >= 1
    assert any("bit.ly" in u for u in urls)


def test_extract_urls_empty():
    urls = extract_urls("")
    assert urls == []


def test_extract_urls_no_urls():
    urls = extract_urls("Hello! This is a normal message with no links.")
    assert urls == []


def test_extract_urls_multiple():
    text = "Visit http://google.com and also http://phishing-bank.ru/login"
    urls = extract_urls(text)
    assert len(urls) == 2


def test_extract_urls_deduplication():
    text = "Go to http://example.com and http://example.com again"
    urls = extract_urls(text)
    # Should deduplicate
    assert len(urls) == 1


def test_ocr_missing_file():
    from backend.services.ocr_service import extract_text
    try:
        extract_text("/nonexistent/path/image.png")
        assert False, "Should have raised an exception"
    except (FileNotFoundError, RuntimeError):
        pass  # Expected


def test_ocr_with_real_image():
    """Generate a test image and attempt OCR."""
    img_path = _create_test_image_with_text("URGENT: Verify your bank account NOW!")
    if img_path is None:
        return  # PIL not available, skip

    try:
        from backend.services.ocr_service import extract_text
        text = extract_text(img_path)
        # Text may not be perfect but should be a string
        assert isinstance(text, str)
    except RuntimeError as e:
        # Tesseract might not be configured — acceptable for CI
        if "tesseract" in str(e).lower() or "Tesseract" in str(e):
            pass
        else:
            raise
    finally:
        try:
            os.unlink(img_path)
        except Exception:
            pass
