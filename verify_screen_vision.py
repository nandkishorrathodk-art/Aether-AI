
import asyncio
import sys
import os
from datetime import datetime

# Add project root to path
sys.path.append(os.getcwd())

try:
    from PIL import ImageGrab
    import pytesseract
    from src.perception.vision.screen_vision import ScreenCapture, OCREngine
except ImportError as e:
    print(f"❌ FAIL: Missing dependencies - {e}")
    sys.exit(1)

def verify_vision():
    print("Initialize Screen Vision...")
    capture = ScreenCapture()
    ocr = OCREngine()
    
    print("Capturing screen...")
    screenshot = capture.capture_screen()
    
    if screenshot is not None and screenshot.size > 0:
        print(f"✅ PASS: Screen captured successfully.")
        print(f"   Shape: {screenshot.shape}")
        
        # Save for proof
        filename = f"verify_vision_{int(datetime.now().timestamp())}.png"
        from PIL import Image
        Image.fromarray(screenshot).save(filename)
        print(f"   Saved proof to: {filename}")
        
        # Try OCR
        print("Attempting to read text from screen (OCR)...")
        try:
            result = ocr.extract_text(screenshot)
            if result.text:
                preview = result.text[:50].replace('\n', ' ')
                print(f"✅ PASS: OCR Read Text: '{preview}...'")
                print(f"   Confidence: {result.confidence:.2f}")
            else:
                print("⚠️ WARNING: OCR ran but found no text (screen might be empty/dark?)")
        except Exception as e:
             if "tesseract is not installed" in str(e).lower():
                 print("⚠️ WARNING: functionality partial - Tesseract OCR not installed/found.")
                 print("   (Image capture works, but text reading needs Tesseract)")
             else:
                 print(f"❌ FAIL: OCR failed - {e}")
            
    else:
        print("❌ FAIL: Capture returned empty data.")

if __name__ == "__main__":
    verify_vision()
