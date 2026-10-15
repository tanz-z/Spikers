# gateway/multimodal_inspector.py
import io
import os
from PIL import Image
import pypdf
import google.generativeai as genai
from typing import Dict, Any, Tuple

class MultimodalInspector:
    """
    Handles extraction and inspection of non-text files:
    - PDFs & Text documents (extracts text & checks for hidden prompt injections)
    - Images & Screenshots (uses Gemini Flash Vision / OCR to detect PII in photos & screenshots)
    """

    def __init__(self):
        gemini_key = os.getenv("GEMINI_API_KEY")
        self.has_vision = False
        if gemini_key and gemini_key != "paste_your_copied_gemini_key_here":
            try:
                genai.configure(api_key=gemini_key)
                self.vision_model = genai.GenerativeModel("gemini-1.5-flash")
                self.has_vision = True
                print("✅ Multimodal Vision Inspector initialized")
            except Exception as e:
                print(f"⚠️ Vision Model Init warning: {e}")

    async def inspect_file(self, file_bytes: bytes, filename: str) -> Tuple[str, Dict[str, Any]]:
        """
        Extracts content from a file and returns:
        (extracted_text, visual_threat_metadata)
        """
        ext = filename.lower().split('.')[-1]
        extracted_text = ""
        metadata = {"file_type": ext, "visual_pii_detected": False, "details": []}

        # 📄 1. PDF / Document Processing
        if ext in ["pdf"]:
            try:
                pdf_reader = pypdf.PdfReader(io.BytesIO(file_bytes))
                text_list = []
                for page in pdf_reader.pages:
                    t = page.extract_text()
                    if t:
                        text_list.append(t)
                extracted_text = "\n".join(text_list)
                metadata["details"].append(f"Extracted {len(pdf_reader.pages)} pages from PDF")
            except Exception as e:
                extracted_text = f"[PDF Extraction Error: {str(e)}]"

        # 🖼️ 2. Image / Screenshot Processing (PNG, JPG, JPEG, WEBP)
        elif ext in ["png", "jpg", "jpeg", "webp"]:
            try:
                image = Image.open(io.BytesIO(file_bytes))
                
                # If Gemini Vision is active, use it to transcribe AND detect physical ID cards / secrets in image
                if self.has_vision:
                    prompt = (
                        "Analyze this image for security concerns:\n"
                        "1. Transcribe ALL visible text in the image exactly.\n"
                        "2. If this image is a photo or screenshot of a sensitive ID (Aadhaar, PAN, Passport, Credit Card, Drivers License) "
                        "or contains API keys/passwords, explicitly write: '[VISUAL_PII_DETECTED: <TYPE>]'.\n"
                        "Output ONLY the transcribed text and any visual security tags."
                    )
                    response = self.vision_model.generate_content([prompt, image])
                    extracted_text = response.text
                    
                    if "[VISUAL_PII_DETECTED" in extracted_text:
                        metadata["visual_pii_detected"] = True
                        metadata["details"].append("Visual PII/Credential detected in uploaded image")
                else:
                    extracted_text = "[Image Upload Received - Vision API key missing for OCR processing]"

            except Exception as e:
                extracted_text = f"[Image Inspection Error: {str(e)}]"

        # 📝 3. Plain Text / Code Files (.txt, .py, .csv, .json, .env)
        elif ext in ["txt", "py", "csv", "json", "env", "md", "log"]:
            try:
                extracted_text = file_bytes.decode("utf-8", errors="ignore")
                metadata["details"].append(f"Extracted text file ({len(extracted_text)} chars)")
            except Exception as e:
                extracted_text = f"[Text Read Error: {str(e)}]"

        else:
            extracted_text = f"[Unsupported File Format: .{ext}]"

        return extracted_text, metadata