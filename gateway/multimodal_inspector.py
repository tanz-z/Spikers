# # gateway/multimodal_inspector.py
# import io
# import os
# from PIL import Image
# import pypdf
# import google.generativeai as genai
# from typing import Dict, Any, Tuple

# class MultimodalInspector:
#     """
#     Handles extraction and inspection of non-text files:
#     - PDFs & Text documents (extracts text & checks for hidden prompt injections)
#     - Images & Screenshots (uses Gemini Flash Vision / OCR to detect PII in photos & screenshots)
#     """

#     def __init__(self):
#         gemini_key = os.getenv("GEMINI_API_KEY")
#         self.has_vision = False
#         if gemini_key and gemini_key != "paste_your_copied_gemini_key_here":
#             try:
#                 genai.configure(api_key=gemini_key)
#                 self.vision_model = genai.GenerativeModel("gemini-1.5-flash")
#                 self.has_vision = True
#                 print("✅ Multimodal Vision Inspector initialized")
#             except Exception as e:
#                 print(f"⚠️ Vision Model Init warning: {e}")

#     async def inspect_file(self, file_bytes: bytes, filename: str) -> Tuple[str, Dict[str, Any]]:
#         """
#         Extracts content from a file and returns:
#         (extracted_text, visual_threat_metadata)
#         """
#         ext = filename.lower().split('.')[-1]
#         extracted_text = ""
#         metadata = {"file_type": ext, "visual_pii_detected": False, "details": []}

#         # 📄 1. PDF / Document Processing
#         if ext in ["pdf"]:
#             try:
#                 pdf_reader = pypdf.PdfReader(io.BytesIO(file_bytes))
#                 text_list = []
#                 for page in pdf_reader.pages:
#                     t = page.extract_text()
#                     if t:
#                         text_list.append(t)
#                 extracted_text = "\n".join(text_list)
#                 metadata["details"].append(f"Extracted {len(pdf_reader.pages)} pages from PDF")
#             except Exception as e:
#                 extracted_text = f"[PDF Extraction Error: {str(e)}]"

#         # 🖼️ 2. Image / Screenshot Processing (PNG, JPG, JPEG, WEBP)
#         elif ext in ["png", "jpg", "jpeg", "webp"]:
#             try:
#                 image = Image.open(io.BytesIO(file_bytes))
                
#                 # If Gemini Vision is active, use it to transcribe AND detect physical ID cards / secrets in image
#                 if self.has_vision:
#                     prompt = (
#                         "Analyze this image for security concerns:\n"
#                         "1. Transcribe ALL visible text in the image exactly.\n"
#                         "2. If this image is a photo or screenshot of a sensitive ID (Aadhaar, PAN, Passport, Credit Card, Drivers License) "
#                         "or contains API keys/passwords, explicitly write: '[VISUAL_PII_DETECTED: <TYPE>]'.\n"
#                         "Output ONLY the transcribed text and any visual security tags."
#                     )
#                     response = self.vision_model.generate_content([prompt, image])
#                     extracted_text = response.text
                    
#                     if "[VISUAL_PII_DETECTED" in extracted_text:
#                         metadata["visual_pii_detected"] = True
#                         metadata["details"].append("Visual PII/Credential detected in uploaded image")
#                 else:
#                     extracted_text = "[Image Upload Received - Vision API key missing for OCR processing]"

#             except Exception as e:
#                 extracted_text = f"[Image Inspection Error: {str(e)}]"

#         # 📝 3. Plain Text / Code Files (.txt, .py, .csv, .json, .env)
#         elif ext in ["txt", "py", "csv", "json", "env", "md", "log"]:
#             try:
#                 extracted_text = file_bytes.decode("utf-8", errors="ignore")
#                 metadata["details"].append(f"Extracted text file ({len(extracted_text)} chars)")
#             except Exception as e:
#                 extracted_text = f"[Text Read Error: {str(e)}]"

#         else:
#             extracted_text = f"[Unsupported File Format: .{ext}]"

#         return extracted_text, metadata


# gateway/multimodal_inspector.py
"""
Local-only file extraction. NOTHING is sent to a cloud model here.

Why: if a screenshot of an Aadhaar card or an API key is sent to Gemini Vision just to
read it, the leak has already happened before the gateway could mask anything.
Flow now:  file -> LOCAL OCR/text extraction -> PromptInspector (detect + mask) -> LLM.

Install:  pip install pymupdf rapidocr_onnxruntime pillow numpy
Same signature as before:  (extracted_text, metadata) = await inspect_file(bytes, filename)
On failure extracted_text is "" and metadata["extraction_ok"] is False -> the caller should
tell the user / block, and must NOT forward an error string to the LLM.
"""
import io
from typing import Any, Dict, Tuple

import numpy as np
import pymupdf
from PIL import Image
from rapidocr_onnxruntime import RapidOCR

MAX_OCR_PAGES = 15      # OCR is ~1s+/page on a laptop; cap it for demo speed
MIN_PAGE_CHARS = 30     # fewer embedded characters than this => treat the page as scanned
MAX_IMAGE_SIDE = 2500   # downscale huge photos before OCR


class MultimodalInspector:
    def __init__(self):
        self._ocr = RapidOCR()  # loads local ONNX models once

    # ---- helpers -------------------------------------------------------
    def _ocr_array(self, arr: np.ndarray) -> str:
        result, _ = self._ocr(arr)
        return "\n".join(line[1] for line in (result or []))

    def _ocr_pdf_page(self, page, zoom: float = 2.0) -> str:
        pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), alpha=False)
        arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
        return self._ocr_array(arr)

    # ---- main entry ----------------------------------------------------
    async def inspect_file(self, file_bytes: bytes, filename: str) -> Tuple[str, Dict[str, Any]]:
        ext = filename.lower().rsplit(".", 1)[-1]
        text = ""
        meta: Dict[str, Any] = {
            "file_type": ext, "visual_pii_detected": False, "details": [],
            "extraction_ok": True, "ocr_used": False,
        }
        try:
            if ext == "pdf":
                parts, ocr_pages = [], 0
                doc = pymupdf.open(stream=file_bytes, filetype="pdf")
                for i, page in enumerate(doc):
                    t = page.get_text().strip()
                    if len(t) < MIN_PAGE_CHARS:            # scanned page -> OCR
                        if ocr_pages >= MAX_OCR_PAGES:
                            meta["details"].append(f"OCR page limit ({MAX_OCR_PAGES}) reached; rest skipped")
                            break
                        t = self._ocr_pdf_page(page)
                        ocr_pages += 1
                    parts.append(t)
                text = "\n\n".join(parts)
                meta["ocr_used"] = ocr_pages > 0
                meta["details"].append(f"PDF: {len(doc)} pages, {ocr_pages} read by local OCR")

            elif ext in ("png", "jpg", "jpeg", "webp"):
                img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
                img.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
                text = self._ocr_array(np.array(img))
                meta["ocr_used"] = True
                meta["details"].append(f"Image read by local OCR ({len(text)} chars)")

            elif ext in ("txt", "py", "csv", "json", "env", "md", "log"):
                text = file_bytes.decode("utf-8", errors="ignore")
                meta["details"].append(f"Text file ({len(text)} chars)")

            else:
                meta["extraction_ok"] = False
                meta["details"].append(f"Unsupported file format: .{ext}")

            if meta["extraction_ok"] and not text.strip():
                # Nothing readable. Don't silently treat an unreadable image as "clean".
                meta["extraction_ok"] = False
                meta["details"].append("No text could be read from this file")
        except Exception as e:
            text = ""
            meta["extraction_ok"] = False
            meta["details"].append(f"Extraction error: {type(e).__name__}: {e}")
        return text, meta