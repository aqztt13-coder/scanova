import os
import io
import struct
import zlib
import base64
import json
import hashlib
import datetime
import urllib.parse
import requests
from pypdf import PdfReader, PdfWriter
import flet as ft


# ==========================================
# 1. المحرك الخلفي (Pure Python 100% متوافق مع iOS)
# ==========================================
class ScannerEngine:
    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        self.docs_dir = os.path.join(storage_dir, "scanned_docs")
        self.vault_dir = os.path.join(storage_dir, "secure_vault")
        self.history_file = os.path.join(storage_dir, "history.json")
        os.makedirs(self.docs_dir, exist_ok=True)
        os.makedirs(self.vault_dir, exist_ok=True)

    @staticmethod
    def read_image_base64(image_path: str) -> tuple[str, bytes]:
        with open(image_path, "rb") as f:
            raw = f.read()
        b64 = base64.b64encode(raw).decode("utf-8")
        return b64, raw

    # --- استخراج أبعاد صورة JPEG ببايثون الخالصة ---
    @staticmethod
    def _get_jpeg_dimensions(data: bytes) -> tuple[int, int]:
        idx = 2
        size = len(data)
        while idx < size:
            while idx < size and data[idx] != 0xFF:
                idx += 1
            while idx < size and data[idx] == 0xFF:
                idx += 1
            if idx >= size:
                break
            marker = data[idx]
            idx += 1
            if marker in (0xD8, 0xD9) or (0xD0 <= marker <= 0xD7):
                continue
            if idx + 2 > size:
                break
            seg_len = struct.unpack(">H", data[idx:idx + 2])[0]
            if marker in (0xC0, 0xC1, 0xC2):
                h, w = struct.unpack(">HH", data[idx + 3:idx + 7])
                return max(w, 1), max(h, 1)
            idx += seg_len
        return 800, 1100

    # --- إنشاء ملف PDF من صور JPEG مباشرة بدون مكتبات C ---
    @staticmethod
    def _build_pdf_from_jpegs(jpeg_bytes_list: list[bytes], out_path: str):
        objects = []

        def add_obj(content: bytes) -> int:
            objects.append(content)
            return len(objects)

        catalog_id = add_obj(b"")
        pages_id = add_obj(b"")
        page_ids = []

        for idx, img_bytes in enumerate(jpeg_bytes_list):
            w, h = ScannerEngine._get_jpeg_dimensions(img_bytes)
            img_name = f"/Im{idx}".encode("ascii")

            img_header = (
                f"<< /Type /XObject /Subtype /Image /Width {w} /Height {h} "
                f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode "
                f"/Length {len(img_bytes)} >>\nstream\n"
            ).encode("ascii")
            img_obj_id = add_obj(img_header + img_bytes + b"\nendstream")

            # ملائمة الصورة داخل صفحة A4 (595 x 842)
            margin = 20
            max_w, max_h = 595 - 2 * margin, 842 - 2 * margin
            scale = min(max_w / w, max_h / h)
            draw_w, draw_h = w * scale, h * scale
            x = (595 - draw_w) / 2
            y = (842 - draw_h) / 2

            stream_cmd = f"q\n{draw_w:.2f} 0 0 {draw_h:.2f} {x:.2f} {y:.2f} cm\n/Im{idx} Do\nQ\n".encode("ascii")
            content_obj = f"<< /Length {len(stream_cmd)} >>\nstream\n".encode("ascii") + stream_cmd + b"endstream"
            content_id = add_obj(content_obj)

            page_obj = (
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /XObject << /Im{idx} {img_obj_id} 0 R >> >> "
                f"/Contents {content_id} 0 R >>"
            ).encode("ascii")
            page_ids.append(add_obj(page_obj))

        kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_ids)} >>".encode("ascii")
        objects[catalog_id - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")

        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, obj in enumerate(objects, start=1):
            offsets.append(out.tell())
            out.write(f"{i} 0 obj\n".encode("ascii"))
            out.write(obj)
            out.write(b"\nendobj\n")

        xref_pos = out.tell()
        out.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        out.write(b"0000000000 65535 f \n")
        for off in offsets:
            out.write(f"{off:010d} 00000 n \n".encode("ascii"))
        out.write(
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n".encode("ascii")
        )

        with open(out_path, "wb") as f:
            f.write(out.getvalue())

    def images_to_pdf(self, image_paths: list[str], output_name: str) -> str:
        if not output_name.lower().endswith(".pdf"):
            output_name += ".pdf"
        out_path = os.path.join(self.docs_dir, output_name)
        jpegs = []
        for p in image_paths:
            with open(p, "rb") as f:
                jpegs.append(f.read())
        self._build_pdf_from_jpegs(jpegs, out_path)
        self.add_history_item(output_name, out_path, "PDF Document")
        return out_path

    # --- استخراج النصوص OCR ---
    @staticmethod
    def extract_text_ocr(image_bytes: bytes, lang: str = "eng") -> str:
        try:
            b64_img = "data:image/jpeg;base64," + base64.b64encode(image_bytes).decode("utf-8")
            payload = {
                "apikey": "helloworld",
                "base64Image": b64_img,
                "language": lang,
                "isOverlayRequired": False,
                "scale": True,
                "OCREngine": 2 if lang == "eng" else 1
            }
            resp = requests.post("https://api.ocr.space/parse/image", data=payload, timeout=25)
            result = resp.json()
            if not result.get("IsErroredOnProcessing"):
                parsed = result.get("ParsedResults", [])
                if parsed and parsed[0].get("ParsedText"):
                    return parsed[0]["ParsedText"].strip()
            return "لم يتم العثور على نص واضح في الصورة. تأكد من الإضاءة الجيدة وأن حجم الصورة أقل من 1 ميجابايت."
        except Exception as e:
            return f"تعذر الاتصال بمحرك OCR: {str(e)}"

    # --- الترجمة الفورية للنصوص ---
    @staticmethod
    def translate_text(text: str, source_lang: str, target_lang: str) -> str:
        if not text.strip():
            return ""
        try:
            lang_map = {"English": "en", "Arabic": "ar", "French": "fr", "Spanish": "es", "Turkish": "tr"}
            sl = lang_map.get(source_lang, "en")
            tl = lang_map.get(target_lang, "ar")
            if sl == tl:
                return text
            url = f"https://api.mymemory.translated.net/get?q={urllib.parse.quote(text[:480])}&langpair={sl}|{tl}"
            r = requests.get(url, timeout=10).json()
            return r.get("responseData", {}).get("translatedText", text)
        except Exception as e:
            return f"خطأ في الترجمة: {e}"

    # --- قراءة الباركود و QR ---
    @staticmethod
    def decode_qr_image(image_path: str) -> str:
        try:
            with open(image_path, "rb") as f:
                files = {"file": ("qr.jpg", f, "image/jpeg")}
                r = requests.post("https://api.qrserver.com/v1/read-qr-code/", files=files, timeout=12)
                data = r.json()
                symbol = data[0]["symbol"][0]
                if symbol.get("data"):
                    return symbol["data"]
                return "لم يتم العثور على رمز QR أو باركود صالح داخل الإطار."
        except Exception as e:
            return f"حدث خطأ أثناء فحص رمز QR: {e}"

    # --- استخراج النص من PDF ---
    @staticmethod
    def pdf_to_text(pdf_path: str) -> str:
        reader = PdfReader(pdf_path)
        extracted = []
        for idx, page in enumerate(reader.pages):
            extracted.append(f"--- Page {idx + 1} ---\n{page.extract_text() or ''}")
        return "\n\n".join(extracted).strip() or "هذا الملف عبارة عن صور ممسوحة ولا يحتوي على طبقة نصية مباشرة."

    # --- دمج ملفات PDF ---
    def merge_pdfs(self, pdf_paths: list[str], output_name: str) -> str:
        writer = PdfWriter()
        for p in pdf_paths:
            reader = PdfReader(p)
            for page in reader.pages:
                writer.add_page(page)
        out_path = os.path.join(self.docs_dir, output_name)
        with open(out_path, "wb") as f:
            writer.write(f)
        self.add_history_item(output_name, out_path, "Merged PDF")
        return out_path

    # --- تقسيم ملف PDF ---
    def split_pdf(self, pdf_path: str) -> list[str]:
        reader = PdfReader(pdf_path)
        created = []
        base_name = os.path.splitext(os.path.basename(pdf_path))[0]
        for idx, page in enumerate(reader.pages):
            writer = PdfWriter()
            writer.add_page(page)
            out_name = f"{base_name}_page_{idx+1}.pdf"
            out_path = os.path.join(self.docs_dir, out_name)
            with open(out_path, "wb") as f:
                writer.write(f)
            created.append(out_name)
        if created:
            self.add_history_item(created[0], os.path.join(self.docs_dir, created[0]), f"Split ({len(created)} pages)")
        return created

    # --- ضغط حجم ملف PDF ---
    def compress_pdf(self, pdf_path: str) -> str:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        for page in reader.pages:
            page.compress_content_streams()
            writer.add_page(page)
        out_name = "Compressed_" + os.path.basename(pdf_path)
        out_path = os.path.join(self.docs_dir, out_name)
        with open(out_path, "wb") as f:
            writer.write(f)
        self.add_history_item(out_name, out_path, "Compressed PDF")
        return out_path

    # --- تشفير الملفات للخزنة الآمنة ---
    def encrypt_file_to_vault(self, file_path: str, pin: str) -> str:
        key = hashlib.sha256(pin.encode("utf-8")).digest()
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        vault_file = os.path.join(self.vault_dir, os.path.basename(file_path) + ".enc")
        with open(vault_file, "wb") as f:
            f.write(base64.b64encode(encrypted))
        return os.path.basename(vault_file)

    # --- إدارة سجل الملفات الأخيرة ---
    def get_history(self) -> list[dict]:
        if not os.path.exists(self.history_file):
            return [
                {"name": "Project_Proposal.pdf", "size": "2.4 MB", "date": "May 20, 2026", "type": "PDF"},
                {"name": "Invoice_2026.pdf", "size": "1.1 MB", "date": "May 18, 2026", "type": "PDF"},
                {"name": "Report_Quarterly.pdf", "size": "3.1 MB", "date": "May 15, 2026", "type": "PDF"},
            ]
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def add_history_item(self, name: str, path: str, doc_type: str = "PDF"):
        items = self.get_history()
        size_kb = os.path.getsize(path) / 1024 if os.path.exists(path) else 250
        size_str = f"{size_kb/1024:.1f} MB" if size_kb >= 1024 else f"{int(size_kb)} KB"
        today = datetime.date.today().strftime("%b %d, %Y")
        items.insert(0, {"name": name, "size": size_str, "date": today, "type": doc_type, "path": path})
