"""Scanova - Document scanner, OCR, translation, PDF tools and secure vault.

Target: Flet 1.1.2+, Python 3.10+

Notes:
- OCR and translation use online services.
- Windows desktop camera preview, document capture, and QR scanning use OpenCV.
- QR decoding is local; ZXing-C++ is optional for wider barcode support.
- PDF-to-image conversion uses the optional PyMuPDF package.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import secrets
import urllib.parse
from pathlib import Path
from typing import Any

import requests
from PIL import Image, ImageEnhance, ImageOps
from fpdf import FPDF
from pypdf import PdfReader, PdfWriter
from cryptography.fernet import Fernet, InvalidToken
import flet as ft

try:
    import cv2
except ImportError:  # Optional: install Scanova with the [camera] extra.
    cv2 = None

try:
    import zxingcpp
except ImportError:  # Optional: enables 1D and additional 2D barcode formats.
    zxingcpp = None


APP_NAME = "Scanova"
APP_VERSION = "1.0.2"


class ScannerEngine:
    """File processing engine. UI-independent functions are easy to test."""

    VAULT_MARKER = b"SCANOVA_VAULT_OK"
    PBKDF2_ITERATIONS = 600_000

    def __init__(self, storage_dir: str | Path):
        self.storage_dir = str(storage_dir)
        self.docs_dir = os.path.join(self.storage_dir, "scanned_docs")
        self.vault_dir = os.path.join(self.storage_dir, "secure_vault")
        self.history_file = os.path.join(self.storage_dir, "history.json")
        self.vault_meta_file = os.path.join(self.vault_dir, "vault_meta.json")
        os.makedirs(self.docs_dir, exist_ok=True)
        os.makedirs(self.vault_dir, exist_ok=True)

    # ------------------------------ Images ------------------------------
    @staticmethod
    def apply_scanner_filter(
        image_path: str, mode: str = "magic"
    ) -> tuple[str, bytes]:
        with Image.open(image_path) as source:
            img = ImageOps.exif_transpose(source).convert("RGB")

        if mode == "magic":
            img = ImageOps.autocontrast(img, cutoff=2)
            img = ImageEnhance.Contrast(img).enhance(1.55)
            img = ImageEnhance.Brightness(img).enhance(1.08)
            img = ImageEnhance.Sharpness(img).enhance(2.0)
        elif mode == "bw":
            gray = ImageOps.autocontrast(img.convert("L"), cutoff=2)
            gray = ImageEnhance.Contrast(gray).enhance(2.0)
            img = gray.point(lambda value: 0 if value < 150 else 255, "1").convert("RGB")
        elif mode == "gray":
            gray = ImageOps.autocontrast(img.convert("L"), cutoff=1)
            img = ImageEnhance.Sharpness(gray).enhance(1.4).convert("RGB")
        elif mode != "original":
            raise ValueError(f"Unsupported image filter: {mode}")

        output = io.BytesIO()
        img.save(output, format="JPEG", quality=90, optimize=True)
        data = output.getvalue()
        return base64.b64encode(data).decode("ascii"), data

    # ------------------------------- OCR --------------------------------
    @staticmethod
    def extract_text_ocr(image_bytes: bytes, lang: str = "eng") -> str:
        """Extract text using OCR.space. Internet and a valid API key are required."""
        if not image_bytes:
            raise ValueError("لم يتم توفير صورة لمعالجتها.")

        with Image.open(io.BytesIO(image_bytes)) as source:
            img = ImageOps.exif_transpose(source).convert("RGB")
            img.thumbnail((2200, 2200))
            output = io.BytesIO()
            img.save(output, format="JPEG", quality=82, optimize=True)

        api_key = os.getenv("SCANOVA_OCR_API_KEY", "helloworld").strip()
        payload = {
            "apikey": api_key,
            "base64Image": "data:image/jpeg;base64," + base64.b64encode(output.getvalue()).decode("ascii"),
            "language": lang,
            "isOverlayRequired": "false",
            "scale": "true",
            "OCREngine": "2" if lang == "eng" else "1",
        }
        response = requests.post(
            "https://api.ocr.space/parse/image", data=payload, timeout=(10, 45)
        )
        response.raise_for_status()
        result = response.json()

        if result.get("IsErroredOnProcessing"):
            details = result.get("ErrorMessage") or result.get("ErrorDetails") or "خطأ غير محدد من خدمة OCR"
            if isinstance(details, list):
                details = "، ".join(map(str, details))
            raise RuntimeError(str(details))

        parsed = result.get("ParsedResults") or []
        text = "\n\n".join(
            item.get("ParsedText", "").strip() for item in parsed if item.get("ParsedText")
        ).strip()
        return text or "لم يتم العثور على نص واضح في الصورة. جرّب تحسين الإضاءة أو اختيار لغة OCR الصحيحة."

    # ---------------------------- Translation ---------------------------
    @staticmethod
    def _split_text(text: str, limit: int = 430) -> list[str]:
        """Split long text without dropping characters, preferring whitespace."""
        chunks: list[str] = []
        remaining = text
        while len(remaining) > limit:
            cut = remaining.rfind(" ", 0, limit + 1)
            if cut < int(limit * 0.55):
                cut = limit
            chunks.append(remaining[:cut])
            remaining = remaining[cut:]
        if remaining:
            chunks.append(remaining)
        return chunks

    @classmethod
    def translate_text(cls, text: str, source_lang: str, target_lang: str) -> str:
        if not text or not text.strip():
            return ""

        language_map = {
            "English": "en", "Arabic": "ar", "French": "fr",
            "Spanish": "es", "Turkish": "tr",
        }
        source = language_map.get(source_lang, source_lang)
        target = language_map.get(target_lang, target_lang)
        if source == target:
            return text

        translated_parts: list[str] = []
        for part in cls._split_text(text):
            params = urllib.parse.urlencode({"q": part, "langpair": f"{source}|{target}"})
            response = requests.get(
                f"https://api.mymemory.translated.net/get?{params}", timeout=(10, 30)
            )
            response.raise_for_status()
            result = response.json()
            response_data = result.get("responseData") or {}
            translated = response_data.get("translatedText")
            if not translated:
                raise RuntimeError(result.get("responseDetails") or "لم تُرجع خدمة الترجمة نتيجة.")
            translated_parts.append(translated)

        # Retain every translated chunk; the original implementation truncated at 480 chars.
        return "".join(translated_parts)

    # ----------------------- Local QR / barcode reader -------------------
    @staticmethod
    def decode_codes_array(image_array) -> str:
        """Decode barcodes locally. ZXing-C++ handles many formats; OpenCV is QR fallback."""
        if image_array is None:
            raise ValueError("الصورة فارغة أو غير صالحة.")

        decoded: list[str] = []
        seen: set[str] = set()

        if zxingcpp is not None:
            try:
                for result in zxingcpp.read_barcodes(image_array):
                    value = (getattr(result, "text", "") or "").strip()
                    if value and value not in seen:
                        fmt = str(getattr(result, "format", "Barcode"))
                        decoded.append(f"{fmt}: {value}")
                        seen.add(value)
            except Exception:
                # If ZXing cannot interpret an image buffer, attempt QR decoding below.
                pass

        if not decoded and cv2 is not None:
            detector = cv2.QRCodeDetector()
            try:
                found, texts, _points, _straight = detector.detectAndDecodeMulti(image_array)
                if found:
                    for value in texts:
                        value = (value or "").strip()
                        if value and value not in seen:
                            decoded.append(f"QR Code: {value}")
                            seen.add(value)
            except (cv2.error, AttributeError):
                pass

            if not decoded:
                try:
                    value, _points, _straight = detector.detectAndDecode(image_array)
                    value = (value or "").strip()
                    if value:
                        decoded.append(f"QR Code: {value}")
                except cv2.error:
                    pass

        if not decoded:
            if cv2 is None and zxingcpp is None:
                raise RuntimeError("قارئ الرموز المحلي غير مثبت. ثبّت إضافات [camera] و[barcode].")
            return "لم يتم العثور على QR أو باركود واضح في الصورة."
        return "\n".join(decoded)

    @classmethod
    def decode_codes_image(cls, image_path: str) -> str:
        """Decode an image locally without uploading it to a third-party website."""
        if not os.path.isfile(image_path):
            raise FileNotFoundError(image_path)
        with Image.open(image_path) as source:
            rgb = source.convert("RGB")
            if cv2 is not None:
                import numpy as np
                image_array = cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2BGR)
            else:
                image_array = rgb
        return cls.decode_codes_array(image_array)

    @classmethod
    def decode_codes_bytes(cls, image_bytes: bytes) -> str:
        if not image_bytes:
            raise ValueError("لم تصل صورة من الكاميرا.")
        with Image.open(io.BytesIO(image_bytes)) as source:
            rgb = source.convert("RGB")
            if cv2 is not None:
                import numpy as np
                image_array = cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2BGR)
            else:
                image_array = rgb
        return cls.decode_codes_array(image_array)

    # Backward-compatible method name used by older code.
    decode_qr_image = decode_codes_image

    # ------------------------------- PDF --------------------------------
    def _output_path(self, output_name: str) -> str:
        safe_name = os.path.basename(output_name.strip())
        if not safe_name or safe_name in {".", ".."}:
            raise ValueError("اسم الملف غير صالح.")
        return os.path.join(self.docs_dir, safe_name)

    def _unique_output_path(self, output_name: str) -> str:
        path = self._output_path(output_name)
        if not os.path.exists(path):
            return path
        stem, ext = os.path.splitext(path)
        suffix = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        candidate = f"{stem}_{suffix}{ext}"
        counter = 2
        while os.path.exists(candidate):
            candidate = f"{stem}_{suffix}_{counter}{ext}"
            counter += 1
        return candidate

    def images_to_pdf(self, image_paths: list[str], output_name: str) -> str:
        if not image_paths:
            raise ValueError("اختر صورة واحدة على الأقل.")
        pdf = FPDF(unit="mm", format="A4")
        pdf.set_auto_page_break(False)

        for path in image_paths:
            if not os.path.isfile(path):
                raise FileNotFoundError(path)
            with Image.open(path) as image:
                width_px, height_px = image.size
            orientation = "L" if width_px > height_px else "P"
            pdf.add_page(orientation=orientation)
            page_width = pdf.w
            page_height = pdf.h
            available_width = page_width - 20
            available_height = page_height - 20
            scale = min(available_width / width_px, available_height / height_px)
            draw_width = width_px * scale
            draw_height = height_px * scale
            x = (page_width - draw_width) / 2
            y = (page_height - draw_height) / 2
            pdf.image(path, x=x, y=y, w=draw_width, h=draw_height)

        if not output_name.lower().endswith(".pdf"):
            output_name += ".pdf"
        out_path = self._unique_output_path(output_name)
        pdf.output(out_path)
        self.add_history_item(os.path.basename(out_path), out_path, "PDF Document")
        return out_path

    @staticmethod
    def pdf_to_text(pdf_path: str) -> str:
        reader = PdfReader(pdf_path)
        if reader.is_encrypted:
            raise RuntimeError("ملف PDF محمي بكلمة مرور؛ أزل الحماية أولاً.")
        page_texts = [(page.extract_text() or "").strip() for page in reader.pages]
        if not any(page_texts):
            return "هذا الملف لا يحتوي على طبقة نصية قابلة للاستخراج. قد يكون ملفاً ممسوحاً ضوئياً ويحتاج إلى OCR."
        return "\n\n".join(
            f"--- Page {index + 1} ---\n{text}" for index, text in enumerate(page_texts)
        ).strip()

    def merge_pdfs(self, pdf_paths: list[str], output_name: str) -> str:
        if len(pdf_paths) < 2:
            raise ValueError("اختر ملفي PDF على الأقل للدمج.")
        writer = PdfWriter()
        for path in pdf_paths:
            reader = PdfReader(path)
            if reader.is_encrypted:
                raise RuntimeError(f"الملف محمي بكلمة مرور: {os.path.basename(path)}")
            for page in reader.pages:
                writer.add_page(page)
        if not output_name.lower().endswith(".pdf"):
            output_name += ".pdf"
        out_path = self._unique_output_path(output_name)
        with open(out_path, "wb") as output:
            writer.write(output)
        self.add_history_item(os.path.basename(out_path), out_path, "Merged PDF")
        return out_path

    def split_pdf(self, pdf_path: str) -> list[str]:
        reader = PdfReader(pdf_path)
        if reader.is_encrypted:
            raise RuntimeError("ملف PDF محمي بكلمة مرور؛ أزل الحماية أولاً.")
        created: list[str] = []
        base_name = os.path.splitext(os.path.basename(pdf_path))[0]
        for index, page in enumerate(reader.pages, start=1):
            writer = PdfWriter()
            writer.add_page(page)
            output_name = f"{base_name}_page_{index}.pdf"
            out_path = self._unique_output_path(output_name)
            with open(out_path, "wb") as output:
                writer.write(output)
            created.append(out_path)
            self.add_history_item(os.path.basename(out_path), out_path, "Split PDF page")
        return created

    def compress_pdf(self, pdf_path: str) -> str:
        """Compress PDF content streams. Embedded images are not recompressed."""
        reader = PdfReader(pdf_path)
        if reader.is_encrypted:
            raise RuntimeError("ملف PDF محمي بكلمة مرور؛ أزل الحماية أولاً.")
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
            # pypdf requires the page to belong to the writer before compression.
            writer.pages[-1].compress_content_streams()
        output_name = "Compressed_" + os.path.basename(pdf_path)
        out_path = self._unique_output_path(output_name)
        with open(out_path, "wb") as output:
            writer.write(output)
        self.add_history_item(os.path.basename(out_path), out_path, "Optimized PDF")
        return out_path

    def pdf_to_images(self, pdf_path: str, dpi: int = 180) -> list[str]:
        try:
            import pymupdf  # PyMuPDF (optional; use the modern package name)
        except ImportError as exc:
            raise RuntimeError("ميزة PDF to Image تحتاج تثبيت PyMuPDF: pip install pymupdf") from exc

        document = pymupdf.open(pdf_path)
        if document.is_encrypted:
            document.close()
            raise RuntimeError("ملف PDF محمي بكلمة مرور.")
        output_paths: list[str] = []
        scale = dpi / 72
        try:
            for index, page in enumerate(document, start=1):
                pixmap = page.get_pixmap(matrix=pymupdf.Matrix(scale, scale), alpha=False)
                output_name = f"{Path(pdf_path).stem}_page_{index}.png"
                out_path = self._unique_output_path(output_name)
                pixmap.save(out_path)
                output_paths.append(out_path)
                self.add_history_item(os.path.basename(out_path), out_path, "PDF Page Image")
        finally:
            document.close()
        return output_paths

    # --------------------------- Secure vault ---------------------------
    @staticmethod
    def _legacy_key(pin: str) -> bytes:
        """Compatibility only for files created by the original Scanova prototype."""
        digest = hashlib.sha256(pin.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    @classmethod
    def _derive_vault_key(cls, pin: str, salt: bytes) -> bytes:
        derived = hashlib.pbkdf2_hmac(
            "sha256", pin.encode("utf-8"), salt, cls.PBKDF2_ITERATIONS, dklen=32
        )
        return base64.urlsafe_b64encode(derived)

    def has_vault_metadata(self) -> bool:
        return os.path.isfile(self.vault_meta_file)

    def setup_vault(self, pin: str) -> None:
        if len(pin) < 8:
            raise ValueError("يجب أن يتكون رمز الخزنة الجديد من 8 أحرف أو أرقام على الأقل.")
        if any(name.endswith(".enc") for name in os.listdir(self.vault_dir)):
            raise RuntimeError("توجد ملفات مشفرة بالنظام القديم. استعدها أولاً قبل إنشاء خزنة جديدة.")
        salt = secrets.token_bytes(16)
        key = self._derive_vault_key(pin, salt)
        verifier = Fernet(key).encrypt(self.VAULT_MARKER).decode("ascii")
        metadata = {
            "version": 2,
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": self.PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "verifier": verifier,
            "created_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        }
        temp_path = self.vault_meta_file + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as output:
            json.dump(metadata, output, ensure_ascii=False, indent=2)
        os.replace(temp_path, self.vault_meta_file)

    def verify_vault_pin(self, pin: str) -> str:
        """Return 'modern' or 'legacy'; raise ValueError for an invalid PIN."""
        if self.has_vault_metadata():
            with open(self.vault_meta_file, "r", encoding="utf-8") as source:
                metadata = json.load(source)
            salt = base64.b64decode(metadata["salt"])
            key = self._derive_vault_key(pin, salt)
            try:
                marker = Fernet(key).decrypt(metadata["verifier"].encode("ascii"))
            except (InvalidToken, KeyError, ValueError) as exc:
                raise ValueError("رمز الخزنة غير صحيح.") from exc
            if marker != self.VAULT_MARKER:
                raise ValueError("تعذر التحقق من رمز الخزنة.")
            return "modern"

        encrypted_files = [
            os.path.join(self.vault_dir, name)
            for name in os.listdir(self.vault_dir)
            if name.endswith(".enc")
        ]
        if encrypted_files:
            legacy_cipher = Fernet(self._legacy_key(pin))
            try:
                with open(encrypted_files[0], "rb") as source:
                    legacy_cipher.decrypt(source.read())
            except (InvalidToken, OSError) as exc:
                raise ValueError("رمز الخزنة غير صحيح أو الملف القديم غير قابل للقراءة.") from exc
            return "legacy"
        raise FileNotFoundError("new_vault")

    def encrypt_file_to_vault(self, file_path: str, pin: str) -> str:
        if not self.has_vault_metadata():
            raise RuntimeError("الخزنة الحالية قديمة أو لم تُنشأ بعد. أنشئ خزنة جديدة برمز قوي أولاً.")
        with open(self.vault_meta_file, "r", encoding="utf-8") as source:
            metadata = json.load(source)
        key = self._derive_vault_key(pin, base64.b64decode(metadata["salt"]))
        # Validate the PIN again before using it for encryption.
        Fernet(key).decrypt(metadata["verifier"].encode("ascii"))
        with open(file_path, "rb") as source:
            encrypted = Fernet(key).encrypt(source.read())

        base_name = os.path.basename(file_path)
        vault_name = base_name + ".enc"
        target = os.path.join(self.vault_dir, vault_name)
        if os.path.exists(target):
            stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            stem = f"{Path(base_name).stem}_{stamp}{Path(base_name).suffix}"
            vault_name = stem + ".enc"
            target = os.path.join(self.vault_dir, vault_name)
            counter = 2
            while os.path.exists(target):
                vault_name = f"{Path(stem).stem}_{counter}{Path(stem).suffix}.enc"
                target = os.path.join(self.vault_dir, vault_name)
                counter += 1
        temp_path = target + ".tmp"
        with open(temp_path, "wb") as output:
            output.write(encrypted)
        os.replace(temp_path, target)
        return vault_name

    def decrypt_vault_file(self, vault_name: str, pin: str, remove_encrypted: bool = False) -> str:
        safe_name = os.path.basename(vault_name)
        if not safe_name.endswith(".enc"):
            raise ValueError("اسم ملف الخزنة غير صالح.")
        encrypted_path = os.path.join(self.vault_dir, safe_name)
        if not os.path.isfile(encrypted_path):
            raise FileNotFoundError(encrypted_path)

        with open(encrypted_path, "rb") as source:
            encrypted = source.read()

        if self.has_vault_metadata():
            with open(self.vault_meta_file, "r", encoding="utf-8") as source:
                metadata = json.load(source)
            key = self._derive_vault_key(pin, base64.b64decode(metadata["salt"]))
            try:
                data = Fernet(key).decrypt(encrypted)
            except InvalidToken as exc:
                raise ValueError("تعذر فك التشفير. تحقق من رمز الخزنة.") from exc
        else:
            try:
                data = Fernet(self._legacy_key(pin)).decrypt(encrypted)
            except InvalidToken as exc:
                raise ValueError("تعذر فك تشفير الملف القديم. تحقق من الرمز.") from exc

        original_name = safe_name[:-4]
        output_path = self._unique_output_path(original_name)
        output_name = os.path.basename(output_path)
        temp_path = output_path + ".tmp"
        with open(temp_path, "wb") as output:
            output.write(data)
        os.replace(temp_path, output_path)
        self.add_history_item(output_name, output_path, "Restored from Vault")

        if remove_encrypted:
            os.remove(encrypted_path)
        return output_path

    def delete_vault_file(self, vault_name: str) -> None:
        safe_name = os.path.basename(vault_name)
        if not safe_name.endswith(".enc"):
            raise ValueError("اسم الملف غير صالح.")
        path = os.path.join(self.vault_dir, safe_name)
        if os.path.isfile(path):
            os.remove(path)

    # ------------------------------ History -----------------------------
    def get_history(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.history_file):
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as source:
                data = json.load(source)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def add_history_item(self, name: str, path: str, doc_type: str = "PDF") -> None:
        size_kb = os.path.getsize(path) / 1024 if os.path.isfile(path) else 0
        size_text = f"{size_kb / 1024:.2f} MB" if size_kb >= 1024 else f"{size_kb:.0f} KB"
        today = dt.datetime.now().astimezone().strftime("%b %d, %Y")
        items = self.get_history()
        # Avoid inserting the same file twice when it is already the newest record.
        items = [item for item in items if item.get("path") != path]
        items.insert(0, {
            "name": name,
            "size": size_text,
            "date": today,
            "type": doc_type,
            "path": path,
        })
        temp_path = self.history_file + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as output:
            json.dump(items[:100], output, ensure_ascii=False, indent=2)
        os.replace(temp_path, self.history_file)


# ============================== Flet UI ================================
def main(page: ft.Page):
    page.title = APP_NAME
    page.theme_mode = ft.ThemeMode.LIGHT
    page.padding = 0
    page.spacing = 0
    page.bgcolor = "#F4F7FC"
    page.window.width = 430
    page.window.height = 900
    page.window.min_width = 360
    page.window.min_height = 640

    PRIMARY = "#1B6BF3"
    NAVY = "#15233C"
    DARK_BG = "#1A2232"
    CARD = "#FFFFFF"
    SUBTEXT = "#6E7A8A"
    SUCCESS = "#18A957"
    DANGER = "#E53935"

    # Preserve the prototype's existing storage directory so previous documents remain available.
    storage_path = os.path.join(os.path.expanduser("~"), "Documents", "OCRScannerApp")
    engine = ScannerEngine(storage_path)
    clipboard = ft.Clipboard()
    scan_picker = ft.FilePicker()
    qr_picker = ft.FilePicker()
    pdf_picker = ft.FilePicker()

    state: dict[str, Any] = {
        "tab": "home",
        "selected_image_path": None,
        "processed_image_bytes": None,
        "filter_mode": "magic",
        "scan_mode": "Single",
        "batch_images": [],
        "extracted_text": "",
        "vault_unlocked": False,
        "vault_pin": "",
        "vault_mode": "modern",
        "pending_pdf_action": "",
        "dark": False,
        "camera_running": False,
        "camera_target": None,
        "camera_cap": None,
        "camera_task": None,
        "camera_last_frame": None,
        "camera_frame_count": 0,
    }

    def icon_data(name: str):
        # Avoid a fatal startup error if a platform's icon font lacks a rarely used symbol.
        return getattr(ft.Icons, name, ft.Icons.DESCRIPTION)

    def icon(name: str, color: str = NAVY, size: int = 22):
        return ft.Icon(icon=icon_data(name), color=color, size=size)

    def show_toast(message: str, color: str = PRIMARY):
        page.show_dialog(
            ft.SnackBar(
                content=ft.Text(message, color="white"),
                bgcolor=color,
                behavior=ft.SnackBarBehavior.FLOATING,
                duration=4000,
            )
        )

    def button(label: str, on_click, *, icon_name: str | None = None,
               bgcolor: str = PRIMARY, color: str = "white", width: float | None = None,
               height: float | None = 44):
        return ft.Button(
            content=label,
            icon=icon_data(icon_name) if icon_name else None,
            bgcolor=bgcolor,
            color=color,
            width=width,
            height=height,
            on_click=on_click,
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=10)),
        )

    def run_in_worker(function, *args):
        return asyncio.to_thread(function, *args)

    def _open_camera_device(index: int = 0):
        if cv2 is None:
            raise RuntimeError("دعم الكاميرا غير مثبت. نفّذ: pip install -e .[camera]")
        if os.name == "nt":
            capture = cv2.VideoCapture(index, cv2.CAP_DSHOW)
        else:
            capture = cv2.VideoCapture(index)
        if not capture.isOpened():
            capture.release()
            raise RuntimeError("تعذر فتح الكاميرا. تحقق من توصيلها وإغلاق البرامج الأخرى التي تستخدمها.")
        capture.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        capture.set(cv2.CAP_PROP_FPS, 24)
        return capture

    async def stop_desktop_camera(e=None):
        state["camera_running"] = False
        task = state.get("camera_task")
        current = asyncio.current_task()
        if task is not None and task is not current:
            try:
                await asyncio.wait_for(task, timeout=1.5)
            except (asyncio.TimeoutError, Exception):
                pass
        capture = state.get("camera_cap")
        state["camera_cap"] = None
        state["camera_task"] = None
        if capture is not None:
            try:
                await run_in_worker(capture.release)
            except Exception:
                pass
        state["camera_last_frame"] = None
        state["camera_target"] = None
        live_camera_image.visible = False
        qr_camera_image.visible = False
        qr_camera_empty_text.visible = True
        if state.get("selected_image_path"):
            preview_image.visible = True
            preview_placeholder.visible = False
        else:
            preview_image.visible = False
            preview_placeholder.visible = True
        try:
            page.update()
        except Exception:
            pass

    async def camera_frame_loop(target: str):
        capture = state.get("camera_cap")
        frame_count = 0
        try:
            while state.get("camera_running") and state.get("camera_target") == target:
                if capture is None:
                    break
                ok, frame = await run_in_worker(capture.read)
                if not ok or frame is None:
                    await asyncio.sleep(0.08)
                    continue

                frame_count += 1
                state["camera_last_frame"] = frame
                if target == "qr" and frame_count % 4 == 0:
                    try:
                        result = await run_in_worker(engine.decode_codes_array, frame)
                    except Exception:
                        result = ""
                    if result and not result.startswith("لم يتم العثور"):
                        qr_result_text.value = result
                        qr_result_text.color = SUCCESS
                        show_toast("تمت قراءة الرمز مباشرة من الكاميرا دون رفع الصورة إلى الإنترنت.", SUCCESS)
                        state["camera_running"] = False
                        break

                encoded_ok, encoded = cv2.imencode(
                    ".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 76]
                )
                if not encoded_ok:
                    continue
                image_b64 = base64.b64encode(encoded.tobytes()).decode("ascii")
                if target == "scanner":
                    live_camera_image.src = image_b64
                    live_camera_image.visible = True
                    preview_image.visible = False
                    preview_placeholder.visible = False
                else:
                    qr_camera_image.src = image_b64
                    qr_camera_image.visible = True
                    qr_camera_empty_text.visible = False
                    qr_result_text.value = "وجّه الكاميرا نحو رمز QR أو الباركود..."
                page.update()
                await asyncio.sleep(0.035)
        except Exception as exc:
            show_toast(f"توقفت الكاميرا بسبب خطأ: {exc}", DANGER)
        finally:
            state["camera_running"] = False
            if capture is not None:
                try:
                    await run_in_worker(capture.release)
                except Exception:
                    pass
            if state.get("camera_cap") is capture:
                state["camera_cap"] = None
            state["camera_task"] = None
            if target == "scanner":
                live_camera_image.visible = False
                if not state.get("selected_image_path"):
                    preview_placeholder.visible = True
            try:
                page.update()
            except Exception:
                pass

    async def start_desktop_camera(target: str):
        if cv2 is None:
            show_toast("الكاميرا تحتاج OpenCV. ثبّت الحزمة بإضافات [camera].", DANGER)
            return
        if state.get("camera_running"):
            await stop_desktop_camera()
        try:
            capture = await run_in_worker(_open_camera_device, 0)
            state["camera_cap"] = capture
            state["camera_target"] = target
            state["camera_running"] = True
            state["camera_last_frame"] = None
            state["camera_frame_count"] = 0
            if target == "scanner":
                preview_image.visible = False
                preview_placeholder.visible = False
                live_camera_image.visible = True
            else:
                qr_result_text.value = "الكاميرا تعمل. وجّه الرمز إلى الإطار الأخضر."
                qr_result_text.color = "white"
                qr_camera_image.src = ""
                qr_camera_image.visible = True
                qr_camera_empty_text.visible = False
            page.update()
            state["camera_task"] = page.run_task(camera_frame_loop, target)
        except Exception as exc:
            state["camera_running"] = False
            state["camera_cap"] = None
            show_toast(f"تعذر تشغيل الكاميرا: {exc}", DANGER)

    def normalize_picker_paths(files) -> list[str]:
        paths: list[str] = []
        for picked in files or []:
            path = getattr(picked, "path", None)
            if path and os.path.isfile(path):
                paths.append(path)
        return paths

    def navigate_to(tab_key: str):
        if state.get("camera_running") and tab_key not in {"scanner", "qr"}:
            page.run_task(stop_desktop_camera)
        state["tab"] = tab_key
        content_holder.content = build_current_view()
        bottom_holder.content = build_bottom_navigation()
        page.update()

    # ------------------------------- scanner ----------------------------
    preview_image = ft.Image(src="", visible=False, fit=ft.BoxFit.CONTAIN, expand=True)
    live_camera_image = ft.Image(src="", visible=False, fit=ft.BoxFit.CONTAIN, expand=True)
    qr_camera_image = ft.Image(src="", visible=False, fit=ft.BoxFit.CONTAIN, expand=True)
    preview_placeholder = ft.Container(
        width=230, height=310, bgcolor="white", border_radius=8, padding=18,
        shadow=ft.BoxShadow(blur_radius=12, color="#33000000"),
        content=ft.Column(
            controls=[
                ft.Text("SCANOVA DOCUMENT", size=10, weight=ft.FontWeight.BOLD, color=SUBTEXT),
                ft.Divider(color="#E0E6ED"),
                *[ft.Container(height=8, width=w, bgcolor=c, border_radius=4)
                  for w, c in [(160, "#D0D7DE"), (180, "#E5E9F0"), (170, "#E5E9F0"), (140, "#E5E9F0"),
                               (175, "#D0D7DE"), (185, "#E5E9F0"), (160, "#E5E9F0"), (120, "#E5E9F0")]],
                ft.Container(expand=True),
                ft.Text("اختر صورة من الجهاز لبدء المسح", size=10, color=PRIMARY),
            ], spacing=7,
        ),
    )

    def refresh_preview(b64: str):
        preview_image.src = b64
        preview_image.visible = True
        preview_placeholder.visible = False
        page.update()

    async def apply_filter(mode: str):
        path = state.get("selected_image_path")
        if not path:
            show_toast("اختر صورة أولاً.", DANGER)
            return
        try:
            b64, raw = await run_in_worker(engine.apply_scanner_filter, path, mode)
            state["filter_mode"] = mode
            state["processed_image_bytes"] = raw
            refresh_preview(b64)
            show_toast(f"تم تطبيق الفلتر: {mode.upper()}")
        except Exception as exc:
            show_toast(f"تعذرت معالجة الصورة: {exc}", DANGER)

    def filter_handler(mode: str):
        async def handler(e):
            await apply_filter(mode)
        return handler

    async def pick_scan_images(e):
        try:
            multiple = state["scan_mode"] == "Batch"
            picked = await scan_picker.pick_files(
                allow_multiple=multiple,
                file_type=ft.FilePickerFileType.IMAGE,
                dialog_title="Select scan image(s)",
            )
            paths = normalize_picker_paths(picked)
            if not paths:
                if picked:
                    show_toast("لم يتم الحصول على مسار محلي للصورة. شغّل التطبيق كتطبيق سطح مكتب.", DANGER)
                return
            if multiple:
                state["batch_images"] = paths
                show_toast(f"تم اختيار {len(paths)} صورة للمسح المتعدد.", SUCCESS)
            else:
                state["batch_images"] = [paths[0]]
            state["selected_image_path"] = paths[-1]
            b64, raw = await run_in_worker(
                engine.apply_scanner_filter, state["selected_image_path"], state["filter_mode"]
            )
            state["processed_image_bytes"] = raw
            refresh_preview(b64)
        except Exception as exc:
            show_toast(f"تعذر اختيار الصور: {exc}", DANGER)

    async def capture_document_photo(e=None):
        frame = state.get("camera_last_frame")
        if frame is None or state.get("camera_target") != "scanner":
            show_toast("ابدأ الكاميرا أولاً، ثم اضغط زر الالتقاط.", DANGER)
            return
        try:
            ok, encoded = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 94])
            if not ok:
                raise RuntimeError("تعذر حفظ إطار الكاميرا.")
            stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            file_name = f"CameraScan_{stamp}.jpg"
            path = engine._unique_output_path(file_name)
            with open(path, "wb") as output:
                output.write(encoded.tobytes())
            if state["scan_mode"] == "Batch":
                state["batch_images"].append(path)
            else:
                state["batch_images"] = [path]
            state["selected_image_path"] = path
            engine.add_history_item(os.path.basename(path), path, "Camera Capture")
            await stop_desktop_camera()
            b64, raw = await run_in_worker(engine.apply_scanner_filter, path, state["filter_mode"])
            state["processed_image_bytes"] = raw
            refresh_preview(b64)
            show_toast("تم التقاط صورة المستند من الكاميرا الحقيقية.", SUCCESS)
        except Exception as exc:
            show_toast(f"فشل التقاط الصورة: {exc}", DANGER)

    async def save_scan_as_pdf(e):
        paths = state.get("batch_images") or ([state["selected_image_path"]] if state.get("selected_image_path") else [])
        if not paths:
            show_toast("يرجى اختيار صورة مستند أولاً.", DANGER)
            return
        temp_files: list[str] = []
        try:
            for index, path in enumerate(paths):
                _, filtered = await run_in_worker(
                    engine.apply_scanner_filter, path, state["filter_mode"]
                )
                temp_path = os.path.join(storage_path, f"scanova_temp_{index}_{secrets.token_hex(3)}.jpg")
                with open(temp_path, "wb") as output:
                    output.write(filtered)
                temp_files.append(temp_path)
            stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = await run_in_worker(
                engine.images_to_pdf, temp_files, f"Scanova_{stamp}.pdf"
            )
            show_toast(f"تم إنشاء PDF من {len(paths)} صورة: {os.path.basename(output_path)}", SUCCESS)
            state["batch_images"] = []
            navigate_to("files")
        except Exception as exc:
            show_toast(f"تعذر إنشاء PDF: {exc}", DANGER)
        finally:
            for path in temp_files:
                try:
                    os.remove(path)
                except OSError:
                    pass

    async def run_ocr(e):
        raw = state.get("processed_image_bytes")
        if not raw:
            show_toast("اختر صورة أولاً لاستخراج النص.", DANGER)
            return
        show_toast("جارٍ استخراج النص. قد تستغرق العملية بعض الوقت...")
        try:
            selected_lang = ocr_language.value or "eng"
            extracted = await run_in_worker(engine.extract_text_ocr, raw, selected_lang)
            state["extracted_text"] = extracted
            extracted_text_field.value = extracted
            navigate_to("ocr")
        except Exception as exc:
            show_toast(f"تعذر استخراج النص: {exc}", DANGER)

    async def pick_qr_image(e):
        try:
            picked = await qr_picker.pick_files(
                allow_multiple=False, file_type=ft.FilePickerFileType.IMAGE,
                dialog_title="Select QR image",
            )
            paths = normalize_picker_paths(picked)
            if not paths:
                return
            qr_result_text.value = "جارٍ تحليل الصورة..."
            page.update()
            result = await run_in_worker(engine.decode_codes_image, paths[0])
            qr_result_text.value = result
            page.update()
            show_toast("اكتملت قراءة الصورة محلياً دون إرسالها إلى خدمة خارجية.", SUCCESS)
        except Exception as exc:
            show_toast(f"تعذر قراءة QR: {exc}", DANGER)

    # ----------------------------- OCR/Translate ------------------------
    source_lang = ft.Dropdown(
        value="English", width=140, text_size=13,
        options=[ft.DropdownOption(key=value, text=value)
                 for value in ["English", "Arabic", "French", "Spanish", "Turkish"]],
    )
    target_lang = ft.Dropdown(
        value="Arabic", width=140, text_size=13,
        options=[ft.DropdownOption(key=value, text=value)
                 for value in ["Arabic", "English", "French", "Spanish", "Turkish"]],
    )
    ocr_language = ft.Dropdown(
        value="eng", width=120, text_size=12,
        options=[
            ft.DropdownOption(key="eng", text="English OCR"),
            ft.DropdownOption(key="ara", text="Arabic OCR"),
        ],
    )
    extracted_text_field = ft.TextField(
        value="", multiline=True, min_lines=12, max_lines=20,
        read_only=True, border=ft.NoInputBorder(), text_size=14,
        color=NAVY, expand=True,
    )

    def toggle_edit_text(e):
        extracted_text_field.read_only = not extracted_text_field.read_only
        if extracted_text_field.read_only:
            state["extracted_text"] = extracted_text_field.value or ""
            show_toast("تم حفظ التعديلات النصية.", SUCCESS)
        else:
            show_toast("يمكنك الآن تعديل النص.")
        page.update()

    async def copy_text(e):
        try:
            await clipboard.set(extracted_text_field.value or "")
            show_toast("تم نسخ النص إلى الحافظة.", SUCCESS)
        except Exception as exc:
            show_toast(f"تعذر النسخ: {exc}", DANGER)

    async def translate_text(e):
        original = extracted_text_field.value or ""
        if not original.strip():
            show_toast("لا يوجد نص لترجمته.", DANGER)
            return
        try:
            show_toast("جارٍ ترجمة النص بالكامل...")
            translated = await run_in_worker(
                engine.translate_text, original, source_lang.value or "English",
                target_lang.value or "Arabic",
            )
            extracted_text_field.value = translated
            state["extracted_text"] = translated
            show_toast(f"اكتملت الترجمة إلى {target_lang.value}.", SUCCESS)
        except Exception as exc:
            show_toast(f"تعذرت الترجمة: {exc}", DANGER)

    async def export_text(e):
        text_value = extracted_text_field.value or ""
        if not text_value.strip():
            show_toast("لا يوجد نص لحفظه.", DANGER)
            return
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = engine._unique_output_path(f"Scanova_Text_{stamp}.txt")
        with open(output_path, "w", encoding="utf-8") as output:
            output.write(text_value)
        engine.add_history_item(os.path.basename(output_path), output_path, "OCR Text")
        try:
            await clipboard.set(text_value)
        except Exception:
            pass
        show_toast("تم حفظ النص داخل مجلد Scanova / scanned_docs.", SUCCESS)

    # ------------------------------- PDF tools --------------------------
    async def choose_pdf_files(action: str, *, multiple: bool = False, images: bool = False):
        state["pending_pdf_action"] = action
        try:
            picked = await pdf_picker.pick_files(
                allow_multiple=multiple,
                file_type=ft.FilePickerFileType.IMAGE if images else ft.FilePickerFileType.CUSTOM,
                allowed_extensions=None if images else ["pdf"],
                dialog_title="Select image(s)" if images else "Select PDF file(s)",
            )
            paths = normalize_picker_paths(picked)
            if not paths:
                if picked:
                    show_toast("تعذر الوصول إلى مسارات الملفات المختارة.", DANGER)
                return
            await process_pdf_action(action, paths)
        except Exception as exc:
            show_toast(f"تعذر اختيار الملفات: {exc}", DANGER)

    async def process_pdf_action(action: str, paths: list[str]):
        try:
            if action == "img_to_pdf":
                stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                out = await run_in_worker(engine.images_to_pdf, paths, f"Scanova_Images_{stamp}.pdf")
                show_toast(f"تم إنشاء PDF: {os.path.basename(out)}", SUCCESS)
            elif action == "pdf_to_text":
                txt = await run_in_worker(engine.pdf_to_text, paths[0])
                state["extracted_text"] = txt
                extracted_text_field.value = txt
                navigate_to("ocr")
                show_toast("تم استخراج النص من PDF.", SUCCESS)
                return
            elif action == "merge_pdf":
                if len(paths) < 2:
                    show_toast("اختر ملفي PDF على الأقل للدمج.", DANGER)
                    return
                stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                out = await run_in_worker(engine.merge_pdfs, paths, f"Scanova_Merged_{stamp}.pdf")
                show_toast(f"تم دمج الملفات: {os.path.basename(out)}", SUCCESS)
            elif action == "split_pdf":
                parts = await run_in_worker(engine.split_pdf, paths[0])
                show_toast(f"تم إنشاء {len(parts)} ملفات صفحات منفصلة.", SUCCESS)
            elif action == "compress_pdf":
                original_size = os.path.getsize(paths[0])
                out = await run_in_worker(engine.compress_pdf, paths[0])
                new_size = os.path.getsize(out)
                if new_size < original_size:
                    show_toast(f"انخفض الحجم من {original_size / 1024:.0f} KB إلى {new_size / 1024:.0f} KB.", SUCCESS)
                else:
                    show_toast("تم تحسين تدفقات PDF، لكن الحجم لم ينخفض. الصور المضمنة لا يعاد ضغطها.")
            elif action == "pdf_to_image":
                images = await run_in_worker(engine.pdf_to_images, paths[0])
                show_toast(f"تم تحويل {len(images)} صفحات إلى صور.", SUCCESS)
            elif action == "vault_encrypt":
                if not state["vault_unlocked"] or state["vault_mode"] != "modern":
                    show_toast("الخزنة القديمة للقراءة والاستعادة فقط. أنشئ خزنة جديدة بعد حفظ الملفات القديمة.", DANGER)
                    return
                enc_name = await run_in_worker(engine.encrypt_file_to_vault, paths[0], state["vault_pin"])
                show_toast(f"تم تشفير الملف داخل الخزنة: {enc_name}", SUCCESS)
                navigate_to("vault")
                return
            navigate_to("files")
        except Exception as exc:
            show_toast(f"فشلت العملية: {exc}", DANGER)

    # -------------------------------- QR --------------------------------
    qr_result_text = ft.Text(
        "اختر صورة أو شغّل الكاميرا لقراءة رمز QR أو باركود.", color="white", size=13,
        text_align=ft.TextAlign.CENTER, selectable=True,
    )
    qr_camera_empty_text = ft.Text(
        "الكاميرا غير مشغلة\nاضغط Start Live Scan", color="white", size=13,
        text_align=ft.TextAlign.CENTER,
    )

    async def start_qr_camera(e=None):
        await start_desktop_camera("qr")

    async def copy_qr_result(e):
        try:
            await clipboard.set(qr_result_text.value or "")
            show_toast("تم نسخ نتيجة QR.", SUCCESS)
        except Exception as exc:
            show_toast(f"تعذر النسخ: {exc}", DANGER)

    # -------------------------------- Vault ------------------------------
    pin_input = ft.TextField(
        label="Vault PIN", password=True, can_reveal_password=True,
        width=280, text_align=ft.TextAlign.CENTER,
    )
    confirm_pin_input = ft.TextField(
        label="Confirm new PIN (first setup)", password=True,
        can_reveal_password=True, width=280, text_align=ft.TextAlign.CENTER,
    )

    async def unlock_vault(e):
        pin = (pin_input.value or "").strip()
        if not pin:
            show_toast("أدخل رمز الخزنة.", DANGER)
            return
        try:
            try:
                mode = await run_in_worker(engine.verify_vault_pin, pin)
            except FileNotFoundError:
                # First use: create a new vault only after explicit PIN confirmation.
                confirmation = (confirm_pin_input.value or "").strip()
                if len(pin) < 8:
                    show_toast("لأول إعداد، استخدم 8 أحرف/أرقام على الأقل.", DANGER)
                    return
                if pin != confirmation:
                    show_toast("رمز التأكيد غير مطابق.", DANGER)
                    return
                await run_in_worker(engine.setup_vault, pin)
                mode = "modern"
                show_toast("تم إنشاء الخزنة الجديدة بمفتاح مشتق بطريقة آمنة.", SUCCESS)
            state["vault_pin"] = pin
            state["vault_mode"] = mode
            state["vault_unlocked"] = True
            if mode == "legacy":
                show_toast("تم فتح خزنة قديمة. يمكنك استعادة الملفات، لكن لا يمكن إضافة ملفات جديدة إليها.", "#C77D11")
            else:
                show_toast("تم فتح الخزنة الآمنة.", SUCCESS)
            navigate_to("vault")
        except Exception as exc:
            show_toast(f"تعذر فتح الخزنة: {exc}", DANGER)

    async def restore_vault_file(file_name: str):
        try:
            path = await run_in_worker(engine.decrypt_vault_file, file_name, state["vault_pin"], False)
            show_toast(f"تم فك التشفير والاستعادة: {os.path.basename(path)}", SUCCESS)
            navigate_to("vault")
        except Exception as exc:
            show_toast(f"تعذر استعادة الملف: {exc}", DANGER)

    async def restore_and_remove_vault_file(file_name: str):
        try:
            path = await run_in_worker(engine.decrypt_vault_file, file_name, state["vault_pin"], True)
            show_toast(f"تمت الاستعادة وحذف النسخة المشفرة: {os.path.basename(path)}", SUCCESS)
            navigate_to("vault")
        except Exception as exc:
            show_toast(f"تعذرت الاستعادة: {exc}", DANGER)

    async def remove_vault_file(file_name: str):
        try:
            await run_in_worker(engine.delete_vault_file, file_name)
            show_toast("تم حذف النسخة المشفرة نهائياً.", SUCCESS)
            navigate_to("vault")
        except Exception as exc:
            show_toast(f"تعذر حذف الملف: {exc}", DANGER)

    def vault_file_handler(operation: str, file_name: str):
        async def handler(e):
            if operation == "restore":
                await restore_vault_file(file_name)
            elif operation == "restore_remove":
                await restore_and_remove_vault_file(file_name)
            else:
                await remove_vault_file(file_name)
        return handler

    async def add_file_to_vault(e):
        await choose_pdf_files("vault_encrypt")

    def pdf_tool_handler(action: str, *, multiple: bool = False, images: bool = False):
        async def handler(e):
            await choose_pdf_files(action, multiple=multiple, images=images)
        return handler

    def vault_file_row(file_name: str):
        return ft.Container(
            bgcolor="#263147", border_radius=10, padding=10,
            content=ft.Column(
                controls=[
                    ft.Row(controls=[icon("ENHANCED_ENCRYPTION", "#26C281"),
                                     ft.Text(file_name, color="white", size=12, expand=True)]),
                    ft.Row(
                        controls=[
                            ft.Button(content="Restore", icon=icon_data("SAVE_ALT"), bgcolor=PRIMARY,
                                      color="white", on_click=vault_file_handler("restore", file_name)),
                            ft.Button(content="Restore + Remove", bgcolor="#A45B18", color="white",
                                      on_click=vault_file_handler("restore_remove", file_name)),
                            ft.IconButton(icon=icon_data("DELETE_OUTLINE"), icon_color="#FF8A80",
                                          tooltip="Delete encrypted file permanently",
                                          on_click=vault_file_handler("delete", file_name)),
                        ], wrap=True,
                    ),
                ], spacing=8,
            ),
        )

    # ---------------------------- UI builders ---------------------------
    def section_title(title: str, subtitle: str | None = None):
        controls = [ft.Text(title, size=20, weight=ft.FontWeight.BOLD, color=NAVY)]
        if subtitle:
            controls.append(ft.Text(subtitle, size=12, color=SUBTEXT))
        return ft.Column(controls=controls, spacing=3)

    def feature_card(title: str, icon_name: str, tint: str, target: str):
        return ft.GestureDetector(
            on_tap=lambda e: navigate_to(target),
            content=ft.Container(
                width=105, height=112, bgcolor=CARD, border_radius=15, padding=10,
                shadow=ft.BoxShadow(blur_radius=8, color="#12000000"),
                content=ft.Column(
                    controls=[
                        ft.Container(width=46, height=46, bgcolor=tint, border_radius=13,
                                     alignment=ft.Alignment(0, 0), content=icon(icon_name, "white", 24)),
                        ft.Text(title, size=11, weight=ft.FontWeight.W_600, color=NAVY,
                                text_align=ft.TextAlign.CENTER),
                    ], alignment=ft.MainAxisAlignment.CENTER,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=8,
                ),
            ),
        )

    def history_row(item: dict[str, Any]):
        name = str(item.get("name", "Unnamed file"))
        size = str(item.get("size", ""))
        date_text = str(item.get("date", ""))
        file_type = str(item.get("type", "File"))
        return ft.Container(
            bgcolor=CARD, border_radius=12, padding=12,
            content=ft.Row(
                controls=[
                    ft.Container(width=40, height=40, bgcolor="#FDECEA", border_radius=9,
                                 alignment=ft.Alignment(0, 0), content=icon("PICTURE_AS_PDF", DANGER, 22)),
                    ft.Column(controls=[
                        ft.Text(name, size=13, weight=ft.FontWeight.BOLD, color=NAVY),
                        ft.Text(f"{file_type} • {size} • {date_text}", size=10, color=SUBTEXT),
                    ], spacing=2, expand=True),
                ],
            ),
        )

    def build_home_view():
        recent = engine.get_history()[:4]
        recent_controls = [history_row(item) for item in recent] or [
            ft.Text("لا توجد ملفات محفوظة بعد. ابدأ بمسح مستند أو تحويل ملف.", color=SUBTEXT, size=12)
        ]
        return ft.Container(
            expand=True, bgcolor="#F4F7FC", padding=18,
            content=ft.Column(
                controls=[
                    ft.Row(
                        controls=[
                            ft.Column(controls=[
                                ft.Text("SCANOVA", size=22, weight=ft.FontWeight.BOLD, color=NAVY),
                                ft.Text("Scan. Extract. Translate. Store Securely.", size=11, color=SUBTEXT),
                            ], spacing=2, expand=True),
                            ft.IconButton(icon=icon_data("QR_CODE_SCANNER"), icon_color=PRIMARY,
                                          tooltip="QR & Barcode", on_click=lambda e: navigate_to("qr")),
                        ]
                    ),
                    ft.Row(controls=[
                        feature_card("Document\nScanner", "DOCUMENT_SCANNER", PRIMARY, "scanner"),
                        feature_card("OCR Text\nExtraction", "TEXT_FIELDS", "#26C281", "ocr"),
                        feature_card("QR & Barcode\nReader", "QR_CODE_2", "#7B2CBF", "qr"),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Row(controls=[
                        feature_card("PDF Tools\n& Converter", "PICTURE_AS_PDF", "#F57C00", "files"),
                        feature_card("Translate\nText", "LANGUAGE", "#1976D2", "ocr"),
                        feature_card("Secure\nVault", "LOCK", "#2E7D32", "vault"),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Row(controls=[
                        ft.Text("Recent Files", size=16, weight=ft.FontWeight.BOLD, color=NAVY),
                        ft.Container(expand=True),
                        ft.Button(content="See All", color=PRIMARY, bgcolor="transparent",
                                  on_click=lambda e: navigate_to("history")),
                    ]),
                    ft.Column(controls=recent_controls, spacing=8, expand=True,
                              scroll=ft.ScrollMode.AUTO),
                ], spacing=13, scroll=ft.ScrollMode.AUTO,
            ),
        )

    def build_scanner_view():
        mode_buttons = []
        for mode in ["Auto", "Single", "Batch"]:
            active = state["scan_mode"] == mode
            mode_buttons.append(
                ft.Button(content=mode, color="white" if active else "#B8C2D0",
                          bgcolor=PRIMARY if active else "#263147", height=34,
                          on_click=lambda e, m=mode: set_scan_mode(m))
            )
        return ft.Container(
            expand=True, bgcolor=DARK_BG,
            content=ft.Column(
                controls=[
                    ft.Container(
                        padding=ft.Padding.only(left=12, right=16, top=12, bottom=8),
                        content=ft.Row(controls=[
                            ft.IconButton(icon=icon_data("ARROW_BACK"), icon_color="white",
                                          on_click=lambda e: navigate_to("home")),
                            ft.Text("Scan Document", color="white", size=18, weight=ft.FontWeight.W_600),
                            ft.Container(expand=True),
                            ft.IconButton(icon=icon_data("PICTURE_AS_PDF"), icon_color="white",
                                          tooltip="Save as PDF", on_click=save_scan_as_pdf),
                        ]),
                    ),
                    ft.Container(
                        expand=True, margin=ft.Margin.symmetric(horizontal=16),
                        border_radius=16, bgcolor="#9E8C7A", alignment=ft.Alignment(0, 0),
                        content=ft.Stack(controls=[
                            ft.Container(alignment=ft.Alignment(0, 0), padding=20,
                                         content=ft.Container(
                                             border=ft.Border.all(2, PRIMARY), border_radius=5, padding=8,
                                             content=ft.Stack(controls=[preview_placeholder, preview_image]),
                                         )),
                            ft.Container(top=8, left=8, right=8,
                                content=ft.Row(controls=[
                                    ft.Button(content="Magic Color", bgcolor=PRIMARY, color="white", height=32,
                                              on_click=filter_handler("magic")),
                                    ft.Button(content="B&W", bgcolor="#2A364F", color="white", height=32,
                                              on_click=filter_handler("bw")),
                                    ft.Button(content="Gray", bgcolor="#2A364F", color="white", height=32,
                                              on_click=filter_handler("gray")),
                                ], alignment=ft.MainAxisAlignment.CENTER, spacing=5)),
                        ]),
                    ),
                    ft.Row(controls=mode_buttons, alignment=ft.MainAxisAlignment.CENTER, spacing=10),
                    ft.Row(controls=[
                        ft.IconButton(icon=icon_data("CAMERA_ALT"), icon_color="white",
                                      icon_size=27, tooltip="Start live camera", on_click=lambda e: page.run_task(start_desktop_camera, "scanner")),
                        ft.IconButton(icon=icon_data("PHOTO_LIBRARY_OUTLINED"), icon_color="white",
                                      icon_size=27, tooltip="Select image(s)", on_click=pick_scan_images),
                        ft.GestureDetector(
                            on_tap=capture_document_photo,
                            content=ft.Container(width=66, height=66, border_radius=33,
                                border=ft.Border.all(4, PRIMARY), padding=4,
                                content=ft.Container(bgcolor="white", border_radius=30)),
                        ),
                        button("OCR Text", run_ocr, icon_name="TEXT_FIELDS", width=105),
                    ], alignment=ft.MainAxisAlignment.SPACE_AROUND),
                    ft.Container(height=8),
                ], spacing=12,
            ),
        )

    def set_scan_mode(mode: str):
        state["scan_mode"] = mode
        if mode == "Auto":
            state["filter_mode"] = "magic"
        navigate_to("scanner")
        if mode == "Auto":
            show_toast("وضع Auto يطبق فلتر Magic Color تلقائياً بعد اختيار الصورة.")
        elif mode == "Batch":
            show_toast("اختر عدة صور دفعة واحدة، ثم اضغط Save as PDF.")

    def build_ocr_view():
        extracted_text_field.value = state.get("extracted_text", "")
        return ft.Container(
            expand=True, bgcolor="#F4F7FC", padding=ft.Padding.symmetric(horizontal=16, vertical=12),
            content=ft.Column(
                controls=[
                    ft.Row(controls=[
                        ft.IconButton(icon=icon_data("ARROW_BACK"), icon_color=NAVY,
                                      on_click=lambda e: navigate_to("scanner")),
                        ft.Text("Text Extracted", size=19, weight=ft.FontWeight.BOLD, color=NAVY),
                        ft.Container(expand=True),
                        ft.IconButton(icon=icon_data("DOCUMENT_SCANNER"), icon_color=PRIMARY,
                                      tooltip="New scan", on_click=lambda e: navigate_to("scanner")),
                    ]),
                    ft.Container(
                        bgcolor=CARD, padding=10, border_radius=12,
                        content=ft.Row(controls=[
                            source_lang, icon("SWAP_HORIZ", PRIMARY), target_lang,
                            button("Translate", translate_text, icon_name="TRANSLATE", width=110, height=40),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, wrap=True),
                    ),
                    ft.Row(controls=[ft.Text("OCR language", color=SUBTEXT, size=11), ocr_language]),
                    ft.Container(
                        expand=True, bgcolor=CARD, border_radius=15, padding=14,
                        shadow=ft.BoxShadow(blur_radius=8, color="#12000000"),
                        content=extracted_text_field,
                    ),
                    ft.Container(
                        bgcolor=CARD, border_radius=14, padding=ft.Padding.symmetric(vertical=8, horizontal=10),
                        content=ft.Row(controls=[
                            ft.Column(controls=[ft.IconButton(icon=icon_data("CONTENT_COPY"), on_click=copy_text),
                                                ft.Text("Copy", size=10, color=SUBTEXT)], spacing=0,
                                      horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                            ft.Column(controls=[ft.IconButton(icon=icon_data("EDIT_OUTLINED"), on_click=toggle_edit_text),
                                                ft.Text("Edit", size=10, color=SUBTEXT)], spacing=0,
                                      horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                            ft.Column(controls=[ft.IconButton(icon=icon_data("SAVE_ALT"), on_click=export_text),
                                                ft.Text("Save", size=10, color=SUBTEXT)], spacing=0,
                                      horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                        ], alignment=ft.MainAxisAlignment.SPACE_AROUND),
                    ),
                ], spacing=9,
            ),
        )

    def build_qr_view():
        return ft.Container(
            expand=True, bgcolor=DARK_BG, padding=18,
            content=ft.Column(
                controls=[
                    ft.Row(controls=[
                        ft.IconButton(icon=icon_data("ARROW_BACK"), icon_color="white",
                                      on_click=lambda e: navigate_to("home")),
                        ft.Text("QR & Barcode Scanner", size=18, weight=ft.FontWeight.BOLD, color="white"),
                    ]),
                    ft.Container(
                        expand=True, width=330, border=ft.Border.all(2, "#26C281"),
                        border_radius=18, bgcolor="#101827", padding=5,
                        alignment=ft.Alignment(0, 0),
                        content=ft.Stack(controls=[
                            qr_camera_image,
                            ft.Container(
                                width=220, height=180, border=ft.Border.all(2, "#26C281"),
                                border_radius=12, alignment=ft.Alignment(0, 0),
                            ),
                            ft.Container(alignment=ft.Alignment(0, 0), content=qr_camera_empty_text),
                        ]),
                    ),
                    ft.Container(height=8),
                    qr_result_text,
                    ft.Text("تتم قراءة QR محلياً على الجهاز. دعم الباركود الإضافي يتطلب ZXing-C++.  ",
                            color="#C5CDD8", size=10, text_align=ft.TextAlign.CENTER),
                    ft.Row(controls=[
                        button("Start Live Scan", start_qr_camera, icon_name="CAMERA_ALT", width=150),
                        button("Stop Camera", stop_desktop_camera, icon_name="STOP", bgcolor="#263147", width=140),
                    ], alignment=ft.MainAxisAlignment.CENTER, wrap=True),
                    ft.Row(controls=[
                        button("Choose Image", pick_qr_image, icon_name="IMAGE_OUTLINED", bgcolor="#263147", width=145),
                        button("Copy Result", copy_qr_result, icon_name="CONTENT_COPY", bgcolor="#263147", width=145),
                    ], alignment=ft.MainAxisAlignment.CENTER),
                    ft.Container(height=10),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10,
            ),
        )

    def tool_card(title: str, icon_name: str, tint: str, on_click):
        return ft.GestureDetector(
            on_tap=on_click,
            content=ft.Container(width=165, height=94, bgcolor=CARD, border_radius=14,
                padding=10, shadow=ft.BoxShadow(blur_radius=7, color="#10000000"),
                content=ft.Column(controls=[
                    ft.Container(width=38, height=38, bgcolor=tint, border_radius=10,
                                 alignment=ft.Alignment(0, 0), content=icon(icon_name, PRIMARY, 21)),
                    ft.Text(title, size=12, weight=ft.FontWeight.W_600, color=NAVY,
                            text_align=ft.TextAlign.CENTER),
                ], alignment=ft.MainAxisAlignment.CENTER,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=7),
            ),
        )

    def build_files_view():
        recent = engine.get_history()[:10]
        recent_controls = [history_row(item) for item in recent] or [ft.Text("لا توجد ملفات محفوظة.", color=SUBTEXT)]
        return ft.Container(
            expand=True, bgcolor="#F4F7FC", padding=ft.Padding.symmetric(horizontal=16, vertical=14),
            content=ft.Column(controls=[
                ft.Row(controls=[
                    section_title("PDF Tools", "Manage and convert your documents"),
                    ft.Container(expand=True),
                    ft.IconButton(icon=icon_data("LOCK_OUTLINE"), icon_color=PRIMARY,
                                  tooltip="Secure Vault", on_click=lambda e: navigate_to("vault")),
                ]),
                ft.Row(controls=[
                    tool_card("PDF to Text", "DESCRIPTION_OUTLINED", "#EBF2FF",
                              pdf_tool_handler("pdf_to_text")),
                    tool_card("Images to PDF", "IMAGE_OUTLINED", "#EBF2FF",
                              pdf_tool_handler("img_to_pdf", multiple=True, images=True)),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Row(controls=[
                    tool_card("Optimize PDF", "COMPRESS", "#FFF3E0",
                              pdf_tool_handler("compress_pdf")),
                    tool_card("Merge PDF", "MERGE_TYPE", "#E0F2F1",
                              pdf_tool_handler("merge_pdf", multiple=True)),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Row(controls=[
                    tool_card("Split PDF", "CALL_SPLIT", "#F3E5F5",
                              pdf_tool_handler("split_pdf")),
                    tool_card("PDF to Image", "COLLECTIONS_OUTLINED", "#FFEBEE",
                              pdf_tool_handler("pdf_to_image")),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Row(controls=[
                    ft.Text("Recent Files", size=16, weight=ft.FontWeight.BOLD, color=NAVY),
                    ft.Container(expand=True),
                    ft.Button(content="History", color=PRIMARY, bgcolor="transparent",
                              on_click=lambda e: navigate_to("history")),
                ]),
                ft.Column(controls=recent_controls, spacing=7, expand=True, scroll=ft.ScrollMode.AUTO),
            ], spacing=10, scroll=ft.ScrollMode.AUTO),
        )

    def build_history_view():
        items = engine.get_history()
        return ft.Container(
            expand=True, bgcolor="#F4F7FC", padding=18,
            content=ft.Column(controls=[
                ft.Row(controls=[
                    ft.IconButton(icon=icon_data("ARROW_BACK"), icon_color=NAVY,
                                  on_click=lambda e: navigate_to("home")),
                    section_title("History", f"{len(items)} saved item(s)"),
                ]),
                ft.Column(controls=[history_row(item) for item in items] or
                          [ft.Text("لا توجد عمليات محفوظة في السجل بعد.", color=SUBTEXT)],
                          spacing=8, expand=True, scroll=ft.ScrollMode.AUTO),
            ]),
        )

    def build_vault_view():
        encrypted_files = sorted(
            name for name in os.listdir(engine.vault_dir)
            if name.endswith(".enc") and not name.endswith(".tmp")
        )
        if not state["vault_unlocked"]:
            return ft.Container(
                expand=True, bgcolor=DARK_BG, padding=22,
                content=ft.Column(controls=[
                    ft.Row(controls=[
                        ft.IconButton(icon=icon_data("ARROW_BACK"), icon_color="white",
                                      on_click=lambda e: navigate_to("home")),
                        ft.Text("Secure Vault", size=19, weight=ft.FontWeight.BOLD, color="white"),
                    ]),
                    ft.Container(expand=True),
                    ft.Container(width=130, height=130, border_radius=65, bgcolor=PRIMARY,
                                 alignment=ft.Alignment(0, 0), content=icon("LOCK", "white", 62),
                                 shadow=ft.BoxShadow(blur_radius=22, color="#661B6BF3")),
                    ft.Text("Your files are safe", size=20, weight=ft.FontWeight.BOLD, color="white"),
                    ft.Text("Create a new PIN or unlock your existing vault.", size=12,
                            color="#C5CDD8", text_align=ft.TextAlign.CENTER),
                    pin_input, confirm_pin_input,
                    button("Unlock / Create Vault", unlock_vault, icon_name="LOCK_OPEN_ROUNDED", width=280),
                    ft.Text("First setup requires a PIN of at least 8 characters and confirmation.",
                            size=10, color="#B7C0CD", text_align=ft.TextAlign.CENTER),
                    ft.Container(expand=True),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12,
                    alignment=ft.MainAxisAlignment.CENTER),
            )

        vault_actions = [
            button("Add File to Vault", add_file_to_vault,
                   icon_name="ADD", width=220),
        ] if state["vault_mode"] == "modern" else [
            ft.Text("Legacy vault: restore old files. New encryption is disabled until the old files are moved out.",
                    color="#FFD180", size=11, text_align=ft.TextAlign.CENTER),
        ]
        rows = [vault_file_row(name) for name in encrypted_files] or [
            ft.Text("الخزنة فارغة حالياً.", color="#C5CDD8", size=12)
        ]
        return ft.Container(
            expand=True, bgcolor=DARK_BG, padding=20,
            content=ft.Column(controls=[
                ft.Row(controls=[
                    ft.IconButton(icon=icon_data("ARROW_BACK"), icon_color="white",
                                  on_click=lambda e: navigate_to("home")),
                    ft.Text("Secure Vault", size=19, weight=ft.FontWeight.BOLD, color="white"),
                    ft.Container(expand=True),
                    ft.IconButton(icon=icon_data("LOCK"), icon_color="white", tooltip="Lock vault",
                                  on_click=lock_vault),
                ]),
                ft.Text("Encrypted files", color="#C5CDD8", size=12),
                ft.Column(controls=rows, spacing=8, expand=True, scroll=ft.ScrollMode.AUTO),
                *vault_actions,
            ], spacing=12),
        )

    def lock_vault(e):
        state["vault_unlocked"] = False
        state["vault_pin"] = ""
        pin_input.value = ""
        confirm_pin_input.value = ""
        navigate_to("vault")

    def build_bottom_navigation():
        def nav_item(label: str, icon_name: str, key: str):
            active = state["tab"] == key
            color = PRIMARY if active else SUBTEXT
            return ft.GestureDetector(
                on_tap=lambda e: navigate_to(key),
                content=ft.Column(controls=[icon(icon_name, color, 22),
                    ft.Text(label, size=10, color=color,
                            weight=ft.FontWeight.W_600 if active else ft.FontWeight.NORMAL)],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=2),
            )
        return ft.Container(
            height=72, bgcolor=CARD, padding=ft.Padding.symmetric(horizontal=14),
            shadow=ft.BoxShadow(blur_radius=12, color="#18000000"),
            content=ft.Row(controls=[
                nav_item("Home", "HOME_OUTLINED", "home"),
                nav_item("History", "HISTORY", "history"),
                ft.GestureDetector(on_tap=lambda e: navigate_to("scanner"),
                    content=ft.Container(width=54, height=54, bgcolor=PRIMARY, border_radius=27,
                        alignment=ft.Alignment(0, 0),
                        shadow=ft.BoxShadow(blur_radius=12, color="#661B6BF3"),
                        content=icon("DOCUMENT_SCANNER", "white", 25))),
                nav_item("Files", "FOLDER_OUTLINED", "files"),
                nav_item("Vault", "LOCK_OUTLINE", "vault"),
            ], alignment=ft.MainAxisAlignment.SPACE_AROUND,
                vertical_alignment=ft.CrossAxisAlignment.CENTER),
        )

    def build_current_view():
        tab = state["tab"]
        builders = {
            "home": build_home_view,
            "scanner": build_scanner_view,
            "ocr": build_ocr_view,
            "qr": build_qr_view,
            "files": build_files_view,
            "history": build_history_view,
            "vault": build_vault_view,
        }
        return builders.get(tab, build_home_view)()

    content_holder = ft.Container(expand=True)
    bottom_holder = ft.Container()
    content_holder.content = build_home_view()
    bottom_holder.content = build_bottom_navigation()
    page.add(ft.Column(controls=[content_holder, bottom_holder], expand=True, spacing=0))


if __name__ == "__main__":
    ft.run(main)
