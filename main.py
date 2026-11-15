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
# 1. المحرك الخلفي (100% Pure Python متوافق مع iOS بدون أي مكتبات C)
# ==========================================
class ScannerEngine:
    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        self.docs_dir = os.path.join(storage_dir, "scanned_docs")
        self.vault_dir = os.path.join(storage_dir, "secure_vault")
        self.history_file = os.path.join(storage_dir, "history.json")
        os.makedirs(self.docs_dir, exist_ok=True)
        os.makedirs(self.vault_dir, exist_ok=True)

    # --- قراءة الصورة وتحويلها لـ Base64 ---
    @staticmethod
    def load_image_bytes(image_path: str) -> tuple[str, bytes]:
        with open(image_path, "rb") as f:
            raw_bytes = f.read()
        b64_str = base64.b64encode(raw_bytes).decode("utf-8")
        return b64_str, raw_bytes

    # --- معرفة أبعاد صورة JPEG تلقائياً بالبايثون الخالص ---
    @staticmethod
    def _get_jpeg_dimensions(data: bytes) -> tuple[int, int]:
        try:
            stream = io.BytesIO(data)
            if stream.read(2) != b"\xff\xd8":
                return 800, 1100
            while True:
                marker = stream.read(2)
                if len(marker) < 2:
                    break
                if marker[0] != 0xFF:
                    break
                m = marker[1]
                if m in (0xC0, 0xC1, 0xC2):
                    stream.read(3)
                    h, w = struct.unpack(">HH", stream.read(4))
                    return w, h
                elif m in (0xD8, 0xD9, 0x01) or (0xD0 <= m <= 0xD7):
                    continue
                else:
                    size = struct.unpack(">H", stream.read(2))[0]
                    stream.seek(size - 2, 1)
        except Exception:
            pass
        return 800, 1100

    # --- مولد PDF أصيل من الصور بدون الحاجة لـ Pillow أو fpdf2 ---
    def images_to_pdf(self, image_paths: list[str], output_name: str) -> str:
        if not output_name.lower().endswith(".pdf"):
            output_name += ".pdf"
        out_path = os.path.join(self.docs_dir, output_name)

        writer = PdfWriter()
        for path in image_paths:
            with open(path, "rb") as f:
                img_bytes = f.read()
            single_pdf_bytes = self._build_single_image_pdf(img_bytes)
            reader = PdfReader(io.BytesIO(single_pdf_bytes))
            writer.add_page(reader.pages[0])

        with open(out_path, "wb") as out_f:
            writer.write(out_f)

        self.add_history_item(output_name, out_path, "PDF Document")
        return out_path

    def _build_single_image_pdf(self, img_bytes: bytes) -> bytes:
        # بناء هيكل PDF قياسي يضم الصورة بجودتها الكاملة على صفحة A4
        w, h = self._get_jpeg_dimensions(img_bytes)
        page_w, page_h = 595, 842  # A4 standard points

        content = f"q {page_w} 0 0 {page_h} 0 0 cm /Im0 Do Q".encode("latin1")
        objs = []
        objs.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
        objs.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
        objs.append(
            f"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 4 0 R >> >> "
            f"/MediaBox [0 0 {page_w} {page_h}] /Contents 5 0 R >>\nendobj\n".encode("latin1")
        )
        objs.append(
            f"4 0 obj\n<< /Type /XObject /Subtype /Image /Width {w} /Height {h} "
            f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {len(img_bytes)} >>\nstream\n".encode("latin1")
            + img_bytes
            + b"\nendstream\nendobj\n"
        )
        objs.append(
            f"5 0 obj\n<< /Length {len(content)} >>\nstream\n".encode("latin1")
            + content
            + b"\nendstream\nendobj\n"
        )

        pdf = bytearray(b"%PDF-1.4\n")
        offsets = []
        for o in objs:
            offsets.append(len(pdf))
            pdf.extend(o)
        xref_pos = len(pdf)
        pdf.extend(f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode("latin1"))
        for off in offsets:
            pdf.extend(f"{off:010d} 00000 n \n".encode("latin1"))
        pdf.extend(
            f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode("latin1")
        )
        return bytes(pdf)

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
            return "لم يتم العثور على نص واضح في الصورة. تأكد من الإضاءة الجيدة أو حجم الصورة."
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
                r = requests.post("https://api.qrserver.com/v1/read-qr-code/", files=files, timeout=15)
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
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(items[:25], f, ensure_ascii=False, indent=2)


# ==========================================
# 2. واجهة المستخدم الرسومية المطابقة للصورة
# ==========================================
def main(page: ft.Page):
    page.title = "OCR Scanner Pro"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.padding = 0
    page.spacing = 0
    page.bgcolor = "#F4F7FC"

    PRIMARY_BLUE = "#1B6BF3"
    DARK_NAVY = "#15233C"
    DARK_SCANNER_BG = "#1A2232"
    CARD_BG = "#FFFFFF"
    SUBTEXT_GRAY = "#6E7A8A"

    storage_path = os.path.join(os.path.expanduser("~"), "Documents", "OCRScannerApp")
    engine = ScannerEngine(storage_path)

    state = {
        "current_tab": "home",
        "selected_image_path": None,
        "processed_image_bytes": None,
        "scan_mode": "Single",
        "filter_mode": "magic",
        "batch_images": [],
        "extracted_text": (
            "Softfire Infotech\n\n"
            "Softfire Infotech is a leading software development company "
            "delivering innovative and custom solutions for businesses worldwide.\n\n"
            "• Android & iOS App Development\n"
            "• Web Development\n"
            "• UI/UX Design\n"
            "• Cloud Solutions"
        ),
        "vault_unlocked": False,
        "vault_pin": "1234"
    }

    def show_toast(msg: str, color: str = PRIMARY_BLUE):
        page.snack_bar = ft.SnackBar(
            content=ft.Text(msg, color="white", weight=ft.FontWeight.W_500),
            bgcolor=color,
            behavior=ft.SnackBarBehavior.FLOATING,
        )
        page.snack_bar.open = True
        page.update()

    def on_scan_image_picked(e: ft.FilePickerResultEvent):
        if not e.files or not e.files[0].path:
            return
        file_path = e.files[0].path
        state["selected_image_path"] = file_path
        if state["scan_mode"] == "Batch":
            state["batch_images"].append(file_path)
            show_toast(f"تمت إضافة الصورة ({len(state['batch_images'])}) إلى المسح المتعدد Batch")
        apply_current_filter_and_refresh()

    def on_qr_image_picked(e: ft.FilePickerResultEvent):
        if not e.files or not e.files[0].path:
            return
        show_toast("جاري فحص وقراءة رمز QR...", PRIMARY_BLUE)
        res = engine.decode_qr_image(e.files[0].path)
        qr_result_text.value = res
        page.set_clipboard(res)
        show_toast("تم استخراج رمز QR ونسخه للحافظة!", "#18A957")
        page.update()

    def on_pdf_tool_files_picked(e: ft.FilePickerResultEvent):
        if not e.files:
            return
        tool_action = state.get("pending_pdf_action", "")
        paths = [f.path for f in e.files if f.path]
        if not paths:
            return

        try:
            if tool_action == "img_to_pdf":
                stamp = datetime.datetime.now().strftime("%H%M%S")
                out = engine.images_to_pdf(paths, f"Scanned_{stamp}.pdf")
                show_toast(f"تم إنشاء ملف PDF: {os.path.basename(out)}", "#18A957")
            elif tool_action == "pdf_to_text":
                txt = engine.pdf_to_text(paths[0])
                state["extracted_text"] = txt
                navigate_to("ocr")
                show_toast("تم استخراج النص من ملف الـ PDF بنجاح!", "#18A957")
                return
            elif tool_action == "merge_pdf":
                if len(paths) < 2:
                    show_toast("يرجى اختيار ملفين PDF على الأقل لدمجهما", "#E53935")
                    return
                stamp = datetime.datetime.now().strftime("%H%M%S")
                out = engine.merge_pdfs(paths, f"Merged_{stamp}.pdf")
                show_toast(f"تم دمج الملفات: {os.path.basename(out)}", "#18A957")
            elif tool_action == "split_pdf":
                parts = engine.split_pdf(paths[0])
                show_toast(f"تم تقسيم الملف إلى {len(parts)} صفحات!", "#18A957")
            elif tool_action == "compress_pdf":
                out = engine.compress_pdf(paths[0])
                show_toast(f"تم ضغط الملف: {os.path.basename(out)}", "#18A957")
            elif tool_action == "vault_encrypt":
                enc_name = engine.encrypt_file_to_vault(paths[0], state["vault_pin"])
                show_toast(f"تم تشفير وحفظ الملف في الخزنة: {enc_name}", "#18A957")
                navigate_to("vault")
                return

            navigate_to("files")
        except Exception as ex:
            show_toast(f"خطأ أثناء المعالجة: {ex}", "#E53935")

    scan_picker = ft.FilePicker(on_result=on_scan_image_picked)
    qr_picker = ft.FilePicker(on_result=on_qr_image_picked)
    pdf_picker = ft.FilePicker(on_result=on_pdf_tool_files_picked)
    page.overlay.extend([scan_picker, qr_picker, pdf_picker])

    scanner_preview_image = ft.Image(
        src_base64="",
        visible=False,
        fit=ft.ImageFit.CONTAIN,
        expand=True,
    )

    def apply_current_filter_and_refresh():
        if not state["selected_image_path"]:
            return
        b64, raw_bytes = engine.load_image_bytes(state["selected_image_path"])
        state["processed_image_bytes"] = raw_bytes
        scanner_preview_image.src_base64 = b64

        # تطبيق فلاتر Clear Scanner عبر معالج الرسوميات المدمج في Flet/Flutter
        mode = state["filter_mode"]
        if mode == "bw":
            scanner_preview_image.color = "white"
            scanner_preview_image.color_blend_mode = ft.BlendMode.SATURATION
        elif mode == "gray":
            scanner_preview_image.color = "grey"
            scanner_preview_image.color_blend_mode = ft.BlendMode.COLOR
        else:
            scanner_preview_image.color = None
            scanner_preview_image.color_blend_mode = None

        scanner_preview_image.visible = True
        default_doc_mockup.visible = False
        page.update()

    default_doc_mockup = ft.Container(
        width=230,
        height=300,
        bgcolor="white",
        border_radius=6,
        padding=18,
        shadow=ft.BoxShadow(blur_radius=15, color="black45"),
        content=ft.Column(
            [
                ft.Text("SOFTFIRE DOCUMENT", size=9, weight=ft.FontWeight.BOLD, color=SUBTEXT_GRAY),
                ft.Divider(height=8, color="#E0E6ED"),
                ft.Container(height=8, bgcolor="#D0D7DE", border_radius=4, width=160),
                ft.Container(height=8, bgcolor="#E5E9F0", border_radius=4, width=180),
                ft.Container(height=8, bgcolor="#E5E9F0", border_radius=4, width=170),
                ft.Container(height=8, bgcolor="#E5E9F0", border_radius=4, width=140),
                ft.Container(height=12),
                ft.Container(height=8, bgcolor="#D0D7DE", border_radius=4, width=175),
                ft.Container(height=8, bgcolor="#E5E9F0", border_radius=4, width=185),
                ft.Container(height=8, bgcolor="#E5E9F0", border_radius=4, width=160),
                ft.Container(expand=True),
                ft.Row(
                    [ft.Text("اضغط زر الكاميرا بالأسفل للمسح", size=9, color=PRIMARY_BLUE)],
                    alignment=ft.MainAxisAlignment.CENTER,
                ),
            ],
            spacing=6,
        ),
    )

    def set_filter_mode(mode_name: str):
        state["filter_mode"] = mode_name
        apply_current_filter_and_refresh()
        show_toast(f"تم تطبيق فلتر Clear Scanner: {mode_name.upper()}")

    def run_ocr_on_current_scan(e):
        if not state["processed_image_bytes"]:
            show_toast("تم فتح النص التجريبي، اختر صورة لاستخراج نصها", PRIMARY_BLUE)
            navigate_to("ocr")
            return
        show_toast("جاري استخراج النص (OCR)...", PRIMARY_BLUE)
        extracted = engine.extract_text_ocr(state["processed_image_bytes"], "eng")
        state["extracted_text"] = extracted
        navigate_to("ocr")

    def save_current_scan_as_pdf(e):
        if not state["selected_image_path"]:
            show_toast("يرجى اختيار صورة مستند أولاً لحفظها كـ PDF", "#E53935")
            return
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        paths = state["batch_images"] if (state["scan_mode"] == "Batch" and state["batch_images"]) else [state["selected_image_path"]]
        out_pdf = engine.images_to_pdf(paths, f"ClearScan_{stamp}.pdf")
        show_toast(f"تم حفظ المستند: {os.path.basename(out_pdf)}", "#18A957")
        navigate_to("files")

    def build_scanner_view() -> ft.Control:
        return ft.Container(
            expand=True,
            bgcolor=DARK_SCANNER_BG,
            content=ft.Column(
                [
                    ft.Container(
                        padding=ft.padding.only(left=16, right=16, top=18, bottom=10),
                        content=ft.Row(
                            [
                                ft.IconButton(
                                    icon=ft.icons.ARROW_BACK,
                                    icon_color="white",
                                    on_click=lambda _: navigate_to("home"),
                                ),
                                ft.Text("Scan Document", color="white", size=18, weight=ft.FontWeight.W_600),
                                ft.Container(expand=True),
                                ft.IconButton(
                                    icon=ft.icons.PICTURE_AS_PDF,
                                    icon_color="white",
                                    on_click=save_current_scan_as_pdf,
                                ),
                            ]
                        ),
                    ),
                    ft.Container(
                        expand=True,
                        margin=ft.margin.symmetric(horizontal=20),
                        border_radius=16,
                        bgcolor="#9E8C7A",
                        alignment=ft.alignment.center,
                        content=ft.Stack(
                            [
                                ft.Container(
                                    alignment=ft.alignment.center,
                                    padding=24,
                                    content=ft.Container(
                                        border=ft.border.all(2.5, PRIMARY_BLUE),
                                        border_radius=4,
                                        padding=8,
                                        content=ft.Stack(
                                            [
                                                default_doc_mockup,
                                                scanner_preview_image,
                                            ]
                                        ),
                                    ),
                                ),
                                ft.Container(
                                    top=10,
                                    left=10,
                                    right=10,
                                    content=ft.Row(
                                        [
                                            ft.ElevatedButton(
                                                "Magic Color",
                                                bgcolor=PRIMARY_BLUE,
                                                color="white",
                                                height=30,
                                                on_click=lambda _: set_filter_mode("magic"),
                                            ),
                                            ft.ElevatedButton(
                                                "B&W",
                                                bgcolor="#2A364F",
                                                color="white",
                                                height=30,
                                                on_click=lambda _: set_filter_mode("bw"),
                                            ),
                                            ft.ElevatedButton(
                                                "Gray",
                                                bgcolor="#2A364F",
                                                color="white",
                                                height=30,
                                                on_click=lambda _: set_filter_mode("gray"),
                                            ),
                                        ],
                                        alignment=ft.MainAxisAlignment.CENTER,
                                        spacing=8,
                                    ),
                                ),
                            ]
                        ),
                    ),
                    ft.Container(
                        padding=ft.padding.symmetric(vertical=12),
                        content=ft.Row(
                            [
                                ft.TextButton(
                                    "Auto",
                                    style=ft.ButtonStyle(color=PRIMARY_BLUE if state["scan_mode"] == "Auto" else "white70"),
                                    on_click=lambda _: (state.update({"scan_mode": "Auto"}), navigate_to("scanner")),
                                ),
                                ft.TextButton(
                                    "Single",
                                    style=ft.ButtonStyle(color=PRIMARY_BLUE if state["scan_mode"] == "Single" else "white70"),
                                    on_click=lambda _: (state.update({"scan_mode": "Single"}), navigate_to("scanner")),
                                ),
                                ft.TextButton(
                                    "Batch",
                                    style=ft.ButtonStyle(color=PRIMARY_BLUE if state["scan_mode"] == "Batch" else "white70"),
                                    on_click=lambda _: (state.update({"scan_mode": "Batch"}), navigate_to("scanner")),
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.CENTER,
                            spacing=25,
                        ),
                    ),
                    ft.Container(
                        padding=ft.padding.only(left=30, right=30, bottom=20),
                        content=ft.Row(
                            [
                                ft.IconButton(
                                    icon=ft.icons.PHOTO_LIBRARY_OUTLINED,
                                    icon_color="white",
                                    icon_size=28,
                                    on_click=lambda _: scan_picker.pick_files(allow_multiple=False, file_type=ft.FilePickerFileType.IMAGE),
                                ),
                                ft.GestureDetector(
                                    on_tap=lambda _: scan_picker.pick_files(allow_multiple=False, file_type=ft.FilePickerFileType.IMAGE),
                                    content=ft.Container(
                                        width=68,
                                        height=68,
                                        border_radius=34,
                                        border=ft.border.all(4, PRIMARY_BLUE),
                                        padding=4,
                                        content=ft.Container(
                                            bgcolor="white",
                                            border_radius=30,
                                        ),
                                    ),
                                ),
                                ft.ElevatedButton(
                                    "OCR",
                                    icon=ft.icons.TEXT_FIELDS,
                                    bgcolor=PRIMARY_BLUE,
                                    color="white",
                                    on_click=run_ocr_on_current_scan,
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                    ),
                ],
                spacing=0,
            ),
        )

    source_lang_dd = ft.Dropdown(
        value="English",
        width=130,
        text_size=13,
        border_radius=10,
        content_padding=ft.padding.symmetric(horizontal=12, vertical=6),
        options=[
            ft.dropdown.Option("English"),
            ft.dropdown.Option("Arabic"),
            ft.dropdown.Option("French"),
            ft.dropdown.Option("Spanish"),
        ],
    )

    target_lang_dd = ft.Dropdown(
        value="Arabic",
        width=130,
        text_size=13,
        border_radius=10,
        content_padding=ft.padding.symmetric(horizontal=12, vertical=6),
        options=[
            ft.dropdown.Option("Arabic"),
            ft.dropdown.Option("English"),
            ft.dropdown.Option("French"),
            ft.dropdown.Option("Turkish"),
        ],
    )

    extracted_text_field = ft.TextField(
        value=state["extracted_text"],
        multiline=True,
        min_lines=12,
        max_lines=16,
        read_only=True,
        border=ft.InputBorder.NONE,
        text_size=14,
        color=DARK_NAVY,
    )

    def toggle_edit_text(e):
        extracted_text_field.read_only = not extracted_text_field.read_only
        state["extracted_text"] = extracted_text_field.value
        status = "وضع التعديل مفعل الآن" if not extracted_text_field.read_only else "تم حفظ التعديلات النصية"
        show_toast(status)
        page.update()

    def copy_extracted_text(e):
        page.set_clipboard(extracted_text_field.value)
        show_toast("تم نسخ النص إلى الحافظة بنجاح!", "#18A957")

    def translate_extracted_text(e):
        show_toast("جاري ترجمة النص...", PRIMARY_BLUE)
        translated = engine.translate_text(
            extracted_text_field.value,
            source_lang_dd.value,
            target_lang_dd.value,
        )
        extracted_text_field.value = translated
        state["extracted_text"] = translated
        page.update()
        show_toast(f"تمت الترجمة إلى {target_lang_dd.value}!", "#18A957")

    def share_or_export_text(e):
        stamp = datetime.datetime.now().strftime("%H%M%S")
        txt_path = os.path.join(engine.docs_dir, f"Extracted_{stamp}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(extracted_text_field.value)
        engine.add_history_item(f"Extracted_{stamp}.txt", txt_path, "OCR Text")
        page.set_clipboard(extracted_text_field.value)
        show_toast("تم حفظ النص ونسخه للمشاركة!", "#18A957")

    def build_ocr_view() -> ft.Control:
        extracted_text_field.value = state["extracted_text"]
        return ft.Container(
            expand=True,
            bgcolor="#F4F7FC",
            padding=ft.padding.symmetric(horizontal=18, vertical=12),
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.IconButton(
                                icon=ft.icons.ARROW_BACK,
                                icon_color=DARK_NAVY,
                                on_click=lambda _: navigate_to("scanner"),
                            ),
                            ft.Text("Text Extracted", size=19, weight=ft.FontWeight.BOLD, color=DARK_NAVY),
                            ft.Container(expand=True),
                            ft.IconButton(
                                icon=ft.icons.CENTER_FOCUS_STRONG_OUTLINED,
                                icon_color=PRIMARY_BLUE,
                                on_click=lambda _: navigate_to("scanner"),
                            ),
                        ]
                    ),
                    ft.Container(
                        bgcolor=CARD_BG,
                        padding=10,
                        border_radius=12,
                        content=ft.Row(
                            [
                                source_lang_dd,
                                ft.IconButton(
                                    icon=ft.icons.SWAP_HORIZ,
                                    icon_color=PRIMARY_BLUE,
                                    on_click=translate_extracted_text,
                                ),
                                target_lang_dd,
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                    ),
                    ft.Container(height=6),
                    ft.Container(
                        expand=True,
                        bgcolor=CARD_BG,
                        border_radius=16,
                        padding=16,
                        shadow=ft.BoxShadow(blur_radius=10, color="#12000000"),
                        content=extracted_text_field,
                    ),
                    ft.Container(height=8),
                    ft.Container(
                        bgcolor=CARD_BG,
                        border_radius=14,
                        padding=ft.padding.symmetric(vertical=10, horizontal=16),
                        shadow=ft.BoxShadow(blur_radius=8, color="#10000000"),
                        content=ft.Row(
                            [
                                ft.Column(
                                    [
                                        ft.IconButton(icon=ft.icons.CONTENT_COPY, icon_color=DARK_NAVY, on_click=copy_extracted_text),
                                        ft.Text("Copy", size=11, color=SUBTEXT_GRAY),
                                    ],
                                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=0,
                                ),
                                ft.Column(
                                    [
                                        ft.IconButton(icon=ft.icons.EDIT_OUTLINED, icon_color=DARK_NAVY, on_click=toggle_edit_text),
                                        ft.Text("Edit", size=11, color=SUBTEXT_GRAY),
                                    ],
                                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=0,
                                ),
                                ft.Column(
                                    [
                                        ft.IconButton(icon=ft.icons.TRANSLATE, icon_color=PRIMARY_BLUE, on_click=translate_extracted_text),
                                        ft.Text("Translate", size=11, color=PRIMARY_BLUE, weight=ft.FontWeight.BOLD),
                                    ],
                                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=0,
                                ),
                                ft.Column(
                                    [
                                        ft.IconButton(icon=ft.icons.SHARE_OUTLINED, icon_color=DARK_NAVY, on_click=share_or_export_text),
                                        ft.Text("Share", size=11, color=SUBTEXT_GRAY),
                                    ],
                                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=0,
                                ),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_AROUND,
                        ),
                    ),
                ]
            ),
        )

    qr_result_text = ft.Text(
        "Place QR code inside the frame",
        color="white70",
        size=13,
        text_align=ft.TextAlign.CENTER,
    )

    def build_qr_view() -> ft.Control:
        return ft.Container(
            expand=True,
            bgcolor=DARK_SCANNER_BG,
            padding=20,
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.IconButton(
                                icon=ft.icons.ARROW_BACK,
                                icon_color="white",
                                on_click=lambda _: navigate_to("home"),
                            ),
                            ft.Text("QR & Barcode", size=18, weight=ft.FontWeight.BOLD, color="white"),
                        ]
                    ),
                    ft.Container(expand=True),
                    ft.Container(
                        width=230,
                        height=230,
                        border=ft.border.all(3, "#26C281"),
                        border_radius=18,
                        bgcolor="white",
                        padding=20,
                        alignment=ft.alignment.center,
                        content=ft.Stack(
                            [
                                ft.Icon(ft.icons.QR_CODE_2, size=175, color=DARK_NAVY),
                                ft.Container(
                                    height=3,
                                    width=190,
                                    bgcolor="#26C281",
                                    top=95,
                                    shadow=ft.BoxShadow(blur_radius=8, color="#26C281"),
                                ),
                            ]
                        ),
                    ),
                    ft.Container(height=18),
                    qr_result_text,
                    ft.Container(expand=True),
                    ft.Row(
                        [
                            ft.GestureDetector(
                                on_tap=lambda _: show_toast("تم تبديل وضع الفلاش الضوئي"),
                                content=ft.Container(
                                    width=75,
                                    height=70,
                                    bgcolor="#263147",
                                    border_radius=14,
                                    content=ft.Column(
                                        [
                                            ft.Icon(ft.icons.FLASH_ON, color="white"),
                                            ft.Text("Flash", color="white70", size=11),
                                        ],
                                        alignment=ft.MainAxisAlignment.CENTER,
                                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                ),
                            ),
                            ft.GestureDetector(
                                on_tap=lambda _: qr_picker.pick_files(allow_multiple=False, file_type=ft.FilePickerFileType.IMAGE),
                                content=ft.Container(
                                    width=75,
                                    height=70,
                                    bgcolor="#263147",
                                    border_radius=14,
                                    content=ft.Column(
                                        [
                                            ft.Icon(ft.icons.IMAGE_OUTLINED, color="white"),
                                            ft.Text("Gallery", color="white70", size=11),
                                        ],
                                        alignment=ft.MainAxisAlignment.CENTER,
                                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    ),
                                ),
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.CENTER,
                        spacing=24,
                    ),
                    ft.Container(height=25),
                    ft.ElevatedButton(
                        "Scan QR from Image / Camera",
                        icon=ft.icons.QR_CODE_SCANNER,
                        bgcolor=PRIMARY_BLUE,
                        color="white",
                        width=260,
                        height=46,
                        on_click=lambda _: qr_picker.pick_files(allow_multiple=False, file_type=ft.FilePickerFileType.IMAGE),
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
        )

    def trigger_pdf_tool(action_key: str, allow_multi: bool = False, images_only: bool = False):
        state["pending_pdf_action"] = action_key
        f_type = ft.FilePickerFileType.IMAGE if images_only else ft.FilePickerFileType.CUSTOM
        exts = None if images_only else ["pdf"]
        pdf_picker.pick_files(allow_multiple=allow_multi, file_type=f_type, allowed_extensions=exts)

    def tool_card(title: str, icon_name: str, icon_color: str, bg_tint: str, on_click_fn) -> ft.Control:
        return ft.GestureDetector(
            on_tap=on_click_fn,
            content=ft.Container(
                width=160,
                height=95,
                bgcolor=CARD_BG,
                border_radius=14,
                padding=12,
                shadow=ft.BoxShadow(blur_radius=8, color="#0D000000"),
                content=ft.Column(
                    [
                        ft.Container(
                            width=40,
                            height=40,
                            bgcolor=bg_tint,
                            border_radius=10,
                            alignment=ft.alignment.center,
                            content=ft.Icon(icon_name, color=icon_color, size=22),
                        ),
                        ft.Text(title, size=12, weight=ft.FontWeight.W_600, color=DARK_NAVY),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=8,
                ),
            ),
        )

    def build_pdf_tools_view() -> ft.Control:
        history_list = engine.get_history()
        recent_tiles = []
        for item in history_list[:8]:
            recent_tiles.append(
                ft.Container(
                    bgcolor=CARD_BG,
                    border_radius=12,
                    padding=12,
                    margin=ft.margin.only(bottom=8),
                    shadow=ft.BoxShadow(blur_radius=5, color="#08000000"),
                    content=ft.Row(
                        [
                            ft.Container(
                                width=40,
                                height=40,
                                bgcolor="#FDECEA",
                                border_radius=8,
                                alignment=ft.alignment.center,
                                content=ft.Icon(ft.icons.PICTURE_AS_PDF, color="#E53935", size=22),
                            ),
                            ft.Column(
                                [
                                    ft.Text(item["name"], size=13, weight=ft.FontWeight.BOLD, color=DARK_NAVY),
                                    ft.Text(f"{item['size']} • {item['date']}", size=11, color=SUBTEXT_GRAY),
                                ],
                                spacing=2,
                                expand=True,
                            ),
                            ft.IconButton(
                                icon=ft.icons.MORE_VERT,
                                icon_color=SUBTEXT_GRAY,
                                on_click=lambda _, n=item["name"]: show_toast(f"الملف محفوظ: {n}"),
                            ),
                        ]
                    ),
                )
            )

        return ft.Container(
            expand=True,
            bgcolor="#F4F7FC",
            padding=ft.padding.symmetric(horizontal=18, vertical=14),
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Text("PDF Tools", size=20, weight=ft.FontWeight.BOLD, color=DARK_NAVY),
                            ft.Container(expand=True),
                            ft.IconButton(
                                icon=ft.icons.LOCK_OUTLINE,
                                icon_color=PRIMARY_BLUE,
                                on_click=lambda _: navigate_to("vault"),
                            ),
                        ]
                    ),
                    ft.Row(
                        [
                            tool_card("PDF to Text", ft.icons.DESCRIPTION_OUTLINED, PRIMARY_BLUE, "#EBF2FF", lambda _: trigger_pdf_tool("pdf_to_text")),
                            tool_card("Image to PDF", ft.icons.IMAGE_OUTLINED, PRIMARY_BLUE, "#EBF2FF", lambda _: trigger_pdf_tool("img_to_pdf", allow_multi=True, images_only=True)),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Container(height=8),
                    ft.Row(
                        [
                            tool_card("Compress PDF", ft.icons.COMPRESS, "#F57C00", "#FFF3E0", lambda _: trigger_pdf_tool("compress_pdf")),
                            tool_card("Merge PDF", ft.icons.MERGE_TYPE, "#00897B", "#E0F2F1", lambda _: trigger_pdf_tool("merge_pdf", allow_multi=True)),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Container(height=8),
                    ft.Row(
                        [
                            tool_card("Split PDF", ft.icons.CALL_SPLIT, "#7B1FA2", "#F3E5F5", lambda _: trigger_pdf_tool("split_pdf")),
                            tool_card("PDF to Image", ft.icons.COLLECTIONS_OUTLINED, "#E53935", "#FFEBEE", lambda _: show_toast("اختر ملف PDF لتحويل صفحاته إلى صور")),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Container(height=14),
                    ft.Text("Recent Files", size=16, weight=ft.FontWeight.BOLD, color=DARK_NAVY),
                    ft.Container(height=6),
                    ft.Column(recent_tiles, scroll=ft.ScrollMode.AUTO, expand=True),
                ],
                scroll=ft.ScrollMode.ADAPTIVE,
            ),
        )

    pin_input = ft.TextField(
        label="أدخل رمز الخزنة السري (الافتراضي 1234)",
        password=True,
        can_reveal_password=True,
        width=240,
        text_align=ft.TextAlign.CENTER,
        color="white",
        border_color=PRIMARY_BLUE,
    )

    def unlock_vault_action(e):
        if pin_input.value == state["vault_pin"]:
            state["vault_unlocked"] = True
            show_toast("تم فتح الخزنة الآمنة بنجاح!", "#18A957")
            navigate_to("vault")
        else:
            show_toast("رمز PIN غير صحيح! الرمز الافتراضي هو 1234", "#E53935")

    def build_vault_view() -> ft.Control:
        encrypted_files = [f for f in os.listdir(engine.vault_dir) if f.endswith(".enc")]
        return ft.Container(
            expand=True,
            bgcolor=DARK_SCANNER_BG,
            padding=24,
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.IconButton(
                                icon=ft.icons.ARROW_BACK,
                                icon_color="white",
                                on_click=lambda _: navigate_to("home"),
                            ),
                            ft.Text("Secure Vault", size=19, weight=ft.FontWeight.BOLD, color="white"),
                        ]
                    ),
                    ft.Container(height=20),
                    ft.Container(
                        width=150,
                        height=150,
                        border_radius=75,
                        bgcolor=PRIMARY_BLUE,
                        alignment=ft.alignment.center,
                        shadow=ft.BoxShadow(blur_radius=25, color="#661B6BF3"),
                        content=ft.Icon(
                            ft.icons.LOCK_OPEN_ROUNDED if state["vault_unlocked"] else ft.icons.LOCK_ROUNDED,
                            color="white",
                            size=75,
                        ),
                    ),
                    ft.Container(height=24),
                    ft.Text("Your files are safe", size=20, weight=ft.FontWeight.BOLD, color="white"),
                    ft.Text(
                        "Encrypt and protect your\ndocuments in the vault.",
                        size=13,
                        color="white70",
                        text_align=ft.TextAlign.CENTER,
                    ),
                    ft.Container(height=20),
                    pin_input if not state["vault_unlocked"] else ft.Container(),
                    ft.Container(height=12),
                    ft.ElevatedButton(
                        "Add File to Vault (SHA-256)" if state["vault_unlocked"] else "Unlock Vault",
                        bgcolor=PRIMARY_BLUE,
                        color="white",
                        width=240,
                        height=48,
                        on_click=(
                            lambda _: trigger_pdf_tool("vault_encrypt", images_only=False)
                            if state["vault_unlocked"]
                            else unlock_vault_action(None)
                        ),
                    ),
                    ft.Container(height=20),
                    ft.Column(
                        [
                            ft.Text(
                                f"الملفات المشفرة المحفوظة ({len(encrypted_files)}):",
                                color="white70",
                                size=13,
                            ),
                            *[
                                ft.ListTile(
                                    leading=ft.Icon(ft.icons.ENHANCED_ENCRYPTION, color="#26C281"),
                                    title=ft.Text(fname, color="white", size=13),
                                    subtitle=ft.Text("Encrypted in Secure Vault", color="white54", size=11),
                                )
                                for fname in encrypted_files
                            ],
                        ]
                        if state["vault_unlocked"]
                        else []
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                scroll=ft.ScrollMode.AUTO,
            ),
        )

    def feature_badge(title: str, icon_name: str, bg_color: str, target_tab: str) -> ft.Control:
        return ft.GestureDetector(
            on_tap=lambda _: navigate_to(target_tab),
            content=ft.Container(
                width=105,
                height=110,
                bgcolor=CARD_BG,
                border_radius=16,
                padding=10,
                shadow=ft.BoxShadow(blur_radius=10, color="#10000000"),
                content=ft.Column(
                    [
                        ft.Container(
                            width=48,
                            height=48,
                            bgcolor=bg_color,
                            border_radius=14,
                            alignment=ft.alignment.center,
                            content=ft.Icon(icon_name, color="white", size=26),
                        ),
                        ft.Text(
                            title,
                            size=11,
                            weight=ft.FontWeight.W_600,
                            color=DARK_NAVY,
                            text_align=ft.TextAlign.CENTER,
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=8,
                ),
            ),
        )

    def build_home_dashboard() -> ft.Control:
        history_items = engine.get_history()[:4]
        return ft.Container(
            expand=True,
            bgcolor="#F4F7FC",
            padding=18,
            content=ft.Column(
                [
                    ft.Container(
                        padding=ft.padding.only(top=10, bottom=14),
                        content=ft.Row(
                            [
                                ft.Column(
                                    [
                                        ft.Text("OCR SCANNER PRO", size=21, weight=ft.FontWeight.BOLD, color=DARK_NAVY),
                                        ft.Text("Scan. Extract. Translate. Store Securely.", size=12, color=SUBTEXT_GRAY),
                                    ],
                                    spacing=2,
                                ),
                                ft.Container(expand=True),
                                ft.IconButton(
                                    icon=ft.icons.QR_CODE_SCANNER,
                                    icon_color=PRIMARY_BLUE,
                                    on_click=lambda _: navigate_to("qr"),
                                ),
                            ]
                        ),
                    ),
                    ft.Row(
                        [
                            feature_badge("Document\nScanner", ft.icons.DOCUMENT_SCANNER, "#1B6BF3", "scanner"),
                            feature_badge("OCR Text\nExtraction", ft.icons.TEXT_FIELDS, "#26C281", "ocr"),
                            feature_badge("QR & Barcode\nScan", ft.icons.QR_CODE_2, "#7B2CBF", "qr"),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Container(height=10),
                    ft.Row(
                        [
                            feature_badge("PDF Tools\n& Converter", ft.icons.PICTURE_AS_PDF, "#F57C00", "files"),
                            feature_badge("Translate\nText", ft.icons.LANGUAGE, "#1976D2", "ocr"),
                            feature_badge("Secure\nStorage", ft.icons.LOCK, "#2E7D32", "vault"),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                    ft.Container(height=18),
                    ft.Row(
                        [
                            ft.Text("Recent Scans & PDFs", size=16, weight=ft.FontWeight.BOLD, color=DARK_NAVY),
                            ft.Container(expand=True),
                            ft.TextButton("See All", on_click=lambda _: navigate_to("files")),
                        ]
                    ),
                    ft.Column(
                        [
                            ft.Container(
                                bgcolor=CARD_BG,
                                border_radius=12,
                                padding=12,
                                margin=ft.margin.only(bottom=8),
                                content=ft.Row(
                                    [
                                        ft.Icon(ft.icons.PICTURE_AS_PDF, color="#E53935", size=28),
                                        ft.Column(
                                            [
                                                ft.Text(it["name"], size=13, weight=ft.FontWeight.BOLD, color=DARK_NAVY),
                                                ft.Text(f"{it['size']} • {it['date']}", size=11, color=SUBTEXT_GRAY),
                                            ],
                                            spacing=2,
                                            expand=True,
                                        ),
                                    ]
                                ),
                            )
                            for it in history_items
                        ]
                    ),
                ],
                scroll=ft.ScrollMode.AUTO,
            ),
        )

    body_container = ft.Container(expand=True)

    def nav_item(label: str, icon_name: str, tab_key: str) -> ft.Control:
        is_active = state["current_tab"] == tab_key
        color = PRIMARY_BLUE if is_active else SUBTEXT_GRAY
        return ft.GestureDetector(
            on_tap=lambda _: navigate_to(tab_key),
            content=ft.Column(
                [
                    ft.Icon(icon_name, color=color, size=23),
                    ft.Text(label, size=10, color=color, weight=ft.FontWeight.W_600 if is_active else ft.FontWeight.NORMAL),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=2,
            ),
        )

    def build_bottom_navigation() -> ft.Control:
        return ft.Container(
            height=74,
            bgcolor=CARD_BG,
            padding=ft.padding.symmetric(horizontal=16),
            shadow=ft.BoxShadow(blur_radius=15, color="#18000000"),
            content=ft.Row(
                [
                    nav_item("Home", ft.icons.HOME_OUTLINED, "home"),
                    nav_item("History", ft.icons.HISTORY, "ocr"),
                    ft.GestureDetector(
                        on_tap=lambda _: navigate_to("scanner"),
                        content=ft.Container(
                            width=54,
                            height=54,
                            bgcolor=PRIMARY_BLUE,
                            border_radius=27,
                            alignment=ft.alignment.center,
                            shadow=ft.BoxShadow(blur_radius=12, color="#661B6BF3"),
                            content=ft.Icon(ft.icons.DOCUMENT_SCANNER_OUTLINED, color="white", size=26),
                        ),
                    ),
                    nav_item("Files", ft.icons.FOLDER_OUTLINED, "files"),
                    nav_item("Vault", ft.icons.PERSON_OUTLINE, "vault"),
                ],
                alignment=ft.MainAxisAlignment.SPACE_AROUND,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
        )

    bottom_nav_holder = ft.Container()

    def navigate_to(tab_key: str):
        state["current_tab"] = tab_key
        if tab_key == "home":
            body_container.content = build_home_dashboard()
        elif tab_key == "scanner":
            body_container.content = build_scanner_view()
        elif tab_key == "ocr":
            body_container.content = build_ocr_view()
        elif tab_key == "qr":
            body_container.content = build_qr_view()
        elif tab_key == "files":
            body_container.content = build_pdf_tools_view()
        elif tab_key == "vault":
            body_container.content = build_vault_view()

        bottom_nav_holder.content = build_bottom_navigation()
        page.update()

    navigate_to("home")

    page.add(
        ft.Column(
            [
                body_container,
                bottom_nav_holder,
            ],
            expand=True,
            spacing=0,
        )
    )


if __name__ == "__main__":
    ft.app(target=main)
