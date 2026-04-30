"""
数字水印模块

支持文本、图片、PDF 三种格式的外发水印添加。
"""

from __future__ import annotations

import io
import os
import time
from pathlib import Path
from typing import Optional

from PIL import Image, ImageDraw, ImageFont, ImageEnhance


def _default_watermark_text(user_id: str) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    return f"CONFIDENTIAL | User:{user_id} | {ts}"


def add_text_watermark(file_path: str, output_path: str, user_id: str, extra: Optional[str] = None) -> None:
    """在文本文件头部添加水印标记。"""
    text = _default_watermark_text(user_id)
    if extra:
        text += f" | {extra}"
    marker = f"[{text}]\n{'=' * 60}\n"
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(marker + content)


def add_image_watermark(file_path: str, output_path: str, user_id: str, extra: Optional[str] = None) -> None:
    """在图片上叠加半透明文字水印（四角+中心）。"""
    text = _default_watermark_text(user_id)
    if extra:
        text += f"\n{extra}"
    img = Image.open(file_path).convert("RGBA")
    overlay = Image.new("RGBA", img.size, (255, 255, 255, 0))
    draw = ImageDraw.Draw(overlay)

    # 尝试获取字体，回退到默认
    try:
        font = ImageFont.truetype("arial.ttf", max(16, img.size[1] // 40))
    except Exception:
        font = ImageFont.load_default()

    # 在四个角和中心添加水印
    positions = [
        (10, 10),
        (img.size[0] // 2, img.size[1] // 2),
        (img.size[0] - 10, img.size[1] - 10),
        (10, img.size[1] - 10),
        (img.size[0] - 10, 10),
    ]
    for pos in positions:
        draw.text(pos, text, font=font, fill=(255, 0, 0, 90), anchor="mm" if pos == positions[1] else "la")

    watermarked = Image.alpha_composite(img, overlay)
    if watermarked.mode == "RGBA":
        # 若原图不含透明通道，转回 RGB
        bg = Image.new("RGB", watermarked.size, (255, 255, 255))
        bg.paste(watermarked, mask=watermarked.split()[-1])
        watermarked = bg
    watermarked.save(output_path)


def add_pdf_watermark(file_path: str, output_path: str, user_id: str, extra: Optional[str] = None) -> None:
    """在 PDF 每页叠加水印文本。"""
    try:
        import pikepdf
        from reportlab.pdfgen import canvas
        from reportlab.lib.colors import Color
    except ImportError:
        # 降级为仅复制文件并旁路提示
        import shutil
        shutil.copy2(file_path, output_path)
        return

    text = _default_watermark_text(user_id)
    if extra:
        text += f" | {extra}"

    def build_overlay(width: float, height: float):
        packet = io.BytesIO()
        c = canvas.Canvas(packet, pagesize=(width, height))
        c.saveState()
        try:
            c.setFillColor(Color(0.85, 0.05, 0.05, alpha=0.18))
        except TypeError:
            c.setFillColorRGB(0.85, 0.05, 0.05)
        c.setFont("Helvetica-Bold", max(18, min(width, height) / 18))
        c.translate(width / 2, height / 2)
        c.rotate(35)
        c.drawCentredString(0, 0, text)
        c.restoreState()
        c.setFont("Helvetica", 9)
        c.setFillColorRGB(0.5, 0.0, 0.0)
        c.drawString(36, 24, text)
        c.save()
        packet.seek(0)
        return pikepdf.Pdf.open(packet)

    with pikepdf.open(file_path) as pdf:
        overlays = []
        for page in pdf.pages:
            box = page.MediaBox
            width = float(box[2]) - float(box[0])
            height = float(box[3]) - float(box[1])
            overlay_pdf = build_overlay(width, height)
            overlays.append(overlay_pdf)
            try:
                page.add_overlay(overlay_pdf.pages[0])
            except Exception:
                annot = pikepdf.Dictionary(
                    Type=pikepdf.Name("/Annot"),
                    Subtype=pikepdf.Name("/FreeText"),
                    Rect=[50, 50, min(500, width - 20), 100],
                    Contents=text,
                    DA="/Helvetica 10 Tf 0.5 0 0 rg",
                    F=4,
                )
                if "/Annots" not in page:
                    page.Annots = pikepdf.Array()
                page.Annots.append(annot)
        pdf.save(output_path)


def apply_watermark(file_path: str, output_path: str, user_id: str, extra: Optional[str] = None) -> None:
    """根据文件类型自动选择水印方式。"""
    suffix = Path(file_path).suffix.lower()
    image_exts = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".webp"}
    if suffix == ".txt" or suffix == ".csv" or suffix == ".log":
        add_text_watermark(file_path, output_path, user_id, extra)
    elif suffix in image_exts:
        add_image_watermark(file_path, output_path, user_id, extra)
    elif suffix == ".pdf":
        add_pdf_watermark(file_path, output_path, user_id, extra)
    else:
        # 对于其他格式，生成同目录下的 .watermark.txt 旁注文件
        import shutil
        shutil.copy2(file_path, output_path)
        sidecar = str(Path(output_path).with_suffix(".watermark.txt"))
        with open(sidecar, "w", encoding="utf-8") as f:
            f.write(_default_watermark_text(user_id))
