import os
from pathlib import Path
from PIL import Image, ImageDraw

out_dir = Path("c:/MCE/test_corrupted_samples")
out_dir.mkdir(parents=True, exist_ok=True)

# 1. Corrupted PDF (Missing %PDF- header, truncated EOF)
pdf_content = (
    b"CORRUPTED_PREFIX_GARBAGE\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Length 220 >>\nstream\n"
    b"BT /F1 14 Tf (NON-DISCLOSURE AND SERVICE LEVEL AGREEMENT) Tj ET\n"
    b"BT /F1 11 Tf (The Parties agree to maintain strict confidentiality of proprietary data.) Tj ET\n"
    b"BT /F1 11 Tf (The Recipient shall not disclose protected information to unauthorized persons.) Tj ET\n"
    b"BT /F1 10 Tf (Executed by: legal@enterprise-corp.com) Tj ET\n"
    b"endstream\nendobj\n"
)
(out_dir / "corrupted_contract.pdf").write_bytes(pdf_content)

# 2. Corrupted JPEG (Glitched / truncated bytes with missing JFIF header)
jpg_content = (
    b"TRUNCATED_BAD_HEADER"
    + b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    + (b"\x80\x20\xff\x55\xaa\x33" * 50)
)
(out_dir / "damaged_photo.jpg").write_bytes(jpg_content)

# 3. Corrupted Excel XLSX (Stripped PK 03 04 zip header)
xlsx_content = (
    b"CORRUPT_ARCHIVE_BYTES"
    + b"[Content_Types].xml\x00\x00xl/worksheets/sheet1.xml\x00\x00"
    + b"<sheetData><row><c r='A1'><v>1500000</v></c></row></sheetData>"
)
(out_dir / "broken_spreadsheet.xlsx").write_bytes(xlsx_content)

# 4. Valid synthetic image pair for safe recovery testing.
# The reference is never modified; the damaged copy has a harmless prefix and
# missing JPEG EOI marker, so the image pipeline can prove a real repair.
width, height = 640, 360
scene = Image.new("RGB", (width, height), (92, 164, 218))
draw = ImageDraw.Draw(scene)
draw.rectangle((0, 220, width, height), fill=(45, 48, 52))
draw.ellipse((70, 45, 210, 175), fill=(250, 194, 86))
draw.polygon([(0, 220), (width, 205), (width, 235), (0, 250)], fill=(116, 120, 126))
# A simple, deterministic car silhouette for recovery tests—not a real photo.
draw.rounded_rectangle((170, 185, 505, 270), radius=22, fill=(205, 35, 45), outline=(35, 20, 24), width=5)
draw.polygon([(245, 185), (292, 135), (402, 135), (454, 185)], fill=(175, 25, 35), outline=(35, 20, 24))
draw.polygon([(285, 146), (307, 146), (319, 178), (268, 178)], fill=(105, 185, 220), outline=(35, 20, 24))
draw.polygon([(326, 146), (394, 146), (425, 178), (332, 178)], fill=(105, 185, 220), outline=(35, 20, 24))
draw.ellipse((205, 238, 265, 298), fill=(20, 22, 25), outline=(150, 155, 160), width=6)
draw.ellipse((414, 238, 474, 298), fill=(20, 22, 25), outline=(150, 155, 160), width=6)
draw.rectangle((477, 207, 496, 222), fill=(255, 224, 150))
draw.rectangle((181, 207, 198, 222), fill=(255, 80, 60))

reference_path = out_dir / "synthetic_car_reference.jpg"
damaged_path = out_dir / "synthetic_car_damaged.jpg"
scene.save(reference_path, format="JPEG", quality=92)
reference_bytes = reference_path.read_bytes()
damaged_path.write_bytes(b"SAFE_TEST_PREFIX\x00\x01" + reference_bytes[:-2])

# Additional controlled fixtures for batch testing. These are synthetic and
# intentionally labeled; they are not claims about recovery of arbitrary data.
(out_dir / "recoverable_missing_eoi.jpg").write_bytes(reference_bytes[:-2])
(out_dir / "recoverable_truncated_scan.jpg").write_bytes(reference_bytes[:-1200])
(out_dir / "recoverable_prefix_only.jpg").write_bytes(b"SAFE_TEST_PREFIX\x00\x01" + reference_bytes)

pixel_corrupted = scene.copy()
pixel_draw = ImageDraw.Draw(pixel_corrupted)
pixel_draw.rectangle((0, 118, width, 154), fill=(20, 235, 35))
pixel_draw.rectangle((0, 205, width, 252), fill=(225, 15, 180))
pixel_draw.line((0, 168, width, 168), fill=(0, 0, 0), width=8)
pixel_corrupted.save(out_dir / "pixel_corrupted_valid_jpeg.jpg", format="JPEG", quality=92)

black = Image.new("RGB", (width, height), (0, 0, 0))
black.save(out_dir / "uniform_black_valid_jpeg.jpg", format="JPEG", quality=92)

(out_dir / "invalid_jpeg_bytes.jpg").write_bytes(
    b"NOT_A_REAL_JPEG_FILE\nThis fixture must be rejected by the image decoder."
)

manifest = {
    "synthetic_car_damaged.jpg": "Recoverable prefix plus missing JPEG EOI",
    "recoverable_missing_eoi.jpg": "Recoverable missing JPEG EOI",
    "recoverable_truncated_scan.jpg": "Truncated JPEG scan; may produce partial output",
    "recoverable_prefix_only.jpg": "Recoverable JPEG with harmless leading bytes",
    "pixel_corrupted_valid_jpeg.jpg": "Valid JPEG with intentionally damaged pixels; exact pixels are unavailable",
    "uniform_black_valid_jpeg.jpg": "Valid but visually uniform image; must not be called a scene recovery",
    "invalid_jpeg_bytes.jpg": "Invalid JPEG bytes; must be rejected",
}
(out_dir / "README.txt").write_text(
    "Controlled FalconDataRescue image-recovery fixtures\n\n"
    + "\n".join(f"{name}: {description}" for name, description in manifest.items())
    + "\n\nUpload several files together to test batch behavior.\n",
    encoding="utf-8",
)

print(f"Sample corrupted files created at: {out_dir.resolve()}")
print(f"Synthetic clean reference: {reference_path.resolve()}")
print(f"Synthetic damaged input: {damaged_path.resolve()}")
print(f"Batch fixture count: {len(manifest)}")
