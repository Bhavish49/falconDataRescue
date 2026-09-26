"""
FalconDataRescue Forensic Data Recovery CLI Tool
Usage:
    python recover_file.py <path_to_corrupted_file_or_folder> [output_dir]
"""

import os
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from app.services.recovery_jobs import recover_uploaded_file



def recover_single_file(file_path: Path, output_dir: Path):
    if not file_path.is_file():
        print(f"[!] File not found: {file_path}")
        return

    print(f"\n=======================================================")
    print(f"[*] Analyzing & Carving: {file_path.name} ({file_path.stat().st_size} bytes)")
    print(f"=======================================================")

    data = file_path.read_bytes()
    repaired_bytes, report = recover_uploaded_file(file_path.name, data)

    print(f"[+] Status:                {report.get('status', report.get('integrity_status', 'UNKNOWN'))}")
    print(f"[+] Confidence:            {report.get('confidence', report.get('integrity_score', 0))}%")
    print(f"[+] Category Identified:   {report.get('category', 'Unknown')}")
    print(f"[+] Priority Level:        {report.get('priority', 'Unknown')}")
    print(f"[+] Fragments Extracted:   {report.get('fragments_recovered_count', 0)}")
    if "entropy_before" in report:
        print(f"[+] Entropy (Before/After): {report['entropy_before']} / {report.get('entropy_after')}")

    if report.get("entities"):
        print(f"[+] Discovered Entities / PII:")
        for ent in report["entities"]:
            print(f"    - {ent['type']}: {', '.join(ent['values'])}")

    print(f"[+] Realism Assessment:")
    print(f"    {report.get('realism_assessment', 'No realism assessment available.')}")

    print(f"[+] Repair Actions Applied:")
    for act in report.get("repair_actions", report.get("operations", [])):
        print(f"    - {act}")
    for warning in report.get("warnings", []):
        print(f"[!] Warning: {warning}")

    # Output files
    output_dir.mkdir(parents=True, exist_ok=True)
    if report.get("status") != "FAILED_RECOVERY":
        out_file = output_dir / f"restored_{file_path.name}"
        out_file.write_bytes(repaired_bytes)
        print(f"\n[>>>] Recovered/Reconstructed File Saved: {out_file.resolve()}")
    else:
        print("\n[!!!] No safe output was created because recovery failed validation.")

    # Save Markdown extracted content
    if report.get("preview_markdown"):
        md_file = output_dir / f"{file_path.stem}_recovered_content.md"
        md_file.write_text(report["preview_markdown"], encoding="utf-8")
        print(f"[>>>] Extracted Notes/Text: {md_file.resolve()}")

    import json
    report_file = output_dir / f"{file_path.stem}_recovery_report.json"
    report_file.write_text(json.dumps(report, indent=2, ensure_ascii=True, default=str), encoding="utf-8")
    print(f"[>>>] Recovery Report: {report_file.resolve()}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python recover_file.py <file_or_directory_path> [output_directory]")
        sys.exit(1)

    target_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("recovered_output")

    if target_path.is_file():
        recover_single_file(target_path, output_dir)
    elif target_path.is_dir():
        for f in target_path.iterdir():
            if f.is_file():
                recover_single_file(f, output_dir)
    else:
        print(f"Target path does not exist: {target_path}")


if __name__ == "__main__":
    main()
