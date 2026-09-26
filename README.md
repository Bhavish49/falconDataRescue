# FalconDataRescue — AI Data Recovery & Forensic Reconstruction Studio

FalconDataRescue is a forensic data-recovery platform that identifies, reconstructs, classifies, and
prioritizes recoverable information from damaged, deleted, or partially corrupted storage.
It pairs a deterministic recovery engine with an evidence-first investigator UI: every result
carries a validation score, and nothing is ever "recovered" that cannot be proven from the
source bytes.

> **Design principle:** *Analyze first. Recover only what can be validated.*
> Source evidence is always treated as read-only.

---

## Features

- **Corrupted file & folder recovery** — repair broken headers, trailers, and container
  structure for PDF, JPEG, PNG, DOCX, XLSX, ZIP, text, and binary evidence.
- **Deleted-file recovery from live NTFS drives** — scans the volume's `$MFT` metadata for
  records marked deleted (outside the Recycle Bin) and reassembles their data runs. No
  Recycle Bin involvement.
- **Forensic disk-image carving** — signature-carve recoverable files from raw bitstream
  images (`.dd`, `.raw`, `.img`, `.e01`, `.vmdk`, `.bin`).
- **Fragment analysis & relationship graphing** — visualize how carved fragments relate to
  the root structure, topic clusters, and extracted symbols.
- **Integrity & realism assessment** — Shannon-entropy diagnostics, anomaly detection, and a
  per-file confidence score with a written investigator assessment.
- **AI-assisted review** — optional LLM/ML enrichment for classification and triage
  (heuristic fallback when no model/API key is configured).
- **Investigator workspace** — per-file inspector with extracted text, relationship graph,
  integrity assessment, and a raw hex sector map; single-file and bundle (`.zip`) downloads.

---

## Architecture

```
                       INPUT
                         |
                         v
                Disk / Storage Image
                         |
                         v
                Evidence Acquisition
                         |
                         v
               File / Fragment Scanner
                         |
                         v
                Fragment Extraction
                         |
              +----------+----------+
              v                     v
        Metadata Analysis     Content Analysis
              +----------+----------+
                         v
               AI Fragment Classifier
                         |
                         v
               Relationship Analysis
                         |
                         v
                   Reconstruction
                         |
                         v
                 Integrity Analysis
                         |
                         v
                 Confidence Scoring
                         |
              +----------+----------+
              v                     v
        Recovered Files       Evidence Graph
              +----------+----------+
                         v
                  Investigator UI
```

The corrupted-files path executes this pipeline end-to-end in
`backend/app/services/forensic_recovery_engine.py` (`execute_full_forensic_recovery`).
The disk-image and live-drive paths are dedicated acquisition routes that perform
signature carving / `$MFT` run-list reassembly and feed the same investigator UI.

### Backend modules

| Module | Responsibility |
| --- | --- |
| `services/forensic_recovery_engine.py` | Core pipeline: entropy, carving, classification, graph, reconstruction, integrity |
| `services/repair_service.py` | Corruption diagnostics and repair orchestration |
| `services/recovery_jobs.py` | Async recovery jobs, deterministic validation, AI review hook |
| `services/image_recovery.py` / `image_scanner.py` | Image format detection, marker/chunk validation, recovery |
| `services/ntfs_deleted_recovery.py` | Raw-volume `$MFT` parsing and deleted-record reassembly |
| `services/pytsk3_recovery.py` | Pure-Python signature carving for disk images |
| `services/ai_assisted_recovery.py` / `hf_service.py` | Optional ML/LLM enrichment |
| `services/evidence_service.py` / `scan_service.py` | Evidence and scan persistence |
| `api/routes/*` | REST endpoints (see API reference) |

---

## Project structure

```
.
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── api/              # Routers (repair, forensics, deleted, ai, evidence, scans, artifacts, health)
│   │   ├── services/         # Recovery engines and analysis pipelines
│   │   ├── models/           # SQLAlchemy models
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── db/               # Session/engine setup
│   │   ├── main.py           # App entrypoint (serves frontend at /)
│   │   └── config.py         # pydantic-settings configuration
│   ├── alembic/              # Database migrations
│   └── requirements.txt
├── frontend/                 # Vanilla HTML/CSS/JS single-page app
│   ├── index.html            # Landing page + recovery workspace + inspector modal
│   ├── styles.css            # Design system (landing + workspace themes)
│   ├── app.js                # Client logic, API wiring, graph/hex rendering
│   └── accets/               # Landing artwork
├── scripts/
│   └── generate_samples.py   # Regenerates controlled-damage test fixtures
├── tests/
│   └── test_ntfs_parser.py   # Synthetic-NTFS unit test for $MFT deleted recovery
├── test_corrupted_samples/   # Controlled-damage fixtures used by the demo buttons
├── recover_file.py           # Command-line recovery tool
├── start_server.bat          # Self-elevating server launcher (Windows)
└── .env.example              # Configuration template
```

---

## Requirements

- **Python 3.10+** (developed on 3.14)
- **Windows** for live-drive `$MFT` scans (raw volume access requires Administrator)
- See `backend/requirements.txt` for the full dependency list

Optional:
- A Hugging Face / OpenAI API key for AI-assisted review (the app degrades gracefully to
  heuristic classification without one).
- `pytsk3` for native disk-image parsing (a pure-Python carver is used otherwise).

---

## Installation

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows

# 2. Install backend dependencies
pip install -r backend/requirements.txt

# 3. (Optional) configure settings
copy .env.example backend\.env
#    edit backend\.env as needed; defaults run out-of-the-box with SQLite
```

---

## Running

### Web application (recommended)

```bash
start_server.bat
```

The launcher **self-elevates to Administrator** (one UAC prompt) so live-drive deleted-file
scans have raw disk access, then serves:

- **UI:** <http://127.0.0.1:8010/>
- **API docs:** <http://127.0.0.1:8010/docs>

Manual equivalent:

```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8010
```

> **Note:** If the server is not running as Administrator, live-drive scans return a clear
> `403` explaining that raw access was denied. Disk-image and corrupted-file modes do not
> require elevation.

### Command-line recovery

Run these commands from the repository root. On Windows, use `py` instead of
`python` if that is how Python is installed.

```bash
# Create and activate a virtual environment (recommended)
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate

# Install the backend dependencies
python -m pip install -r backend/requirements.txt

# Recover one damaged file into recovered_output/
python recover_file.py path/to/damaged_file.pdf

# Recover every file directly inside a folder into a custom output folder
python recover_file.py path/to/damaged_files recovered_output
```

For example, on Windows:

```powershell
python recover_file.py "C:\Users\You\Desktop\damaged.jpg" "C:\Users\You\Desktop\recovered"
```

The CLI writes a `restored_<filename>` payload when validation succeeds, plus a
`*_recovery_report.json` report and, when text was extracted, a
`*_recovered_content.md` file. A `FAILED_RECOVERY` result does not create a
downloadable payload. The CLI handles uploaded/corrupted files and folders; use
the web UI or `/api/deleted/scan-drive` for deleted files on a live NTFS drive.

---

## Using the web UI

### Netlify deployment

This repository includes `netlify.toml`; Netlify should use `frontend` as the
publish directory automatically. If configuring the site manually, set:

```text
Base directory: (leave blank)
Build command: (leave blank)
Publish directory: frontend
```

Netlify hosts the static frontend only. The FastAPI backend must be deployed
separately, and the frontend API base URL must point to that public backend
instead of `127.0.0.1:8010`. Before deploying, edit the inline setting in
`frontend/index.html`, for example:

```html
<script>window.FALCON_API_BASE_URL = "https://api.example.com";</script>
```

1. **Landing page** — full-bleed artwork hero with navigation (Home / About / Features /
   Contact) and a **Recover Now** button that opens the workspace.
2. **Choose a recovery mode:**
   - *Corrupted Files & Folders* — drag-and-drop or select files/folders.
   - *Deleted Files from Disk Image* — upload a `.dd` / `.raw` / `.img` / `.e01` image.
   - *Deleted Files from Drive (NTFS)* — pick a drive and scan its `$MFT`.
3. **Review results** — classification, integrity/damage scores, and fragment counts per file.
4. **Start Recovery Job** — reconstruct and validate; restored artifacts appear with
   per-file and bundle downloads.
5. **Inspect** — open any file for extracted text, the fragment relationship graph, the
   integrity & realism assessment, and the raw hex sector map.

Demo fixtures are available via the **"Start with a sample"** pills (regenerate them with
`python scripts/generate_samples.py`).

---

## API reference

All endpoints are prefixed with `/api`. Interactive docs at `/docs`.

| Prefix | Purpose |
| --- | --- |
| `/api/health` | Liveness and version |
| `/api/repair` | Upload, diagnose, queue jobs, process/repair, download restored files |
| `/api/forensics` | Disk-image carving and carved-artifact download |
| `/api/deleted` | Drive listing, NTFS deleted scan, deleted-artifact download |
| `/api/ai` | AI-assisted review endpoints |
| `/api/evidence` | Evidence records |
| `/api/scans` | Scan records |
| `/api/artifacts` | Recovered artifact records |

Key endpoints:

- `POST /api/repair/diagnose` — pre-analysis of uploaded files
- `POST /api/repair/jobs` / `GET /api/repair/jobs/{id}` — pollable recovery jobs
- `POST /api/repair/process` — full repair + bundle creation
- `POST /api/forensics/carve-image` — carve a disk image
- `GET  /api/deleted/drives` — list scannable drives
- `POST /api/deleted/scan-drive` — `$MFT` deleted-file scan (Administrator required)

---

## Testing

```bash
# Synthetic-NTFS unit test (no real disk access required)
python tests/test_ntfs_parser.py

# Regenerate controlled-damage fixtures
python scripts/generate_samples.py
```

`tests/test_ntfs_parser.py` builds an in-memory NTFS volume with deleted non-resident and
resident records and asserts exact payload reassembly.

---

## Configuration

Settings load from environment variables / `backend/.env` (see `.env.example`).
For production, copy `.env.example` to `.env`, set a strong `SECRET_KEY`, set
`APP_ENV=production`, keep `DEBUG=false`, and replace `CORS_ORIGINS` with the
exact frontend origin(s).
Notable values:

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite+aiosqlite:///./mce_forensics.db` | Async DB URL |
| `MAX_UPLOAD_SIZE_MB` | `512` | Upload size cap |
| `CORS_ORIGINS` | localhost origins | Comma-separated allowed browser origins |
| `AI_VISUAL_ENABLED` | `true` | Enable optional visual-similarity stage |
| `AI_ALLOW_MODEL_DOWNLOAD` | `false` | Permit downloading model weights |
| `HUGGINGFACE_API_KEY` / `OPENAI_API_KEY` | *(empty)* | Enable AI-assisted review |

The app runs fully offline with SQLite and heuristic analysis when no keys are provided.

---

## Security & forensic integrity

- Source evidence is **never modified**; all recovery operates on in-memory copies.
- Upload filenames are sanitized; download headers and ZIP entries are path-traversal safe.
- Recovery is **honest by design**: outputs are labeled `VALIDATED_REPAIR`,
  `PARTIAL_RECOVERY`, `ORIGINAL_VALID`, or `FAILED_RECOVERY` with an explicit confidence
  score and warnings when the original byte stream was not fully proven intact.
- Live-drive access requires Administrator and is gated behind an explicit user action.

## Container deployment

The container deployment is intended for uploaded files and disk images. It does
not provide direct access to a host's live Windows drives; use the native
Administrator launcher for `/api/deleted/scan-drive`.

```bash
copy .env.example .env
# edit .env: SECRET_KEY, CORS_ORIGINS, database/storage settings
docker compose -f docker-compose.production.yml up --build -d
```

The production container listens on port `8010`. Configure TLS and authentication
at the hosting platform or reverse proxy before exposing it publicly. Recovery
jobs and in-memory download indexes are process-local in this release, so use a
single application replica and plan a persistent job/artifact backend before
horizontal scaling.

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `Raw access to C: was denied` | Server not elevated. Relaunch via `start_server.bat` and accept the UAC prompt. |
| Port 8010 already in use | Stop the previous server instance, or change `--port`. |
| AI review returns heuristic results | No API key configured, or `AI_ALLOW_MODEL_DOWNLOAD=false`. Expected offline behavior. |
| Demo sample buttons 404 | Fixtures missing; run `python scripts/generate_samples.py`. |
