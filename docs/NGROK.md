# Expose local backend with ngrok

Steps to run the backend locally and expose it via `ngrok` for demos.

Prerequisites
- Python 3.10+ and virtualenv
- `ngrok` CLI installed and authed (https://ngrok.com/)
- Project dependencies installed (see `backend/requirements.txt`)

Quick commands (PowerShell):

```powershell
# Create a venv and install deps
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

# set sovereign mode to demonstrate quarantine blocking (optional)
$env:DEPLOYMENT_REGION = "PK"

# start using the helper script (this will start uvicorn and then ngrok)
./scripts/run_with_ngrok.ps1
```

What you'll see
- Uvicorn will run the API at `http://127.0.0.1:8000`.
- `ngrok` will output a `Forwarding` URL (https://xxxx.ngrok.io) — use that URL to share with your teacher.

Notes
- If using Tika or OCR features, ensure Java and Tesseract are installed in the runtime.
- For a production-like demo (no external LLM calls), set `DEPLOYMENT_REGION=PK` to block LLM requests and quarantine payloads.
- If you prefer Linux/macOS, replace PowerShell commands with the equivalent shell commands and use `./scripts/run_with_ngrok.sh` (not provided).
