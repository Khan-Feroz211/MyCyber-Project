<#
Simple helper to run the backend and expose it via ngrok on Windows PowerShell.

Prerequisites:
- Install Python deps in a virtualenv (see README).
- Install ngrok and sign in: https://ngrok.com/

Usage:
1. Open PowerShell in project root.
2. `./scripts/run_with_ngrok.ps1`

This script launches Uvicorn on port 8000 and then starts `ngrok http 8000`.
#>

$ErrorActionPreference = 'Stop'

$venv = Join-Path $PSScriptRoot '..\.venv\Scripts\Activate.ps1'
if (Test-Path $venv) {
    Write-Host "Activating virtualenv..."
    & $venv
} else {
    Write-Host "Virtualenv not found at .venv. Create one and install requirements first." -ForegroundColor Yellow
}

$port = 8000

Write-Host "Starting Uvicorn on port $port..."
$uvicorn = Start-Process -FilePath "python" -ArgumentList "-m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port $port" -NoNewWindow -PassThru
Start-Sleep -Seconds 2

if ($uvicorn -and -not $uvicorn.HasExited) {
    Write-Host "Uvicorn started (PID $($uvicorn.Id)). Now starting ngrok..."
    # Start ngrok - ensure ngrok is on PATH
    Start-Process -FilePath "ngrok" -ArgumentList "http $port" -NoNewWindow
    Write-Host "ngrok should open and display a forwarding URL. Press Ctrl-C to stop both processes." -ForegroundColor Green
} else {
    Write-Host "Failed to start Uvicorn. Check logs." -ForegroundColor Red
}
