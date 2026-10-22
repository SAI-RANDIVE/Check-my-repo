#!/usr/bin/env sh
# CodeSentinel: one-step local setup and launch (Linux / macOS).
set -eu
cd "$(dirname "$0")"

command -v git >/dev/null 2>&1 || { echo "git is required and must be on PATH."; exit 1; }
PY=${PYTHON:-python3}

if [ ! -x .venv/bin/python ]; then
  echo "Creating virtual environment..."
  "$PY" -m venv .venv
fi
. .venv/bin/activate

echo "Installing dependencies..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

[ -f .env ] || cp .env.example .env

echo "Generating demo repositories..."
python demo/make_demo_repo.py

echo
echo "CodeSentinel is starting on http://localhost:8000  (Ctrl+C to stop)"
exec python -m uvicorn app.main:app --reload --port 8000
