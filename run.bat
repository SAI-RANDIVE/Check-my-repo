@echo off
REM CodeSentinel: one-step local setup and launch (Windows).
setlocal
cd /d "%~dp0"

where git >nul 2>nul || (echo git is required and must be on PATH. & exit /b 1)

if not exist .venv\Scripts\python.exe (
    echo Creating virtual environment...
    python -m venv .venv || (echo Python 3.11+ is required. & exit /b 1)
)
call .venv\Scripts\activate.bat

echo Installing dependencies...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt || exit /b 1

if not exist .env copy .env.example .env >nul

echo Generating demo repositories...
python demo\make_demo_repo.py || exit /b 1

echo.
echo CodeSentinel is starting on http://localhost:8000  (Ctrl+C to stop)
python -m uvicorn app.main:app --reload --port 8000
