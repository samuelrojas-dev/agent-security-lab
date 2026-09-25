@echo off
cd /d "%~dp0"
call .venv\Scripts\activate
python -m src.evaluate --model gemini
echo.
echo Listo. Revisa results\gemini\report.md si ya termino.
pause
