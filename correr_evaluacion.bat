@echo off
cd /d "%~dp0"
call .venv\Scripts\activate
python -m src.evaluate
echo.
echo Listo. Revisa results\results.md si ya termino.
pause
