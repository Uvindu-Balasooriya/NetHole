@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt
python -m PyInstaller --onefile --noconsole --uac-admin --icon nethole.ico --name NetHole nethole.py
echo.
echo Done. Your app is dist\NetHole.exe
pause
