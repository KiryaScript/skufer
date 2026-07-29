@echo off
setlocal enableextensions
cd /d "%~dp0"

echo Installing dependencies...
python -m pip install --upgrade pip
pip install colorama tqdm

echo Running SKUFER...
timeout /t 2 /nobreak

python main_start.py

@pause
