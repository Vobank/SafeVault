@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Сейф
echo === Сейф: подготовка ===

REM Создаём виртуальное окружение при первом запуске
if not exist ".venv\Scripts\python.exe" (
    echo Первый запуск: создаю окружение и ставлю библиотеку...
    python -m venv .venv
    ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
    ".venv\Scripts\python.exe" -m pip install cryptography
)

echo Запускаю Сейф...
start "" ".venv\Scripts\pythonw.exe" "sejf.py"
