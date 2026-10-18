@echo off
set "PATH=%LOCALAPPDATA%\Programs\Python\Python312\Scripts;%LOCALAPPDATA%\Programs\Python\Python312;%PATH%"
python "%~dp0tamper_demo.py" %*
