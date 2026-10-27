@echo off
rem CheckMyWeb launcher for Windows: runs checkmyweb.pyz with the Python launcher (py) or python.
setlocal
where py >nul 2>nul && goto run_py
where python >nul 2>nul && goto run_python
echo Python 3.11 or later is required: https://www.python.org/downloads/
exit /b 9009

:run_py
py -3 "%~dp0checkmyweb.pyz" %*
exit /b %errorlevel%

:run_python
python "%~dp0checkmyweb.pyz" %*
exit /b %errorlevel%
