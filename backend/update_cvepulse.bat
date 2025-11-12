@echo off
setlocal
cd /d %~dp0
call venv\Scripts\activate
python scheduler.py
:: if you open index.html directly or serve static files, keep a local copy:
copy data\trending_cves.json ..\frontend\trending_cves.json /Y
endlocal
