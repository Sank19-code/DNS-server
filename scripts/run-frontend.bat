@echo off
REM Start the React dashboard on http://localhost:5173
cd /d "%~dp0..\frontend"
if not exist node_modules call npm install
npm run dev
