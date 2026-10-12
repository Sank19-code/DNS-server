@echo off
REM Builds the dashboard and the server jar, then runs everything as ONE process:
REM   dashboard -> http://localhost:8081      DNS -> UDP 5300
cd /d "%~dp0..\frontend"
call npm ci || exit /b 1
call npm run build || exit /b 1
cd /d "%~dp0..\backend"
call mvn -q package -DskipTests || exit /b 1
java -jar target\dns-filter.jar
