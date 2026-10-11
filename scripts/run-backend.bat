@echo off
REM Build and run the DNS server + REST API (from the project root)
cd /d "%~dp0..\backend"
call mvn -q package -DskipTests || exit /b 1
java -jar target\dns-filter.jar
