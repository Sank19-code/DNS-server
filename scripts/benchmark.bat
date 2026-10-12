@echo off
REM Load-tests the running DNS server (start scripts\run-backend.bat first, in another window).
REM Extra options are passed through, e.g.:  scripts\benchmark.bat --queries 50000 --concurrency 32
cd /d "%~dp0..\backend"
if not exist target\dns-filter.jar call mvn -q package -DskipTests || exit /b 1
java -cp target\dns-filter.jar com.sankar.dnsfilter.bench.Benchmark %*
