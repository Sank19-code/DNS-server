# Fires a few test queries at the local DNS server (default dev port 5300).
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\test-dns.ps1
param([int]$Port = 5300)

$domains = @("google.com", "github.com", "doubleclick.net", "ad.doubleclick.net", "google-analytics.com", "google.com")
foreach ($d in $domains) {
    Write-Host "`n=== $d ===" -ForegroundColor Cyan
    $t = Measure-Command { nslookup "-port=$Port" $d 127.0.0.1 | Out-Host }
    Write-Host ("took {0:N1} ms" -f $t.TotalMilliseconds) -ForegroundColor DarkGray
}
# The second google.com should be noticeably faster (cache hit).
