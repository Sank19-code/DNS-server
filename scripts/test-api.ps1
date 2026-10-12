# Smoke-tests the REST API (backend must be running). Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\test-api.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\test-api.ps1 -Token mysecret   # if DNSFILTER_API_TOKEN is set
param([string]$Base = "http://localhost:8081/api", [string]$Token = "")

$headers = @{}
if ($Token) { $headers["Authorization"] = "Bearer $Token" }

function Show($label, $value) {
    Write-Host "`n=== $label ===" -ForegroundColor Cyan
    $value | ConvertTo-Json -Depth 6 | Write-Host
}

Show "health"            (Invoke-RestMethod "$Base/health")
Show "resolve google.com" (Invoke-RestMethod "$Base/resolve?name=google.com")
Show "resolve again (should be CACHED)" (Invoke-RestMethod "$Base/resolve?name=google.com")
Show "resolve doubleclick (should be BLOCKED)" (Invoke-RestMethod "$Base/resolve?name=ad.doubleclick.net")
Show "block test-block.example.com" (Invoke-RestMethod -Method Post "$Base/blocklist" -Headers $headers `
    -ContentType "application/json" -Body '{"domain":"test-block.example.com","category":"custom"}')
Show "check sub.test-block.example.com" (Invoke-RestMethod "$Base/blocklist?domain=sub.test-block.example.com")
Show "unblock" (Invoke-RestMethod -Method Delete "$Base/blocklist?domain=test-block.example.com" -Headers $headers)
Show "top" (Invoke-RestMethod "$Base/top?n=5")
Show "stats" (Invoke-RestMethod "$Base/stats")
