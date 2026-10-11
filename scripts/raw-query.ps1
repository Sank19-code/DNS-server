# Sends ONE raw DNS query over UDP to the local server, bypassing nslookup.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\raw-query.ps1 google.com
param([string]$Name = "google.com", [int]$Port = 5300, [string]$Server = "127.0.0.1")

$q = [System.Collections.Generic.List[byte]]::new()
$q.AddRange([byte[]](0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00))
foreach ($label in $Name.Split('.')) {
    $q.Add([byte]$label.Length)
    $q.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
}
$q.AddRange([byte[]](0x00, 0x00,0x01, 0x00,0x01))   # end of name, type A, class IN

$udp = New-Object System.Net.Sockets.UdpClient
$udp.Client.ReceiveTimeout = 5000
$bytes = $q.ToArray()
[void]$udp.Send($bytes, $bytes.Length, $Server, $Port)
Write-Host "Sent $($bytes.Length) bytes to ${Server}:$Port, waiting up to 5 s..."
try {
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $r = $udp.Receive([ref]$ep)
    $rcode = $r[3] -band 0x0F
    $an = ($r[6] -shl 8) + $r[7]
    Write-Host "Got $($r.Length) bytes back: rcode=$rcode answers=$an" -ForegroundColor Green
    if ($an -gt 0 -and $r[$r.Length-6] -eq 0 -and $r[$r.Length-5] -eq 4) {
        Write-Host ("Last A record: {0}.{1}.{2}.{3}" -f $r[-4],$r[-3],$r[-2],$r[-1])
    }
} catch {
    Write-Host "No reply: $($_.Exception.Message)" -ForegroundColor Red
} finally { $udp.Close() }
