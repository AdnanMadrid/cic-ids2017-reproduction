<#
================================================================
 benign_windows.ps1  --  B-Profile-style benign traffic generator
 Run on Windows benign clients: 192.168.10.5, .8, .9, .14, .15

 Same behaviour as the Linux version: several concurrent "users",
 each looping HTTP / DNS (and SSH/FTP where available) to the
 internal services host (.51) with randomised think-time.

 USAGE (PowerShell, as normal user):
     powershell -ExecutionPolicy Bypass -File benign_windows.ps1 -RunMinutes 60
================================================================
#>

param(
    [int]$RunMinutes = 60,
    [string]$Server  = "192.168.10.51",
    [int]$UsersPerHost = 3
)

$End = (Get-Date).AddMinutes($RunMinutes)
$Log = "$env:TEMP\benign_$(hostname)_$(Get-Date -Format HHmmss).log"
"benign generator on $(hostname)  target $Server  run $RunMinutes min" | Tee-Object $Log

function Http-Action($u) {
    $r = Get-Random -Maximum 6
    try {
        switch ($r) {
            0 { Invoke-WebRequest "http://$Server/"                       -UseBasicParsing -TimeoutSec 5 | Out-Null }
            1 { Invoke-WebRequest "http://$Server/index.html"             -UseBasicParsing -TimeoutSec 5 | Out-Null }
            2 { Invoke-WebRequest "http://$Server/?user=u$u&q=$(Get-Random)" -UseBasicParsing -TimeoutSec 5 | Out-Null }
            3 { Invoke-WebRequest "http://$Server/" -Method POST -Body @{user="u$u";pass="x$(Get-Random)"} -UseBasicParsing -TimeoutSec 5 | Out-Null }
            4 { Invoke-WebRequest "http://$Server/" -Headers @{Cookie="session=u$u$(Get-Random)"} -UseBasicParsing -TimeoutSec 5 | Out-Null }
            5 { Invoke-WebRequest "http://$Server/nonexistent-$(Get-Random)" -UseBasicParsing -TimeoutSec 5 | Out-Null }
        }
    } catch { }   # 404s / timeouts are fine, they are realistic
}

function Dns-Action {
    try { Resolve-DnsName -Server $Server -Name "host$(Get-Random).local" -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Resolve-DnsName -Server $Server -Name "www.example.com"        -ErrorAction SilentlyContinue | Out-Null } catch {}
}

function Ssh-Action {
    # Windows 10 ships an OpenSSH client; older Windows may not. Skip if absent.
    if (Get-Command ssh -ErrorAction SilentlyContinue) {
        # note: unattended password auth on Windows ssh needs a key or plink;
        # we attempt a connect that will simply generate SSH handshake traffic.
        try { echo "n" | ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 benign@$Server "echo ok" 2>$null } catch {}
    }
}

function User-Loop($id) {
    while ((Get-Date) -lt $End) {
        $r = Get-Random -Maximum 10
        if     ($r -le 5) { Http-Action $id }
        elseif ($r -le 7) { Dns-Action }
        else              { Ssh-Action }
        Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 8)
    }
}

"starting $UsersPerHost users..." | Tee-Object $Log -Append
$jobs = @()
for ($i=1; $i -le $UsersPerHost; $i++) {
    $jobs += Start-Job -ScriptBlock ${function:User-Loop} -ArgumentList $i
}
# keep script alive until all user-jobs finish
$jobs | Wait-Job | Out-Null
$jobs | Remove-Job
"benign generator finished on $(hostname)" | Tee-Object $Log -Append
