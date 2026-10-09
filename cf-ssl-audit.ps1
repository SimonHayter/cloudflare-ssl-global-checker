#Requires -Version 5.1
<#
  Cloudflare SSL audit - multi-account
  - Keeps any number of named Cloudflare accounts, each with its own API token
  - Menu: run one account, several (e.g. 1,3), or all; add or remove accounts
  - Tokens are saved encrypted with Windows DPAPI in %APPDATA%\cf-ssl-audit\accounts.json
    (only your Windows user on this PC can decrypt them)
  - Each token needs Zone > Zone > Read and Zone > SSL and Certificates > Read, scoped to that account's zones
  - Flags zones that are not active, have no active certificate pack, have a pack in an unexpected
    status, or whose active certificate expires within -ExpiryWarningDays (default 14)
  - Prints a success message per account if everything is healthy, otherwise lists the problems
  Works on Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$ExpiryWarningDays = 14
)

$ErrorActionPreference = 'Stop'
$base         = 'https://api.cloudflare.com/client/v4'
$dir          = Join-Path $env:APPDATA 'cf-ssl-audit'
$store        = Join-Path $dir 'accounts.json'
$oldTokenFile = Join-Path $dir 'token.txt'   # single-token file from the previous version
$maxAttempts  = 4                            # per API call, for 429 / 5xx / network errors
$script:accounts = @()

# Older .NET defaults can lack TLS 1.2; leave SystemDefault alone so the OS can negotiate TLS 1.3
$sp = [Net.ServicePointManager]::SecurityProtocol
if ($sp -ne [Net.SecurityProtocolType]::SystemDefault -and -not ($sp -band [Net.SecurityProtocolType]::Tls12)) {
    [Net.ServicePointManager]::SecurityProtocol = $sp -bor [Net.SecurityProtocolType]::Tls12
}

# ---------------------------------------------------------------- helpers

function Read-Line {
    param([string]$Prompt)
    $v = Read-Host $Prompt
    if ($null -eq $v) { return '' }   # input redirected / EOF
    return $v.Trim()
}

function Get-CFErrorText {
    # Turns a failed Invoke-RestMethod into "code: message" text.
    # PS 7 puts the body in ErrorDetails; PS 5.1 leaves that empty, so read the response stream.
    param($ErrorRecord)
    $body = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $body = $ErrorRecord.ErrorDetails.Message
    }
    elseif ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response -is [Net.WebResponse]) {
        try {
            $stream = $ErrorRecord.Exception.Response.GetResponseStream()
            if ($stream.CanSeek) { $stream.Position = 0 }
            $body = (New-Object IO.StreamReader($stream)).ReadToEnd()
        } catch { }
    }
    if (-not $body) { return $ErrorRecord.Exception.Message }

    try {
        $errors = @((ConvertFrom-Json $body).errors)
        if ($errors.Count -gt 0) { return ($errors | ForEach-Object { "$($_.code): $($_.message)" }) -join '; ' }
    } catch { }
    $body = $body -replace '\s+', ' '
    if ($body.Length -gt 300) { $body = $body.Substring(0, 300) + '...' }
    return $body
}

function Get-CF {
    # GET a Cloudflare API path. Retries rate limits, server errors and network failures with backoff.
    # Throws an exception whose Data['HttpStatus'] holds the HTTP status (0 = no response).
    param([string]$Path, [hashtable]$Headers)
    for ($attempt = 1; ; $attempt++) {
        try {
            $r = Invoke-RestMethod -Uri "$base$Path" -Headers $Headers -Method Get -TimeoutSec 30 -UseBasicParsing
        }
        catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if (($status -eq 0 -or $status -eq 429 -or $status -ge 500) -and $attempt -lt $maxAttempts) {
                Start-Sleep -Seconds ([int][math]::Pow(2, $attempt))
                continue
            }
            $what = if ($status) { "HTTP $status" } else { "No response after $attempt attempts" }
            $ex = New-Object Exception ("$what on GET $Path - $(Get-CFErrorText $_)")
            $ex.Data['HttpStatus'] = $status
            throw $ex
        }
        if ($r.success -eq $false) {
            $ex = New-Object Exception ("GET $Path returned success=false - $((@($r.errors) | ForEach-Object { "$($_.code): $($_.message)" }) -join '; ')")
            $ex.Data['HttpStatus'] = 200
            throw $ex
        }
        return $r
    }
}

function ConvertFrom-SecureToPlain {
    param([securestring]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try     { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-AuthHeader {
    param($Account)
    try { $sec = ConvertTo-SecureString $Account.Token }
    catch {
        throw "Could not decrypt the saved token for '$($Account.Name)'. It was probably saved by another Windows user or on another PC. Remove the account and add it again."
    }
    @{ Authorization = "Bearer $(ConvertFrom-SecureToPlain $sec)" }
}

function ConvertTo-UtcDate {
    # PS 7 ConvertFrom-Json yields [datetime]; PS 5.1 leaves ISO 8601 strings. Returns $null if unparseable.
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function Get-Accounts {
    if (-not (Test-Path $store)) { return @() }
    $raw = Get-Content $store -Raw -Encoding UTF8
    if (-not $raw -or -not $raw.Trim()) { return @() }
    try   { $parsed = ConvertFrom-Json $raw }
    catch { throw "Could not read $store ($($_.Exception.Message)). Fix or delete that file." }
    # PS 5.1 returns a JSON array as a single object; ForEach-Object unrolls it on both versions
    return @($parsed | ForEach-Object { $_ } | Where-Object { $_.Name -and $_.Token })
}

function Save-Accounts {
    if ($script:accounts.Count -eq 0) {
        if (Test-Path $store) { Remove-Item $store -Force }
        return
    }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # Write to a temp file then swap, so an interrupted save cannot corrupt the store
    $tmp = "$store.tmp"
    ConvertTo-Json -InputObject @($script:accounts | Select-Object Name, Token) | Set-Content -Path $tmp -Encoding UTF8
    Move-Item -Path $tmp -Destination $store -Force
}

function Add-Account {
    $name = Read-Line 'Name for this account (e.g. My Account)'
    if (-not $name) { Write-Host 'Cancelled.' -ForegroundColor Yellow; return }

    $sec = Read-Host "API token for '$name'" -AsSecureString
    if (-not $sec -or $sec.Length -eq 0) { Write-Host 'Cancelled (no token entered).' -ForegroundColor Yellow; return }

    # Trim stray whitespace from pasting, then re-encrypt the cleaned value
    $plain = (ConvertFrom-SecureToPlain $sec).Trim()
    try {
        if (-not $plain) { Write-Host 'Cancelled (no token entered).' -ForegroundColor Yellow; return }
        $encrypted = ConvertTo-SecureString $plain -AsPlainText -Force | ConvertFrom-SecureString

        # Validate before saving so a bad token never gets stored
        try {
            $r = Get-CF '/zones?per_page=1' @{ Authorization = "Bearer $plain" }
            if ([int]$r.result_info.total_count -eq 0) {
                Write-Host 'Warning: this token can see 0 zones. Saving anyway; check its zone scope.' -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "Token rejected, not saved: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }
    finally { $plain = $null }

    $existing = $script:accounts | Where-Object { $_.Name -eq $name }
    $script:accounts = @($script:accounts | Where-Object { $_.Name -ne $name }) +
        [pscustomobject]@{ Name = $name; Token = $encrypted }
    Save-Accounts
    if ($existing) { Write-Host "Updated the token for '$name'." -ForegroundColor Green }
    else           { Write-Host "Saved '$name'." -ForegroundColor Green }
}

function Remove-Account {
    $n = Read-Line 'Number of the account to remove (blank to cancel)'
    if ($n -notmatch '^\d{1,5}$' -or [int]$n -lt 1 -or [int]$n -gt $script:accounts.Count) {
        Write-Host 'Cancelled.' -ForegroundColor Yellow; return
    }
    $victim = $script:accounts[[int]$n - 1]
    $ok = Read-Line "Remove '$($victim.Name)' and its saved token? (Y/N)"
    if ($ok -match '^[Yy]') {
        $script:accounts = @($script:accounts | Where-Object { $_.Name -ne $victim.Name })
        Save-Accounts
        Write-Host "Removed '$($victim.Name)'. Roll the token in Cloudflare too if it is no longer needed." -ForegroundColor Green
    }
    else { Write-Host 'Cancelled.' -ForegroundColor Yellow }
}

function New-Problem {
    param([string]$Zone, [string]$Issue, [string]$Detail = '')
    [pscustomobject]@{ Zone = $Zone; Issue = $Issue; Detail = $Detail }
}

function Invoke-Audit {
    param($Account)

    Write-Host ''
    Write-Host "=== $($Account.Name) ===" -ForegroundColor Cyan
    $result = [pscustomobject]@{ Account = $Account.Name; Zones = 0; Problems = 0; Result = '' }
    $now = [datetime]::UtcNow

    try {
        $h = Get-AuthHeader $Account

        # All zones (paginated; 50 is the API maximum per page)
        $zones = New-Object System.Collections.Generic.List[object]
        $page = 1
        do {
            $r = Get-CF "/zones?per_page=50&page=$page" $h
            foreach ($z in @($r.result)) { $zones.Add($z) }
            $totalPages = [int]$r.result_info.total_pages
            $page++
        } while ($page -le $totalPages)

        if ($zones.Count -eq 0) { throw 'The token can see 0 zones. Check its zone scope and permissions.' }
        $result.Zones = $zones.Count
        Write-Host "Checking $($zones.Count) zones..." -ForegroundColor DarkGray

        $problems = New-Object System.Collections.Generic.List[object]
        $i = 0
        foreach ($z in $zones) {
            $i++
            Write-Progress -Activity "Checking $($Account.Name)" -Status "$i / $($zones.Count): $($z.name)" -PercentComplete (($i / $zones.Count) * 100)

            if ($z.status -ne 'active') {
                $problems.Add((New-Problem $z.name "Zone status is '$($z.status)'"))
                continue
            }

            # One zone failing (API error, odd data) must not abort the rest of the account
            try {
                $packs = @((Get-CF "/zones/$($z.id)/ssl/certificate_packs?status=all" $h).result)

                $active = @($packs | Where-Object { $_.status -eq 'active' })
                if ($active.Count -eq 0) {
                    $seen = (@($packs | ForEach-Object { $_.status } | Select-Object -Unique) -join ', ')
                    $problems.Add((New-Problem $z.name 'No active certificate pack' $(if ($seen) { "Pack statuses: $seen" } else { 'No packs at all' })))
                }

                foreach ($p in $packs) {
                    if ($p.status -notin 'active', 'backup_issued') {
                        $problems.Add((New-Problem $z.name "Pack status '$($p.status)'" "$($p.certificate_authority) / $($p.type) / $($p.validation_method) / $($p.id)"))
                    }
                }

                # Active but about to lapse is the failure mode repeated DCV failures lead to
                foreach ($p in $active) {
                    $soonest = @($p.certificates | ForEach-Object { ConvertTo-UtcDate $_.expires_on } | Where-Object { $_ } | Sort-Object) | Select-Object -First 1
                    if (-not $soonest) { continue }
                    $daysLeft = [int][math]::Floor(($soonest - $now).TotalDays)
                    if ($daysLeft -lt $ExpiryWarningDays) {
                        $issue = if ($soonest -le $now) { 'Certificate has expired' } else { "Certificate expires in $daysLeft day(s)" }
                        $problems.Add((New-Problem $z.name $issue "$($p.certificate_authority) / $($p.type) / expires $($soonest.ToString('yyyy-MM-dd HH:mm')) UTC / $($p.id)"))
                    }
                }
            }
            catch {
                $problems.Add((New-Problem $z.name 'API error' ($_.Exception.Message -replace '\s+', ' ')))
            }
        }
        Write-Progress -Activity "Checking $($Account.Name)" -Completed

        if ($problems.Count -eq 0) {
            Write-Host "Successful: All SSLs are working as intended. ($($zones.Count) zones checked)" -ForegroundColor Green
            $result.Result = 'OK'
        }
        else {
            Write-Host "$($problems.Count) problem(s) found across $($zones.Count) zones:" -ForegroundColor Yellow
            $problems | Format-Table -AutoSize -Wrap | Out-Host
            $result.Problems = $problems.Count
            $result.Result   = 'PROBLEMS'
        }
    }
    catch {
        Write-Progress -Activity "Checking $($Account.Name)" -Completed
        Write-Host "Audit could not complete: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Data['HttpStatus'] -in 400, 401, 403) {
            Write-Host 'The saved token may have been rolled, expired or lost permissions. Remove the account and add it again.' -ForegroundColor Yellow
        }
        $result.Result = 'ERROR'
    }
    finally { $h = $null }

    return $result
}

# ---------------------------------------------------------------- main

try {
    # One-time migration from the old single-token file
    if (-not (Test-Path $store) -and (Test-Path $oldTokenFile)) {
        $oldToken = (Get-Content $oldTokenFile -Raw).Trim()
        if ($oldToken) {
            $script:accounts = @([pscustomobject]@{ Name = 'Default'; Token = $oldToken })
            Save-Accounts
            Write-Host "Imported your previously saved token as account 'Default'." -ForegroundColor DarkGray
        }
        Remove-Item $oldTokenFile -Force
    }
    else {
        $script:accounts = @(Get-Accounts)
    }

    $selected = $null
    while (-not $selected) {
        if ($script:accounts.Count -eq 0) {
            Write-Host 'No saved accounts yet. Add one now.' -ForegroundColor Yellow
            Add-Account
            if ($script:accounts.Count -eq 0) { return }
        }

        Write-Host ''
        Write-Host 'Saved Cloudflare accounts:' -ForegroundColor Cyan
        for ($i = 0; $i -lt $script:accounts.Count; $i++) {
            Write-Host ('  {0}) {1}' -f ($i + 1), $script:accounts[$i].Name)
        }
        Write-Host '  A) Run ALL accounts'
        Write-Host '  N) Add a new account'
        Write-Host '  R) Remove an account'
        Write-Host '  Q) Quit'

        $choice = Read-Line 'Choose (a number, or several like 1,3)'

        switch -Regex ($choice) {
            '^[Qq]$' { return }
            '^[Aa]$' { $selected = @($script:accounts) }
            '^[Nn]$' { Add-Account }
            '^[Rr]$' { Remove-Account }
            '^\d{1,5}(\s*,\s*\d{1,5})*$' {
                $idx = @($choice -split '\s*,\s*' | ForEach-Object { [int]$_ - 1 } | Select-Object -Unique)
                if (@($idx | Where-Object { $_ -lt 0 -or $_ -ge $script:accounts.Count }).Count -gt 0) {
                    Write-Host 'One of those numbers is not in the list.' -ForegroundColor Yellow
                }
                else {
                    $selected = @($idx | ForEach-Object { $script:accounts[$_] })
                }
            }
            default { Write-Host 'Not a valid choice.' -ForegroundColor Yellow }
        }
    }

    $results = @(foreach ($a in $selected) { Invoke-Audit $a })

    if ($results.Count -gt 1) {
        Write-Host ''
        Write-Host '=== Summary ===' -ForegroundColor Cyan
        $results | Format-Table Account, Zones, Problems, Result -AutoSize | Out-Host
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    $script:accounts = @()
}
