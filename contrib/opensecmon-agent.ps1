<#
opensecmon-agent.ps1 - reports Windows and its installed programs to opensecmon over its agent API
(docs/agent-api.md). Needs Windows 10 (1803 or later), Windows 11 or Windows Server 2019 or later, with Windows
PowerShell 5.1 and curl.exe, both part of Windows.

In a PowerShell window run as administrator, in the folder with the script:

  powershell -ExecutionPolicy Bypass -File .\opensecmon-agent.ps1 enroll <https://server:port> <code> [opensecmon.pem]
      Enrolls the computer with the one-time code from its page in opensecmon, keeps the token in
      C:\ProgramData\opensecmon-agent (SYSTEM and administrators only), copies itself there, adds the scheduled
      task "opensecmon-agent" (as SYSTEM, at start-up and every 6 hours) and sends the first report. Pass the
      certificate when opensecmon runs with its own self-signed certificate (download it from the computer's page).
  ... -File C:\ProgramData\opensecmon-agent\opensecmon-agent.ps1 report     sends the report now
  ... -File C:\ProgramData\opensecmon-agent\opensecmon-agent.ps1 status     checks the token and the connection
  ... -File C:\ProgramData\opensecmon-agent\opensecmon-agent.ps1 uninstall  removes the task, the token and itself
  ... -File .\opensecmon-agent.ps1 update   puts a newer version of the script in place of the old one

What is sent: the Windows version (ProductName, DisplayVersion, CurrentBuild, UBR, InstallationType), the
architecture, the computer name and, per installed program, its registry key name, name, version and publisher
(the Uninstall entries of the machine, 64 and 32 bit, and of the users signed in, without naming them) and the store
apps (package family name, name, version, publisher). Nothing else: no user names, no files, no network details.
The last answer is kept in last-report.txt.

SPDX-License-Identifier: AGPL-3.0-or-later
#>
param(
    [Parameter(Position = 0)][string]$Command = '',
    [Parameter(Position = 1)][string]$Url = '',
    [Parameter(Position = 2)][string]$Code = '',
    [Parameter(Position = 3)][string]$Cert = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Version = '1'
$Self = $PSCommandPath
$Dir = if ($env:OPENSECMON_AGENT_DIR) { $env:OPENSECMON_AGENT_DIR } else { Join-Path $env:ProgramData 'opensecmon-agent' }
$Bin = Join-Path $Dir 'opensecmon-agent.ps1'
$TaskName = 'opensecmon-agent'
$Utf8 = New-Object System.Text.UTF8Encoding $false
# At most this many entries, as opensecmon takes them (docs/agent-api.md).
$MaxItems = 50000

function Fail([string]$Message) {
    [Console]::Error.WriteLine("opensecmon-agent: $Message")
    exit 1
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# A property of a registry value or object, or $null (Set-StrictMode does not allow missing ones).
function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

# A text field: trimmed, without control characters, at most $Max characters.
function Get-Text($Value, [int]$Max) {
    if ($null -eq $Value) { return '' }
    $s = ([string]$Value) -replace '[\x00-\x1f\x7f]', ''
    $s = $s.Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) }
    $s
}

function Write-File([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, $Utf8)
}

function Get-Sid([string]$Sid) { New-Object Security.Principal.SecurityIdentifier $Sid }

# Only SYSTEM and the administrators may read or change the folder: it holds the token and the script that the
# scheduled task runs as SYSTEM. A new folder gets its rights when it is created; an existing one must belong to
# SYSTEM or the administrators (users may create folders in ProgramData) and gets its rights replaced.
function Protect-Dir {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((Get-Sid $sid), 'FullControl',
                    'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    $acl.SetOwner((Get-Sid 'S-1-5-32-544'))
    if (-not (Test-Path -LiteralPath $Dir)) {
        [IO.Directory]::CreateDirectory($Dir, $acl) | Out-Null
        return
    }
    $item = Get-Item -LiteralPath $Dir -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$Dir is a link; remove it first" }
    $owner = (Get-Acl -LiteralPath $Dir).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (@('S-1-5-18', 'S-1-5-32-544') -notcontains $owner) {
        Fail "$Dir belongs to $owner, not to SYSTEM or the administrators; remove it first"
    }
    Set-Acl -LiteralPath $Dir -AclObject $acl
}

# curl.exe over HTTPS only, without redirects; the certificate as the only trust anchor when there is one.
# The token goes in a header file, so it never shows on a command line.
function Invoke-Curl([string[]]$Arguments) {
    $pem = Join-Path $Dir 'opensecmon.pem'
    $base = @('--silent', '--show-error', '--fail-with-body', '--proto', '=https', '--max-time', '300')
    if (Test-Path $pem) {
        # Schannel checks revocation, which a self-signed certificate cannot answer.
        $base += @('--cacert', $pem, '--ssl-no-revoke')
    }
    # Windows PowerShell turns every line curl writes to stderr into an error; with 'Stop' the first one would end
    # the script before the answer could be shown.
    $ErrorActionPreference = 'Continue'
    $out = (& curl.exe @base @Arguments 2>&1 | ForEach-Object { "$_" }) -join "`n"
    [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Text = $out.Trim() }
}

function Get-BaseUrl {
    $f = Join-Path $Dir 'url'
    if (-not (Test-Path $f)) { Fail "not enrolled (no $f); run: opensecmon-agent.ps1 enroll <url> <code>" }
    (Get-Content -LiteralPath $f -TotalCount 1).Trim()
}

function Get-HeaderFile {
    $f = Join-Path $Dir 'auth-header'
    if (-not (Test-Path $f)) { Fail 'not enrolled (no token); run: opensecmon-agent.ps1 enroll <url> <code>' }
    $f
}

function Get-OsInfo {
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $display = Get-Prop $cv 'DisplayVersion'
    if (-not $display) { $display = Get-Prop $cv 'ReleaseId' }
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'x64' } 'ARM64' { 'arm64' } 'x86' { 'x86' } default { 'other' } }
    [ordered]@{
        family            = 'windows'
        product_name      = Get-Text (Get-Prop $cv 'ProductName') 200
        display_version   = Get-Text $display 20
        build             = [int](Get-Prop $cv 'CurrentBuildNumber')
        ubr               = [int](Get-Prop $cv 'UBR')
        installation_type = Get-Text (Get-Prop $cv 'InstallationType') 40
        arch              = $arch
    }
}

# Programs from the Uninstall entries of the machine (64 and 32 bit) and of the users signed in (their hives are
# loaded), without updates and system components.
function Get-Programs {
    $keys = @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'machine'),
        @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'machine')
    )
    foreach ($hive in Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
        if ($hive.PSChildName -match '^S-1-5-21-[0-9-]+$') {
            $keys += , @("Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall", 'user')
        }
    }
    $seen = @{}
    foreach ($pair in $keys) {
        $key = $pair[0]
        if (-not (Test-Path -LiteralPath $key)) { continue }
        foreach ($entry in Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty -LiteralPath $entry.PSPath -ErrorAction SilentlyContinue
            $name = Get-Text (Get-Prop $p 'DisplayName') 200
            if (-not $name) { continue }
            if ((Get-Prop $p 'SystemComponent') -eq 1) { continue }
            if (Get-Prop $p 'ParentKeyName') { continue }
            if (@('Update', 'Hotfix', 'Security Update') -contains (Get-Prop $p 'ReleaseType')) { continue }
            $id = Get-Text $entry.PSChildName 200
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            [ordered]@{
                type      = 'win'
                id        = $id
                name      = $name
                version   = Get-Text (Get-Prop $p 'DisplayVersion') 100
                publisher = Get-Text (Get-Prop $p 'Publisher') 200
                scope     = $pair[1]
            }
        }
    }
}

# Store apps of all users (installed per user), without frameworks and resource packages, once per package family.
function Get-StoreApps {
    $seen = @{}
    try {
        $packages = Get-AppxPackage -AllUsers -ErrorAction Stop
    } catch {
        return
    }
    foreach ($a in $packages) {
        if ((Get-Prop $a 'IsFramework') -or (Get-Prop $a 'IsResourcePackage')) { continue }
        $id = Get-Text (Get-Prop $a 'PackageFamilyName') 200
        if (-not $id -or $seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $publisher = Get-Text ((Get-Text (Get-Prop $a 'Publisher') 400) -replace '^CN=([^,]+).*$', '$1') 200
        [ordered]@{
            type      = 'appx'
            id        = $id
            name      = Get-Text (Get-Prop $a 'Name') 200
            version   = Get-Text ([string](Get-Prop $a 'Version')) 100
            publisher = $publisher
            scope     = 'user'
        }
    }
}

function Get-Report {
    $items = @(Get-Programs) + @(Get-StoreApps)
    if ($items.Count -gt $MaxItems) { $items = $items[0..($MaxItems - 1)] }
    [ordered]@{
        schema   = 1
        agent    = [ordered]@{ name = 'opensecmon-agent.ps1'; version = $Version }
        hostname = Get-Text $env:COMPUTERNAME 253
        os       = Get-OsInfo
        items    = $items
    }
}

function Assert-Admin {
    if (-not (Test-Admin)) { Fail 'run PowerShell as administrator' }
}

function Send-Report {
    Assert-Admin
    $base = Get-BaseUrl
    $header = Get-HeaderFile
    $json = (Get-Report) | ConvertTo-Json -Depth 5 -Compress
    $body = Join-Path $Dir 'report.json.gz'
    $bytes = $Utf8.GetBytes($json)
    $file = [IO.File]::Create($body)
    try {
        $gzip = New-Object IO.Compression.GZipStream($file, [IO.Compression.CompressionMode]::Compress)
        $gzip.Write($bytes, 0, $bytes.Length)
        $gzip.Close()
    } finally {
        $file.Close()
    }
    $r = Invoke-Curl @('-H', "@$header", '-H', 'Content-Type: application/json', '-H', 'Content-Encoding: gzip',
        '--data-binary', "@$body", "$base/api/v1/agent/report")
    Remove-Item -LiteralPath $body -ErrorAction SilentlyContinue
    Write-File (Join-Path $Dir 'last-report.txt') ("{0:u}`r`n{1}`r`n" -f (Get-Date), $r.Text)
    if (-not $r.Ok) { Fail "the report failed: $($r.Text)" }
    $r.Text
}

function Get-Status {
    Assert-Admin
    $base = Get-BaseUrl
    $header = Get-HeaderFile
    $r = Invoke-Curl @('-H', "@$header", "$base/api/v1/agent/status")
    if (-not $r.Ok) { Fail "the check failed: $($r.Text)" }
    $r.Text
}

function Install-Task {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Bin`" report"
    $start = New-ScheduledTaskTrigger -AtStartup
    $start.Delay = 'PT10M'
    $repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(30) -RepetitionInterval (New-TimeSpan -Hours 6) `
        -RandomDelay (New-TimeSpan -Minutes 30)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($start, $repeat) -Principal $principal `
        -Settings $settings -Description 'Reports Windows and its programs to opensecmon' -Force | Out-Null
    "scheduled task '$TaskName' added (at start-up and every 6 hours)"
}

function Invoke-Enroll {
    if (-not $Url -or -not $Code) { Fail 'usage: opensecmon-agent.ps1 enroll <https://server:port> <code> [opensecmon.pem]' }
    Assert-Admin
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        Fail 'curl.exe is missing (it comes with Windows 10 1803 and Windows Server 2019 and later)'
    }
    $base = $Url.TrimEnd('/')
    if (-not $base.StartsWith('https://')) { Fail 'the address must start with https://' }
    $cleanCode = $Code -replace '[^A-Za-z0-9-]', ''
    Protect-Dir
    $pem = Join-Path $Dir 'opensecmon.pem'
    if ($Cert) {
        $text = Get-Content -LiteralPath $Cert -Raw
        if ($text -notmatch '-----BEGIN CERTIFICATE-----') { Fail "$Cert is not a certificate" }
        if ($text -match 'PRIVATE KEY') { Fail "$Cert contains a private key" }
        Write-File $pem $text
    } elseif (Test-Path $pem) {
        Remove-Item -LiteralPath $pem
    }
    Write-File (Join-Path $Dir 'url') "$base`r`n"
    $request = [ordered]@{
        schema   = 1
        code     = $cleanCode
        hostname = Get-Text $env:COMPUTERNAME 253
        agent    = [ordered]@{ name = 'opensecmon-agent.ps1'; version = $Version }
    } | ConvertTo-Json -Compress
    $body = Join-Path $Dir 'enroll.json'
    Write-File $body $request
    $r = Invoke-Curl @('-H', 'Content-Type: application/json', '--data-binary', "@$body", "$base/api/v1/agent/enroll")
    Remove-Item -LiteralPath $body -ErrorAction SilentlyContinue
    if (-not $r.Ok) { Fail "the enrollment failed: $($r.Text)" }
    $answer = $r.Text | ConvertFrom-Json
    $token = [string](Get-Prop $answer 'token')
    if ($token -notmatch '^osm1_[A-Za-z0-9_-]+$') { Fail "the answer holds no token: $($r.Text)" }
    Write-File (Join-Path $Dir 'auth-header') "Authorization: Bearer $token`n"
    "enrolled as $(Get-Prop $answer 'device')"
    Install-Self
    Send-Report
}

# The scheduled task runs the copy in the protected folder, never the downloaded file.
function Install-Self {
    if ($Self -ne $Bin) {
        Copy-Item -LiteralPath $Self -Destination $Bin -Force
        Unblock-File -LiteralPath $Bin
    }
    Install-Task
}

function Invoke-Update {
    Assert-Admin
    Get-BaseUrl | Out-Null
    Protect-Dir
    Install-Self
    "updated to version $Version"
}

function Invoke-Uninstall {
    Assert-Admin
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $Dir) { Remove-Item -LiteralPath $Dir -Recurse -Force }
    'removed; remove or revoke the computer in opensecmon as well'
}

try {
    switch ($Command) {
        'enroll' { Invoke-Enroll }
        'report' { Send-Report }
        'status' { Get-Status }
        'uninstall' { Invoke-Uninstall }
        'update' { Invoke-Update }
        'version' { "opensecmon-agent.ps1 $Version" }
        default {
            $lines = @(Get-Content -LiteralPath $Self)
            $lines[1..([Array]::IndexOf($lines, '#>') - 1)]
            exit 2
        }
    }
} catch {
    Fail $_.Exception.Message
}
