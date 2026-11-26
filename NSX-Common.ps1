#Requires -Version 5.1
<#
.SYNOPSIS
    Shared functions for the NSX Migration Toolkit.

.DESCRIPTION
    Every script in the toolkit dot-sources this file:

        . (Join-Path $PSScriptRoot 'NSX-Common.ps1')

    so the same action is always done the same way:

      LOGGING            Write-Log, Initialize-NSXLog, Write-NSXBanner, Write-NSXSummary
      CONNECTION         Connect-NSXManager (credentials, certificates, connectivity check)
      REST               Invoke-NSXRequest and the Invoke-NSXGet/Post/Put/Patch/Delete
                         wrappers, Get-NSXAllPages, Test-NSXObjectExists
      OBJECTS            Get-SafeProp, Format-Tags, Format-PropList, Remove-ReadOnlyFields,
                         Test-IsServiceGroup, Get-GroupDependency, Get-ServiceDependency,
                         Get-DependencyOrder
      CSV FILES          Resolve-CsvFile, Read-CsvFile
      SANITIZATION       Rename-NSXObjectId (the shared groups/services rename step),
                         ConvertTo-NSXId, Get-UniqueNewId, ConvertFrom-UnicodeEscape,
                         New-IdPathRegex, Update-IdPath, Set-JsonIdentity, Clear-JsonTag,
                         Clear-JsonDescription, Remove-UnusedTag, Format-TagColumn,
                         Export-IdMappingCsv
      TAG SAFETY CHECK   Get-NSXTagsInUse
      CONSTANTS          $NSXPseudoSystemGroupIds, $NSXPseudoSystemPolicyIds

    Script-level variables the functions use when a parameter is omitted:
      $LogTarget, $LogFile  — Write-Log
      $NSXManager, $Headers — the REST functions (set by the calling script)

    Functions are defined in the calling script's scope (dot-sourcing), so
    -Scope Script below always refers to the script that loaded this file.

.NOTES
    Changelog:
      1.0.0  Initial release. Collects the helpers that were copied into every
             script (logging, certificates, credentials, REST calls,
             pagination, dependency sorting, CSV selection, sanitization
             helpers) and Get-NSXTagsInUse (previously Get-NSXTagsInUse.ps1).
      1.0.1  Fix: with -WhatIf the log file was not written (Add-Content and
             New-Item honour the caller's $WhatIfPreference); both now run
             with -WhatIf:$false -Confirm:$false.
#>

$NSXCommonVersion = '1.0.1'

# ═════════════════════════════════════════════════════════════
# CONSTANTS
# ═════════════════════════════════════════════════════════════
# Groups that NSX manages itself but does not flag as _system_owned
# (provisioned by NSX Threat Intelligence, IDS/IPS and related services).
$NSXPseudoSystemGroupIds = @(
    'DefaultMaliciousIpGroup',
    'DefaultUDAGroup'
)

# Policies that NSX manages itself but does not flag as _system_owned.
# NSX rejects DELETE requests for these with a 400/403 error.
$NSXPseudoSystemPolicyIds = @(
    'default-layer3-section',
    'default-malicious-ip-block-rules',
    'default-layer2-section'
)

# ═════════════════════════════════════════════════════════════
# LOGGING
# ═════════════════════════════════════════════════════════════
function Write-Log {
    <# Writes a timestamped log line to the screen, a file, or both.
       Controlled by the calling script's $LogTarget and $LogFile:
         Screen : colored output to the console only (default)
         File   : writes to $LogFile only (no console output)
         Both   : colored console output AND appends to $LogFile #>
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO'
    )
    $target = Get-Variable -Name LogTarget -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $target) { $target = 'Screen' }
    $file = Get-Variable -Name LogFile -Scope Script -ValueOnly -ErrorAction SilentlyContinue

    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "[$ts][$Level] $Message"
    $color = switch ($Level) {
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
        default   { 'Cyan' }
    }

    if ($target -eq 'Screen' -or $target -eq 'Both') {
        Write-Host $line -ForegroundColor $color
    }

    if (($target -eq 'File' -or $target -eq 'Both') -and $file) {
        try {
            # -WhatIf:$false / -Confirm:$false: the log is written even when the
            # calling script runs with -WhatIf or -Confirm (Add-Content honours
            # the caller's $WhatIfPreference and would silently skip the line).
            Add-Content -Path $file -Value $line -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }
        catch {
            # Fall back to screen if file write fails
            Write-Host "[WARN] Could not write to log file: $_" -ForegroundColor Yellow
            Write-Host $line -ForegroundColor $color
        }
    }
}

function Initialize-NSXLog {
    <# Gives the calling script a log file when -LogTarget is File or Both and
       no -LogFile was passed: <ScriptName>_<timestamp>.log in -Folder (default:
       the current folder). Creates the folder of the log file if needed. #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [string]$Folder = (Get-Location).Path
    )
    $target = Get-Variable -Name LogTarget -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $file   = Get-Variable -Name LogFile   -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($target -and $target -ne 'Screen' -and -not $file) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
        $file = Join-Path $Folder "${name}_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Set-Variable -Name LogFile -Scope Script -Value $file
    }
    if ($file) {
        $dir = Split-Path -Parent $file
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -Confirm:$false | Out-Null }
    }
}

function Write-NSXBanner {
    <# Prints the start-of-run banner: a title and aligned "Label : value" lines. #>
    param(
        [Parameter(Mandatory)][string]$Title,
        [System.Collections.IDictionary]$Details = @{}
    )
    $width = 0
    foreach ($k in $Details.Keys) { if ("$k".Length -gt $width) { $width = "$k".Length } }
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log " $Title" INFO
    foreach ($k in $Details.Keys) {
        Write-Log (" {0} : {1}" -f "$k".PadRight($width), $Details[$k]) INFO
    }
    Write-Log "════════════════════════════════════════════" INFO
}

function Write-NSXSummary {
    <# Prints the end-of-run summary. Each entry is "Label = count".
       A label containing 'error' is logged as ERROR when its count is above 0,
       a label containing 'skip' or 'not found' as WARN; all others as INFO.
       -Footer lines are logged after the counts. #>
    param(
        [Parameter(Mandatory)][string]$Title,
        [System.Collections.IDictionary]$Counts = @{},
        [string[]]$Footer = @()
    )
    $width = 0
    foreach ($k in $Counts.Keys) { if ("$k".Length -gt $width) { $width = "$k".Length } }
    Write-Log "════════════════════════════════════════════" INFO
    Write-Log " $Title" INFO
    Write-Log "────────────────────────────────────────────" INFO
    foreach ($k in $Counts.Keys) {
        $value = $Counts[$k]
        $level = 'INFO'
        if ($value -is [int] -and $value -gt 0) {
            if ("$k" -match 'error')             { $level = 'ERROR' }
            elseif ("$k" -match 'skip|not found') { $level = 'WARN' }
        }
        Write-Log ("  {0} : {1}" -f "$k".PadRight($width), $value) $level
    }
    Write-Log "════════════════════════════════════════════" INFO
    foreach ($line in $Footer) { Write-Log $line INFO }
}

# ═════════════════════════════════════════════════════════════
# CONNECTION
# ═════════════════════════════════════════════════════════════
function Enable-NSXCertificateBypass {
    <# Accept self-signed NSX certificates.
       Windows PowerShell 5.1: a process-wide ServicePointManager policy.
       PowerShell 6+: ServicePointManager is ignored there, so
       Invoke-NSXRequest passes -SkipCertificateCheck on every call instead
       (nothing global is changed in the session). #>
    if ($PSVersionTable.PSVersion.Major -ge 6) { return }
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
    [System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]::Tls12
}

function New-NSXAuthHeader {
    <# Builds the request headers (Basic authentication + JSON). #>
    param([Parameter(Mandatory)][pscredential]$Credential)
    $pair  = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    return @{
        Authorization  = "Basic $([Convert]::ToBase64String($bytes))"
        'Content-Type' = 'application/json'
    }
}

function Connect-NSXManager {
    <# Prompts for credentials when -Credential is not given, enables the
       certificate bypass, checks connectivity (/api/v1/node) and returns the
       request headers. Throws when the manager cannot be reached. #>
    param(
        [Parameter(Mandatory)][string]$Manager,
        [pscredential]$Credential,
        [string]$Label = 'NSX Manager'
    )
    if (-not $Credential) {
        Write-Log "Enter credentials for $($Label): $Manager" INFO
        $Credential = Get-Credential -Message "$Label ($Manager) credentials"
        if (-not $Credential) { throw "No credentials entered for $Manager." }
    }
    Enable-NSXCertificateBypass
    $hdrs = New-NSXAuthHeader -Credential $Credential

    Write-Log "Verifying connectivity to $Label ($Manager)..." INFO
    $info = Invoke-NSXGet -Path '/api/v1/node' -Manager $Manager -Headers $hdrs
    if (-not $info) { throw "Cannot connect to NSX Manager $Manager." }
    Write-Log "  Connected: NSX $($info.product_version)" SUCCESS
    return $hdrs
}

# ═════════════════════════════════════════════════════════════
# REST
# ═════════════════════════════════════════════════════════════
function Resolve-NSXTarget {
    <# Returns @(manager, headers): the explicit values, or else the calling
       script's $NSXManager and $Headers. #>
    param([string]$Manager, [hashtable]$Headers)
    if (-not $Manager) { $Manager = Get-Variable -Name NSXManager -Scope Script -ValueOnly -ErrorAction SilentlyContinue }
    if (-not $Headers) { $Headers = Get-Variable -Name Headers    -Scope Script -ValueOnly -ErrorAction SilentlyContinue }
    if (-not $Manager -or -not $Headers) {
        throw "No NSX Manager or headers available. Call Connect-NSXManager first, or pass -Manager and -Headers."
    }
    return @($Manager, $Headers)
}

function Get-NSXStatusCode {
    <# HTTP status code of a failed request (works on PowerShell 5.1 and 7), or $null. #>
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    $ex = $ErrorRecord.Exception
    if ($ex.PSObject.Properties['Response'] -and $ex.Response) { return [int]$ex.Response.StatusCode }
    return $null
}

function Get-NSXErrorDetail {
    <# The NSX error body of a failed request as " | Detail: ...", or ''. #>
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { return " | Detail: $($ErrorRecord.ErrorDetails.Message)" }
    return ''
}

function Invoke-NSXRequest {
    <# The single place that calls Invoke-RestMethod. Throws on failure —
       use the Invoke-NSXGet/Post/Put/Patch/Delete wrappers for the usual
       "log the error and return a failure value" behaviour. #>
    param(
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [string]$Body,
        [string]$Manager,
        [hashtable]$Headers
    )
    $target = Resolve-NSXTarget -Manager $Manager -Headers $Headers
    $params = @{ Uri = "https://$($target[0])$Path"; Method = $Method; Headers = $target[1] }
    if ($PSBoundParameters.ContainsKey('Body')) { $params.Body = $Body }
    if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
    return Invoke-RestMethod @params
}

function Invoke-NSXGet {
    <# GET. Returns the response, or $null on failure (logged unless -Quiet). #>
    param([Parameter(Mandatory)][string]$Path, [string]$Manager, [hashtable]$Headers, [switch]$Quiet)
    try {
        return Invoke-NSXRequest -Method GET -Path $Path -Manager $Manager -Headers $Headers
    }
    catch {
        if (-not $Quiet) { Write-Log "GET $Path failed: $_$(Get-NSXErrorDetail $_)" ERROR }
        return $null
    }
}

function Invoke-NSXPost {
    <# POST. Returns the response ($true when the body is empty), or $null on failure. #>
    param([Parameter(Mandatory)][string]$Path, [string]$JsonBody, [string]$Manager, [hashtable]$Headers)
    try {
        $resp = Invoke-NSXRequest -Method POST -Path $Path -Body $JsonBody -Manager $Manager -Headers $Headers
        # An empty response (e.g. 204 No Content) comes back as $null or ''
        if ($null -eq $resp -or ($resp -is [string] -and $resp.Trim() -eq '')) { return $true }
        return $resp
    }
    catch {
        Write-Log "POST $Path failed: $_$(Get-NSXErrorDetail $_)" ERROR
        return $null
    }
}

function Invoke-NSXPut {
    <# PUT. Returns $true on success, $false on failure. #>
    param([Parameter(Mandatory)][string]$Path, [string]$JsonBody, [string]$Manager, [hashtable]$Headers)
    try {
        Invoke-NSXRequest -Method PUT -Path $Path -Body $JsonBody -Manager $Manager -Headers $Headers | Out-Null
        return $true
    }
    catch {
        Write-Log "PUT $Path failed: $_$(Get-NSXErrorDetail $_)" ERROR
        return $false
    }
}

function Invoke-NSXPatch {
    <# PATCH. Returns $true on success, $false on failure. #>
    param([Parameter(Mandatory)][string]$Path, [string]$JsonBody, [string]$Manager, [hashtable]$Headers)
    try {
        Invoke-NSXRequest -Method PATCH -Path $Path -Body $JsonBody -Manager $Manager -Headers $Headers | Out-Null
        return $true
    }
    catch {
        Write-Log "PATCH $Path failed: $_$(Get-NSXErrorDetail $_)" ERROR
        return $false
    }
}

function Invoke-NSXDelete {
    <# DELETE. Returns $true on success, $false on failure. #>
    param([Parameter(Mandatory)][string]$Path, [string]$Manager, [hashtable]$Headers)
    try {
        Invoke-NSXRequest -Method DELETE -Path $Path -Manager $Manager -Headers $Headers | Out-Null
        return $true
    }
    catch {
        Write-Log "DELETE $Path failed: $_$(Get-NSXErrorDetail $_)" ERROR
        return $false
    }
}

function Get-NSXAllPages {
    <# Returns every result of a paginated NSX list call (1000 per page).
       - Uses '&' instead of '?' when the path already has a query string.
       - URL-encodes the cursor.
       - Throws when any page fails, so an incomplete list is never treated
         as a complete one. #>
    param([Parameter(Mandatory)][string]$Path, [string]$Manager, [hashtable]$Headers, [int]$PageSize = 1000)
    $allResults = [System.Collections.Generic.List[object]]::new()
    $separator  = if ($Path.Contains('?')) { '&' } else { '?' }
    $cursor     = $null
    $page       = 0
    do {
        $page++
        $url = "$Path${separator}page_size=$PageSize"
        if ($cursor) { $url += "&cursor=$([uri]::EscapeDataString($cursor))" }
        $resp = Invoke-NSXGet -Path $url -Manager $Manager -Headers $Headers
        if ($null -eq $resp) {
            throw "Could not read page $page of $Path. Stopping so an incomplete list is not used."
        }
        if ($resp.PSObject.Properties['results'] -and $resp.results) { $allResults.AddRange([object[]]@($resp.results)) }
        $cursor = if ($resp.PSObject.Properties['cursor']) { $resp.cursor } else { $null }
    } while ($cursor)
    return $allResults.ToArray()
}

function Test-NSXObjectExists {
    <# $true when the object exists, $false ONLY when NSX answers 404 Not Found.
       Any other error (authentication, permissions, server error, timeout) is
       re-thrown: treating it as "not found" would skip conflict checks and
       overwrite (or skip) objects without warning. #>
    param([Parameter(Mandatory)][string]$Path, [string]$Manager, [hashtable]$Headers)
    try {
        Invoke-NSXRequest -Method GET -Path $Path -Manager $Manager -Headers $Headers | Out-Null
        return $true
    }
    catch {
        $status = Get-NSXStatusCode $_
        if ($status -eq 404) { return $false }
        throw "Could not check whether $Path exists (HTTP $status): $($_.Exception.Message)"
    }
}

# ═════════════════════════════════════════════════════════════
# OBJECTS
# ═════════════════════════════════════════════════════════════
function Get-SafeProp {
    <# Reads an optional property; $null when it is absent (StrictMode-safe). #>
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj.PSObject.Properties[$Name]) { return $Obj.$Name }
    return $null
}

function Format-Tags {
    <# Tags as "scope:tag; scope:tag", or '' when there are none. #>
    param([object]$Obj)
    $tags = Get-SafeProp $Obj 'tags'
    if ($tags) { return (@($tags) | ForEach-Object { "$(Get-SafeProp $_ 'scope'):$(Get-SafeProp $_ 'tag')" }) -join '; ' }
    return ''
}

function Format-PropList {
    <# An optional array property joined with '; ', or -Fallback. #>
    param([object]$Obj, [string]$Name, [string]$Fallback = '')
    $val = Get-SafeProp $Obj $Name
    if ($val) { return (@($val) -join '; ') }
    return $Fallback
}

function Remove-ReadOnlyFields {
    <# Returns a copy of an NSX object without the read-only / server-managed
       fields, ready to send back with PATCH/PUT. #>
    param([object]$Obj)
    $clone = $Obj | ConvertTo-Json -Depth 50 | ConvertFrom-Json
    foreach ($field in @('_create_time', '_last_modified_time', '_system_owned', '_revision',
            '_create_user', '_last_modified_user', '_protection', '_links', '_self', '_schema')) {
        if ($clone.PSObject.Properties[$field]) { $clone.PSObject.Properties.Remove($field) }
    }
    return $clone
}

function Test-IsServiceGroup {
    <# In the NSX Policy API every object under /infra/services has
       resource_type 'Service'; there is no separate service-group type.
       A "service group" is a Service whose entries are ALL
       NestedServiceServiceEntry (references to other services). #>
    param([object]$Service)
    $entries = Get-SafeProp $Service 'service_entries'
    if (-not $entries) { return $false }
    $entries = @($entries)
    $nested  = @($entries | Where-Object { (Get-SafeProp $_ 'resource_type') -eq 'NestedServiceServiceEntry' })
    return ($nested.Count -gt 0 -and $nested.Count -eq $entries.Count)
}

function Get-GroupDependency {
    <# Ids of the groups a security group references (PathExpression paths,
       at any depth inside NestedExpression blocks). #>
    param([object]$Group)
    $deps  = [System.Collections.Generic.List[string]]::new()
    $queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($e in @(Get-SafeProp $Group 'expression')) { if ($null -ne $e) { $queue.Enqueue($e) } }
    while ($queue.Count -gt 0) {
        $expr = $queue.Dequeue()
        switch (Get-SafeProp $expr 'resource_type') {
            'NestedExpression' {
                foreach ($inner in @(Get-SafeProp $expr 'expressions')) { if ($null -ne $inner) { $queue.Enqueue($inner) } }
            }
            'PathExpression' {
                foreach ($p in @(Get-SafeProp $expr 'paths')) {
                    if ("$p" -match '/groups/([^/]+)$') { $deps.Add($Matches[1]) }
                }
            }
        }
    }
    return @($deps | Select-Object -Unique)
}

function Get-ServiceDependency {
    <# Ids of the services a service (group) references: nested service
       entries and, for older objects, members[].path. #>
    param([object]$Service)
    $deps = [System.Collections.Generic.List[string]]::new()
    foreach ($m in @(Get-SafeProp $Service 'members')) {
        $p = Get-SafeProp $m 'path'
        if ("$p" -match '/services/([^/]+)$') { $deps.Add($Matches[1]) }
    }
    foreach ($e in @(Get-SafeProp $Service 'service_entries')) {
        if ((Get-SafeProp $e 'resource_type') -eq 'NestedServiceServiceEntry') {
            $p = Get-SafeProp $e 'nested_service_path'
            if ("$p" -match '/services/([^/]+)$') { $deps.Add($Matches[1]) }
        }
    }
    return @($deps | Select-Object -Unique)
}

function Get-DependencyOrder {
    <# Topological sort (iterative post-order DFS, no recursion).
       Returns -Items ordered so every item comes AFTER the items it depends on
       (create order). With -Reverse, every item comes BEFORE the items it
       depends on (delete order). Dependencies that are not in -Items are
       ignored; circular dependencies are logged and broken.
         -IdOf            { param($item) ... }  -> the item's Id
         -DependenciesOf  { param($item) ... }  -> Ids the item depends on #>
    param(
        [object[]]$Items,
        [Parameter(Mandatory)][scriptblock]$IdOf,
        [Parameter(Mandatory)][scriptblock]$DependenciesOf,
        [switch]$Reverse,
        [string]$Label = 'object'
    )
    $order  = [System.Collections.Generic.List[string]]::new()
    $lookup = @{}
    $depMap = @{}
    foreach ($item in @($Items)) {
        if ($null -eq $item) { continue }
        $id = & $IdOf $item
        if ($lookup.ContainsKey($id)) { continue }
        $order.Add($id)
        $lookup[$id] = $item
        $depMap[$id] = @(& $DependenciesOf $item)
    }

    $sorted  = [System.Collections.Generic.List[object]]::new()
    $visited = @{}   # 1 = in progress, 2 = done

    foreach ($startId in $order) {
        if ($visited.ContainsKey($startId)) { continue }
        $stack = [System.Collections.Generic.Stack[hashtable]]::new()
        $stack.Push(@{ Id = $startId; Index = 0 })
        $visited[$startId] = 1

        while ($stack.Count -gt 0) {
            $frame = $stack.Peek()
            $deps  = $depMap[$frame.Id]
            if ($frame.Index -lt $deps.Count) {
                $depId = $deps[$frame.Index]
                $frame.Index++
                if (-not $lookup.ContainsKey($depId)) { continue }
                $state = if ($visited.ContainsKey($depId)) { $visited[$depId] } else { 0 }
                if ($state -eq 1) { Write-Log "    Circular $Label dependency between '$($frame.Id)' and '$depId' — continuing." WARN; continue }
                if ($state -eq 2) { continue }
                $visited[$depId] = 1
                $stack.Push(@{ Id = $depId; Index = 0 })
            }
            else {
                $stack.Pop() | Out-Null
                $visited[$frame.Id] = 2
                $sorted.Add($lookup[$frame.Id])
            }
        }
    }

    $result = $sorted.ToArray()
    if ($Reverse) { [Array]::Reverse($result) }
    return $result
}

# ═════════════════════════════════════════════════════════════
# CSV FILES
# ═════════════════════════════════════════════════════════════
function Resolve-CsvFile {
    <# Returns the full path of the CSV file to use for one object type:
         1. -Path, when the matching -<Type>Csv parameter was given
            (unattended runs, or no GUI available);
         2. otherwise a Windows file dialog, filtered to CSV files and
            starting in -InitialFolder.
       Throws when the file does not exist, the dialog is cancelled, or no
       dialog is available and no path was given. #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [string]$Path,
        [string]$InitialFolder,
        [string]$ParameterName
    )
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "[$Label] CSV file not found: $Path" }
        $full = (Resolve-Path -LiteralPath $Path).Path
        Write-Log "  [$Label] Using: $full" SUCCESS
        return $full
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    }
    catch {
        $hint = if ($ParameterName) { " Pass the file with -$ParameterName." } else { '' }
        throw "[$Label] No file dialog available on this platform.$hint"
    }

    $dialog                  = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title            = "[$Label] Select the CSV file"
    if ($InitialFolder) { $dialog.InitialDirectory = $InitialFolder }
    $dialog.Filter           = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $dialog.FilterIndex      = 1
    $dialog.Multiselect      = $false

    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        throw "[$Label] File selection cancelled."
    }
    Write-Log "  [$Label] Selected: $(Split-Path $dialog.FileName -Leaf)" SUCCESS
    return $dialog.FileName
}

function Read-CsvFile {
    <# Loads a CSV file (UTF-8) and logs the row count. #>
    param([Parameter(Mandatory)][string]$Path, [string]$Label = 'CSV')
    $rows = @(Import-Csv -Path $Path -Encoding UTF8)
    Write-Log "  [$Label] Loaded $($rows.Count) rows from $(Split-Path $Path -Leaf)" INFO
    return $rows
}

# ═════════════════════════════════════════════════════════════
# SANITIZATION
# ═════════════════════════════════════════════════════════════
function ConvertTo-NSXId {
    <# Replaces characters that are invalid in NSX Ids with a hyphen. #>
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return [regex]::Replace($Value.Trim(), '[^a-zA-Z0-9_-]', '-')
}

function Get-UniqueNewId {
    <# Assigns new Ids (from DisplayName) that are unique within a scope (all
       rows, or one policy for rules). Duplicate DisplayNames get a numeric
       suffix (-1, -2, ...); rows with an empty DisplayName keep their old Id;
       a final check makes sure no Id is used twice in the same scope or is
       one of -ReservedIds (Ids already taken elsewhere, e.g. services when the
       service groups file is processed).
       Returns the new Ids in the same order as -Rows. #>
    param(
        [object[]]$Rows,
        [Parameter(Mandatory)][scriptblock]$ScopeOf,
        [string]$Label = 'Ids',
        [string[]]$ReservedIds = @()
    )
    $count = @{}
    foreach ($row in $Rows) {
        $sanitized = ConvertTo-NSXId $row.DisplayName
        if (-not $sanitized) { continue }
        $key = "$(& $ScopeOf $row)`0$sanitized"
        $count[$key] = ($count[$key] -as [int]) + 1
    }

    $counter  = @{}
    $taken    = @{}
    $reserved = [System.Collections.Generic.HashSet[string]]::new([string[]]@($ReservedIds | Where-Object { $_ }))
    $newIds   = [System.Collections.Generic.List[string]]::new()

    foreach ($row in $Rows) {
        $scope     = & $ScopeOf $row
        $oldId     = $row.Id.Trim()
        $sanitized = ConvertTo-NSXId $row.DisplayName
        $key       = "$scope`0$sanitized"

        if (-not $sanitized) {
            Write-Log "  [$Label] '$oldId' has an empty DisplayName - keeping its Id." WARN
            $newId = $oldId
        }
        elseif ($count[$key] -gt 1) {
            $counter[$key] = ($counter[$key] -as [int]) + 1
            $newId = "$sanitized-$($counter[$key])"
            Write-Log "  [$Label] Duplicate DisplayName '$sanitized' - assigned '$newId' to Id '$oldId'." WARN
        }
        else {
            $newId = $sanitized
        }

        $candidate = $newId
        $n = 1
        while ($taken.ContainsKey("$scope`0$candidate") -or ($candidate -ne $oldId -and $reserved.Contains($candidate))) {
            $n++
            $candidate = "$newId-$n"
        }
        if ($candidate -ne $newId) {
            Write-Log "  [$Label] Id '$newId' already assigned - using '$candidate' for '$oldId'." WARN
        }
        $taken["$scope`0$candidate"] = $true
        $newIds.Add($candidate)
    }
    return , $newIds.ToArray()
}

function ConvertFrom-UnicodeEscape {
    <# Decodes \uXXXX escapes in a JSON string so Ids and names match
       plain-text patterns. Characters that must stay escaped inside a JSON
       string (double quote, backslash, control characters) are left encoded so
       the JSON stays valid; an escaped backslash followed by "u" (\\u0041) is
       not an escape and is left alone. #>
    param([string]$Text)
    if (-not $Text) { return $Text }
    return [regex]::Replace($Text, '(?<=(?:^|[^\\])(?:\\\\)*)\\u([0-9a-fA-F]{4})', {
            param($m)
            $code = [convert]::ToInt32($m.Groups[1].Value, 16)
            if ($code -lt 0x20 -or $code -eq 0x22 -or $code -eq 0x5C) { return $m.Value }
            return [string][char]$code
        })
}

function New-IdPathRegex {
    <# ONE regex that matches any old Id directly after /<Segment>/, so all Ids
       are replaced in a single pass (a new Id that equals another old Id is
       never replaced again). Longest Ids first, so an Id that is a prefix of
       another (IPNET_DATA-SER4 vs IPNET_DATA-SER4/4A) never wins. The match
       must end at '/', '"' (end of a JSON string) or end-of-string (CSV
       column). Returns $null for an empty map. #>
    param([hashtable]$Map, [Parameter(Mandatory)][string]$Segment)
    if (-not $Map -or $Map.Count -eq 0) { return $null }
    $alternation = ($Map.Keys | Sort-Object { $_.Length } -Descending |
        ForEach-Object { [regex]::Escape($_) }) -join '|'
    return [regex]::new("(?<=/$([regex]::Escape($Segment))/)(?:$alternation)(?=/|""|$)")
}

function Update-IdPath {
    <# Applies a regex from New-IdPathRegex: every matched old Id -> $Map[old]. #>
    param([string]$Text, [regex]$Regex, [hashtable]$Map)
    if (-not $Text -or -not $Regex) { return $Text }
    return $Regex.Replace($Text, { param($m) $Map[$m.Value] })
}

function Set-JsonIdentity {
    <# Sets id, relative_path and display_name to -NewId and replaces the
       /<PathSegment>/<OldId> segment at the end of "path". Works on the parsed
       object, so it does not depend on field order or the domain. #>
    param([string]$Json, [string]$OldId, [string]$NewId, [string]$PathSegment)
    $obj = $Json | ConvertFrom-Json
    foreach ($field in @('id', 'relative_path', 'display_name')) {
        if ($obj.PSObject.Properties[$field]) { $obj.$field = $NewId }
    }
    if ($obj.PSObject.Properties['path'] -and $obj.path) {
        $pattern = "(?<=/$([regex]::Escape($PathSegment))/)$([regex]::Escape($OldId))$"
        $obj.path = [regex]::Replace($obj.path, $pattern, { param($m) $NewId })
    }
    return ($obj | ConvertTo-Json -Depth 50 -Compress)
}

function Clear-JsonTag {
    <# Replaces every "tags":[...] array with "tags":[]. JSON strings inside
       the array are matched whole, so a ']' in a tag value is safe. #>
    param([string]$Json)
    return [regex]::Replace($Json, '"tags":\[(?:[^\[\]"]|"(?:[^"\\]|\\.)*")*\]', '"tags":[]')
}

function Clear-JsonDescription {
    <# Clears every "description" value; escaped quotes (\") are handled. #>
    param([string]$Json)
    return [regex]::Replace($Json, '"description":"(?:[^"\\]|\\.)*"', '"description":""')
}

function Remove-UnusedTag {
    <# Removes the tags of an object, but KEEPS every tag whose scope|value or
       bare value is in -InUseTags (used in group membership conditions, see
       Get-NSXTagsInUse) and logs a warning for each kept tag. #>
    param([string]$Json, [string]$ObjectId, [hashtable]$InUseTags = @{})
    try {
        $obj  = $Json | ConvertFrom-Json
        $tags = if ($obj.PSObject.Properties['tags']) { @($obj.tags) } else { @() }
        if ($tags.Count -eq 0) { return $Json }

        $keep = [System.Collections.Generic.List[object]]::new()
        foreach ($tag in $tags) {
            $scope = if ($tag.PSObject.Properties['scope']) { $tag.scope } else { '' }
            $value = if ($tag.PSObject.Properties['tag']) { $tag.tag } else { '' }

            # Tag conditions use "scope|value" when a scope is set, or the bare value
            $usedBy = @()
            if ($scope -and $InUseTags.ContainsKey("$scope|$value")) { $usedBy += $InUseTags["$scope|$value"] }
            if ($value -and $InUseTags.ContainsKey($value)) { $usedBy += $InUseTags[$value] }
            $usedBy = @($usedBy | Select-Object -Unique)

            if ($usedBy.Count -gt 0) {
                $keep.Add($tag)
                Write-Log "  [TagCheck] Keeping tag '$($scope):$value' on '$ObjectId' — referenced by group(s): $($usedBy -join ', ')" WARN
            }
        }
        $obj.tags = $keep.ToArray()
        return ($obj | ConvertTo-Json -Depth 50 -Compress)
    }
    catch {
        Write-Log "  [TagCheck] Could not parse tags for '$ObjectId' — removing all tags: $_" WARN
        return (Clear-JsonTag -Json $Json)
    }
}

function Rename-NSXObjectId {
    <# The rename step shared by Sanitize-NSXGroups.ps1 and Sanitize-NSXServices.ps1.
       For every CSV row: new Id = sanitized DisplayName (unique, see
       Get-UniqueNewId); every /<Segment>/<oldId> path in every row is
       rewritten in one pass; id / relative_path / display_name are set on
       the parsed JSON; tags are removed unless they are in -InUseTags; the
       Tags column is rebuilt. Rows are changed in place.
         -Segment      'groups' or 'services'
         -SeedMap      renames from an earlier pass (e.g. services, when the
                       service groups file is processed); applied to paths
                       but not logged again
         -ReservedIds  Ids that may not be assigned (see Get-UniqueNewId)
       Returns @{ Map = oldId -> newId (incl. seed); Log = renamed rows }. #>
    param(
        [object[]]$Rows,
        [Parameter(Mandatory)][string]$Segment,
        [string]$Label = $Segment,
        [hashtable]$InUseTags = @{},
        [hashtable]$SeedMap = @{},
        [string[]]$ReservedIds = @()
    )
    $idMap = @{}
    foreach ($key in $SeedMap.Keys) { $idMap[$key] = $SeedMap[$key] }

    $newIds = Get-UniqueNewId -Rows $Rows -ScopeOf { param($r) 'all' } -Label $Label -ReservedIds $ReservedIds
    for ($i = 0; $i -lt @($Rows).Count; $i++) {
        $oldId = $Rows[$i].Id.Trim()
        $newId = $newIds[$i]
        if ($oldId -ne $newId) {
            if ($idMap.ContainsKey($oldId)) { Write-Log "  [$Label] Duplicate old ID '$oldId' — skipping." WARN }
            else { $idMap[$oldId] = $newId }
        }
    }
    Write-Log "  [$Label] $($idMap.Count - $SeedMap.Count) ID(s) need renaming." INFO

    $regex = New-IdPathRegex -Map $idMap -Segment $Segment
    $log   = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($row in $Rows) {
        $oldId = $row.Id.Trim()
        $row.RawJson = ConvertFrom-UnicodeEscape -Text $row.RawJson

        # All /<Segment>/<oldId> paths (own path and references to other
        # objects) are rewritten in ONE pass first, so a new Id is never
        # renamed again; then id / relative_path / display_name.
        $json = Update-IdPath -Text $row.RawJson -Regex $regex -Map $idMap
        if ($idMap.ContainsKey($oldId) -and -not $SeedMap.ContainsKey($oldId)) {
            $newId = $idMap[$oldId]
            $row.Id          = $newId
            $row.DisplayName = $newId
            $json = Set-JsonIdentity -Json $json -OldId $oldId -NewId $newId -PathSegment $Segment
            $log.Add([PSCustomObject]@{ OldId = $oldId; NewId = $newId })
        }
        $row.RawJson = Remove-UnusedTag -Json $json -ObjectId $row.Id -InUseTags $InUseTags

        # Rebuild the Tags CSV column from whatever tags survived
        if ($row.PSObject.Properties['Tags']) { $row.Tags = Format-TagColumn -Json $row.RawJson }
    }
    return @{ Map = $idMap; Log = $log.ToArray() }
}

function Export-IdMappingCsv {
    <# Writes an Id mapping log (OldId/NewId, optionally PolicyId). An empty
       log still gets a header row, so the file is always a valid CSV. #>
    param([object[]]$Rows, [Parameter(Mandatory)][string]$Path, [string[]]$Columns = @('OldId', 'NewId'))
    if (@($Rows | Where-Object { $_ }).Count -gt 0) {
        $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
    else {
        (($Columns | ForEach-Object { '"' + $_ + '"' }) -join ',') | Set-Content -Path $Path -Encoding UTF8
    }
}

function Format-TagColumn {
    <# The CSV Tags column ("scope:tag; ...") rebuilt from RawJson. #>
    param([string]$Json)
    try {
        $obj = $Json | ConvertFrom-Json
        return (Format-Tags $obj)
    }
    catch { return '' }
}

# ═════════════════════════════════════════════════════════════
# TAG SAFETY CHECK
# ═════════════════════════════════════════════════════════════
function Get-NSXTagsInUse {
    <# Discovers which tag scope:value pairs are referenced by security group
       Condition expressions (key = Tag, any member_type), so sanitization can
       keep those tags instead of removing them as migration artefacts.
       Stripping a tag that a group condition matches on would silently remove
       objects from that group, without any API error.

       Phase 1 (always): scans the groups CSV (RawJson of every exported group).
       Phase 2 (when -NSXManager and -Headers are given): scans the
       system-owned groups on the live NSX Manager, which are not in the CSV.
       If phase 2 fails, a warning is logged and the CSV results are returned.

       Returns a hashtable: key "scope|value" (or bare "value") ->
       array of "GroupName [member_type=X] [source=csv|system]".

       Known limitation: Gateway Firewall policy conditions are not scanned. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupsCsv,
        [string]$NSXManager = '',
        [hashtable]$Headers = @{},
        [string]$DomainId = 'default'
    )

    $inUse = @{}

    # Scans a list of parsed groups; returns the number of NEW tag values found.
    $scan = {
        param([object[]]$Groups, [string]$Source)
        $newTags = 0
        foreach ($grp in $Groups) {
            $grpName = if (Get-SafeProp $grp 'display_name') { $grp.display_name } else { Get-SafeProp $grp 'id' }
            $queue = [System.Collections.Generic.Queue[object]]::new()
            foreach ($e in @(Get-SafeProp $grp 'expression')) { if ($null -ne $e) { $queue.Enqueue($e) } }
            while ($queue.Count -gt 0) {
                $e = $queue.Dequeue()
                $type = Get-SafeProp $e 'resource_type'
                if ($type -eq 'NestedExpression') {
                    foreach ($inner in @(Get-SafeProp $e 'expressions')) { if ($null -ne $inner) { $queue.Enqueue($inner) } }
                    continue
                }
                if ($type -ne 'Condition' -or (Get-SafeProp $e 'key') -ne 'Tag') { continue }
                $tagValue = Get-SafeProp $e 'value'
                if (-not $tagValue) { continue }
                $memberType = Get-SafeProp $e 'member_type'
                if (-not $memberType) { $memberType = 'Unknown' }
                if (-not $inUse.ContainsKey($tagValue)) { $inUse[$tagValue] = @(); $newTags++ }
                $inUse[$tagValue] += "$grpName [member_type=$memberType] [source=$Source]"
            }
        }
        return $newTags
    }

    # ── Phase 1 — CSV scan ─────────────────────────────────
    Write-Log "  [TagCheck] Phase 1: scanning exported groups CSV..." INFO
    if (-not (Test-Path $GroupsCsv)) {
        Write-Log "  [TagCheck] Groups CSV not found at '$GroupsCsv' — phase 1 skipped." WARN
    }
    else {
        $csvRows = @(Import-Csv -Path $GroupsCsv -Encoding UTF8)
        $parsed  = [System.Collections.Generic.List[object]]::new()
        foreach ($row in $csvRows) {
            try { $parsed.Add(($row.RawJson | ConvertFrom-Json)) }
            catch { Write-Log "  [TagCheck] Could not parse RawJson for group '$($row.Id)': $_" WARN }
        }
        $found = & $scan $parsed.ToArray() 'csv'
        Write-Log "  [TagCheck] Phase 1 complete: $($csvRows.Count) group(s) scanned, $found tag value(s) in use." INFO
    }

    # ── Phase 2 — system-owned groups on the live NSX Manager ──
    if (-not $NSXManager -or $Headers.Count -eq 0) {
        Write-Log "  [TagCheck] Phase 2 skipped: no NSX Manager connection. System-owned groups are NOT checked." WARN
        Write-Log "  [TagCheck] This is safe when no system-owned group uses a member_type=Group Tag condition (the common case)." WARN
    }
    else {
        Write-Log "  [TagCheck] Phase 2: scanning system-owned groups on $NSXManager (domain $DomainId)..." INFO
        try {
            $sysGroups = Get-NSXAllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups?_system_owned=true" -Manager $NSXManager -Headers $Headers
            $found = & $scan $sysGroups 'system'
            Write-Log "  [TagCheck] Phase 2 complete: $(@($sysGroups).Count) system-owned group(s) scanned, $found additional tag value(s) in use." INFO
        }
        catch {
            Write-Log "  [TagCheck] Phase 2 failed — $_ — continuing with the CSV results only. System-owned groups were NOT checked." WARN
        }
    }

    Write-Log "  [TagCheck] Total: $($inUse.Count) tag value(s) in use." INFO
    foreach ($k in ($inUse.Keys | Sort-Object)) {
        Write-Log "    '$k'  →  $($inUse[$k] -join ' | ')" WARN
    }
    return $inUse
}
