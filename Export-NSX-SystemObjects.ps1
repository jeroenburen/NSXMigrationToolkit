#Requires -Version 5.1
<#
.SYNOPSIS
    STEP 1b of 4 — Exports user-modifiable fields of NSX system-owned Services and Groups to CSV.

.DESCRIPTION
    System-owned objects (built-in NSX services like HTTPS, DNS, and default
    groups) cannot be created or deleted, but their 'tags' and 'description'
    fields can be modified by users. This script exports those fields so they
    can be re-applied on a destination NSX 9 Manager using
    Import-NSX-SystemObjects.ps1 (step 3b).

    Exports to:
      - NSX_SystemServices.csv   — system-owned services with user-modified fields
      - NSX_SystemGroups.csv     — system-owned groups with user-modified fields

.PARAMETER NSXManager
    FQDN or IP of the source NSX 4 Manager.

.PARAMETER ExportServices
    Export system-owned Services. Default: $false

.PARAMETER ExportGroups
    Export system-owned Groups. Default: $false

.PARAMETER OnlyModified
    When $true (default), only export objects that have tags or a non-empty
    description, since unmodified system objects require no action on the
    destination. Set to $false to export ALL system-owned objects.

.PARAMETER OutputFolder
    Folder where CSV files will be written. Created if it doesn't exist.
    Default: .\NSX_SystemObjects_Export_<timestamp>

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER Credential
    Credentials for the NSX Manager. Prompted for when omitted.

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Export-NSX-SystemObjects_<timestamp>.log in -OutputFolder.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    .\Export-NSX-SystemObjects.ps1 -NSXManager nsx4.corp.local -ExportServices $true -ExportGroups $true

.EXAMPLE
    .\Export-NSX-SystemObjects.ps1 -NSXManager nsx4.corp.local -ExportGroups $true -OnlyModified $false

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error, 2 = finished with errors.

    Changelog:
      1.0.0  Initial release.
      1.1.0  Bug fixes from code review: a single tag is exported as a JSON
             array; per-section skipped counts; pagination fixed;
             PowerShell 6+/7 certificates; UTF-8 BOM.
      1.2.0  Standard toolkit layout on NSX-Common.ps1: logging with
             -LogTarget/-LogFile like the other scripts (was Start-Transcript
             with -LogFile); new -Credential parameter; exit codes 0/1/2.
             -ExportServices and -ExportGroups now default to $false, like
             every other action flag in the toolkit, and the script stops with
             a message when neither is set.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NSXManager,

    # What to export — all default to $false
    [bool]$ExportServices = $false,
    [bool]$ExportGroups   = $false,

    # Options
    [bool]$OnlyModified   = $true,
    [string]$OutputFolder = ".\NSX_SystemObjects_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$DomainId     = 'default',

    # Connection and logging
    [pscredential]$Credential,
    [string]$LogFile = '',
    [ValidateSet('Screen', 'File', 'Both')]
    [string]$LogTarget = 'Screen'
)

$ScriptVersion = '1.2.0'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'NSX-Common.ps1')

# The output folder is created first: the default log file lives in it.
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }
$OutputFolder = (Resolve-Path $OutputFolder).Path
Initialize-NSXLog -ScriptPath $PSCommandPath -Folder $OutputFolder

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ Services = 0; Groups = 0; Skipped = 0; Errors = 0 }

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
function Test-UserModification {
    # $true when the object has any tags or a non-empty description
    param([object]$Obj)
    $tags = Get-SafeProp $Obj 'tags'
    $desc = Get-SafeProp $Obj 'description'
    return ($tags -and @($tags).Count -gt 0) -or ($desc -and $desc.Trim() -ne '')
}

# ═════════════════════════════════════════════════════════════
# 1. EXPORT SYSTEM-OWNED SERVICES
# ═════════════════════════════════════════════════════════════
function Export-SystemServices {
    Write-Log "━━━ Exporting System-Owned Services ━━━" INFO
    $all    = Get-NSXAllPages -Path "/policy/api/v1/infra/services"
    $system = $all | Where-Object { (Get-SafeProp $_ '_system_owned') -eq $true }

    if (-not $system) { Write-Log "No system-owned Services found." WARN; return }
    Write-Log "  Found $(@($system).Count) system-owned services total." INFO

    $skipped = 0
    $rows = foreach ($svc in $system) {
        if ($OnlyModified -and -not (Test-UserModification $svc)) {
            $skipped++
            continue
        }

        [PSCustomObject]@{
            ObjectType   = 'SystemService'
            Id           = $svc.id
            DisplayName  = $svc.display_name
            Description  = (Get-SafeProp $svc 'description')
            Tags         = (Format-Tags $svc)
            # Store tags as JSON for reliable round-trip on import
            # -InputObject @(...) keeps a single tag as a JSON array ([{...}])
            # instead of a bare object, which NSX rejects on import.
            TagsJson     = ConvertTo-Json -InputObject @(Get-SafeProp $svc 'tags' | Where-Object { $_ }) -Depth 5 -Compress
        }
    }

    # Count per section; previously one shared counter made the groups
    # message include the skipped services as well.
    $Stats.Skipped += $skipped

    if (-not $rows) {
        Write-Log "  No system services with user modifications found." WARN
        return
    }

    $csvPath = Join-Path $OutputFolder 'NSX_SystemServices.csv'
    @($rows) | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.Services = @($rows).Count
    Write-Log "  Exported $($Stats.Services) system services → $csvPath" SUCCESS
    if ($OnlyModified) {
        Write-Log "  ($skipped unmodified system services skipped)" INFO
    }
}

# ═════════════════════════════════════════════════════════════
# 2. EXPORT SYSTEM-OWNED GROUPS
# ═════════════════════════════════════════════════════════════
function Export-SystemGroups {
    Write-Log "━━━ Exporting System-Owned Groups ━━━" INFO
    $all    = Get-NSXAllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups"
    $system = $all | Where-Object { (Get-SafeProp $_ '_system_owned') -eq $true }

    if (-not $system) { Write-Log "No system-owned Groups found." WARN; return }
    Write-Log "  Found $(@($system).Count) system-owned groups total." INFO

    $skipped = 0
    $rows = foreach ($grp in $system) {
        if ($OnlyModified -and -not (Test-UserModification $grp)) {
            $skipped++
            continue
        }

        [PSCustomObject]@{
            ObjectType  = 'SystemGroup'
            Id          = $grp.id
            DisplayName = $grp.display_name
            Description = (Get-SafeProp $grp 'description')
            Tags        = (Format-Tags $grp)
            # -InputObject @(...) keeps a single tag as a JSON array ([{...}])
            # instead of a bare object, which NSX rejects on import.
            TagsJson    = ConvertTo-Json -InputObject @(Get-SafeProp $grp 'tags' | Where-Object { $_ }) -Depth 5 -Compress
        }
    }

    # Count per section; previously one shared counter made the groups
    # message include the skipped services as well.
    $Stats.Skipped += $skipped

    if (-not $rows) {
        Write-Log "  No system groups with user modifications found." WARN
        return
    }

    $csvPath = Join-Path $OutputFolder 'NSX_SystemGroups.csv'
    @($rows) | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.Groups = @($rows).Count
    Write-Log "  Exported $($Stats.Groups) system groups → $csvPath" SUCCESS
    if ($OnlyModified) {
        Write-Log "  ($skipped unmodified system groups skipped)" INFO
    }
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Export-NSX-SystemObjects.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

# Guard — refuse to run if no export flags are set
if (-not ($ExportServices -or $ExportGroups)) {
    Write-Log "No export actions selected. Specify at least one -Export* flag." WARN
    Write-Log "Example: -ExportServices `$true -ExportGroups `$true" WARN
    exit 0
}

Write-NSXBanner -Title 'NSX SYSTEM OBJECTS EXPORT' -Details ([ordered]@{
        'Source'          = $NSXManager
        'Output'          = $OutputFolder
        'Domain'          = $DomainId
        'Only Modified'   = $OnlyModified
        'Export Services' = $ExportServices
        'Export Groups'   = $ExportGroups
    })

$fatal = $false
try {
    $Headers = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'source NSX Manager'

    if ($ExportServices) { Export-SystemServices }
    if ($ExportGroups)   { Export-SystemGroups }
}
catch {
    Write-Log "FATAL: $_" ERROR
    $fatal = $true
}
finally {
    Write-NSXSummary -Title 'EXPORT SUMMARY' -Counts ([ordered]@{
            'System Services exported' = $Stats.Services
            'System Groups exported'   = $Stats.Groups
            'Unmodified (skipped)'     = $Stats.Skipped
            'Errors'                   = $Stats.Errors
        }) -Footer @(
        "Output folder : $OutputFolder",
        "Next: review the CSVs, then run (step 3b)",
        "      .\Import-NSX-SystemObjects.ps1 -NSXManager <nsx9> -InputFolder '$OutputFolder' -ImportServices `$true -ImportGroups `$true"
    )
}

if ($fatal) { exit 1 }
if ($Stats.Errors -gt 0) { exit 2 }
exit 0
