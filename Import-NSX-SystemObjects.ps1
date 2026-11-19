#Requires -Version 5.1
<#
.SYNOPSIS
    STEP 3b of 4 — Re-applies user-modified fields (tags, description) onto NSX system-owned objects.

.DESCRIPTION
    Reads the CSV files produced by Export-NSX-SystemObjects.ps1 and applies the
    exported 'tags' and 'description' values onto the matching system-owned
    objects on the destination NSX 9 Manager.

    System-owned objects already exist on every NSX deployment and cannot be
    created or deleted. This script only updates their user-modifiable fields:
    it reads the current object, sets tags and description, and PATCHes it back
    with the X-Allow-Overwrite: true header that system-owned objects require.

    FILE RESOLUTION
    ---------------
    Same as Import-NSX-DFW.ps1: the CSV file for each enabled type comes from
    -ServicesCsv / -GroupsCsv when given; otherwise a Windows file dialog opens
    in -InputFolder (NSX_SystemServices.csv / NSX_SystemGroups.csv).

.PARAMETER NSXManager
    FQDN or IP of the destination NSX 9 Manager.

.PARAMETER InputFolder
    Folder containing the CSV files produced by Export-NSX-SystemObjects.ps1.

.PARAMETER ImportServices
    Import system-owned service modifications. Default: $false

.PARAMETER ImportGroups
    Import system-owned group modifications. Default: $false

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER ServicesCsv
    CSV file for -ImportServices (skips the file dialog). Same for -GroupsCsv.

.PARAMETER Credential
    Credentials for the NSX Manager. Prompted for when omitted.

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Import-NSX-SystemObjects_<timestamp>.log in the current folder.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    .\Import-NSX-SystemObjects.ps1 -NSXManager nsx9.corp.local `
        -InputFolder .\NSX_SystemObjects_Export_20250101_120000 -ImportServices $true -ImportGroups $true

.EXAMPLE
    .\Import-NSX-SystemObjects.ps1 -NSXManager nsx9.corp.local `
        -InputFolder .\NSX_SystemObjects_Export_20250101_120000 -ImportGroups $true -WhatIf

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error, 2 = finished with errors.

    Changelog:
      1.0.0  Initial release.
      1.1.0  Bug fixes from code review: tags always sent as an array (also
             repairs old single-tag CSVs); existence check only treats 404 as
             missing; default log file; PowerShell 6+/7 certificates; UTF-8 BOM.
      1.2.0  Standard toolkit layout on NSX-Common.ps1: shared logging,
             connection and REST helpers; CSV files are selected like in
             Import-NSX-DFW.ps1 (file dialog or -ServicesCsv / -GroupsCsv;
             previously fixed file names); one Import-SystemObjectChange
             function for services and groups; new -Credential parameter;
             exit codes 0/1/2.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [Parameter(Mandatory)][string]$InputFolder,

    # What to import — all default to $false
    [bool]$ImportServices = $false,
    [bool]$ImportGroups   = $false,

    # Options
    [string]$DomainId = 'default',

    # CSV files (skip the file dialog for that type)
    [string]$ServicesCsv = '',
    [string]$GroupsCsv   = '',

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
Initialize-NSXLog -ScriptPath $PSCommandPath

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ Services = 0; Groups = 0; NotFound = 0; Errors = 0 }

# ═════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════
function Update-NSXSystemObject {
    <# Reads the current object, sets the given fields, strips the read-only
       fields and PATCHes it back with X-Allow-Overwrite: true (required for
       system-owned objects). Returns $true on success. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Fields)

    $current = Invoke-NSXGet -Path $Path
    if (-not $current) { return $false }

    foreach ($key in $Fields.Keys) {
        $current | Add-Member -NotePropertyName $key -NotePropertyValue $Fields[$key] -Force
    }
    $body = Remove-ReadOnlyFields $current | ConvertTo-Json -Depth 50 -Compress

    $overwriteHeaders = $Headers.Clone()
    $overwriteHeaders['X-Allow-Overwrite'] = 'true'
    return (Invoke-NSXPatch -Path $Path -JsonBody $body -Headers $overwriteHeaders)
}

# ═════════════════════════════════════════════════════════════
# IMPORT SYSTEM OBJECT MODIFICATIONS (services and groups)
# ═════════════════════════════════════════════════════════════
function Import-SystemObjectChange {
    <# Applies tags + description from one CSV onto the matching system-owned
       objects. -Kind selects the label, the API path and the statistic. #>
    param(
        [Parameter(Mandatory)][ValidateSet('Service', 'Group')][string]$Kind,
        [Parameter(Mandatory)][string]$CsvPath
    )
    Write-Log "━━━ Importing System $Kind Modifications ━━━" INFO
    $rows = Read-CsvFile -Path $CsvPath -Label "System ${Kind}s"
    if (-not $rows) { return }

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = if ($Kind -eq 'Service') { "/policy/api/v1/infra/services/$id" }
                else { "/policy/api/v1/infra/domains/$DomainId/groups/$id" }

        # System objects always exist on the destination — but verify just in case
        if (-not (Test-NSXObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: $Kind '$id' does not exist on destination (different NSX version?)" WARN
            $Stats.NotFound++
            continue
        }

        # TagsJson back into an array. @() keeps a single tag as an array; this
        # also repairs CSVs written by older exports (single tag as a bare object).
        $tags = @()
        try {
            if ($row.TagsJson -and $row.TagsJson -ne '[]') { $tags = @($row.TagsJson | ConvertFrom-Json) }
        }
        catch {
            Write-Log "  Could not parse TagsJson for $Kind '$id': $_" WARN
        }

        if ($PSCmdlet.ShouldProcess($id, "Update system $Kind tags/description")) {
            if (Update-NSXSystemObject -Path $path -Fields @{ tags = $tags; description = $row.Description }) {
                if ($Kind -eq 'Service') { $Stats.Services++ } else { $Stats.Groups++ }
                $tagStr = if ($row.Tags) { $row.Tags } else { '(no tags)' }
                Write-Log "  ✔ ${Kind}: $id ($($row.DisplayName)) — $tagStr" SUCCESS
            }
            else {
                $Stats.Errors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Import-NSX-SystemObjects.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

# Guard — refuse to run if no import flags are set
if (-not ($ImportServices -or $ImportGroups)) {
    Write-Log "No import actions selected. Specify at least one -Import* flag." WARN
    Write-Log "Example: -ImportServices `$true -ImportGroups `$true" WARN
    exit 0
}

if (-not (Test-Path $InputFolder)) {
    Write-Log "Input folder not found: $InputFolder" ERROR
    exit 1
}
$InputFolder = (Resolve-Path $InputFolder).Path

Write-NSXBanner -Title 'NSX SYSTEM OBJECTS IMPORT' -Details ([ordered]@{
        'Destination'     = $NSXManager
        'Input folder'    = $InputFolder
        'Domain'          = $DomainId
        'Import Services' = $ImportServices
        'Import Groups'   = $ImportGroups
    })
Write-Log " NOTE: Only 'tags' and 'description' are updated. Core definitions of system objects are immutable." WARN

$fatal = $false
try {
    $Headers = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'destination NSX Manager'

    # Upfront CSV file selection
    Write-Log "━━━ Selecting CSV files ━━━" INFO
    $servicesFile = if ($ImportServices) { Resolve-CsvFile -Label 'System Services' -Path $ServicesCsv -InitialFolder $InputFolder -ParameterName 'ServicesCsv' }
    $groupsFile   = if ($ImportGroups)   { Resolve-CsvFile -Label 'System Groups'   -Path $GroupsCsv   -InitialFolder $InputFolder -ParameterName 'GroupsCsv' }

    if ($ImportServices) { Import-SystemObjectChange -Kind Service -CsvPath $servicesFile }
    if ($ImportGroups)   { Import-SystemObjectChange -Kind Group   -CsvPath $groupsFile }
}
catch {
    Write-Log "FATAL: $_" ERROR
    $fatal = $true
}
finally {
    Write-NSXSummary -Title 'IMPORT SUMMARY' -Counts ([ordered]@{
            'System Services updated'  = $Stats.Services
            'System Groups updated'    = $Stats.Groups
            'Not found on destination' = $Stats.NotFound
            'Errors'                   = $Stats.Errors
        })
}

if ($fatal) { exit 1 }
if ($Stats.Errors -gt 0) { exit 2 }
exit 0
