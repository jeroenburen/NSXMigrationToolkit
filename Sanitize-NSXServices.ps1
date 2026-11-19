#Requires -Version 5.1
<#
.SYNOPSIS
    STEP 2 of 4 (part of Sanitize-NSX.ps1) — Renames service and service group Ids to match their DisplayName.

.DESCRIPTION
    In NSX exports, a service's Id can differ from its DisplayName, e.g.

      Id: application-228      DisplayName: HTTP-8080
      Id: applicationgroup-45  DisplayName: Web-Services-Group

    This script renames every Id in one services CSV (NSX_Services.csv or
    NSX_ServiceGroups.csv) to its (sanitized) DisplayName and updates all
    /services/<oldId> references — service group members
    (nested_service_path) — so paths stay consistent. It uses exactly the
    same rename logic as Sanitize-NSXGroups.ps1 (Rename-NSXObjectId).

    Process NSX_Services.csv first, then NSX_ServiceGroups.csv with
    -SeedMap <services map> -ReservedIds <service Ids>, so group members
    follow the renamed services and a group never gets a service's Id.
    Sanitize-NSX.ps1 does this for you.

    TAG SAFETY CHECK
    Same as Sanitize-NSXGroups.ps1: tags referenced by group membership
    conditions are kept. The groups CSV is scanned (-GroupsCsv); with
    -NSXManager the system-owned groups on the live NSX Manager as well.

    OUTPUTS
      <InputFile>_sanitized.csv   CSV with corrected Ids and RawJson
      <InputFile>_id_mapping.csv  OldId -> NewId audit log (standalone mode;
                                  with -PassThruMap the map is returned instead)

.PARAMETER InputFile
    NSX_Services.csv or NSX_ServiceGroups.csv produced by Export-NSX-DFW.ps1.

.PARAMETER OutputFile
    Sanitized CSV. Default: <InputFile>_sanitized.csv

.PARAMETER MappingFile
    Id mapping CSV (standalone mode). Default: <InputFile>_id_mapping.csv

.PARAMETER GroupsCsv
    Groups CSV scanned by the tag safety check.
    Default: NSX_Groups.csv in the folder of -InputFile.

.PARAMETER SeedMap
    OldId -> NewId map from an earlier pass (the services, when the service
    groups file is processed).

.PARAMETER ReservedIds
    Ids already used by an earlier pass; never assigned again.

.PARAMETER NSXManager
    Source NSX Manager for the live tag check of system-owned groups. Optional.

.PARAMETER DomainId
    NSX Policy domain for the live tag check. Default: "default"

.PARAMETER PassThruMap
    Return the OldId -> NewId hashtable (including -SeedMap) instead of
    writing the mapping CSV (used by Sanitize-NSX.ps1).

.PARAMETER InUseTags
    Result of Get-NSXTagsInUse from the caller (Sanitize-NSX.ps1 runs the tag
    check once for all steps). When given, this script does not run it again.

.PARAMETER Headers
    Request headers from a caller that is already connected (Sanitize-NSX.ps1).

.PARAMETER Credential
    Credentials for -NSXManager. Prompted for when omitted (and no -Headers).

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Sanitize-NSXServices_<timestamp>.log in the current folder.

.PARAMETER LogTarget
    Controls where log output is written: Screen (default), File or Both.

.EXAMPLE
    .\Sanitize-NSXServices.ps1 -InputFile .\NSX_Services.csv -NSXManager nsx4.corp.local

.EXAMPLE
    # Offline: CSV-only tag check
    .\Sanitize-NSXServices.ps1 -InputFile .\NSX_Services.csv

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error.

    Changelog:
      1.0.0  Initial release.
      1.1.0  Bug fixes from code review: single-pass Id replacement (no
             chained renames); unique new Ids; renames on the parsed JSON;
             unicode decoding keeps the JSON valid; tag regex fallback fixed;
             -ReservedIds; PowerShell 6+/7 certificates.
      1.2.0  Standard toolkit layout on NSX-Common.ps1: the rename logic is
             the shared Rename-NSXObjectId (identical for groups and services)
             and Get-NSXTagsInUse moved into NSX-Common.ps1; logging through
             Write-Log with -LogTarget/-LogFile; new -GroupsCsv and
             -Credential parameters.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputFile,

    # Options
    [string]$OutputFile    = ($InputFile -replace '\.csv$', '_sanitized.csv'),
    [string]$MappingFile   = ($InputFile -replace '\.csv$', '_id_mapping.csv'),
    [string]$GroupsCsv     = '',
    [hashtable]$SeedMap    = @{},
    [string[]]$ReservedIds = @(),
    [string]$NSXManager    = '',
    [string]$DomainId      = 'default',
    [switch]$PassThruMap,
    [hashtable]$InUseTags,

    # Connection and logging
    [hashtable]$Headers = @{},
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

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Sanitize-NSXServices.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

try {
    if (-not (Test-Path $InputFile)) { throw "Input file not found: $InputFile" }
    if (-not $GroupsCsv) { $GroupsCsv = Join-Path (Split-Path -Parent (Resolve-Path $InputFile).Path) 'NSX_Groups.csv' }

    # Tag safety check: groups CSV scan, plus the live system-owned groups when connected
    if ($PSBoundParameters.ContainsKey('InUseTags') -and $null -ne $InUseTags) {
        Write-Log "  [TagCheck] Using the tag check from the caller ($($InUseTags.Count) tag value(s) in use)." INFO
    }
    else {
        if ($NSXManager -and $Headers.Count -eq 0) {
            $Headers = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'source NSX Manager (tag check)'
        }
        $InUseTags = Get-NSXTagsInUse -GroupsCsv $GroupsCsv -NSXManager $NSXManager -Headers $Headers -DomainId $DomainId
    }

    Write-Log "  [Services] Reading: $InputFile" INFO
    $rows = @(Import-Csv -Path $InputFile -Encoding UTF8)
    if ($rows.Count -eq 0) {
        Write-Log "  [Services] No rows found in $InputFile — nothing to do." WARN
        $result = @{ Map = @{} + $SeedMap; Log = @() }
    }
    else {
        $result = Rename-NSXObjectId -Rows $rows -Segment 'services' -Label 'Services' `
            -InUseTags $InUseTags -SeedMap $SeedMap -ReservedIds $ReservedIds
    }

    Write-Log "  [Services] Writing: $OutputFile" INFO
    $rows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
}

if ($PassThruMap) { return $result.Map }

Write-Log "  [Services] Writing mapping log: $MappingFile" INFO
Export-IdMappingCsv -Rows $result.Log -Path $MappingFile
Write-Log "Done! $(@($result.Log).Count) service(s) renamed." SUCCESS
exit 0
