#Requires -Version 5.1
<#
.SYNOPSIS
    STEP 2 of 4 (part of Sanitize-NSX.ps1) — Renames security group Ids to match their DisplayName.

.DESCRIPTION
    In NSX exports, a group's Id (internal identifier) often differs from its
    DisplayName (human-readable label), for example:

      Id: securitygroup-223   DisplayName: Datacenter
      Id: ipset-286           DisplayName: IPNET_1314-ETZ_Beheer_ICT

    This script renames every group Id to its (sanitized) DisplayName and
    updates all group-to-group references so paths stay consistent.

    WHAT GETS CHANGED (renamed groups)
      CSV columns : Id and DisplayName -> new Id; Tags rebuilt
      RawJson     : id, relative_path, display_name, path; every
                    /groups/<oldId> path segment in every row (PathExpression
                    paths etc.), in ONE pass; tags removed unless in use
    New Ids are unique: duplicate DisplayNames get -1, -2 …; groups with an
    empty DisplayName keep their Id.

    TAG SAFETY CHECK
    Tags referenced by group membership conditions (key = Tag) are KEPT, with
    a warning: removing them would silently change group membership. The
    exported groups CSV is always scanned; with -NSXManager the system-owned
    groups on the live NSX Manager are scanned as well (Get-NSXTagsInUse).

    OUTPUTS
      <InputFile>_sanitized.csv   groups CSV with corrected Ids and RawJson
      <InputFile>_id_mapping.csv  OldId -> NewId audit log (standalone mode;
                                  with -PassThruMap the map is returned instead)

.PARAMETER InputFile
    The groups CSV produced by Export-NSX-DFW.ps1 (NSX_Groups.csv).

.PARAMETER OutputFile
    Sanitized CSV. Default: <InputFile>_sanitized.csv

.PARAMETER MappingFile
    Id mapping CSV (standalone mode). Default: <InputFile>_id_mapping.csv

.PARAMETER NSXManager
    Source NSX Manager for the live tag check of system-owned groups. Optional.

.PARAMETER DomainId
    NSX Policy domain for the live tag check. Default: "default"

.PARAMETER PassThruMap
    Return the OldId -> NewId hashtable instead of writing the mapping CSV
    (used by Sanitize-NSX.ps1).

.PARAMETER InUseTags
    Result of Get-NSXTagsInUse from the caller (Sanitize-NSX.ps1 runs the tag
    check once for all steps). When given, this script does not run it again.

.PARAMETER Headers
    Request headers from a caller that is already connected (Sanitize-NSX.ps1).

.PARAMETER Credential
    Credentials for -NSXManager. Prompted for when omitted (and no -Headers).

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Sanitize-NSXGroups_<timestamp>.log in the current folder.

.PARAMETER LogTarget
    Controls where log output is written: Screen (default), File or Both.

.EXAMPLE
    .\Sanitize-NSXGroups.ps1 -InputFile .\NSX_Groups.csv -NSXManager nsx4.corp.local

.EXAMPLE
    # Offline: CSV-only tag check
    .\Sanitize-NSXGroups.ps1 -InputFile .\NSX_Groups.csv

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error.

    Changelog:
      1.0.0  Initial release.
      1.1.0  Bug fixes from code review: single-pass Id replacement (no
             chained renames); unique new Ids; renames on the parsed JSON;
             unicode decoding keeps the JSON valid; tag regex fallback fixed;
             PowerShell 6+/7 certificates.
      1.2.0  Standard toolkit layout on NSX-Common.ps1: the rename logic is
             the shared Rename-NSXObjectId (identical for groups and services)
             and Get-NSXTagsInUse moved into NSX-Common.ps1; logging through
             Write-Log with -LogTarget/-LogFile; new -Credential parameter.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputFile,

    # Options
    [string]$OutputFile  = ($InputFile -replace '\.csv$', '_sanitized.csv'),
    [string]$MappingFile = ($InputFile -replace '\.csv$', '_id_mapping.csv'),
    [string]$NSXManager  = '',
    [string]$DomainId    = 'default',
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
Write-Log "Sanitize-NSXGroups.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

try {
    if (-not (Test-Path $InputFile)) { throw "Input file not found: $InputFile" }

    # Tag safety check: CSV scan, plus the live system-owned groups when connected
    if ($PSBoundParameters.ContainsKey('InUseTags') -and $null -ne $InUseTags) {
        Write-Log "  [TagCheck] Using the tag check from the caller ($($InUseTags.Count) tag value(s) in use)." INFO
    }
    else {
        if ($NSXManager -and $Headers.Count -eq 0) {
            $Headers = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'source NSX Manager (tag check)'
        }
        $InUseTags = Get-NSXTagsInUse -GroupsCsv $InputFile -NSXManager $NSXManager -Headers $Headers -DomainId $DomainId
    }

    Write-Log "  [Groups] Reading: $InputFile" INFO
    $rows   = @(Import-Csv -Path $InputFile -Encoding UTF8)
    $result = Rename-NSXObjectId -Rows $rows -Segment 'groups' -Label 'Groups' -InUseTags $InUseTags

    Write-Log "  [Groups] Writing: $OutputFile" INFO
    $rows | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
}

if ($PassThruMap) { return $result.Map }

Write-Log "  [Groups] Writing mapping log: $MappingFile" INFO
Export-IdMappingCsv -Rows $result.Log -Path $MappingFile
Write-Log "Done! $(@($result.Log).Count) group(s) renamed." SUCCESS
exit 0
