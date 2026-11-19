#Requires -Version 5.1
<#
.SYNOPSIS
    STEP 2 of 4 (part of Sanitize-NSX.ps1) — Renames DFW policy and rule Ids and updates their group/service references.

.DESCRIPTION
    Firewall rules and policies reference groups and services by Id inside
    full NSX paths (e.g. /infra/domains/default/groups/securitygroup-223).
    After Sanitize-NSXGroups.ps1 / Sanitize-NSXServices.ps1 rename those Ids,
    these paths are stale. This script applies the same Id maps to the rules
    and policies exports, and renames policy and rule Ids to their DisplayName.

    POLICIES (NSX_Policies.csv)
      - The legacy suffix ":: NSX Service Composer - Firewall" is stripped
        from the DisplayName.
      - Id -> sanitized DisplayName (unique; duplicates get -1, -2 …;
        an empty DisplayName keeps its Id).
      - RawJson: id, relative_path, display_name, path (parsed JSON);
        scope[] group paths; description cleared; tags removed.
      - CSV: Id, DisplayName, Scope, Description, Tags.

    RULES (NSX_Rules.csv)
      - Id -> sanitized DisplayName, unique WITHIN each policy (two rules
        named "Allow web" become Allow-web-1 and Allow-web-2).
      - RawJson: id, relative_path, display_name, path; source_groups[],
        destination_groups[], scope[] (group map); services[] (service map);
        path / parent_path (policy map); tags removed.
      - CSV: Id, DisplayName, SourceGroups, DestGroups, AppliedTo, Services,
        PolicyId, PolicyName, Tags.

    All Id replacements are single-pass (a new Id that equals another old Id
    is never renamed again). Values of "ANY" and empty fields are left as-is.

    OUTPUTS
      <RulesFile>_sanitized.csv / <PoliciesFile>_sanitized.csv
      <RulesFile>_id_mapping.csv     PolicyId, OldId, NewId (rule Ids are only
                                     unique within a policy; PolicyId is the
                                     SOURCE policy Id, used by Compare)
      <PoliciesFile>_id_mapping.csv  OldId, NewId

.PARAMETER RulesFile
    NSX_Rules.csv produced by Export-NSX-DFW.ps1.

.PARAMETER PoliciesFile
    NSX_Policies.csv. Optional: when omitted only the rules are processed.

.PARAMETER IdMap
    Group OldId -> NewId hashtable (passed by Sanitize-NSX.ps1). An empty map
    is valid: it means no group was renamed.

.PARAMETER MappingFile
    Group mapping CSV from Sanitize-NSXGroups.ps1 (standalone use instead of -IdMap).

.PARAMETER ServiceIdMap
    Service OldId -> NewId hashtable (passed by Sanitize-NSX.ps1). Optional.

.PARAMETER RulesOut
    Default: <RulesFile>_sanitized.csv. Likewise -PoliciesOut,
    -RulesIdMappingFile and -PoliciesIdMappingFile.

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Sanitize-NSXFirewallRules_<timestamp>.log in the current folder.

.PARAMETER LogTarget
    Controls where log output is written: Screen (default), File or Both.

.EXAMPLE
    # Standalone, with the group mapping CSV produced by Sanitize-NSXGroups.ps1
    .\Sanitize-NSXFirewallRules.ps1 -RulesFile .\NSX_Rules.csv -PoliciesFile .\NSX_Policies.csv `
        -MappingFile .\NSX_Groups_id_mapping.csv

.EXAMPLE
    # From Sanitize-NSX.ps1, with live hashtables
    .\Sanitize-NSXFirewallRules.ps1 -RulesFile rules.csv -PoliciesFile policies.csv `
        -IdMap $groupIdMap -ServiceIdMap $serviceIdMap

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error.

    Changelog:
      1.3.5  (previous release)
      1.3.6  Bug fixes from code review: an empty -IdMap is accepted; rule Ids
             unique within each policy and empty names keep their Id;
             single-pass Id replacement; description/tag regexes and unicode
             decoding keep the JSON valid; renames on the parsed JSON (no
             field-order or 'default' domain assumptions); no null-valued
             errors without -PoliciesFile; UTF-8 BOM.
      1.4.0  Standard toolkit layout on NSX-Common.ps1: all helpers (Id
             sanitizing, unique Ids, unicode decoding, path regexes, JSON
             identity, tag/description clearing) are the shared ones; policy
             and rule processing are the functions Update-PolicyCsv and
             Update-RuleCsv; logging through Write-Log with
             -LogTarget/-LogFile; exit codes 0/1.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RulesFile,
    [string]$PoliciesFile = '',

    # Id maps: a live hashtable (from Sanitize-NSX.ps1) or a mapping CSV
    [hashtable]$IdMap,
    [string]$MappingFile = '',
    [hashtable]$ServiceIdMap = @{},

    # Outputs
    [string]$RulesOut              = ($RulesFile -replace '\.csv$', '_sanitized.csv'),
    [string]$RulesIdMappingFile    = ($RulesFile -replace '\.csv$', '_id_mapping.csv'),
    [string]$PoliciesOut           = '',
    [string]$PoliciesIdMappingFile = '',

    # Logging
    [string]$LogFile = '',
    [ValidateSet('Screen', 'File', 'Both')]
    [string]$LogTarget = 'Screen'
)

$ScriptVersion = '1.4.0'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'NSX-Common.ps1')
Initialize-NSXLog -ScriptPath $PSCommandPath

if ($PoliciesFile -and -not $PoliciesOut)           { $PoliciesOut           = $PoliciesFile -replace '\.csv$', '_sanitized.csv' }
if ($PoliciesFile -and -not $PoliciesIdMappingFile) { $PoliciesIdMappingFile = $PoliciesFile -replace '\.csv$', '_id_mapping.csv' }

# Filled in MAIN: Id maps and the single-pass path regexes built from them
$GroupMap         = @{}
$PolicyIdMap      = @{}
$GroupPathRegex   = $null
$ServicePathRegex = $null
$PolicyPathRegex  = $null

# ═════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════
function Update-GroupPaths   { param([string]$Text) Update-IdPath -Text $Text -Regex $GroupPathRegex   -Map $GroupMap }
function Update-ServicePaths { param([string]$Text) Update-IdPath -Text $Text -Regex $ServicePathRegex -Map $ServiceIdMap }
function Update-PolicyPaths  { param([string]$Text) Update-IdPath -Text $Text -Regex $PolicyPathRegex  -Map $PolicyIdMap }

function Update-PathColumn {
    <# A CSV column with ';'-separated paths (or "ANY"): each path updated
       with -Updater, then rejoined. "ANY" and empty values are left as-is. #>
    param([string]$Value, [Parameter(Mandatory)][scriptblock]$Updater)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq 'ANY') { return $Value }
    return (($Value -split ';' | ForEach-Object { & $Updater $_.Trim() }) -join '; ')
}

# ═════════════════════════════════════════════════════════════
# 1. POLICIES
# ═════════════════════════════════════════════════════════════
function Update-PolicyCsv {
    <# Renames policy Ids, updates scope group paths, clears description and
       tags. Fills $PolicyIdMap (used by the rules step). #>
    Write-Log "  [Policies] Reading: $PoliciesFile" INFO
    $policyRows = @(Import-Csv -Path $PoliciesFile -Encoding UTF8)

    # Strip the legacy suffix from the DisplayName (RawJson display_name is
    # overwritten when the Id is renamed)
    $legacySuffix = ':: NSX Service Composer - Firewall'
    foreach ($row in $policyRows) {
        if ($row.DisplayName -like "*$legacySuffix*") { $row.DisplayName = $row.DisplayName.Replace($legacySuffix, '').Trim() }
        $row.RawJson     = ConvertFrom-UnicodeEscape -Text $row.RawJson
        $row.Description = ''
        $row.RawJson     = Clear-JsonDescription -Json $row.RawJson
    }

    # Policy Id map: OldId -> sanitized DisplayName, unique across the policies
    $newIds     = Get-UniqueNewId -Rows $policyRows -ScopeOf { param($r) 'policies' } -Label 'Policies'
    $mappingLog = [System.Collections.Generic.List[PSCustomObject]]::new()
    for ($i = 0; $i -lt $policyRows.Count; $i++) {
        $oldId = $policyRows[$i].Id.Trim()
        $newId = $newIds[$i]
        if ($oldId -ne $newId) {
            if ($PolicyIdMap.ContainsKey($oldId)) { Write-Log "  [Policies] Duplicate old Id '$oldId' - skipping." WARN }
            else { $PolicyIdMap[$oldId] = $newId }
        }
        $mappingLog.Add([PSCustomObject]@{ OldId = $oldId; NewId = $newId })
    }
    Write-Log "  [Policies] $($PolicyIdMap.Count) policy Id(s) need renaming." INFO

    $updated = 0
    foreach ($row in $policyRows) {
        $oldId  = $row.Id.Trim()
        $before = $row | ConvertTo-Json -Compress

        if ($PolicyIdMap.ContainsKey($oldId)) {
            $newId           = $PolicyIdMap[$oldId]
            $row.Id          = $newId
            $row.DisplayName = $newId
            $row.RawJson     = Set-JsonIdentity -Json $row.RawJson -OldId $oldId -NewId $newId -PathSegment 'security-policies'
        }
        $row.Scope   = Update-PathColumn -Value $row.Scope -Updater { param($p) Update-GroupPaths $p }
        $row.RawJson = Clear-JsonTag -Json (Update-GroupPaths $row.RawJson)
        $row.Tags    = ''

        if ($before -ne ($row | ConvertTo-Json -Compress)) { $updated++ }
    }

    Write-Log "  [Policies] Writing: $PoliciesOut" INFO
    $policyRows | Export-Csv -Path $PoliciesOut -NoTypeInformation -Encoding UTF8
    Write-Log "  [Policies] $updated policy row(s) updated." INFO
    Write-Log "  [Policies] Writing mapping log: $PoliciesIdMappingFile" INFO
    Export-IdMappingCsv -Rows $mappingLog.ToArray() -Path $PoliciesIdMappingFile
    Write-Log "  [Policies] $($PolicyIdMap.Count) policies renamed." SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 2. RULES
# ═════════════════════════════════════════════════════════════
function Update-RuleCsv {
    <# Renames rule Ids (unique per policy) and updates group, service and
       policy references. #>
    Write-Log "  [Rules] Reading: $RulesFile" INFO
    $ruleRows = @(Import-Csv -Path $RulesFile -Encoding UTF8)
    foreach ($row in $ruleRows) { $row.RawJson = ConvertFrom-UnicodeEscape -Text $row.RawJson }

    # Rule Ids only need to be unique within their policy
    $newIds     = Get-UniqueNewId -Rows $ruleRows -ScopeOf { param($r) $r.PolicyId } -Label 'Rules'
    $mappingLog = [System.Collections.Generic.List[PSCustomObject]]::new()
    $updated    = 0

    for ($i = 0; $i -lt $ruleRows.Count; $i++) {
        $row    = $ruleRows[$i]
        $before = $row | ConvertTo-Json -Compress
        $oldId  = $row.Id.Trim()
        $newId  = $newIds[$i]

        if ($oldId -ne $newId) {
            $row.Id          = $newId
            $row.DisplayName = $newId
            $row.RawJson     = Set-JsonIdentity -Json $row.RawJson -OldId $oldId -NewId $newId -PathSegment 'rules'
            # PolicyId is the SOURCE policy Id: Compare looks rules up per source policy
            $mappingLog.Add([PSCustomObject]@{ PolicyId = $row.PolicyId; OldId = $oldId; NewId = $newId })
        }

        $row.SourceGroups = Update-PathColumn -Value $row.SourceGroups -Updater { param($p) Update-GroupPaths $p }
        $row.DestGroups   = Update-PathColumn -Value $row.DestGroups   -Updater { param($p) Update-GroupPaths $p }
        $row.AppliedTo    = Update-PathColumn -Value $row.AppliedTo    -Updater { param($p) Update-GroupPaths $p }
        $row.Services     = Update-PathColumn -Value $row.Services     -Updater { param($p) Update-ServicePaths $p }

        if ($PolicyIdMap.ContainsKey($row.PolicyId)) {
            $row.PolicyId   = $PolicyIdMap[$row.PolicyId]
            $row.PolicyName = $row.PolicyId   # PolicyName mirrors the new Id
        }

        # source_groups[] / destination_groups[] / scope[], services[], path / parent_path
        $json = Update-PolicyPaths (Update-ServicePaths (Update-GroupPaths $row.RawJson))
        $row.RawJson = Clear-JsonTag -Json $json
        $row.Tags    = ''

        if ($before -ne ($row | ConvertTo-Json -Compress)) { $updated++ }
    }

    Write-Log "  [Rules] Writing: $RulesOut" INFO
    $ruleRows | Export-Csv -Path $RulesOut -NoTypeInformation -Encoding UTF8
    Write-Log "  [Rules] $updated rule row(s) had group/service references updated." INFO
    Write-Log "  [Rules] Writing mapping log: $RulesIdMappingFile" INFO
    Export-IdMappingCsv -Rows $mappingLog.ToArray() -Path $RulesIdMappingFile -Columns @('PolicyId', 'OldId', 'NewId')
    Write-Log "  [Rules] $($mappingLog.Count) rules renamed." SUCCESS
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Sanitize-NSXFirewallRules.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

try {
    if (-not (Test-Path $RulesFile)) { throw "Input file not found: $RulesFile" }

    # Group Id map: the live hashtable when passed (an empty map is valid —
    # it means no group was renamed), otherwise the mapping CSV.
    if ($PSBoundParameters.ContainsKey('IdMap') -and $null -ne $IdMap) {
        $GroupMap = $IdMap
        Write-Log "  [Rules/Policies] Using provided group Id map ($($GroupMap.Count) entries)." INFO
    }
    elseif ($MappingFile) {
        foreach ($m in (Import-Csv -Path $MappingFile -Encoding UTF8)) { $GroupMap[$m.OldId] = $m.NewId }
        Write-Log "  [Rules/Policies] Loaded $($GroupMap.Count) group mapping(s) from $MappingFile" INFO
    }
    else {
        throw "Provide either -IdMap <hashtable> or -MappingFile <path>."
    }

    $GroupPathRegex   = New-IdPathRegex -Map $GroupMap     -Segment 'groups'
    $ServicePathRegex = New-IdPathRegex -Map $ServiceIdMap -Segment 'services'

    if ($PoliciesFile) {
        if (Test-Path $PoliciesFile) { Update-PolicyCsv }
        else { Write-Log "  [Policies] File not found, skipping: $PoliciesFile" WARN }
    }
    $PolicyPathRegex = New-IdPathRegex -Map $PolicyIdMap -Segment 'security-policies'

    Update-RuleCsv
}
catch {
    Write-Log "FATAL: $_" ERROR
    exit 1
}
exit 0
