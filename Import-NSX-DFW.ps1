#Requires -Version 5.1
<#
.SYNOPSIS
    STEP 3 of 4 — Imports NSX Distributed Firewall objects from CSV files into NSX 9.

.DESCRIPTION
    Reads CSV files produced by Export-NSX-DFW.ps1 (and optionally sanitized by
    Sanitize-NSX.ps1) and creates/updates objects on an NSX 9 Manager.
    Import order respects dependencies:
      1. IP Sets (Manager API: POST to create, PUT to update)
      2. Services and/or Service Groups — one dependency-ordered pass
      3. Security Groups — dependency-ordered (nested groups first)
      4. Context Profiles
      5. DFW Policies + Rules
      6. VM Tags (added to the tags already on the VM)

    FILE RESOLUTION
    ---------------
    For every enabled -Import* type the CSV file is taken from its -<Type>Csv
    parameter when given; otherwise a Windows file dialog opens, filtered to
    CSV files and starting in -InputFolder. All files are selected upfront,
    before any import work begins. Without a GUI, pass the -<Type>Csv
    parameters.

.PARAMETER NSXManager
    FQDN or IP of the destination NSX 9 Manager.

.PARAMETER InputFolder
    Folder containing the CSV files to import (start folder of the file dialogs).

.PARAMETER ImportIPSets
    Import IP Sets. Default: $false

.PARAMETER ImportServices
    Import plain Services (NSX_Services.csv). Default: $false

.PARAMETER ImportServiceGroups
    Import Service Groups (NSX_ServiceGroups.csv). Default: $false

.PARAMETER ImportGroups
    Import Security Groups. Default: $false

.PARAMETER ImportProfiles
    Import custom Context Profiles (NSX_Profiles.csv). Default: $false

.PARAMETER ImportPolicies
    Import DFW Policies and Rules. Default: $false

.PARAMETER ImportTags
    Import VM tags onto fabric VMs. Default: $false

.PARAMETER ConflictAction
    How to handle objects that already exist on the destination.
    Values: Skip | Overwrite | Prompt | Abort. Default: Skip

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER IPSetsCsv
    CSV file for -ImportIPSets. Skips the file dialog for that type. The same
    applies to -ServicesCsv, -ServiceGroupsCsv, -GroupsCsv, -ProfilesCsv,
    -PoliciesCsv, -RulesCsv and -TagsCsv.

.PARAMETER Credential
    Credentials for the NSX Manager. Prompted for when omitted.

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Import-NSX-DFW_<timestamp>.log in the current folder.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    # File dialogs open for each selected type
    .\Import-NSX-DFW.ps1 -NSXManager nsx9.corp.local `
        -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -ImportGroups $true -ImportPolicies $true

.EXAMPLE
    # Dry run — shows what would be imported without making changes
    .\Import-NSX-DFW.ps1 -NSXManager nsx9.corp.local `
        -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -ImportGroups $true -ImportPolicies $true -WhatIf

.EXAMPLE
    # Unattended: no dialogs, credentials passed in
    .\Import-NSX-DFW.ps1 -NSXManager nsx9.corp.local -InputFolder .\export `
        -ImportGroups $true -GroupsCsv .\export\NSX_Groups_sanitized.csv `
        -Credential (Get-Credential) -LogTarget Both

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error, 2 = finished with errors.

    Changelog:
      1.0.0  Initial release.
      1.1.0  Added $ScriptVersion variable and startup version log line.
      1.2.0  Replaced hardcoded CSV filenames with auto-detection + Out-GridView
             fallback picker. Errors if file cannot be resolved.
      1.2.1  Fixed variable name collision in Import-Policies.
      1.2.2  Fixed "$label:" being parsed as a scope modifier.
      1.2.3  Renamed reserved automatic variable $pid to $policyId.
      1.3.0  Removed auto-detection of default filenames.
      1.4.0  Standard Windows file dialog (OpenFileDialog) for CSV selection.
      1.5.0  (previous release)
      1.6.0  All CSV file dialogs open upfront at script start.
      1.7.0  Added -ImportProfiles and Import-Profiles.
      1.8.0  Bug fixes from code review: existence check only treats 404 as
             missing; IP sets via POST/PUT (+_revision); VM tags via add_tags;
             services heading; default log file; PowerShell 6+/7 certificates.
      1.9.0  Standard toolkit layout on NSX-Common.ps1: shared logging,
             connection, REST, CSV and dependency-sort helpers (the two copied
             topological sorts are now Get-DependencyOrder, which also follows
             PathExpressions inside nested expressions); new -Credential and
             -<Type>Csv parameters for unattended runs; credentials and
             connectivity are checked before the file dialogs; exit codes 0/1/2.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [Parameter(Mandatory)][string]$InputFolder,

    # What to import — all default to $false
    [bool]$ImportIPSets        = $false,
    [bool]$ImportServices      = $false,
    [bool]$ImportServiceGroups = $false,
    [bool]$ImportGroups        = $false,
    [bool]$ImportProfiles      = $false,
    [bool]$ImportPolicies      = $false,
    [bool]$ImportTags          = $false,

    # Options
    [ValidateSet('Skip', 'Overwrite', 'Prompt', 'Abort')]
    [string]$ConflictAction = 'Skip',
    [string]$DomainId       = 'default',

    # CSV files (skip the file dialog for that type)
    [string]$IPSetsCsv        = '',
    [string]$ServicesCsv      = '',
    [string]$ServiceGroupsCsv = '',
    [string]$GroupsCsv        = '',
    [string]$ProfilesCsv      = '',
    [string]$PoliciesCsv      = '',
    [string]$RulesCsv         = '',
    [string]$TagsCsv          = '',

    # Connection and logging
    [pscredential]$Credential,
    [string]$LogFile = '',
    [ValidateSet('Screen', 'File', 'Both')]
    [string]$LogTarget = 'Screen'
)

$ScriptVersion = '1.9.0'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'NSX-Common.ps1')
Initialize-NSXLog -ScriptPath $PSCommandPath

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ IPSets = 0; Services = 0; ServiceGroups = 0; Groups = 0; Profiles = 0; Policies = 0; Rules = 0; Tags = 0; TagErrors = 0; Skipped = 0; Errors = 0 }

# CSV file per object type, filled in by the upfront file selection in MAIN
$Script:CsvPath_IPSets        = $null
$Script:CsvPath_Services      = $null
$Script:CsvPath_ServiceGroups = $null
$Script:CsvPath_Groups        = $null
$Script:CsvPath_Profiles      = $null
$Script:CsvPath_Policies      = $null
$Script:CsvPath_Rules         = $null
$Script:CsvPath_Tags          = $null

# ─────────────────────────────────────────────────────────────
# CONFLICT RESOLUTION
# ─────────────────────────────────────────────────────────────
function Resolve-Conflict {
    param([string]$ObjectType, [string]$ObjectId)
    switch ($ConflictAction) {
        'Skip'      { Write-Log "SKIP: $ObjectType '$ObjectId' already exists." WARN; return $false }
        'Overwrite' { Write-Log "OVERWRITE: $ObjectType '$ObjectId'." WARN; return $true }
        'Abort'     { Write-Log "ABORT: $ObjectType '$ObjectId' already exists." ERROR; throw "Conflict on $ObjectType '$ObjectId'. Aborting." }
        'Prompt'    { $answer = Read-Host "[$ObjectType] '$ObjectId' exists on destination. Overwrite? (y/N)"; return ($answer -match '^[Yy]$') }
    }
}

# ═════════════════════════════════════════════════════════════
# 1. IMPORT IP SETS
# ═════════════════════════════════════════════════════════════
function Import-IPSets {
    <# IP Sets live in the Manager API (/api/v1/ip-sets, deprecated), which
       does not support PATCH: a new IP set is created with POST (NSX assigns
       the Id) and an existing one is replaced with PUT plus its current
       _revision. Because NSX assigns new Ids, an existing IP set is found by
       Id first and then by display_name, so re-running the import does not
       create duplicates. #>
    Write-Log "━━━ Importing IP Sets ━━━" INFO
    $csvPath = $Script:CsvPath_IPSets
    $rows    = Read-CsvFile -Path $csvPath -Label 'IP Sets'
    if (-not $rows) { return }

    # Destination IP sets by display_name (for objects whose Id was assigned by NSX)
    $existingByName = @{}
    foreach ($s in (Get-NSXAllPages -Path '/api/v1/ip-sets')) {
        if ($s.PSObject.Properties['display_name'] -and -not $existingByName.ContainsKey($s.display_name)) {
            $existingByName[$s.display_name] = $s
        }
    }

    foreach ($row in $rows) {
        $id   = $row.Id
        $body = $row.RawJson | ConvertFrom-Json

        $existing = $null
        if (Test-NSXObjectExists -Path "/api/v1/ip-sets/$id") {
            $existing = Invoke-NSXGet -Path "/api/v1/ip-sets/$id"
        } elseif ($existingByName.ContainsKey($row.DisplayName)) {
            $existing = $existingByName[$row.DisplayName]
        }

        if ($existing) {
            if (-not (Resolve-Conflict -ObjectType 'IPSet' -ObjectId "$id ($($row.DisplayName))")) { $Stats.Skipped++; continue }

            if ($PSCmdlet.ShouldProcess("$id ($($row.DisplayName))", "Update IP Set")) {
                # PUT replaces the object and requires the current _revision
                $body | Add-Member -NotePropertyName id        -NotePropertyValue $existing.id        -Force
                $body | Add-Member -NotePropertyName _revision -NotePropertyValue $existing._revision -Force
                $ok = Invoke-NSXPut -Path "/api/v1/ip-sets/$($existing.id)" -JsonBody ($body | ConvertTo-Json -Depth 20 -Compress)
                if ($ok) { $Stats.IPSets++; Write-Log "  ✔ IP Set updated: $($existing.id) ($($row.DisplayName))" SUCCESS }
                else      { $Stats.Errors++ }
            }
        } else {
            if ($PSCmdlet.ShouldProcess("$id ($($row.DisplayName))", "Create IP Set")) {
                # NSX assigns the Id on create
                $body.PSObject.Properties.Remove('id')
                $resp = Invoke-NSXPost -Path '/api/v1/ip-sets' -JsonBody ($body | ConvertTo-Json -Depth 20 -Compress)
                if ($resp) {
                    $Stats.IPSets++
                    $newId = if ($resp -isnot [bool] -and $resp.PSObject.Properties['id']) { $resp.id } else { '?' }
                    Write-Log "  ✔ IP Set created: $($row.DisplayName) (source Id $id → new Id $newId)" SUCCESS
                } else { $Stats.Errors++ }
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 2. IMPORT SERVICES & SERVICE GROUPS
# ═════════════════════════════════════════════════════════════
function Import-Services {
    # Determine which types are active and build a meaningful header label
    # 'break' stops at the first match; without it every matching clause
    # added its text ("Services & Service Groups Services Service Groups").
    $typeLabel = switch ($true) {
        ($ImportServices -and $ImportServiceGroups) { 'Services & Service Groups'; break }
        $ImportServices                             { 'Services'; break }
        $ImportServiceGroups                        { 'Service Groups'; break }
    }
    Write-Log "━━━ Importing $typeLabel ━━━" INFO

    # Only open the file picker for types that are enabled
    $svcRows = @()
    $sgRows  = @()

    if ($ImportServices) {
        $svcPath = $Script:CsvPath_Services
        $svcRows = @(Read-CsvFile -Path $svcPath -Label 'Services')
    }

    if ($ImportServiceGroups) {
        $sgPath = $Script:CsvPath_ServiceGroups
        $sgRows = @(Read-CsvFile -Path $sgPath -Label 'Service Groups')
    }

    if (-not $svcRows -and -not $sgRows) {
        Write-Log "  No rows loaded — nothing to import." WARN
        return
    }

    Write-Log "  Resolving service dependency order..." INFO
    # Services before the service groups that reference them
    $orderedRows = Get-DependencyOrder -Items (@($svcRows) + @($sgRows)) -Label 'service' `
        -IdOf { param($r) $r.Id } `
        -DependenciesOf { param($r) Get-ServiceDependency ($r.RawJson | ConvertFrom-Json) }
    Write-Log "  Import order resolved for $(@($orderedRows).Count) item(s)." INFO

    foreach ($row in $orderedRows) {
        $id         = $row.Id
        $path       = "/policy/api/v1/infra/services/$id"
        $isGroup    = $row.ObjectType -eq 'ServiceGroup'
        $objectType = if ($isGroup) { 'ServiceGroup' } else { 'Service' }
        $label      = if ($isGroup) { 'Service Group' } else { 'Service' }

        if (Test-NSXObjectExists -Path $path) {
            if (-not (Resolve-Conflict -ObjectType $objectType -ObjectId $id)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($id, "Import $label")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.RawJson
            if ($ok) {
                if ($isGroup) { $Stats.ServiceGroups++ } else { $Stats.Services++ }
                Write-Log "  ✔ $($label): $id ($($row.DisplayName))" SUCCESS
            } else { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 3. IMPORT SECURITY GROUPS
# ═════════════════════════════════════════════════════════════
function Import-Groups {
    Write-Log "━━━ Importing Security Groups ━━━" INFO
    $csvPath = $Script:CsvPath_Groups
    $rows    = Read-CsvFile -Path $csvPath -Label 'Security Groups'
    if (-not $rows) { return }

    Write-Log "  Resolving group dependency order..." INFO
    # Referenced groups before the groups that reference them
    $rows = Get-DependencyOrder -Items $rows -Label 'group' `
        -IdOf { param($r) $r.Id } `
        -DependenciesOf { param($r) Get-GroupDependency ($r.RawJson | ConvertFrom-Json) }
    Write-Log "  Import order resolved for $(@($rows).Count) groups." INFO

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$id"

        if (Test-NSXObjectExists -Path $path) {
            if (-not (Resolve-Conflict -ObjectType 'Group' -ObjectId $id)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($id, "Import Group")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.RawJson
            if ($ok) { $Stats.Groups++; Write-Log "  ✔ Group: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 4. IMPORT CONTEXT PROFILES
# ═════════════════════════════════════════════════════════════
function Import-Profiles {
    Write-Log "━━━ Importing Context Profiles ━━━" INFO
    $csvPath = $Script:CsvPath_Profiles
    $rows    = Read-CsvFile -Path $csvPath -Label 'Context Profiles'
    if (-not $rows) { return }

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/policy/api/v1/infra/context-profiles/$id"

        if (Test-NSXObjectExists -Path $path) {
            if (-not (Resolve-Conflict -ObjectType 'ContextProfile' -ObjectId $id)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($id, "Import Context Profile")) {
            $ok = Invoke-NSXPatch -Path $path -JsonBody $row.RawJson
            if ($ok) { $Stats.Profiles++; Write-Log "  ✔ Context Profile: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 5. IMPORT DFW POLICIES & RULES
# ═════════════════════════════════════════════════════════════
function Import-Policies {
    Write-Log "━━━ Importing DFW Policies ━━━" INFO

    $polCsvPath  = $Script:CsvPath_Policies
    $ruleCsvPath = $Script:CsvPath_Rules
    $policyRows  = Read-CsvFile -Path $polCsvPath  -Label 'DFW Policies'
    $ruleRows    = Read-CsvFile -Path $ruleCsvPath -Label 'DFW Rules'

    if (-not $policyRows) { return }

    $rulesByPolicy = @{}
    foreach ($rRow in $ruleRows) {
        $policyId = $rRow.PolicyId
        if (-not $rulesByPolicy[$policyId]) { $rulesByPolicy[$policyId] = @() }
        $rulesByPolicy[$policyId] += $rRow
    }

    $policyRows = $policyRows | Sort-Object { [int]$_.SequenceNumber }

    foreach ($pRow in $policyRows) {
        $polId   = $pRow.Id
        $polPath = "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId"

        if (Test-NSXObjectExists -Path $polPath) {
            if (-not (Resolve-Conflict -ObjectType 'DFW Policy' -ObjectId $polId)) { $Stats.Skipped++; continue }
        }

        if ($PSCmdlet.ShouldProcess($polId, "Import DFW Policy")) {
            $ok = Invoke-NSXPatch -Path $polPath -JsonBody $pRow.RawJson
            if ($ok) {
                $Stats.Policies++
                Write-Log "  ✔ Policy: $polId ($($pRow.DisplayName)) [seq $($pRow.SequenceNumber)]" SUCCESS
            } else { $Stats.Errors++; continue }
        }

        $rules = $rulesByPolicy[$polId]
        if ($rules) {
            $rules = $rules | Sort-Object { [int]$_.SequenceNumber }
            foreach ($rRow in $rules) {
                $ruleId      = $rRow.Id
                $ruleApiPath = "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId/rules/$ruleId"

                if ($PSCmdlet.ShouldProcess($ruleId, "Import Rule in Policy $polId")) {
                    $ok = Invoke-NSXPatch -Path $ruleApiPath -JsonBody $rRow.RawJson
                    if ($ok) { $Stats.Rules++; Write-Log "    ✔ Rule: $ruleId ($($rRow.DisplayName)) — $($rRow.Action)" SUCCESS }
                    else      { $Stats.Errors++ }
                }
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 6. IMPORT VM TAGS
# ═════════════════════════════════════════════════════════════
function Import-Tags {
    Write-Log "━━━ Importing VM Tags ━━━" INFO
    Write-Log "  NOTE: VMs must already exist in the destination NSX/vCenter inventory." WARN

    $csvPath = $Script:CsvPath_Tags
    $rows    = Read-CsvFile -Path $csvPath -Label 'VM Tags'
    if (-not $rows) { return }

    $tagsByVM = @{}
    foreach ($row in $rows) {
        $eid = $row.ExternalId
        if (-not $tagsByVM[$eid]) { $tagsByVM[$eid] = @{ DisplayName = $row.VMDisplayName; Tags = @() } }
        $tagsByVM[$eid].Tags += @{ scope = $row.TagScope; tag = $row.TagValue }
    }

    foreach ($eid in $tagsByVM.Keys) {
        $vmName = $tagsByVM[$eid].DisplayName
        $tags   = $tagsByVM[$eid].Tags

        $checkResp = Invoke-NSXGet -Path "/api/v1/fabric/virtual-machines?external_id=$([uri]::EscapeDataString($eid))&included_fields=display_name"
        if ($null -eq $checkResp) {
            Write-Log "  SKIP: Could not verify VM '$vmName' ($eid) in destination." WARN
            $Stats.Skipped++; continue
        }
        if (-not (Get-SafeProp $checkResp 'results') -or @($checkResp.results).Count -eq 0) {
            Write-Log "  SKIP: VM '$vmName' (external_id: $eid) not found in destination inventory." WARN
            $Stats.Skipped++; continue
        }

        # add_tags ADDS the tags to whatever the VM already has. update_tags
        # (used before) REPLACES all tags, wiping tags that were already set
        # on the destination VM.
        $body = @{ external_id = $eid; tags = @($tags) } | ConvertTo-Json -Depth 5 -Compress

        if ($PSCmdlet.ShouldProcess($vmName, "Apply $($tags.Count) tag(s)")) {
            if (Invoke-NSXPost -Path '/api/v1/fabric/virtual-machines?action=add_tags' -JsonBody $body) {
                $Stats.Tags++
                $tagSummary = ($tags | ForEach-Object { "$($_.scope):$($_.tag)" }) -join ', '
                Write-Log "  ✔ VM: $vmName — $tagSummary" SUCCESS
            } else {
                Write-Log "  ✗ Failed to apply tags to '$vmName' ($eid)." ERROR
                $Stats.TagErrors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Import-NSX-DFW.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

# Guard — refuse to run if no import flags are set
$anyAction = $ImportIPSets -or $ImportServices -or $ImportServiceGroups -or $ImportGroups -or $ImportProfiles -or $ImportPolicies -or $ImportTags
if (-not $anyAction) {
    Write-Log "No import actions selected. Specify at least one -Import* flag." WARN
    Write-Log "Example: -ImportPolicies `$true -ImportGroups `$true" WARN
    exit 0
}

if (-not (Test-Path $InputFolder)) {
    Write-Log "Input folder not found: $InputFolder" ERROR
    exit 1
}
$InputFolder = (Resolve-Path $InputFolder).Path

Write-NSXBanner -Title 'NSX DFW IMPORT' -Details ([ordered]@{
        'Destination'       = $NSXManager
        'Input folder'      = $InputFolder
        'Conflict'          = $ConflictAction
        'Domain'            = $DomainId
        'Import IP Sets'    = $ImportIPSets
        'Import Services'   = $ImportServices
        'Import Svc Groups' = $ImportServiceGroups
        'Import Groups'     = $ImportGroups
        'Import Profiles'   = $ImportProfiles
        'Import Policies'   = $ImportPolicies
        'Import Tags'       = $ImportTags
    })

$fatal = $false
try {
    $Headers = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'destination NSX Manager'

    # Upfront CSV file selection — every file is chosen before anything is imported
    Write-Log "━━━ Selecting CSV files ━━━" INFO
    $pick = @{ InitialFolder = $InputFolder }
    if ($ImportIPSets)        { $Script:CsvPath_IPSets        = Resolve-CsvFile @pick -Label 'IP Sets'          -Path $IPSetsCsv        -ParameterName 'IPSetsCsv' }
    if ($ImportServices)      { $Script:CsvPath_Services      = Resolve-CsvFile @pick -Label 'Services'         -Path $ServicesCsv      -ParameterName 'ServicesCsv' }
    if ($ImportServiceGroups) { $Script:CsvPath_ServiceGroups = Resolve-CsvFile @pick -Label 'Service Groups'   -Path $ServiceGroupsCsv -ParameterName 'ServiceGroupsCsv' }
    if ($ImportGroups)        { $Script:CsvPath_Groups        = Resolve-CsvFile @pick -Label 'Security Groups'  -Path $GroupsCsv        -ParameterName 'GroupsCsv' }
    if ($ImportProfiles)      { $Script:CsvPath_Profiles      = Resolve-CsvFile @pick -Label 'Context Profiles' -Path $ProfilesCsv      -ParameterName 'ProfilesCsv' }
    if ($ImportPolicies) {
        $Script:CsvPath_Policies = Resolve-CsvFile @pick -Label 'DFW Policies' -Path $PoliciesCsv -ParameterName 'PoliciesCsv'
        $Script:CsvPath_Rules    = Resolve-CsvFile @pick -Label 'DFW Rules'    -Path $RulesCsv    -ParameterName 'RulesCsv'
    }
    if ($ImportTags)          { $Script:CsvPath_Tags          = Resolve-CsvFile @pick -Label 'VM Tags'          -Path $TagsCsv          -ParameterName 'TagsCsv' }

    if ($ImportIPSets)                            { Import-IPSets }
    if ($ImportServices -or $ImportServiceGroups) { Import-Services }
    if ($ImportGroups)                            { Import-Groups }
    if ($ImportProfiles)                          { Import-Profiles }
    if ($ImportPolicies)                          { Import-Policies }
    if ($ImportTags)                              { Import-Tags }
}
catch {
    Write-Log "FATAL: $_" ERROR
    $fatal = $true
}
finally {
    Write-NSXSummary -Title 'IMPORT SUMMARY' -Counts ([ordered]@{
            'IP Sets imported'    = $Stats.IPSets
            'Services imported'   = $Stats.Services
            'Svc Groups imported' = $Stats.ServiceGroups
            'Groups imported'     = $Stats.Groups
            'Profiles imported'   = $Stats.Profiles
            'Policies imported'   = $Stats.Policies
            'Rules imported'      = $Stats.Rules
            'VMs tagged'          = $Stats.Tags
            'Tag errors'          = $Stats.TagErrors
            'Skipped (conflicts)' = $Stats.Skipped
            'Errors'              = $Stats.Errors
        }) -Footer @("Next: .\Compare-NSX-Migration.ps1 (step 4) to validate the migration")
}

if ($fatal) { exit 1 }
if ($Stats.Errors + $Stats.TagErrors -gt 0) { exit 2 }
exit 0
