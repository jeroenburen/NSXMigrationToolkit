#Requires -Version 5.1
<#
.SYNOPSIS
    ROLLBACK — Removes NSX DFW objects that were imported with Import-NSX-DFW.ps1.

.DESCRIPTION
    Reads the CSV files that were imported with Import-NSX-DFW.ps1 and deletes
    the corresponding objects from the destination NSX Manager. This allows you
    to cleanly roll back a migration and start over.

    FILE RESOLUTION
    ---------------
    Same as Import-NSX-DFW.ps1: the CSV file for each enabled type comes from
    its -<Type>Csv parameter when given; otherwise a file dialog opens upfront,
    starting in -InputFolder. Select the SAME files you imported — the
    *_sanitized.csv files when the export was sanitized, because the
    destination objects carry the sanitized Ids.

    Deletion order is the reverse of import order to respect dependencies:
      1. DFW Policies (with their rules)
      2. Context Profiles
      3. Security Groups      (dependents first)
      4. Service Groups / Services (dependents first)
      5. IP Sets
      6. VM tags listed in the CSV (-ClearVMTags); other tags stay on the VM

    NOTE: This script does NOT touch system-owned objects.

.PARAMETER NSXManager
    FQDN or IP of the NSX Manager to clean up.

.PARAMETER InputFolder
    Folder containing the imported CSV files (start folder of the file dialogs).

.PARAMETER RemovePolicies
    Remove imported DFW Policies and all their Rules. Default: $false

.PARAMETER RemoveProfiles
    Remove imported custom Context Profiles. Default: $false

.PARAMETER RemoveGroups
    Remove imported Security Groups. Default: $false

.PARAMETER RemoveServiceGroups
    Remove imported Service Groups. Default: $false

.PARAMETER RemoveServices
    Remove imported Services. Default: $false

.PARAMETER RemoveIPSets
    Remove imported IP Sets. Default: $false

.PARAMETER ClearVMTags
    Remove the tags listed in the VM tags CSV from those VMs. Tags that are
    not in the CSV stay on the VM. Default: $false

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER PoliciesCsv
    CSV file for -RemovePolicies (skips the file dialog). The same applies to
    -RulesCsv, -ProfilesCsv, -GroupsCsv, -ServiceGroupsCsv, -ServicesCsv,
    -IPSetsCsv and -TagsCsv.

.PARAMETER Credential
    Credentials for the NSX Manager. Prompted for when omitted.

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Remove-NSX-ImportedObjects_<timestamp>.log in the current folder.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    # Dry run first — see what would be deleted without making changes
    .\Remove-NSX-ImportedObjects.ps1 -NSXManager nsx9.corp.local -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -RemovePolicies $true -RemoveGroups $true -WhatIf

.EXAMPLE
    # Remove everything including the imported VM tags
    .\Remove-NSX-ImportedObjects.ps1 -NSXManager nsx9.corp.local -InputFolder .\NSX_DFW_Export_20250101_120000 `
        -RemovePolicies $true -RemoveProfiles $true -RemoveGroups $true -RemoveServiceGroups $true `
        -RemoveServices $true -RemoveIPSets $true -ClearVMTags $true

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error, 2 = finished with errors.

    Changelog:
      1.0.0  Initial release.
      1.1.0  Added $ScriptVersion variable and startup version log line.
      1.1.1  Renamed reserved automatic variable $pid to $policyId.
      1.2.0  Merged Remove-ServiceGroups and Remove-Services into one
             dependency-ordered function.
      1.3.0  Bug fixes from code review: CSV files selected like Import (so the
             sanitized files can be chosen); -RemoveServices/-RemoveServiceGroups
             independent; -RemoveProfiles; -ClearVMTags removes only the CSV
             tags; IP sets matched by Id then name; no-action guard; existence
             check only treats 404 as missing; default log file; PowerShell
             6+/7 certificates.
      1.4.0  Standard toolkit layout on NSX-Common.ps1: shared logging,
             connection, REST, CSV and dependency-sort helpers (the two copied
             sorts are now Get-DependencyOrder -Reverse); new -Credential and
             -<Type>Csv parameters; exit codes 0/1/2.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$NSXManager,
    [Parameter(Mandatory)][string]$InputFolder,

    # What to remove — all default to $false
    [bool]$RemovePolicies      = $false,
    [bool]$RemoveProfiles      = $false,
    [bool]$RemoveGroups        = $false,
    [bool]$RemoveServiceGroups = $false,
    [bool]$RemoveServices      = $false,
    [bool]$RemoveIPSets        = $false,
    [bool]$ClearVMTags         = $false,

    # Options
    [string]$DomainId = 'default',

    # CSV files (skip the file dialog for that type)
    [string]$PoliciesCsv      = '',
    [string]$RulesCsv         = '',
    [string]$ProfilesCsv      = '',
    [string]$GroupsCsv        = '',
    [string]$ServiceGroupsCsv = '',
    [string]$ServicesCsv      = '',
    [string]$IPSetsCsv        = '',
    [string]$TagsCsv          = '',

    # Connection and logging
    [pscredential]$Credential,
    [string]$LogFile = '',
    [ValidateSet('Screen', 'File', 'Both')]
    [string]$LogTarget = 'Screen'
)

$ScriptVersion = '1.4.0'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'NSX-Common.ps1')
Initialize-NSXLog -ScriptPath $PSCommandPath

# ─────────────────────────────────────────────────────────────
# STATISTICS
# ─────────────────────────────────────────────────────────────
$Stats = @{ Policies = 0; Rules = 0; Profiles = 0; Groups = 0; ServiceGroups = 0; Services = 0; IPSets = 0; VMsCleared = 0; NotFound = 0; Errors = 0 }

# CSV file per object type, filled in by the upfront file selection in MAIN
$Script:CsvPath_IPSets        = $null
$Script:CsvPath_Services      = $null
$Script:CsvPath_ServiceGroups = $null
$Script:CsvPath_Groups        = $null
$Script:CsvPath_Profiles      = $null
$Script:CsvPath_Policies      = $null
$Script:CsvPath_Rules         = $null
$Script:CsvPath_Tags          = $null

# ═════════════════════════════════════════════════════════════
# 1. REMOVE DFW POLICIES
# ═════════════════════════════════════════════════════════════
function Remove-Policies {
    Write-Log "━━━ Removing DFW Policies ━━━" INFO
    $policyRows = Read-CsvFile -Path $Script:CsvPath_Policies -Label 'DFW Policies'
    $ruleRows   = Read-CsvFile -Path $Script:CsvPath_Rules    -Label 'DFW Rules'
    if (-not $policyRows) { return }

    $ruleCount = @{}
    foreach ($r in $ruleRows) {
        $policyId = $r.PolicyId
        $ruleCount[$policyId] = ($ruleCount[$policyId] -as [int]) + 1
    }

    $policyRows = $policyRows | Sort-Object { [int]$_.SequenceNumber } -Descending

    foreach ($row in $policyRows) {
        $polId = $row.Id
        $path  = "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId"

        if (-not (Test-NSXObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: Policy '$polId' — already removed or never imported." WARN
            $Stats.NotFound++; continue
        }

        $rCount = if ($ruleCount[$polId]) { $ruleCount[$polId] } else { 0 }

        if ($PSCmdlet.ShouldProcess("Policy '$polId' ($($row.DisplayName)) + $rCount rule(s)", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                $Stats.Policies++
                $Stats.Rules += $rCount
                Write-Log "  ✔ Deleted Policy: $polId ($($row.DisplayName)) — $rCount rule(s) removed" SUCCESS
            } else { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 2. REMOVE CONTEXT PROFILES
# ═════════════════════════════════════════════════════════════
function Remove-Profiles {
    Write-Log "━━━ Removing Context Profiles ━━━" INFO
    $rows = Read-CsvFile -Path $Script:CsvPath_Profiles -Label 'Context Profiles'
    if (-not $rows) { return }

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/policy/api/v1/infra/context-profiles/$id"

        if (-not (Test-NSXObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: Context Profile '$id' — already removed or never imported." WARN
            $Stats.NotFound++; continue
        }

        if ($PSCmdlet.ShouldProcess("Context Profile '$id' ($($row.DisplayName))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.Profiles++; Write-Log "  ✔ Deleted Context Profile: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 3. REMOVE SECURITY GROUPS  (dependents first)
# ═════════════════════════════════════════════════════════════
function Remove-Groups {
    Write-Log "━━━ Removing Security Groups ━━━" INFO
    $rows = Read-CsvFile -Path $Script:CsvPath_Groups -Label 'Security Groups'
    if (-not $rows) { return }

    Write-Log "  Resolving group deletion order..." INFO
    # Groups that reference other groups are deleted first
    $rows = Get-DependencyOrder -Items $rows -Reverse -Label 'group' `
        -IdOf { param($r) $r.Id } `
        -DependenciesOf { param($r) Get-GroupDependency ($r.RawJson | ConvertFrom-Json) }

    foreach ($row in $rows) {
        $id   = $row.Id
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$id"

        if (-not (Test-NSXObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: Group '$id' — already removed or never imported." WARN
            $Stats.NotFound++; continue
        }

        if ($PSCmdlet.ShouldProcess("Group '$id' ($($row.DisplayName))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.Groups++; Write-Log "  ✔ Deleted Group: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 4. REMOVE SERVICE GROUPS AND SERVICES  (dependents first)
# ═════════════════════════════════════════════════════════════
function Remove-Services {
    $typeLabel = switch ($true) {
        ($RemoveServices -and $RemoveServiceGroups) { 'Service Groups and Services'; break }
        $RemoveServiceGroups                        { 'Service Groups'; break }
        $RemoveServices                             { 'Services'; break }
    }
    Write-Log "━━━ Removing $typeLabel ━━━" INFO

    # Only the types that were selected: -RemoveServices on its own used to
    # delete the service groups as well (both files were always read).
    $sgRows  = if ($RemoveServiceGroups) { @(Read-CsvFile -Path $Script:CsvPath_ServiceGroups -Label 'Service Groups') } else { @() }
    $svcRows = if ($RemoveServices)      { @(Read-CsvFile -Path $Script:CsvPath_Services      -Label 'Services') }       else { @() }

    $allRows = @($sgRows | Where-Object { $_ }) + @($svcRows | Where-Object { $_ })
    if ($allRows.Count -eq 0) { Write-Log "  No Service Groups or Services found in CSVs." WARN; return }

    Write-Log "  Found $(@($sgRows).Count) service group(s) and $(@($svcRows).Count) service(s). Resolving deletion order..." INFO
    # Service groups (and other referencing services) are deleted first
    $ordered = Get-DependencyOrder -Items $allRows -Reverse -Label 'service' `
        -IdOf { param($r) $r.Id } `
        -DependenciesOf { param($r) Get-ServiceDependency ($r.RawJson | ConvertFrom-Json) }

    foreach ($row in $ordered) {
        $id      = $row.Id
        $path    = "/policy/api/v1/infra/services/$id"
        $isGroup = $row.ObjectType -eq 'ServiceGroup'
        $label   = if ($isGroup) { 'Service Group' } else { 'Service' }

        if (-not (Test-NSXObjectExists -Path $path)) {
            Write-Log "  NOT FOUND: $($label) '$id' — already removed or never imported." WARN
            $Stats.NotFound++; continue
        }

        if ($PSCmdlet.ShouldProcess("$($label) '$id' ($($row.DisplayName))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                if ($isGroup) { $Stats.ServiceGroups++ } else { $Stats.Services++ }
                Write-Log "  ✔ Deleted $($label): $id ($($row.DisplayName))" SUCCESS
            } else { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 5. REMOVE IP SETS
# ═════════════════════════════════════════════════════════════
function Remove-IPSets {
    <# Import-NSX-DFW.ps1 creates IP sets with POST, so NSX assigns a new Id.
       The IP set is therefore looked up by Id first and then by display_name. #>
    Write-Log "━━━ Removing IP Sets ━━━" INFO
    $rows = Read-CsvFile -Path $Script:CsvPath_IPSets -Label 'IP Sets'
    if (-not $rows) { return }

    $byName = @{}
    foreach ($s in (Get-NSXAllPages -Path '/api/v1/ip-sets')) {
        if (-not $byName.ContainsKey($s.display_name)) { $byName[$s.display_name] = $s }
    }

    foreach ($row in $rows) {
        $id = $row.Id
        if (-not (Test-NSXObjectExists -Path "/api/v1/ip-sets/$id")) {
            if ($byName.ContainsKey($row.DisplayName)) {
                $id = $byName[$row.DisplayName].id
            } else {
                Write-Log "  NOT FOUND: IP Set '$($row.Id)' ($($row.DisplayName)) — already removed or never imported." WARN
                $Stats.NotFound++; continue
            }
        }
        $path = "/api/v1/ip-sets/$id"

        if ($PSCmdlet.ShouldProcess("IP Set '$id' ($($row.DisplayName))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.IPSets++; Write-Log "  ✔ Deleted IP Set: $id ($($row.DisplayName))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 6. REMOVE IMPORTED VM TAGS
# ═════════════════════════════════════════════════════════════
function Clear-VMTags {
    <# Removes ONLY the tags listed in the CSV, with the remove_tags action.
       Previously update_tags with an empty list wiped every tag on the VM,
       including tags that were never imported. #>
    Write-Log "━━━ Removing imported VM Tags ━━━" INFO
    $rows = Read-CsvFile -Path $Script:CsvPath_Tags -Label 'VM Tags'
    if (-not $rows) { return }

    $tagsByVM = @{}
    foreach ($row in $rows) {
        $eid = $row.ExternalId
        if (-not $tagsByVM.ContainsKey($eid)) { $tagsByVM[$eid] = @{ DisplayName = $row.VMDisplayName; Tags = @() } }
        $tagsByVM[$eid].Tags += @{ scope = $row.TagScope; tag = $row.TagValue }
    }

    foreach ($eid in $tagsByVM.Keys) {
        $vmName   = $tagsByVM[$eid].DisplayName
        $tags     = $tagsByVM[$eid].Tags
        $checkResp = Invoke-NSXGet -Path "/api/v1/fabric/virtual-machines?external_id=$([uri]::EscapeDataString($eid))&included_fields=display_name"
        if ($null -eq $checkResp) {
            Write-Log "  Could not verify VM '$vmName' ($eid)." WARN
            $Stats.NotFound++; continue
        }
        if (-not (Get-SafeProp $checkResp 'results') -or @($checkResp.results).Count -eq 0) {
            Write-Log "  NOT FOUND: VM '$vmName' ($eid) not in destination inventory." WARN
            $Stats.NotFound++; continue
        }

        $body = @{ external_id = $eid; tags = @($tags) } | ConvertTo-Json -Depth 5 -Compress
        $tagSummary = ($tags | ForEach-Object { "$($_.scope):$($_.tag)" }) -join ', '

        if ($PSCmdlet.ShouldProcess("VM '$vmName' ($eid)", "Remove tag(s) $tagSummary")) {
            $ok = Invoke-NSXPost -Path "/api/v1/fabric/virtual-machines?action=remove_tags" -JsonBody $body
            if ($ok) { $Stats.VMsCleared++; Write-Log "  ✔ Removed tags on VM: $vmName — $tagSummary" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Remove-NSX-ImportedObjects.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

# Guard — refuse to run if no action flags are set
$anyAction = $RemovePolicies -or $RemoveProfiles -or $RemoveGroups -or $RemoveServiceGroups -or
             $RemoveServices -or $RemoveIPSets -or $ClearVMTags
if (-not $anyAction) {
    Write-Log "No actions selected. Specify at least one -Remove* or -ClearVMTags flag." WARN
    Write-Log "Example: -RemovePolicies `$true -RemoveGroups `$true" WARN
    exit 0
}

if (-not (Test-Path $InputFolder)) {
    Write-Log "Input folder not found: $InputFolder" ERROR
    exit 1
}
$InputFolder = (Resolve-Path $InputFolder).Path

Write-NSXBanner -Title 'NSX DFW ROLLBACK / CLEANUP' -Details ([ordered]@{
        'Target'             = $NSXManager
        'Input folder'       = $InputFolder
        'Domain'             = $DomainId
        'Remove Policies'    = $RemovePolicies
        'Remove Profiles'    = $RemoveProfiles
        'Remove Groups'      = $RemoveGroups
        'Remove Svc Groups'  = $RemoveServiceGroups
        'Remove Services'    = $RemoveServices
        'Remove IP Sets'     = $RemoveIPSets
        'Clear VM Tags'      = $ClearVMTags
    })
Write-Log " WARNING: This will permanently delete imported objects! Run with -WhatIf first to preview." WARN

$fatal = $false
try {
    $Headers = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'NSX Manager'

    # Upfront CSV file selection — the same files that were IMPORTED
    Write-Log "━━━ Selecting the CSV files that were IMPORTED ━━━" INFO
    $pick = @{ InitialFolder = $InputFolder }
    if ($RemovePolicies) {
        $Script:CsvPath_Policies = Resolve-CsvFile @pick -Label 'DFW Policies' -Path $PoliciesCsv -ParameterName 'PoliciesCsv'
        $Script:CsvPath_Rules    = Resolve-CsvFile @pick -Label 'DFW Rules'    -Path $RulesCsv    -ParameterName 'RulesCsv'
    }
    if ($RemoveProfiles)      { $Script:CsvPath_Profiles      = Resolve-CsvFile @pick -Label 'Context Profiles' -Path $ProfilesCsv      -ParameterName 'ProfilesCsv' }
    if ($RemoveGroups)        { $Script:CsvPath_Groups        = Resolve-CsvFile @pick -Label 'Security Groups'  -Path $GroupsCsv        -ParameterName 'GroupsCsv' }
    if ($RemoveServiceGroups) { $Script:CsvPath_ServiceGroups = Resolve-CsvFile @pick -Label 'Service Groups'   -Path $ServiceGroupsCsv -ParameterName 'ServiceGroupsCsv' }
    if ($RemoveServices)      { $Script:CsvPath_Services      = Resolve-CsvFile @pick -Label 'Services'         -Path $ServicesCsv      -ParameterName 'ServicesCsv' }
    if ($RemoveIPSets)        { $Script:CsvPath_IPSets        = Resolve-CsvFile @pick -Label 'IP Sets'          -Path $IPSetsCsv        -ParameterName 'IPSetsCsv' }
    if ($ClearVMTags)         { $Script:CsvPath_Tags          = Resolve-CsvFile @pick -Label 'VM Tags'          -Path $TagsCsv          -ParameterName 'TagsCsv' }

    if ($RemovePolicies)                          { Remove-Policies }
    if ($RemoveProfiles)                          { Remove-Profiles }
    if ($RemoveGroups)                            { Remove-Groups }
    if ($RemoveServiceGroups -or $RemoveServices) { Remove-Services }
    if ($RemoveIPSets)                            { Remove-IPSets }
    if ($ClearVMTags)                             { Clear-VMTags }
}
catch {
    Write-Log "FATAL: $_" ERROR
    $fatal = $true
}
finally {
    Write-NSXSummary -Title 'REMOVAL SUMMARY' -Counts ([ordered]@{
            'Policies deleted'         = $Stats.Policies
            'Rules removed (with pol)' = $Stats.Rules
            'Profiles deleted'         = $Stats.Profiles
            'Groups deleted'           = $Stats.Groups
            'Service Groups deleted'   = $Stats.ServiceGroups
            'Services deleted'         = $Stats.Services
            'IP Sets deleted'          = $Stats.IPSets
            'VMs with tags removed'    = $Stats.VMsCleared
            'Not found (skipped)'      = $Stats.NotFound
            'Errors'                   = $Stats.Errors
        })
}

if ($fatal) { exit 1 }
if ($Stats.Errors -gt 0) { exit 2 }
exit 0
