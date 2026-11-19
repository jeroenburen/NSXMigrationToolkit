#Requires -Version 5.1
<#
.SYNOPSIS
    ROLLBACK — Removes all custom (non-system-owned) NSX DFW objects directly from inventory.

.DESCRIPTION
    Queries the NSX Manager live inventory and removes all user-created DFW objects.
    Unlike Remove-NSX-ImportedObjects.ps1, this script does NOT need CSV files —
    it discovers objects directly from the NSX Manager and removes them.

    Deletion order respects dependencies:
      1. DFW Policies (with their rules)
      2. Context Profiles
      3. Service Groups / Services (dependents first)
      4. Security Groups           (dependents first)
      5. IP Sets (custom only; IP sets realized by NSX Policy are skipped)
      6. VM tags (-ClearVMTags)

    All object types are opt-in and default to $false for safety.
    Use -WhatIf to preview all deletions before committing.

    NOTE: System-owned objects are never touched by this script.

.PARAMETER NSXManager
    FQDN or IP of the NSX Manager to clean up.

.PARAMETER RemovePolicies
    Remove all custom DFW Policies and their Rules. Default: $false

.PARAMETER RemoveProfiles
    Remove all custom Context Profiles. Default: $false

.PARAMETER RemoveGroups
    Remove all custom Security Groups. Default: $false

.PARAMETER RemoveServiceGroups
    Remove all custom Service Groups. Default: $false

.PARAMETER RemoveServices
    Remove all custom Services. Default: $false

.PARAMETER RemoveIPSets
    Remove all custom IP Sets. Default: $false

.PARAMETER ClearVMTags
    Clear tags on VMs in the NSX fabric inventory. Default: $false
    Which tags: see -ClearTagScope.

.PARAMETER ClearTagScope
    Tag scope to clear with -ClearVMTags (e.g. "env"); other tags stay on the
    VM. Use '*' to clear ALL tags on ALL VMs. When omitted you are prompted
    (blank answer = all tags, confirmed by typing YES).

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER Credential
    Credentials for the NSX Manager. Prompted for when omitted.

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Remove-NSX-AllCustomObjects_<timestamp>.log in the current folder.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    # Preview everything that would be removed
    .\Remove-NSX-AllCustomObjects.ps1 -NSXManager nsx9.corp.local -WhatIf `
        -RemovePolicies $true -RemoveProfiles $true -RemoveGroups $true `
        -RemoveServiceGroups $true -RemoveServices $true -RemoveIPSets $true

.EXAMPLE
    # Remove only policies and groups
    .\Remove-NSX-AllCustomObjects.ps1 -NSXManager nsx9.corp.local `
        -RemovePolicies $true -RemoveGroups $true

.EXAMPLE
    # Full cleanup including VM tags with scope "env", without prompts
    .\Remove-NSX-AllCustomObjects.ps1 -NSXManager nsx9.corp.local `
        -RemovePolicies $true -RemoveProfiles $true -RemoveGroups $true `
        -RemoveServiceGroups $true -RemoveServices $true -RemoveIPSets $true `
        -ClearVMTags $true -ClearTagScope env -Confirm:$false

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error, 2 = finished with errors.

    Changelog:
      1.0.0  Initial release.
      1.1.0  Merged Remove-ServiceGroups and Remove-Services into one
             dependency-ordered function.
      1.2.0  Added -RemoveProfiles flag and Remove-Profiles function.
      1.3.0  Bug fixes from code review: inverted group filter (custom groups
             were skipped, protected groups selected); -RemoveServices and
             -RemoveServiceGroups independent; NSX-realized IP sets skipped;
             pagination fixed; default log file; PowerShell 6+/7
             certificates; UTF-8 BOM.
      1.4.0  Standard toolkit layout on NSX-Common.ps1: shared logging,
             connection, REST and dependency-sort helpers (the two copied
             sorts are now Get-DependencyOrder -Reverse); credentials are only
             asked after the no-action guard; new -Credential and
             -ClearTagScope parameters for unattended runs; exit codes 0/1/2.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$NSXManager,

    # What to remove — all default to $false
    [bool]$RemovePolicies      = $false,
    [bool]$RemoveProfiles      = $false,
    [bool]$RemoveGroups        = $false,
    [bool]$RemoveServiceGroups = $false,
    [bool]$RemoveServices      = $false,
    [bool]$RemoveIPSets        = $false,
    [bool]$ClearVMTags         = $false,

    # Options
    [string]$ClearTagScope = '',
    [string]$DomainId      = 'default',

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
$Stats = @{ Policies = 0; Rules = 0; Profiles = 0; Groups = 0; ServiceGroups = 0; Services = 0; IPSets = 0; VMsCleared = 0; Errors = 0 }

# ═════════════════════════════════════════════════════════════
# 1. REMOVE DFW POLICIES
# ═════════════════════════════════════════════════════════════
function Remove-Policies {
    Write-Log "━━━ Removing DFW Policies ━━━" INFO
    $policies = Get-NSXAllPages -Path "/policy/api/v1/infra/domains/$DomainId/security-policies"
    $custom = $policies | Where-Object {
      if ((Get-SafeProp $_ '_system_owned') -eq $true) { return $false }
      if ($_.id -in $NSXPseudoSystemPolicyIds) {
        Write-Log "  Skipping protected policy: $($_.id)" WARN
        return $false
      }
      return $true
   }

    if (-not $custom) { Write-Log "  No custom DFW Policies found." WARN; return }

    # Fetch rule counts for reporting, then delete highest sequence first
    $custom = $custom | Sort-Object -Property sequence_number -Descending

    foreach ($pol in $custom) {
        $polId = $pol.id
        $path  = "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId"

        # Count rules for reporting
        $rules  = Get-NSXAllPages -Path "/policy/api/v1/infra/domains/$DomainId/security-policies/$polId/rules"
        $rCount = @($rules).Count

        if ($PSCmdlet.ShouldProcess("Policy '$polId' ($($pol.display_name)) + $rCount rule(s)", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                $Stats.Policies++
                $Stats.Rules += $rCount
                Write-Log "  ✔ Deleted Policy: $polId ($($pol.display_name)) — $rCount rule(s)" SUCCESS
            } else {
                $Stats.Errors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 2. REMOVE CONTEXT PROFILES
# ═════════════════════════════════════════════════════════════
function Remove-Profiles {
    Write-Log "━━━ Removing Context Profiles ━━━" INFO
    $all    = Get-NSXAllPages -Path "/policy/api/v1/infra/context-profiles"
    $custom = $all | Where-Object { (Get-SafeProp $_ '_system_owned') -ne $true }

    if (-not $custom) { Write-Log "  No custom Context Profiles found." WARN; return }

    Write-Log "  Found $(@($custom).Count) custom Context Profile(s)." INFO

    foreach ($prof in $custom) {
        $id   = $prof.id
        $path = "/policy/api/v1/infra/context-profiles/$id"

        if ($PSCmdlet.ShouldProcess("Context Profile '$id' ($($prof.display_name))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.Profiles++; Write-Log "  ✔ Deleted Context Profile: $id ($($prof.display_name))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 3. REMOVE SERVICE GROUPS AND SERVICES  (dependents first)
# ═════════════════════════════════════════════════════════════
function Remove-ServicesAndGroups {
    $typeLabel = switch ($true) {
        ($RemoveServices -and $RemoveServiceGroups) { 'Service Groups and Services'; break }
        $RemoveServiceGroups                        { 'Service Groups'; break }
        $RemoveServices                             { 'Services'; break }
    }
    Write-Log "━━━ Removing $typeLabel ━━━" INFO
    $all = Get-NSXAllPages -Path "/policy/api/v1/infra/services"

    # Custom objects of the SELECTED types only. Both have resource_type
    # 'Service'; Test-IsServiceGroup tells them apart. Previously
    # -RemoveServiceGroups on its own also deleted every custom service.
    $custom = @($all | Where-Object {
        if ((Get-SafeProp $_ '_system_owned') -eq $true) { return $false }
        if (Test-IsServiceGroup $_) { return [bool]$RemoveServiceGroups }
        return [bool]$RemoveServices
    })

    if ($custom.Count -eq 0) { Write-Log "  No custom $typeLabel found." WARN; return }

    $sgCount  = @($custom | Where-Object { Test-IsServiceGroup $_ }).Count
    $svcCount = $custom.Count - $sgCount
    Write-Log "  Found $sgCount service group(s) and $svcCount service(s). Resolving deletion order..." INFO

    # Service groups (and other referencing services) are deleted first
    $ordered = Get-DependencyOrder -Items $custom -Reverse -Label 'service' `
        -IdOf { param($s) $s.id } -DependenciesOf { param($s) Get-ServiceDependency $s }

    foreach ($svc in $ordered) {
        $id      = $svc.id
        $path    = "/policy/api/v1/infra/services/$id"
        $isGroup = Test-IsServiceGroup $svc
        $label   = if ($isGroup) { 'Service Group' } else { 'Service' }

        if ($PSCmdlet.ShouldProcess("${label} '$id' ($($svc.display_name))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) {
                if ($isGroup) { $Stats.ServiceGroups++ } else { $Stats.Services++ }
                Write-Log "  ✔ Deleted ${label}: $id ($($svc.display_name))" SUCCESS
            } else {
                $Stats.Errors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 4. REMOVE SECURITY GROUPS  (dependents first)
# ═════════════════════════════════════════════════════════════
function Remove-Groups {
    Write-Log "━━━ Removing Security Groups ━━━" INFO
    $groups = Get-NSXAllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups"
    $custom = @($groups | Where-Object {
        # Exclude system-owned groups and groups created by the system user
        if ((Get-SafeProp $_ '_system_owned') -eq $true -or (Get-SafeProp $_ '_create_user') -eq 'system') { return $false }
        # Exclude groups that are system-managed but not flagged as such
        if ($_.id -in $NSXPseudoSystemGroupIds) {
            Write-Log "  Skipping protected group: $($_.id)" WARN
            return $false
        }
        return $true
    })

    if ($custom.Count -eq 0) { Write-Log "  No custom Security Groups found." WARN; return }

    Write-Log "  Found $($custom.Count) custom groups. Resolving deletion order..." INFO
    # Groups that reference other groups are deleted first
    $ordered = Get-DependencyOrder -Items $custom -Reverse -Label 'group' `
        -IdOf { param($g) $g.id } -DependenciesOf { param($g) Get-GroupDependency $g }

    foreach ($grp in $ordered) {
        $id   = $grp.id
        $path = "/policy/api/v1/infra/domains/$DomainId/groups/$id"

        if ($PSCmdlet.ShouldProcess("Group '$id' ($($grp.display_name))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.Groups++; Write-Log "  ✔ Deleted Group: $id ($($grp.display_name))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 5. REMOVE IP SETS
# ═════════════════════════════════════════════════════════════
function Remove-IPSets {
    Write-Log "━━━ Removing IP Sets ━━━" INFO
    $all = Get-NSXAllPages -Path "/api/v1/ip-sets"

    # Skip IP sets that NSX Policy created itself (realized from Policy groups)
    # or that are protected: deleting them through the Manager API fails, and
    # NSX manages their lifecycle. Same filter as Export-NSX-DFW.ps1.
    $custom = @($all | Where-Object {
        (Get-SafeProp $_ '_create_user') -ne 'nsx_policy' -and
        (Get-SafeProp $_ '_protection') -notin @('PROTECTED', 'REQUIRE_OVERRIDE') -and
        (Get-SafeProp $_ '_system_owned') -ne $true
    })

    if ($custom.Count -eq 0) { Write-Log "  No custom IP Sets found." WARN; return }

    foreach ($obj in $custom) {
        $id   = $obj.id
        $path = "/api/v1/ip-sets/$id"

        if ($PSCmdlet.ShouldProcess("IP Set '$id' ($($obj.display_name))", "DELETE")) {
            $ok = Invoke-NSXDelete -Path $path
            if ($ok) { $Stats.IPSets++; Write-Log "  ✔ Deleted IP Set: $id ($($obj.display_name))" SUCCESS }
            else      { $Stats.Errors++ }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# 6. CLEAR VM TAGS  (optional, with scope filter)
# ═════════════════════════════════════════════════════════════
function Clear-VMTags {
    Write-Log "━━━ Clearing VM Tags ━━━" INFO

    # Scope filter from -ClearTagScope ('*' = all tags); prompt when not given
    if ($ClearTagScope -eq '*') {
        $scopeFilter = ''
        Write-Log "  -ClearTagScope '*' — ALL tags on ALL VMs will be cleared." WARN
    }
    elseif ($ClearTagScope) {
        $scopeFilter = $ClearTagScope
    }
    else {
        $scopeFilter = Read-Host "  Enter tag scope to clear (e.g. 'env', 'tier') — leave blank to clear ALL tags on ALL VMs"
        if (-not $scopeFilter) {
            $confirm = Read-Host "  Are you sure you want to clear ALL tags on ALL VMs? Type YES to confirm"
            if ($confirm -ne 'YES') {
                Write-Log "  Aborted by user." WARN
                return
            }
        }
    }

    if ($scopeFilter) {
        Write-Log "  Scope filter: '$scopeFilter' — only tags with this scope will be cleared." WARN
    } else {
        Write-Log "  No scope filter — ALL tags on ALL VMs will be cleared." WARN
    }

    $vms = Get-NSXAllPages -Path "/api/v1/fabric/virtual-machines?included_fields=display_name,external_id,tags"
    if (-not $vms) { Write-Log "  No VMs found in fabric inventory." WARN; return }

    # Filter to VMs that actually have tags matching the scope filter
    $targetVMs = $vms | Where-Object {
        $tags = Get-SafeProp $_ 'tags'
        if (-not $tags) { return $false }
        if ($scopeFilter) {
            return @($tags | Where-Object { (Get-SafeProp $_ 'scope') -eq $scopeFilter }).Count -gt 0
        }
        return $true
    }

    if (-not $targetVMs) {
        Write-Log "  No VMs with matching tags found." WARN
        return
    }

    Write-Log "  Found $(@($targetVMs).Count) VMs with matching tags." INFO

    foreach ($vm in $targetVMs) {
        $eid    = $vm.external_id
        $name   = $vm.display_name
        $tags   = Get-SafeProp $vm 'tags'

        # If scope filter set: retain tags that do NOT match the scope
        # If no scope filter: send empty array to clear all tags
        $remainingTags = @()
        if ($scopeFilter -and $tags) {
            $remainingTags = @($tags | Where-Object { (Get-SafeProp $_ 'scope') -ne $scopeFilter })
        }

        $body = @{ external_id = $eid; tags = $remainingTags } | ConvertTo-Json -Depth 5 -Compress

        if ($PSCmdlet.ShouldProcess("VM '$name' ($eid)", "Clear tags$(if ($scopeFilter) { " with scope '$scopeFilter'" })")) {
            $ok = Invoke-NSXPost -Path "/api/v1/fabric/virtual-machines?action=update_tags" -JsonBody $body
            if ($ok) {
                $Stats.VMsCleared++
                Write-Log "  ✔ Cleared tags on VM: $name" SUCCESS
            } else {
                $Stats.Errors++
            }
        }
    }
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Remove-NSX-AllCustomObjects.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

# Guard — refuse to run if no action flags are set
$anyAction = $RemovePolicies -or $RemoveProfiles -or $RemoveGroups -or $RemoveServiceGroups -or
             $RemoveServices -or $RemoveIPSets -or $ClearVMTags
if (-not $anyAction) {
    Write-Log "No actions selected. Specify at least one -Remove* or -ClearVMTags flag." WARN
    Write-Log "Example: -RemovePolicies `$true -RemoveGroups `$true" WARN
    exit 0
}

Write-NSXBanner -Title 'NSX INVENTORY-BASED CLEANUP' -Details ([ordered]@{
        'Target'            = $NSXManager
        'Domain'            = $DomainId
        'Remove Policies'   = $RemovePolicies
        'Remove Profiles'   = $RemoveProfiles
        'Remove Groups'     = $RemoveGroups
        'Remove Svc Groups' = $RemoveServiceGroups
        'Remove Services'   = $RemoveServices
        'Remove IP Sets'    = $RemoveIPSets
        'Clear VM Tags'     = $(if ($ClearVMTags) { "True (scope: $(if ($ClearTagScope) { $ClearTagScope } else { 'ask' }))" } else { 'False' })
    })
Write-Log " WARNING: Deletes ALL custom objects of the selected types! Run with -WhatIf first to preview." WARN

$fatal = $false
try {
    $Headers = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'NSX Manager'

    if ($RemovePolicies)                          { Remove-Policies }
    if ($RemoveProfiles)                          { Remove-Profiles }
    if ($RemoveServiceGroups -or $RemoveServices) { Remove-ServicesAndGroups }
    if ($RemoveGroups)                            { Remove-Groups }
    if ($RemoveIPSets)                            { Remove-IPSets }
    if ($ClearVMTags)                             { Clear-VMTags }
}
catch {
    Write-Log "FATAL: $_" ERROR
    $fatal = $true
}
finally {
    Write-NSXSummary -Title 'CLEANUP SUMMARY' -Counts ([ordered]@{
            'Policies deleted'         = $Stats.Policies
            'Rules removed (with pol)' = $Stats.Rules
            'Profiles deleted'         = $Stats.Profiles
            'Groups deleted'           = $Stats.Groups
            'Service Groups deleted'   = $Stats.ServiceGroups
            'Services deleted'         = $Stats.Services
            'IP Sets deleted'          = $Stats.IPSets
            'VMs with tags cleared'    = $Stats.VMsCleared
            'Errors'                   = $Stats.Errors
        })
}

if ($fatal) { exit 1 }
if ($Stats.Errors -gt 0) { exit 2 }
exit 0
