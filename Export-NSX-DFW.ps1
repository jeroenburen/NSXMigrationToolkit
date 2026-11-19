#Requires -Version 5.1
<#
.SYNOPSIS
    STEP 1 of 4 — Exports NSX 4 Distributed Firewall objects to CSV files.

.DESCRIPTION
    Connects to an NSX 4 Manager and exports the following DFW objects to CSV:
      - IP Sets (Manager API)          → NSX_IPSets.csv
      - Services                       → NSX_Services.csv
      - Service Groups                 → NSX_ServiceGroups.csv
      - Security Groups                → NSX_Groups.csv
      - Context Profiles               → NSX_Profiles.csv
      - DFW Policies                   → NSX_Policies.csv
      - DFW Rules                      → NSX_Rules.csv
      - VM Tags                        → NSX_VMTags.csv

    Each CSV row contains key readable columns PLUS a RawJson column with the
    full object payload. The import script reads RawJson to reconstruct objects,
    so do not remove that column. All other columns are for review purposes only.

    Toolkit pipeline:
      1. Export-NSX-DFW.ps1          (this script)   1b. Export-NSX-SystemObjects.ps1
      2. Sanitize-NSX.ps1                             2b. Seed-NSX-DFW-Dummy-VMs.ps1 (optional)
      3. Import-NSX-DFW.ps1                           3b. Import-NSX-SystemObjects.ps1
      4. Compare-NSX-Migration.ps1
      Rollback: Remove-NSX-ImportedObjects.ps1 / Remove-NSX-AllCustomObjects.ps1

.PARAMETER NSXManager
    FQDN or IP of the source NSX 4 Manager.

.PARAMETER ExportIPSets
    Export IP Sets (Manager API, deprecated). Default: $false
    IP sets that NSX Policy created itself (_create_user nsx_policy) or that
    are protected are skipped: they are recreated by NSX on the destination.

.PARAMETER ExportServices
    Export Services and Service Groups. Default: $false

.PARAMETER ExportGroups
    Export Security Groups. Default: $false

.PARAMETER ExportProfiles
    Export custom Context Profiles (NSX_Profiles.csv). Default: $false
    Only custom (non-system-owned) profiles are exported. System profiles
    such as those bundled with NSX (e.g. SSL, HTTP) are present on every
    NSX instance and do not need to be migrated.

.PARAMETER ExportPolicies
    Export DFW Policies and Rules. Default: $false

.PARAMETER ExportTags
    Export VM tags from the fabric inventory. Default: $false

.PARAMETER OutputFolder
    Folder where CSV files will be written. Created if it doesn't exist.
    Default: .\NSX_DFW_Export_<timestamp>

.PARAMETER DomainId
    NSX Policy domain. Default: "default"

.PARAMETER Credential
    Credentials for the NSX Manager. Prompted for when omitted.

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both'.
    Default: Export-NSX-DFW_<timestamp>.log in -OutputFolder.

.PARAMETER LogTarget
    Controls where log output is written.
      Screen : colored output to the console only (default)
      File   : write to -LogFile only, no console output
      Both   : colored console output AND written to -LogFile

.EXAMPLE
    .\Export-NSX-DFW.ps1 -NSXManager nsx4.corp.local `
        -ExportServices $true -ExportGroups $true -ExportPolicies $true

.EXAMPLE
    .\Export-NSX-DFW.ps1 -NSXManager nsx4.corp.local -OutputFolder C:\NSX\Export `
        -ExportIPSets $true -ExportServices $true -ExportGroups $true `
        -ExportProfiles $true -ExportPolicies $true -ExportTags $true -LogTarget Both

.NOTES
    Requires NSX-Common.ps1 in the same folder.
    Exit code: 0 = success, 1 = fatal error, 2 = finished with errors.

    Changelog:
      1.1.0  (previous release)
      1.2.0  Bug fixes from code review:
             - Help said every -Export* flag defaults to $true; the code
               defaults to $false. Help fixed, and the script now stops with
               a message when no -Export* flag is set.
             - Output folder is created before the first log line.
             - Pagination fixed ('&' with an existing query string, encoded
               cursor, stops when a page fails).
             - Service groups detected correctly and exported to
               NSX_ServiceGroups.csv; services fetched once.
             - ServiceEntries summary column fixed.
             - IP sets created by NSX Policy itself or protected are skipped.
             - PowerShell 6+/7: self-signed certificates accepted.
      1.3.0  Standard toolkit layout on NSX-Common.ps1: shared logging,
             connection, REST and pagination helpers; new -Credential
             parameter; exit codes 0/1/2.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NSXManager,

    # What to export — all default to $false
    [bool]$ExportIPSets   = $false,
    [bool]$ExportServices = $false,
    [bool]$ExportGroups   = $false,
    [bool]$ExportProfiles = $false,
    [bool]$ExportPolicies = $false,
    [bool]$ExportTags     = $false,

    # Options
    [string]$OutputFolder = ".\NSX_DFW_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [string]$DomainId     = 'default',

    # Connection and logging
    [pscredential]$Credential,
    [string]$LogFile = '',
    [ValidateSet('Screen', 'File', 'Both')]
    [string]$LogTarget = 'Screen'
)

$ScriptVersion = '1.3.0'

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
$Stats = @{ IPSets = 0; Services = 0; ServiceGroups = 0; Groups = 0; Profiles = 0; Policies = 0; Rules = 0; Tags = 0; Errors = 0 }

# ═════════════════════════════════════════════════════════════
# 1. EXPORT IP SETS
# ═════════════════════════════════════════════════════════════
function Export-IPSets {
    Write-Log "━━━ Exporting IP Sets ━━━" INFO
    $all = Get-NSXAllPages -Path "/api/v1/ip-sets"
    # Skip IP sets that NSX Policy created itself (realized from Policy
    # groups) or that are protected: NSX recreates those on the destination
    # and they cannot be created or deleted through the Manager API.
    $objects = @($all | Where-Object {
        (Get-SafeProp $_ '_create_user') -ne 'nsx_policy' -and
        (Get-SafeProp $_ '_protection') -notin @('PROTECTED', 'REQUIRE_OVERRIDE') -and
        (Get-SafeProp $_ '_system_owned') -ne $true
    })
    if ($objects.Count -eq 0) { Write-Log "No custom IP Sets found." WARN; return }

    $rows = foreach ($obj in $objects) {
        $clean = Remove-ReadOnlyFields $obj
        [PSCustomObject]@{
            ObjectType  = 'IPSet'
            Id          = $obj.id
            DisplayName = $obj.display_name
            Description = (Get-SafeProp $obj 'description')
            IPAddresses = (Format-PropList $obj 'ip_addresses')
            Tags        = (Format-Tags $obj)
            RawJson     = ($clean | ConvertTo-Json -Depth 20 -Compress)
        }
    }

    $csvPath = Join-Path $OutputFolder 'NSX_IPSets.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.IPSets = @($rows).Count
    Write-Log "  Exported $($Stats.IPSets) IP Sets → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 2. EXPORT SERVICES & SERVICE GROUPS
# ═════════════════════════════════════════════════════════════
function Export-Services {
    # Services and service groups share the /infra/services endpoint and both
    # have resource_type 'Service'. They are fetched ONCE and split with
    # Test-IsServiceGroup, so every object lands in exactly one CSV.
    Write-Log "━━━ Exporting Services ━━━" INFO
    $objects  = Get-NSXAllPages -Path "/policy/api/v1/infra/services"
    $customAll = @($objects | Where-Object { (Get-SafeProp $_ '_system_owned') -ne $true })
    $custom    = @($customAll | Where-Object { -not (Test-IsServiceGroup $_) })
    $customSGs = @($customAll | Where-Object { Test-IsServiceGroup $_ })

    if ($custom.Count -eq 0) { Write-Log "No custom Services found." WARN }
    else {
        $rows = foreach ($svc in $custom) {
            $clean = Remove-ReadOnlyFields $svc
            $entries = Get-SafeProp $svc 'service_entries'
            $entrySummary = ''
            if ($entries) {
                $entrySummary = ($entries | ForEach-Object {
                        # Inside switch, $_ is the switched value (the type
                        # name), so keep the entry in its own variable.
                        $entry = $_
                        $type  = $entry.resource_type
                        switch -Wildcard ($type) {
                            '*L4Port*' { "$(Get-SafeProp $entry 'l4_protocol'):$(((Get-SafeProp $entry 'destination_ports') -join ','))" }
                            '*ICMPType*' { "ICMP:$(Get-SafeProp $entry 'icmp_type')" }
                            '*IPProtocol*' { "IPProto:$(Get-SafeProp $entry 'protocol_number')" }
                            'NestedServiceServiceEntry' { "Nested:$(Get-SafeProp $entry 'nested_service_path')" }
                            default { $type }
                        }
                    }) -join '; '
            }
            [PSCustomObject]@{
                ObjectType     = 'Service'
                Id             = $svc.id
                DisplayName    = $svc.display_name
                Description    = (Get-SafeProp $svc 'description')
                ServiceEntries = $entrySummary
                Tags           = (Format-Tags $svc)
                RawJson        = ($clean | ConvertTo-Json -Depth 20 -Compress)
            }
        }
        $csvPath = Join-Path $OutputFolder 'NSX_Services.csv'
        $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $Stats.Services = @($rows).Count
        Write-Log "  Exported $($Stats.Services) Services → $csvPath" SUCCESS
    }

    Write-Log "━━━ Exporting Service Groups ━━━" INFO

    if ($customSGs.Count -eq 0) { Write-Log "No custom Service Groups found." WARN; return }

    $rows = foreach ($sg in $customSGs) {
        $clean = Remove-ReadOnlyFields $sg
        # Members of a service group are its nested service references
        $members = @(Get-SafeProp $sg 'service_entries') | Where-Object { $_ } |
            ForEach-Object { Get-SafeProp $_ 'nested_service_path' } | Where-Object { $_ }
        [PSCustomObject]@{
            ObjectType  = 'ServiceGroup'
            Id          = $sg.id
            DisplayName = $sg.display_name
            Description = (Get-SafeProp $sg 'description')
            Members     = (@($members) -join '; ')
            Tags        = (Format-Tags $sg)
            RawJson     = ($clean | ConvertTo-Json -Depth 20 -Compress)
        }
    }
    $csvPath = Join-Path $OutputFolder 'NSX_ServiceGroups.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.ServiceGroups = @($rows).Count
    Write-Log "  Exported $($Stats.ServiceGroups) Service Groups → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 3. EXPORT SECURITY GROUPS
# ═════════════════════════════════════════════════════════════
function Export-Groups {
    Write-Log "━━━ Exporting Security Groups ━━━" INFO
    $objects = Get-NSXAllPages -Path "/policy/api/v1/infra/domains/$DomainId/groups"
    $custom = $objects | Where-Object {
        (Get-SafeProp $_ '_system_owned') -ne $true -and
        (Get-SafeProp $_ '_create_user') -ne 'system' -and
        $_.id -notin $NSXPseudoSystemGroupIds
    }

    if (-not $custom) { Write-Log "No custom Security Groups found." WARN; return }

    $rows = foreach ($grp in $custom) {
        $clean = Remove-ReadOnlyFields $grp
        $expression = Get-SafeProp $grp 'expression'
        $exprSummary = if ($expression) {
            ($expression | ForEach-Object { $_.resource_type }) -join '; '
        }
        else { 'Static' }

        [PSCustomObject]@{
            ObjectType      = 'Group'
            Id              = $grp.id
            DisplayName     = $grp.display_name
            Description     = (Get-SafeProp $grp 'description')
            ExpressionTypes = $exprSummary
            Tags            = (Format-Tags $grp)
            RawJson         = ($clean | ConvertTo-Json -Depth 20 -Compress)
        }
    }

    $csvPath = Join-Path $OutputFolder 'NSX_Groups.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.Groups = @($rows).Count
    Write-Log "  Exported $($Stats.Groups) Security Groups → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 4. EXPORT CONTEXT PROFILES
# ═════════════════════════════════════════════════════════════
function Export-Profiles {
    Write-Log "━━━ Exporting Context Profiles ━━━" INFO
    $objects = Get-NSXAllPages -Path "/policy/api/v1/infra/context-profiles"
    $custom = $objects | Where-Object { (Get-SafeProp $_ '_system_owned') -ne $true }

    if (-not $custom) { Write-Log "No custom Context Profiles found." WARN; return }

    $rows = foreach ($prof in $custom) {
        $clean = Remove-ReadOnlyFields $prof
        $attributes = Get-SafeProp $prof 'attributes'
        $attrSummary = if ($attributes) {
            ($attributes | ForEach-Object {
                $key = Get-SafeProp $_ 'key'
                $vals = Get-SafeProp $_ 'value'
                $vStr = if ($vals) { $vals -join ',' } else { '' }
                "$key=$vStr"
            }) -join '; '
        }
        else { '' }

        [PSCustomObject]@{
            ObjectType  = 'ContextProfile'
            Id          = $prof.id
            DisplayName = $prof.display_name
            Description = (Get-SafeProp $prof 'description')
            Attributes  = $attrSummary
            Tags        = (Format-Tags $prof)
            RawJson     = ($clean | ConvertTo-Json -Depth 20 -Compress)
        }
    }

    $csvPath = Join-Path $OutputFolder 'NSX_Profiles.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Stats.Profiles = @($rows).Count
    Write-Log "  Exported $($Stats.Profiles) Context Profiles → $csvPath" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 5. EXPORT DFW POLICIES & RULES
# ═════════════════════════════════════════════════════════════
function Export-Policies {
    Write-Log "━━━ Exporting DFW Policies ━━━" INFO
    $policies = Get-NSXAllPages -Path "/policy/api/v1/infra/domains/$DomainId/security-policies"
    $custom = $policies | Where-Object { 
        (Get-SafeProp $_ '_system_owned') -ne $true -and 
        $_.Id -notin $NSXPseudoSystemPolicyIds 
    } | Sort-Object -Property sequence_number

    if (-not $custom) { Write-Log "No custom DFW Policies found." WARN; return }

    $policyRows = @()
    $ruleRows = @()

    foreach ($pol in $custom) {
        $cleanPol = Remove-ReadOnlyFields $pol
        $scope = Get-SafeProp $pol 'scope'

        $policyRows += [PSCustomObject]@{
            ObjectType     = 'Policy'
            Id             = $pol.id
            DisplayName    = $pol.display_name
            Description    = (Get-SafeProp $pol 'description')
            SequenceNumber = $pol.sequence_number
            Category       = (Get-SafeProp $pol 'category')
            Stateful       = (Get-SafeProp $pol 'stateful')
            TCPStrict      = (Get-SafeProp $pol 'tcp_strict')
            Scope          = if ($scope) { $scope -join '; ' } else { 'ANY' }
            Tags           = (Format-Tags $pol)
            RawJson        = ($cleanPol | ConvertTo-Json -Depth 20 -Compress)
        }
        $Stats.Policies++

        $rules = Get-NSXAllPages -Path "/policy/api/v1/infra/domains/$DomainId/security-policies/$($pol.id)/rules"
        if ($rules) {
            $rules = $rules | Sort-Object -Property sequence_number
            foreach ($rule in $rules) {
                $cleanRule = Remove-ReadOnlyFields $rule
                $ruleRows += [PSCustomObject]@{
                    ObjectType     = 'Rule'
                    PolicyId       = $pol.id
                    PolicyName     = $pol.display_name
                    Id             = $rule.id
                    DisplayName    = $rule.display_name
                    Description    = (Get-SafeProp $rule 'description')
                    SequenceNumber = $rule.sequence_number
                    Action         = $rule.action
                    Direction      = (Get-SafeProp $rule 'direction')
                    IPProtocol     = (Get-SafeProp $rule 'ip_protocol')
                    Disabled       = (Get-SafeProp $rule 'disabled')
                    Logged         = (Get-SafeProp $rule 'logged')
                    SourceGroups   = (Format-PropList $rule 'source_groups'      'ANY')
                    DestGroups     = (Format-PropList $rule 'destination_groups' 'ANY')
                    Services       = (Format-PropList $rule 'services'           'ANY')
                    AppliedTo      = (Format-PropList $rule 'scope'              'ANY')
                    Tags           = (Format-Tags $rule)
                    RawJson        = ($cleanRule | ConvertTo-Json -Depth 20 -Compress)
                }
                $Stats.Rules++
            }
        }
    }

    $polCsv = Join-Path $OutputFolder 'NSX_Policies.csv'
    $ruleCsv = Join-Path $OutputFolder 'NSX_Rules.csv'
    $policyRows | Export-Csv -Path $polCsv  -NoTypeInformation -Encoding UTF8
    $ruleRows   | Export-Csv -Path $ruleCsv -NoTypeInformation -Encoding UTF8
    Write-Log "  Exported $($Stats.Policies) Policies → $polCsv" SUCCESS
    Write-Log "  Exported $($Stats.Rules) Rules → $ruleCsv" SUCCESS
}

# ═════════════════════════════════════════════════════════════
# 6. EXPORT VM TAGS
# ═════════════════════════════════════════════════════════════
function Export-Tags {
    Write-Log "━━━ Exporting VM Tags ━━━" INFO
    # Retrieve all VMs from the fabric inventory including their tags
    $vms = Get-NSXAllPages -Path "/api/v1/fabric/virtual-machines?included_fields=display_name,external_id,tags"

    if (-not $vms) { Write-Log "No VMs found in fabric inventory." WARN; return }

    # Only export VMs that actually have tags assigned
    $taggedVMs = $vms | Where-Object { Get-SafeProp $_ 'tags' }

    if (-not $taggedVMs) { Write-Log "No VMs with tags found." WARN; return }

    $rows = foreach ($vm in $taggedVMs) {
        $tags = Get-SafeProp $vm 'tags'
        foreach ($tag in $tags) {
            [PSCustomObject]@{
                VMDisplayName = $vm.display_name
                ExternalId    = $vm.external_id   # vCenter UUID — required for import
                TagScope      = (Get-SafeProp $tag 'scope')
                TagValue      = (Get-SafeProp $tag 'tag')
            }
        }
        $Stats.Tags++
    }

    $csvPath = Join-Path $OutputFolder 'NSX_VMTags.csv'
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "  Exported tags for $($Stats.Tags) VMs → $csvPath" SUCCESS
    Write-Log "  NOTE: Tags are applied per VM using the ExternalId (vCenter UUID)." WARN
    Write-Log "        VMs must exist in the destination NSX/vCenter inventory before importing." WARN
}

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Export-NSX-DFW.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

# Guard — refuse to run if no export flags are set
$anyAction = $ExportIPSets -or $ExportServices -or $ExportGroups -or $ExportProfiles -or $ExportPolicies -or $ExportTags
if (-not $anyAction) {
    Write-Log "No export actions selected. Specify at least one -Export* flag." WARN
    Write-Log "Example: -ExportGroups `$true -ExportPolicies `$true" WARN
    exit 0
}

Write-NSXBanner -Title 'NSX DFW EXPORT' -Details ([ordered]@{
        'Source'          = $NSXManager
        'Output'          = $OutputFolder
        'Domain'          = $DomainId
        'Export IP Sets'  = $ExportIPSets
        'Export Services' = $ExportServices
        'Export Groups'   = $ExportGroups
        'Export Profiles' = $ExportProfiles
        'Export Policies' = $ExportPolicies
        'Export Tags'     = $ExportTags
    })

$fatal = $false
try {
    $Headers = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'source NSX Manager'

    if ($ExportIPSets)   { Export-IPSets }
    if ($ExportServices) { Export-Services }
    if ($ExportGroups)   { Export-Groups }
    if ($ExportProfiles) { Export-Profiles }
    if ($ExportPolicies) { Export-Policies }
    if ($ExportTags)     { Export-Tags }
}
catch {
    Write-Log "FATAL: $_" ERROR
    $fatal = $true
}
finally {
    Write-NSXSummary -Title 'EXPORT SUMMARY' -Counts ([ordered]@{
            'IP Sets'       = $Stats.IPSets
            'Services'      = $Stats.Services
            'Svc Groups'    = $Stats.ServiceGroups
            'Groups'        = $Stats.Groups
            'Profiles'      = $Stats.Profiles
            'Policies'      = $Stats.Policies
            'Rules'         = $Stats.Rules
            'VMs with Tags' = $Stats.Tags
            'Errors'        = $Stats.Errors
        }) -Footer @(
        "Output folder : $OutputFolder",
        "Next: review the CSV files and remove rows you do NOT want to migrate, then run",
        "      .\Sanitize-NSX.ps1 (step 2) or .\Import-NSX-DFW.ps1 -NSXManager <nsx9> -InputFolder '$OutputFolder' (step 3)"
    )
}

if ($fatal) { exit 1 }
if ($Stats.Errors -gt 0) { exit 2 }
exit 0
