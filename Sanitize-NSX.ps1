#Requires -Version 5.1
<#
.SYNOPSIS
    STEP 2 of 4 — Sanitizes an NSX DFW export: object Ids are renamed to match their DisplayName.

.DESCRIPTION
    NSX exports can contain groups, services and policies whose Id differs
    from the DisplayName, e.g.

      Id: securitygroup-223   DisplayName: Datacenter
      Id: application-228     DisplayName: HTTP-8080

    This orchestrator runs the sanitization steps in order, so every Id
    matches its DisplayName and every reference to an old Id is updated:

      Step 1  Sanitize-NSXGroups.ps1        groups CSV       -> group Id map
      Step 2  Sanitize-NSXServices.ps1      services CSV     -> service Id map
              (again for the service groups CSV, seeded with the service map)
      Step 3  Sanitize-NSXFirewallRules.ps1 rules + policies CSVs, using both maps
      Step 4  Context profiles: tags removed (profile Ids are not renamed)

    Tags that group membership conditions match on are kept (tag safety
    check, see Get-NSXTagsInUse in NSX-Common.ps1). With -NSXManager the
    system-owned groups on the live source NSX Manager are checked as well.

    OUTPUTS (next to the input files)
      <file>_sanitized.csv            sanitized CSV for each input file
      <GroupsFile>_id_mapping.csv     group OldId -> NewId
      <ServicesFile>_id_mapping.csv   service AND service group OldId -> NewId
      <RulesFile>_id_mapping.csv      PolicyId, OldId, NewId
      <PoliciesFile>_id_mapping.csv   policy OldId -> NewId
    Pass the mapping files to Compare-NSX-Migration.ps1 (step 4).

.PARAMETER GroupsFile
    NSX_Groups.csv produced by Export-NSX-DFW.ps1.

.PARAMETER ServicesFile
    NSX_Services.csv. Optional.

.PARAMETER ServiceGroupsFile
    NSX_ServiceGroups.csv. Optional; requires -ServicesFile.

.PARAMETER RulesFile
    NSX_Rules.csv. Optional.

.PARAMETER PoliciesFile
    NSX_Policies.csv. Optional; processed together with -RulesFile.

.PARAMETER ProfilesFile
    NSX_Profiles.csv. Optional; tags are removed, Ids are kept.

.PARAMETER NSXManager
    Source NSX Manager for the live tag check of system-owned groups.
    Optional: without it only the exported groups CSV is checked.

.PARAMETER DomainId
    NSX Policy domain for the live tag check. Default: "default"

.PARAMETER GroupsOut
    Output paths default to <input>_sanitized.csv and <input>_id_mapping.csv;
    override them with -GroupsOut, -ServicesOut, -ServiceGroupsOut, -RulesOut,
    -PoliciesOut, -ProfilesOut, -GroupMappingOut and -ServiceMappingOut.
    -MappingOut is kept as an alias for -GroupMappingOut.

.PARAMETER Credential
    Credentials for -NSXManager. Prompted for when omitted.

.PARAMETER LogFile
    Path to a log file, used when -LogTarget is 'File' or 'Both' (shared by
    all steps). Default: Sanitize-NSX_<timestamp>.log in the current folder.

.PARAMETER LogTarget
    Controls where log output is written: Screen (default), File or Both.

.EXAMPLE
    .\Sanitize-NSX.ps1 -GroupsFile NSX_Groups.csv -ServicesFile NSX_Services.csv `
        -ServiceGroupsFile NSX_ServiceGroups.csv -RulesFile NSX_Rules.csv `
        -PoliciesFile NSX_Policies.csv -ProfilesFile NSX_Profiles.csv `
        -NSXManager nsx4.corp.local

.EXAMPLE
    # Groups and rules only, offline
    .\Sanitize-NSX.ps1 -GroupsFile NSX_Groups.csv -RulesFile NSX_Rules.csv

.NOTES
    Requires NSX-Common.ps1 and the Sanitize-NSX*.ps1 step scripts in the same folder.
    Exit code: 0 = success, 1 = fatal error.

    Changelog:
      1.4.0  (previous release)
      1.4.1  Bug fixes from code review: step 3 called a non-existent
             Sanitize-NSXFirewallRules1.3.5.ps1; profile tag removal no
             longer breaks the JSON on ']' in a tag value; -ServiceGroupsFile.
      1.5.0  Standard toolkit layout on NSX-Common.ps1: logging through
             Write-Log with -LogTarget/-LogFile, passed on to every step; new
             -NSXManager, -Credential and -DomainId so the live tag check of
             system-owned groups runs (the orchestrator could not enable it
             before); every step's exit code is checked and a failing step
             stops the run; the step counter counts the steps that run.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GroupsFile,
    [string]$ServicesFile      = '',
    [string]$ServiceGroupsFile = '',
    [string]$RulesFile         = '',
    [string]$PoliciesFile      = '',
    [string]$ProfilesFile      = '',

    # Live tag check (optional)
    [string]$NSXManager = '',
    [string]$DomainId   = 'default',

    # Outputs (default: <input>_sanitized.csv / <input>_id_mapping.csv)
    [string]$GroupsOut         = '',
    [string]$ServicesOut       = '',
    [string]$ServiceGroupsOut  = '',
    [string]$RulesOut          = '',
    [string]$PoliciesOut       = '',
    [string]$ProfilesOut       = '',
    [string]$GroupMappingOut   = '',
    [string]$ServiceMappingOut = '',
    [string]$MappingOut        = '',   # legacy alias for -GroupMappingOut

    # Connection and logging
    [pscredential]$Credential,
    [string]$LogFile = '',
    [ValidateSet('Screen', 'File', 'Both')]
    [string]$LogTarget = 'Screen'
)

$ScriptVersion = '1.5.0'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'NSX-Common.ps1')
Initialize-NSXLog -ScriptPath $PSCommandPath

# Default output paths
function Get-DerivedPath { param([string]$Value, [string]$From, [string]$Suffix) if ($Value) { $Value } elseif ($From) { $From -replace '\.csv$', $Suffix } else { '' } }
$GroupsOut         = Get-DerivedPath $GroupsOut         $GroupsFile        '_sanitized.csv'
$ServicesOut       = Get-DerivedPath $ServicesOut       $ServicesFile      '_sanitized.csv'
$ServiceGroupsOut  = Get-DerivedPath $ServiceGroupsOut  $ServiceGroupsFile '_sanitized.csv'
$RulesOut          = Get-DerivedPath $RulesOut          $RulesFile         '_sanitized.csv'
$PoliciesOut       = Get-DerivedPath $PoliciesOut       $PoliciesFile      '_sanitized.csv'
$ProfilesOut       = Get-DerivedPath $ProfilesOut       $ProfilesFile      '_sanitized.csv'
$GroupMappingOut   = Get-DerivedPath $(if ($MappingOut) { $MappingOut } else { $GroupMappingOut }) $GroupsFile '_id_mapping.csv'
$ServiceMappingOut = Get-DerivedPath $ServiceMappingOut $ServicesFile      '_id_mapping.csv'

# ═════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════
function Invoke-SanitizeStep {
    <# Runs one step script with the shared logging parameters, returns its
       output (the Id map with -PassThruMap) and stops the run when the step
       fails. #>
    param([Parameter(Mandatory)][string]$Script, [hashtable]$Parameters = @{})
    $Parameters['LogTarget'] = $LogTarget
    if ($LogFile) { $Parameters['LogFile'] = $LogFile }
    $global:LASTEXITCODE = 0
    $output = & (Join-Path $PSScriptRoot $Script) @Parameters
    if ($LASTEXITCODE -ne 0) { throw "$Script failed (exit code $LASTEXITCODE)." }
    return $output
}

$step = 0
$totalSteps = 1 + [int][bool]$ServicesFile + [int][bool]$RulesFile + [int][bool]$ProfilesFile
function Write-StepHeader { param([string]$Text) $script:step++; Write-Log "━━━ Step $script:step/$totalSteps — $Text ━━━" INFO }

# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════
Write-Log "Sanitize-NSX.ps1 v$ScriptVersion (NSX-Common v$NSXCommonVersion)" INFO

# Validate inputs and step scripts before starting
$problems = @()
foreach ($f in @($GroupsFile, $ServicesFile, $ServiceGroupsFile, $RulesFile, $PoliciesFile, $ProfilesFile)) {
    if ($f -and -not (Test-Path $f)) { $problems += "Input file not found: $f" }
}
if ($ServiceGroupsFile -and -not $ServicesFile) { $problems += "-ServiceGroupsFile requires -ServicesFile (service groups reference services)." }
if ($PoliciesFile -and -not $RulesFile)        { $problems += "-PoliciesFile is processed together with -RulesFile; pass -RulesFile as well." }
$required = @('Sanitize-NSXGroups.ps1')
if ($ServicesFile) { $required += 'Sanitize-NSXServices.ps1' }
if ($RulesFile)    { $required += 'Sanitize-NSXFirewallRules.ps1' }
foreach ($s in $required) {
    if (-not (Test-Path (Join-Path $PSScriptRoot $s))) { $problems += "Required script not found: $s (must be in the same folder as this script)" }
}
if ($problems) {
    foreach ($p in $problems) { Write-Log $p ERROR }
    exit 1
}

Write-NSXBanner -Title 'NSX EXPORT SANITIZATION' -Details ([ordered]@{
        'Groups'         = $GroupsFile
        'Services'       = $(if ($ServicesFile) { $ServicesFile } else { '-' })
        'Service Groups' = $(if ($ServiceGroupsFile) { $ServiceGroupsFile } else { '-' })
        'Rules'          = $(if ($RulesFile) { $RulesFile } else { '-' })
        'Policies'       = $(if ($PoliciesFile) { $PoliciesFile } else { '-' })
        'Profiles'       = $(if ($ProfilesFile) { $ProfilesFile } else { '-' })
        'Tag check'      = $(if ($NSXManager) { "CSV + live system-owned groups on $NSXManager" } else { 'CSV only' })
    })

$groupIdMap   = @{}
$serviceIdMap = @{}
$fatal = $false
try {
    # Tag safety check — run once, the result is passed to every step
    $hdrs = @{}
    if ($NSXManager) {
        $hdrs = Connect-NSXManager -Manager $NSXManager -Credential $Credential -Label 'source NSX Manager (tag check)'
    }
    Write-Log "━━━ Tag safety check ━━━" INFO
    $tagCheck = @{ InUseTags = (Get-NSXTagsInUse -GroupsCsv $GroupsFile -NSXManager $NSXManager -Headers $hdrs -DomainId $DomainId) }

    # Step 1 — groups
    Write-StepHeader 'Sanitizing groups'
    $groupIdMap = Invoke-SanitizeStep -Script 'Sanitize-NSXGroups.ps1' -Parameters (@{
            InputFile = $GroupsFile; OutputFile = $GroupsOut; PassThruMap = $true } + $tagCheck)
    Write-Log "  [Groups] Writing mapping log: $GroupMappingOut" INFO
    Export-IdMappingCsv -Path $GroupMappingOut -Rows @($groupIdMap.GetEnumerator() |
            Sort-Object Key | ForEach-Object { [PSCustomObject]@{ OldId = $_.Key; NewId = $_.Value } })

    # Step 2 — services, then service groups seeded with the service map
    if ($ServicesFile) {
        Write-StepHeader 'Sanitizing services and service groups'
        $serviceIdMap = Invoke-SanitizeStep -Script 'Sanitize-NSXServices.ps1' -Parameters (@{
                InputFile = $ServicesFile; OutputFile = $ServicesOut; GroupsCsv = $GroupsFile; PassThruMap = $true } + $tagCheck)

        if ($ServiceGroupsFile) {
            # Seeded with the service map (members follow the renamed
            # services) and with the service Ids reserved (a service group
            # never gets the Id of a service and overwrites it on import).
            Write-Log "  [Service Groups] Sanitizing: $ServiceGroupsFile" INFO
            $serviceIdsInUse = @(Import-Csv -Path $ServicesOut -Encoding UTF8 | ForEach-Object { $_.Id })
            $serviceIdMap = Invoke-SanitizeStep -Script 'Sanitize-NSXServices.ps1' -Parameters (@{
                    InputFile = $ServiceGroupsFile; OutputFile = $ServiceGroupsOut; GroupsCsv = $GroupsFile
                    SeedMap = $serviceIdMap; ReservedIds = $serviceIdsInUse; PassThruMap = $true } + $tagCheck)
        }

        Write-Log "  [Services] Writing mapping log: $ServiceMappingOut" INFO
        Export-IdMappingCsv -Path $ServiceMappingOut -Rows @($serviceIdMap.GetEnumerator() |
                Sort-Object Key | ForEach-Object { [PSCustomObject]@{ OldId = $_.Key; NewId = $_.Value } })
    }

    # Step 3 — rules and policies, with both maps
    if ($RulesFile) {
        Write-StepHeader 'Sanitizing firewall rules and policies'
        $fwParams = @{ RulesFile = $RulesFile; RulesOut = $RulesOut; IdMap = $groupIdMap; ServiceIdMap = $serviceIdMap }
        if ($PoliciesFile) { $fwParams.PoliciesFile = $PoliciesFile; $fwParams.PoliciesOut = $PoliciesOut }
        Invoke-SanitizeStep -Script 'Sanitize-NSXFirewallRules.ps1' -Parameters $fwParams | Out-Null
    }

    # Step 4 — context profiles: tags removed, Ids kept (already readable)
    if ($ProfilesFile) {
        Write-StepHeader 'Sanitizing context profiles'
        Write-Log "  [Profiles] Reading: $ProfilesFile" INFO
        $profileRows = @(Import-Csv -Path $ProfilesFile -Encoding UTF8)
        $updated = 0
        foreach ($row in $profileRows) {
            $before      = $row.RawJson
            $row.RawJson = Clear-JsonTag -Json $row.RawJson
            $row.Tags    = ''
            if ($row.RawJson -ne $before) { $updated++ }
        }
        Write-Log "  [Profiles] Writing: $ProfilesOut" INFO
        $profileRows | Export-Csv -Path $ProfilesOut -NoTypeInformation -Encoding UTF8
        Write-Log "  [Profiles] $updated profile row(s) had tags removed." INFO
    }
}
catch {
    Write-Log "FATAL: $_" ERROR
    $fatal = $true
}
finally {
    $outputs = [ordered]@{ 'Groups (sanitized)' = $GroupsOut; 'Groups ID mapping' = $GroupMappingOut }
    if ($ServicesFile)      { $outputs['Services (sanitized)'] = $ServicesOut; $outputs['Services ID mapping'] = $ServiceMappingOut }
    if ($ServiceGroupsFile) { $outputs['Svc Groups (sanitized)'] = $ServiceGroupsOut }
    if ($RulesFile)         { $outputs['Rules (sanitized)'] = $RulesOut }
    if ($PoliciesFile)      { $outputs['Policies (sanitized)'] = $PoliciesOut }
    if ($ProfilesFile)      { $outputs['Profiles (sanitized)'] = $ProfilesOut }
    $outputs['Groups renamed']   = $groupIdMap.Count
    $outputs['Services renamed'] = $serviceIdMap.Count
    Write-NSXSummary -Title $(if ($fatal) { 'SANITIZATION FAILED' } else { 'SANITIZATION COMPLETE' }) -Counts $outputs -Footer @(
        'Next: import the *_sanitized.csv files with .\Import-NSX-DFW.ps1 (step 3),',
        '      then validate with .\Compare-NSX-Migration.ps1 and the *_id_mapping.csv files (step 4).'
    )
}

if ($fatal) { exit 1 }
exit 0
