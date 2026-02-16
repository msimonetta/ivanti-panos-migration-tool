Param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile,

    [Parameter(Mandatory=$true)]
    [string]$OutputFile,

    [Parameter(Mandatory=$true)]
    [string]$DeviceGroup,

    [Parameter(Mandatory=$true)]
    [ValidateSet('pre', 'post')]
    [string]$Rulebase,

    [string]$SecurityProfileGroup = $null,
    [string]$LogForwardingProfile = $null,
    [string]$FromZone = 'trust',
    [string]$ToZone = 'trust',
    [string]$LogFile = 'migration.log'
)

try {
    Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Error: Could not start transcript log '$LogFile'. $_"
    exit 1
}

# --- Helper function to normalize PAN-OS names ---
function Normalize-PanosName {
    param(
        [string]$Name,
        [string]$Fallback = 'unnamed'
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $Fallback
    }

    $normalized = [regex]::Replace($Name, '[^A-Za-z0-9._-]', '_')
    $normalized = [regex]::Replace($normalized, '_+', '_')
    $normalized = $normalized.Trim('_')

    if ([string]::IsNullOrEmpty($normalized)) {
        return $Fallback
    }

    return $normalized
}

# --- Helper function to make rule names unique ---
function Get-UniqueRuleName {
    param(
        [string]$BaseName,
        [ref]$RuleNameCounts
    )

    if ($RuleNameCounts.Value.ContainsKey($BaseName)) {
        $RuleNameCounts.Value[$BaseName] += 1
    } else {
        $RuleNameCounts.Value[$BaseName] = 1
    }

    $count = $RuleNameCounts.Value[$BaseName]
    if ($count -eq 1) {
        return $BaseName
    }

    return "$BaseName-$count"
}

# --- Helper function to normalize a processed rule group ---
function Normalize-RuleGroup {
    param(
        [pscustomobject]$Group
    )

    $destAddresses = @($Group.DestAddresses | Sort-Object -Unique)
    if ($destAddresses -contains 'any') {
        $destAddresses = @('any')
    } elseif ($destAddresses.Count -eq 0) {
        $destAddresses = @('any')
    }

    $services = @($Group.Services | Sort-Object -Unique)
    if ($services -contains 'any') {
        $services = @('any')
    } elseif ($services.Count -eq 0) {
        $services = @('any')
    }

    $applications = @('any')
    if ($null -ne $Group.PSObject.Properties['Applications']) {
        $applications = @($Group.Applications | Sort-Object -Unique)
        if ($applications -contains 'any') {
            $applications = @('any')
        } elseif ($applications.Count -eq 0) {
            $applications = @('any')
        }
    }

    $useAppDefaultService = $false
    if ($null -ne $Group.PSObject.Properties['UseAppDefaultService']) {
        $useAppDefaultService = [bool]$Group.UseAppDefaultService
    }

    return [PSCustomObject]@{
        DestAddresses        = $destAddresses
        Services             = $services
        Applications         = $applications
        UseAppDefaultService = $useAppDefaultService
    }
}

# --- Helper function to merge sibling rule groups with identical signatures ---
function Merge-RuleGroupsBySignature {
    param(
        [System.Array]$RuleGroups
    )

    $signatureBuckets = @{}

    foreach ($group in @($RuleGroups)) {
        $normalizedGroup = Normalize-RuleGroup -Group $group

        $signatureKey = [string]::Join('|', @(
            "services=$($normalizedGroup.Services -join ',')"
            "applications=$($normalizedGroup.Applications -join ',')"
            "app-default=$($normalizedGroup.UseAppDefaultService.ToString().ToLower())"
        ))

        if (-not $signatureBuckets.ContainsKey($signatureKey)) {
            $signatureBuckets[$signatureKey] = [PSCustomObject]@{
                SignatureKey         = $signatureKey
                DestAddressSet       = New-Object System.Collections.Generic.HashSet[string]
                Services             = $normalizedGroup.Services
                Applications         = $normalizedGroup.Applications
                UseAppDefaultService = $normalizedGroup.UseAppDefaultService
            }
        }

        foreach ($dest in $normalizedGroup.DestAddresses) {
            $signatureBuckets[$signatureKey].DestAddressSet.Add($dest) | Out-Null
        }
    }

    $mergedGroups = @()
    foreach ($bucket in ($signatureBuckets.GetEnumerator() | Sort-Object Name)) {
        $destAddresses = @($bucket.Value.DestAddressSet | Sort-Object -Unique)
        if ($destAddresses -contains 'any') {
            $destAddresses = @('any')
        } elseif ($destAddresses.Count -eq 0) {
            $destAddresses = @('any')
        }

        $mergedGroups += [PSCustomObject]@{
            DestAddresses        = $destAddresses
            Services             = $bucket.Value.Services
            Applications         = $bucket.Value.Applications
            UseAppDefaultService = $bucket.Value.UseAppDefaultService
        }
    }

    return $mergedGroups
}

# --- Helper function to append parsed PAN-OS rules from processed resource groups ---
function Add-ParsedRulesFromProcessed {
    param(
        [string]$BaseRuleName,
        [string]$Description,
        [string]$Action,
        [System.Array]$BaseTags,
        [pscustomobject]$Processed,
        [ref]$parsedRules,
        [ref]$ruleNameCounts
    )

    $groups = @($Processed.RuleGroups)
    if ($groups.Count -eq 0) {
        $groups = @([PSCustomObject]@{
            DestAddresses        = @('any')
            Services             = @('any')
            Applications         = @('any')
            UseAppDefaultService = $false
        })
    }
    $groups = @(Merge-RuleGroupsBySignature -RuleGroups $groups)

    $groupIndex = 1
    foreach ($group in $groups) {
        $groupBaseName = if ($groups.Count -gt 1) { "$BaseRuleName-$groupIndex" } else { $BaseRuleName }
        $finalRuleName = Get-UniqueRuleName -BaseName $groupBaseName -RuleNameCounts $ruleNameCounts

        $ruleTags = @() + $BaseTags
        $normalizedGroup = Normalize-RuleGroup -Group $group

        $parsedRules.Value += [PSCustomObject]@{
            Name                 = $finalRuleName
            Description          = $Description
            Action               = $Action
            Tags                 = $ruleTags | Sort-Object -Unique
            DestAddresses        = $normalizedGroup.DestAddresses
            Services             = $normalizedGroup.Services
            Applications         = $normalizedGroup.Applications
            UseAppDefaultService = $normalizedGroup.UseAppDefaultService
        }

        $groupIndex++
    }
}

# --- Helper function to process resources ---
function Process-Resources {
    param(
        [System.Array]$resources,
        [string]$ruleName,
        [ref]$allAddressObjects,
        [ref]$allServiceObjects
    )

    # Destination-first grouping:
    # - Non-ICMP resources build destination -> service set
    # - ICMP resources build destination -> ICMP flag (to emit app ping + service application-default)
    $destServiceGroups = @{} # key: destination object/any, value: HashSet of service objects/any
    $destHasIcmp = @{}       # key: destination object/any, value: $true

    foreach ($resource_str in $resources) {
        $resource_str = $resource_str.Trim()

        if ($resource_str -like '*1.1.1.1*') {
            Write-Warning "Resource '$resource_str' for rule '$ruleName' had no valid match and was ignored (contains 1.1.1.1)."
            continue
        }

        $resourcePattern = "^(?:(?<protocol>\w+)://)?(?:(?<address>[\d\.\*]+)(?:/(?<mask>\d+))?)?(?::(?<ports>[\d,\-\*]+))?$"
        $resourceMatch = $resource_str | Select-String -Pattern $resourcePattern
        
        if (-not $resourceMatch) {
            Write-Warning "Resource '$resource_str' for rule '$ruleName' had no valid match and was ignored."
            continue
        }

        $protocol_raw = $resourceMatch.Matches[0].Groups['protocol'].Value
        $address_raw = $resourceMatch.Matches[0].Groups['address'].Value
        $mask_raw = $resourceMatch.Matches[0].Groups['mask'].Value
        $ports_raw = $resourceMatch.Matches[0].Groups['ports'].Value

        $protocol = if (-not [string]::IsNullOrEmpty($protocol_raw)) { $protocol_raw.ToLower() } else { '' }
        $protocols = if (-not [string]::IsNullOrEmpty($protocol)) { @($protocol) } else { @('tcp', 'udp') }

        $destinationsForResource = @()
        if ([string]::IsNullOrEmpty($address_raw) -or $address_raw -eq '*.*' -or $address_raw -eq '*') {
            $destinationsForResource = @('any')
        } else {
            $ip_address = $address_raw
            $mask = if (-not [string]::IsNullOrEmpty($mask_raw)) { $mask_raw } else { '32' }
            
            $addrObjName = ''
            if ($mask -eq '32') {
                $addrObjName = "HO_$ip_address"
            } else {
                $addrObjName = "NET_$ip_address-$mask"
            }
            $addrObjName = Normalize-PanosName -Name $addrObjName -Fallback 'addr_unnamed'
            
            $allAddressObjects.Value[$addrObjName] = [PSCustomObject]@{
                ip_address = $ip_address
                mask       = $mask
            }
            $destinationsForResource = @($addrObjName)
        }

        if ($protocol -eq 'icmp') {
            foreach ($destObj in $destinationsForResource) {
                $destHasIcmp[$destObj] = $true
            }
            continue
        }

        $servicesForResource = New-Object System.Collections.Generic.HashSet[string]
        if ([string]::IsNullOrEmpty($ports_raw) -or $ports_raw -eq '*') {
            $explicitTcpUdp = @($protocols | Where-Object { $_ -in @('tcp', 'udp') })
            if ((-not [string]::IsNullOrEmpty($protocol_raw)) -and $explicitTcpUdp.Count -gt 0) {
                foreach ($proto in $explicitTcpUdp) {
                    $svcName = Normalize-PanosName -Name "$proto-any" -Fallback 'svc_unnamed'
                    $allServiceObjects.Value[$svcName] = [PSCustomObject]@{
                        protocol   = $proto
                        port_start = '0'
                        port_end   = '65535'
                    }
                    $servicesForResource.Add($svcName) | Out-Null
                }
            } else {
                $servicesForResource.Add('any') | Out-Null
            }
        } else {
            $port_entries = $ports_raw.Split(',')
            foreach ($port_entry in $port_entries) {
                $portParts = $port_entry.Split('-')
                $start_port = $portParts[0]
                $end_port = if ($portParts.Count -gt 1) { $portParts[1] } else { $start_port }
                
                foreach ($proto in $protocols) {
                    $svcName = ''
                    if ($start_port -eq $end_port) {
                        $svcName = "$($proto.ToUpper())-$start_port"
                    } else {
                        $svcName = "$($proto.ToUpper())-$start_port-$end_port"
                    }
                    $svcName = Normalize-PanosName -Name $svcName -Fallback 'svc_unnamed'
                    
                    $allServiceObjects.Value[$svcName] = [PSCustomObject]@{
                        protocol   = $proto
                        port_start = $start_port
                        port_end   = $end_port
                    }
                    $servicesForResource.Add($svcName) | Out-Null
                }
            }
        }

        foreach ($destObj in $destinationsForResource) {
            if (-not $destServiceGroups.ContainsKey($destObj)) {
                $destServiceGroups[$destObj] = New-Object System.Collections.Generic.HashSet[string]
            }
            foreach ($svcObj in $servicesForResource) {
                $destServiceGroups[$destObj].Add($svcObj) | Out-Null
            }
        }
    }

    $ruleGroups = @()
    $allDestinations = New-Object System.Collections.Generic.HashSet[string]
    foreach ($destKey in $destServiceGroups.Keys) {
        $allDestinations.Add($destKey) | Out-Null
    }
    foreach ($destKey in $destHasIcmp.Keys) {
        $allDestinations.Add($destKey) | Out-Null
    }

    foreach ($destKey in ($allDestinations | Sort-Object)) {
        if ($destServiceGroups.ContainsKey($destKey)) {
            $finalServices = @($destServiceGroups[$destKey] | Sort-Object -Unique)
            if ($finalServices -contains 'any') {
                $finalServices = @('any')
            } elseif ($finalServices.Count -eq 0) {
                $finalServices = @('any')
            }

            $ruleGroups += [PSCustomObject]@{
                DestAddresses        = @($destKey)
                Services             = $finalServices
                Applications         = @('any')
                UseAppDefaultService = $false
            }
        }

        if ($destHasIcmp.ContainsKey($destKey)) {
            $ruleGroups += [PSCustomObject]@{
                DestAddresses        = @($destKey)
                Services             = @('application-default')
                Applications         = @('ping')
                UseAppDefaultService = $true
            }
        }
    }

    if ($ruleGroups.Count -eq 0) {
        $ruleGroups = @([PSCustomObject]@{
            DestAddresses        = @('any')
            Services             = @('any')
            Applications         = @('any')
            UseAppDefaultService = $false
        })
    }

    return [PSCustomObject]@{
        RuleGroups = $ruleGroups
    }
}

# --- Read Input File ---
try {
    $ivantiConfig = Get-Content -Raw $InputFile -ErrorAction Stop
} catch {
    Write-Error "Error: Input file '$InputFile' not found. $_"
    exit 1
}

# --- Data Structures for Deduplication ---
$allTags = @{} # Hashtable to store unique tag names (key = tag name, value = $true)
$allAddressObjects = @{} # Hashtable to store unique address objects (key = object name, value = PSCustomObject {ip_address, mask})
$allServiceObjects = @{} # Hashtable to store unique service objects (key = object name, value = PSCustomObject {protocol, port_start, port_end})
$parsedRules = @() # Array to store PSCustomObjects, each representing a parsed Ivanti rule
$ruleNameCounts = @{} # Hashtable to ensure generated PAN-OS rule names are unique

# --- Extract and Process Ivanti Policy Blocks ---
# Using Select-String with -AllMatches and -Pattern to find all blocks
$blockMatches = Select-String -InputObject $ivantiConfig -Pattern "(?s)<network-connect-acl>(.*?)</network-connect-acl>" -AllMatches
if (-not $blockMatches) {
    Write-Warning "No <network-connect-acl> blocks found in the input file."
    exit 0
}

# Iterate through each matched block
foreach ($match in $blockMatches.Matches) {
    $blockContent = $match.Value
    $blockContent = $blockContent -replace ' xsi:nil="true"', ''
    
    try {
        [xml]$xmlBlock = $blockContent
    } catch {
        Write-Error "Error parsing XML block: $_. Content:`n$blockContent"
        continue
    }

    $parentNameRaw = $xmlBlock.'network-connect-acl'.name
    if ([string]::IsNullOrEmpty($parentNameRaw) -or $parentNameRaw -eq 'network-connect-acl') {
        $parentNameRaw = $xmlBlock.'network-connect-acl'.roles
    }
    $parentName = Normalize-PanosName -Name $parentNameRaw -Fallback 'unnamed_rule'
    $parentDescription = $xmlBlock.'network-connect-acl'.description
    $parentAction = $xmlBlock.'network-connect-acl'.action
    $parentRolesRaw = $xmlBlock.'network-connect-acl'.roles
    $parentRoles = if (-not [string]::IsNullOrWhiteSpace($parentRolesRaw)) { Normalize-PanosName -Name $parentRolesRaw -Fallback 'tag_unnamed' } else { $null }

    if (-not [string]::IsNullOrEmpty($parentRoles)) {
        $allTags[$parentRoles] = $true
    }

    $baseTags = @()
    if (-not [string]::IsNullOrEmpty($parentRoles)) {
        $baseTags += $parentRoles
    }

    if ($parentAction -eq 'rules') {
        $nestedRulesRaw = $xmlBlock.'network-connect-acl'.rules.rule
        $nestedRules = @()
        if ($null -ne $nestedRulesRaw) {
            if ($nestedRulesRaw -is [System.Array]) {
                $nestedRules = @($nestedRulesRaw | Where-Object { $null -ne $_ })
            } else {
                $nestedRules = @($nestedRulesRaw)
            }
        }

        # If action is "rules" but no nested rules are present, fallback to top-level resources.
        if ($nestedRules.Count -eq 0) {
            $ruleAction = 'allow'
            $ruleBaseName = $parentName

            $resources = $xmlBlock.'network-connect-acl'.resource
            if ($resources -isnot [System.Array]) {
                $resources = @($resources)
            }

            $processed = Process-Resources -resources $resources -ruleName $ruleBaseName -allAddressObjects ([ref]$allAddressObjects) -allServiceObjects ([ref]$allServiceObjects)

            Add-ParsedRulesFromProcessed -BaseRuleName $ruleBaseName -Description $parentDescription -Action $ruleAction -BaseTags $baseTags -Processed $processed -parsedRules ([ref]$parsedRules) -ruleNameCounts ([ref]$ruleNameCounts)
            continue
        }

        $i = 1
        foreach ($nestedRule in $nestedRules) {
            $ruleBaseName = Normalize-PanosName -Name ('{0}-{1}' -f $parentName, $i) -Fallback 'unnamed_rule'
            $ruleAction = if ($nestedRule.action -eq 'deny') { 'drop' } else { 'allow' }

            $resources = if ($null -ne $nestedRule.resource) {
                if ($nestedRule.resource -isnot [System.Array]) {
                    @($nestedRule.resource)
                } else {
                    $nestedRule.resource
                }
            } else {
                @() # No resources
            }

            $processed = Process-Resources -resources $resources -ruleName $ruleBaseName -allAddressObjects ([ref]$allAddressObjects) -allServiceObjects ([ref]$allServiceObjects)
            Add-ParsedRulesFromProcessed -BaseRuleName $ruleBaseName -Description $parentDescription -Action $ruleAction -BaseTags $baseTags -Processed $processed -parsedRules ([ref]$parsedRules) -ruleNameCounts ([ref]$ruleNameCounts)
            $i++
        }
    } else {
        $ruleAction = if ($parentAction -eq 'deny') { 'drop' } else { 'allow' }
        $ruleBaseName = $parentName
        
        $resources = $xmlBlock.'network-connect-acl'.resource
        if ($resources -isnot [System.Array]) {
            $resources = @($resources) # Ensure it's an array
        }

        $processed = Process-Resources -resources $resources -ruleName $ruleBaseName -allAddressObjects ([ref]$allAddressObjects) -allServiceObjects ([ref]$allServiceObjects)
        Add-ParsedRulesFromProcessed -BaseRuleName $ruleBaseName -Description $parentDescription -Action $ruleAction -BaseTags $baseTags -Processed $processed -parsedRules ([ref]$parsedRules) -ruleNameCounts ([ref]$ruleNameCounts)
    }
} # End foreach block

# --- Generate PAN-OS Commands ---
$panosCommands = @()

# Generate Tag creation commands (sorted for consistent output)
foreach ($tag in ($allTags.Keys | Sort-Object)) {
    $panosCommands += "set device-group $DeviceGroup tag $tag"
}

# Generate Address Object creation commands (sorted for consistent output)
foreach ($addrObj in ($allAddressObjects.GetEnumerator() | Sort-Object Name)) {
    $objName = $addrObj.Name
    $ip = $addrObj.Value.ip_address
    $mask = $addrObj.Value.mask
    $panosCommands += "set device-group $DeviceGroup address $objName ip-netmask $ip/$mask"
}

# Generate Service Object creation commands (sorted for consistent output)
foreach ($svcObj in ($allServiceObjects.GetEnumerator() | Sort-Object Name)) {
    $objName = $svcObj.Name
    $proto = $svcObj.Value.protocol
    $startPort = $svcObj.Value.port_start
    $endPort = $svcObj.Value.port_end

    if ($startPort -eq $endPort) {
        $panosCommands += "set device-group $DeviceGroup service $objName protocol $proto port $startPort"
    } else {
        $panosCommands += "set device-group $DeviceGroup service $objName protocol $proto port $startPort-$endPort"
    }
}

# Generate Security Policy creation commands
foreach ($rule in $parsedRules) {
    $ruleName = $rule.Name
    $description = $rule.Description
    $action = $rule.Action
    $tagsStr = $rule.Tags -join ' ' # Space-separated tags
    $destAddressesStr = $rule.DestAddresses -join ' ' # Space-separated destination objects
    $applications = @($rule.Applications | Sort-Object -Unique)
    if ($applications.Count -eq 0) {
        $applications = @('any')
    }
    $services = @($rule.Services | Sort-Object -Unique)
    if ($services.Count -eq 0) {
        $services = @('any')
    }

    $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" description `"$description`""
    $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" source any"
    $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" from $FromZone"
    $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" to $ToZone"
    $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" destination [ $destAddressesStr ]"
    $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" source-user any"
    $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" category any"

    if ($applications.Count -eq 1) {
        $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" application $($applications[0])"
    } else {
        $applicationsStr = $applications -join ' '
        $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" application [ $applicationsStr ]"
    }

    if ($rule.UseAppDefaultService) {
        $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" service application-default"
    } elseif ($services.Count -eq 1) {
        $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" service $($services[0])"
    } else {
        $servicesStr = $services -join ' '
        $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" service [ $servicesStr ]"
    }
    
    if (-not [string]::IsNullOrEmpty($SecurityProfileGroup)) {
        $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" profile-setting group $SecurityProfileGroup"
    }
    
    if (-not [string]::IsNullOrEmpty($LogForwardingProfile)) {
        $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" log-setting $LogForwardingProfile"
    }
    
    if (-not [string]::IsNullOrEmpty($tagsStr)) {
        $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" tag [ $tagsStr ]"
    }
    
    $panosCommands += "set device-group $DeviceGroup $Rulebase-rulebase security rules `"$ruleName`" action $action"
}

# --- Write Output File ---
try {
    # Join commands with newline and write to output file
    $panosCommands -join "`n" | Set-Content $OutputFile -ErrorAction Stop
    Write-Host "PAN-OS commands successfully written to '$OutputFile'."
} catch {
    Write-Error "Error writing to output file '$OutputFile': $_"
    exit 1
}

Stop-Transcript | Out-Null
