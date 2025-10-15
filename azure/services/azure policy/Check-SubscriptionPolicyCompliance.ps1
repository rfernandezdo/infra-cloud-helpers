
<#
.SYNOPSIS
    Verifica el cumplimiento de políticas Deny al mover una suscripción entre management groups en Azure.

.DESCRIPTION
    Este script comprueba los recursos de una suscripción frente a las políticas/iniciativas con efecto Deny asignadas en el management group destino. Permite identificar incumplimientos antes de realizar la migración.

.PARAMETER SubscriptionId
    ID de la suscripción a mover.
.PARAMETER SourceMG
    Management group origen.
.PARAMETER TargetMG
    Management group destino.
.PARAMETER Mode
    "incumple" (default): solo incumplimientos
    "cumple": solo cumplimientos
    "todos": todo    if ($resultados.Count -gt 0) {
        # Filtra solo los que incumplen para el reporte detallado
        $violatingResults = $resultados | Where-Object { $_.Estado -eq "❌ INCUMPLE" }
        
        if ($violatingResults.Count -gt 0) {
            Write-Host "`n⚠️  RECURSOS QUE INCUMPLEN (CRÍTICO):" -ForegroundColor Red
            Write-Host "=" * 120 -ForegroundColor Gray
            
            # Agrupa por política/iniciativa
            $groupedByPolicy = $violatingResults | Group-Object -Property PolicyOrInitiative
            
            foreach ($group in $groupedByPolicy) {
                Write-Host "`n❌ Política/Iniciativa: $($group.Name)" -ForegroundColor Red
                Write-Host "   Recursos que INCUMPLEN: $($group.Count)" -ForegroundColor Red
                
                # Agrupa por tipo de recurso dentro de cada política
                $byType = $group.Group | Group-Object -Property ResourceType
                foreach ($typeGroup in $byType) {
                    Write-Host "`n   📦 Tipo: $($typeGroup.Name) ($($typeGroup.Count) recursos)" -ForegroundColor Yellow
                    $typeGroup.Group | Select-Object ResourceName, ResourceLocation, Impacto | Format-Table -AutoSize
                }
            }
        }
        
        # Si el modo es "todos" o "cumple", muestra también los que cumplen
        if ($Mode -eq "todos" -or $Mode -eq "cumple") {
            $compliantResults = $resultados | Where-Object { $_.Estado -eq "✓ CUMPLE" }
            
            if ($compliantResults.Count -gt 0) {
                Write-Host "`n✓ RECURSOS QUE CUMPLEN:" -ForegroundColor Green
                Write-Host "=" * 120 -ForegroundColor Gray
                
                $groupedByPolicy = $compliantResults | Group-Object -Property PolicyOrInitiative
                
                foreach ($group in $groupedByPolicy) {
                    Write-Host "`n✓ Política/Iniciativa: $($group.Name)" -ForegroundColor Green
                    Write-Host "   Recursos que CUMPLEN: $($group.Count)" -ForegroundColor Green
                    
                    $byType = $group.Group | Group-Object -Property ResourceType
                    foreach ($typeGroup in $byType) {
                        Write-Host "`n   📦 Tipo: $($typeGroup.Name) ($($typeGroup.Count) recursos)" -ForegroundColor Cyan
                        $typeGroup.Group | Select-Object ResourceName, ResourceLocation | Format-Table -AutoSize
                    }
                }
            }
        }
    }uados

.EXAMPLE

    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Mode incumple

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Mode cumple

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Mode todos

.NOTES
    Si algún parámetro no se indica, el script lo solicitará de forma interactiva.
    Requiere permisos para consultar políticas y recursos en Azure.

.LINK
    https://github.com/rfernandezdo/infra-cloud-helpers
#>


[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="ID de la suscripción a mover")]
    [string]$SubscriptionId,
    [Parameter(Mandatory=$false, HelpMessage="Management group origen")]
    [string]$SourceMG,
    [Parameter(Mandatory=$false, HelpMessage="Management group destino")]
    [string]$TargetMG,
    [Parameter(Mandatory=$false, HelpMessage="Modo de salida: incumple, cumple, todos")]
    [ValidateSet("incumple", "cumple", "todos")]
    [string]$Mode = "incumple"
)


function PromptIfMissing {
    param(
        [string]$Value,
        [string]$PromptText
    )
    if (-not $Value) {
        Write-Host $PromptText -ForegroundColor Yellow
        return Read-Host
    }
    return $Value
}

# Comprobación e instalación de Az.Resources si no está presente
if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
    Write-Host "El módulo Az.Resources no está instalado. Instalando..." -ForegroundColor Cyan
    try {
        Install-Module -Name Az.Resources -Scope CurrentUser -Force -ErrorAction Stop
        Write-Host "Módulo Az.Resources instalado correctamente." -ForegroundColor Green
    } catch {
        Write-Error "No se pudo instalar el módulo Az.Resources. Ejecute PowerShell como administrador o instale manualmente."
        exit 1
    }
}

$SubscriptionId = PromptIfMissing $SubscriptionId "Introduce el ID de la suscripción:"
$SourceMG      = PromptIfMissing $SourceMG      "Introduce el management group origen:"
$TargetMG      = PromptIfMissing $TargetMG      "Introduce el management group destino:"

# Login if needed
if (-not (Get-AzContext)) {
    Write-Host "Autenticando en Azure..." -ForegroundColor Cyan
    Connect-AzAccount | Out-Null
}

# Selecciona la suscripción
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# Obtiene las asignaciones de políticas en el management group destino (simulación de herencia)
Write-Host "Obteniendo asignaciones de políticas del management group destino y superiores..." -ForegroundColor Cyan

# Función para obtener todas las asignaciones heredadas (del MG destino y sus ancestros)
function Get-InheritedPolicyAssignments {
    param([string]$ManagementGroupName)
    
    $allAssignments = @()
    $currentMG = $ManagementGroupName
    
    # Recorre la jerarquía hacia arriba para obtener todas las políticas heredadas
    while ($currentMG) {
        $mgScope = "/providers/Microsoft.Management/managementGroups/$currentMG"
        $assignments = Get-AzPolicyAssignment -Scope $mgScope -ErrorAction SilentlyContinue
        
        if ($assignments) {
            $allAssignments += $assignments
        }
        
        # Obtiene el management group padre
        $mgInfo = Get-AzManagementGroup -GroupId $currentMG -Expand -ErrorAction SilentlyContinue
        if ($mgInfo.ParentId) {
            $currentMG = $mgInfo.ParentId.Split('/')[-1]
        } else {
            $currentMG = $null
        }
    }
    
    return $allAssignments
}

$policyAssignments = Get-InheritedPolicyAssignments -ManagementGroupName $TargetMG

if (-not $policyAssignments -or $policyAssignments.Count -eq 0) {
    Write-Host "No se encontraron asignaciones de políticas en el management group destino." -ForegroundColor Yellow
    exit 0
}

Write-Host "Asignaciones encontradas (incluyendo heredadas): $($policyAssignments.Count)" -ForegroundColor Cyan

# Procesa todas las políticas e iniciativas (cualquier efecto)
$allPolicies = @()
$processedDefs = @{}

Write-Host "Analizando definiciones de políticas e iniciativas..." -ForegroundColor Cyan

foreach ($assignment in $policyAssignments) {
    if (-not $assignment -or -not $assignment.Properties) {
        continue
    }
    
    $policyDefId = $assignment.Properties.PolicyDefinitionId
    
    # Valida que el ID no esté vacío
    if ([string]::IsNullOrWhiteSpace($policyDefId)) {
        continue
    }
    
    # Evita procesar la misma definición múltiples veces
    if ($processedDefs.ContainsKey($policyDefId)) {
        if ($processedDefs[$policyDefId]) {
            $allPolicies += @{
                Assignment = $assignment
                Definition = $processedDefs[$policyDefId]
                IsInitiative = $policyDefId -match "/policySetDefinitions/"
            }
        }
        continue
    }
    
    # Obtiene la definición de la política o iniciativa
    if ($policyDefId -match "/policySetDefinitions/") {
        # Es una iniciativa
        $policyDef = Get-AzPolicySetDefinition -Id $policyDefId -ErrorAction SilentlyContinue
        if ($policyDef -and $policyDef.Properties -and $policyDef.Properties.PolicyDefinitions) {
            # Obtiene todas las políticas de la iniciativa
            $innerPolicies = @()
            foreach ($policyRef in $policyDef.Properties.PolicyDefinitions) {
                if (-not $policyRef.policyDefinitionId) {
                    continue
                }
                
                $innerPolicy = Get-AzPolicyDefinition -Id $policyRef.policyDefinitionId -ErrorAction SilentlyContinue
                if ($innerPolicy -and $innerPolicy.Properties -and $innerPolicy.Properties.PolicyRule) {
                    # Agrega la política con sus parámetros de la iniciativa
                    $innerPolicies += @{
                        Definition = $innerPolicy
                        Parameters = $policyRef.parameters
                    }
                }
            }
            
            if ($innerPolicies.Count -gt 0) {
                $processedDefs[$policyDefId] = $innerPolicies
                $allPolicies += @{
                    Assignment = $assignment
                    Definition = $innerPolicies
                    IsInitiative = $true
                }
            } else {
                $processedDefs[$policyDefId] = $null
            }
        } else {
            $processedDefs[$policyDefId] = $null
        }
    } else {
        # Es una política individual
        $policyDef = Get-AzPolicyDefinition -Id $policyDefId -ErrorAction SilentlyContinue
        if ($policyDef -and $policyDef.Properties -and $policyDef.Properties.PolicyRule) {
            $processedDefs[$policyDefId] = $policyDef
            $allPolicies += @{
                Assignment = $assignment
                Definition = $policyDef
                IsInitiative = $false
            }
        } else {
            $processedDefs[$policyDefId] = $null
        }
    }
}

if ($allPolicies.Count -eq 0) {
    Write-Host "No hay políticas/iniciativas en el management group destino." -ForegroundColor Green
    exit 0
}

Write-Host "Políticas/iniciativas encontradas: $($allPolicies.Count)" -ForegroundColor Cyan

# Obtiene los recursos de la suscripción
Write-Host "Obteniendo recursos de la suscripción..." -ForegroundColor Cyan
$resources = Get-AzResource -SubscriptionId $SubscriptionId

if (-not $resources -or $resources.Count -eq 0) {
    Write-Host "No se encontraron recursos en la suscripción." -ForegroundColor Yellow
    exit 0
}

Write-Host "Recursos encontrados: $($resources.Count)" -ForegroundColor Cyan
Write-Host "`n=== ANÁLISIS DE IMPACTO DE MIGRACIÓN ===" -ForegroundColor Yellow
Write-Host "Analizando qué políticas Deny del MG destino aplicarían a los recursos..." -ForegroundColor Yellow
Write-Host "==================================================`n" -ForegroundColor Yellow

# Función para obtener el valor de una propiedad usando alias de Azure Policy
function Get-ResourcePropertyByAlias {
    param(
        $Resource,
        [string]$Alias
    )
    
    # Obtiene las propiedades completas del recurso
    $fullResource = Get-AzResource -ResourceId $Resource.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
    
    if (-not $fullResource) {
        return $null
    }
    
    # Maneja aliases especiales
    if ($Alias -eq "type") {
        return $fullResource.ResourceType
    }
    if ($Alias -eq "location") {
        return $fullResource.Location
    }
    if ($Alias -eq "name") {
        return $fullResource.Name
    }
    if ($Alias -eq "id") {
        return $fullResource.ResourceId
    }
    if ($Alias -eq "tags") {
        return $fullResource.Tags
    }
    if ($Alias -match "^tags\['(.+)'\]$" -or $Alias -match '^tags\["(.+)"\]$') {
        $tagName = $Matches[1]
        return $fullResource.Tags[$tagName]
    }
    
    # Para otros aliases, intenta mapear a propiedades
    # El formato típico es: Microsoft.ResourceType/resourceName/propertyPath
    $aliasParts = $Alias -split '/', 3
    
    if ($aliasParts.Count -ge 3 -and $fullResource.Properties) {
        # Navega por la estructura de propiedades
        $propertyPath = $aliasParts[2] -split '\.'
        $value = $fullResource.Properties
        
        foreach ($part in $propertyPath) {
            # Maneja arrays con índices
            if ($part -match '^(.+)\[(\d+|\*)\]$') {
                $propName = $Matches[1]
                $index = $Matches[2]
                
                if ($value.$propName) {
                    if ($index -eq '*') {
                        # Devuelve el array completo
                        $value = $value.$propName
                    } else {
                        $value = $value.$propName[$index]
                    }
                } else {
                    return $null
                }
            } else {
                if ($value -and $value.PSObject.Properties[$part]) {
                    $value = $value.$part
                } else {
                    return $null
                }
            }
        }
        
        return $value
    }
    
    return $null
}

# Función para evaluar una condición de política
function Test-PolicyCondition {
    param(
        $Condition,
        $Resource,
        $PolicyParameters
    )
    
    if (-not $Condition) {
        return $true
    }
    
    # Maneja operadores lógicos
    if ($Condition.allOf) {
        foreach ($subCondition in $Condition.allOf) {
            if (-not (Test-PolicyCondition -Condition $subCondition -Resource $Resource -PolicyParameters $PolicyParameters)) {
                return $false
            }
        }
        return $true
    }
    
    if ($Condition.anyOf) {
        foreach ($subCondition in $Condition.anyOf) {
            if (Test-PolicyCondition -Condition $subCondition -Resource $Resource -PolicyParameters $PolicyParameters) {
                return $true
            }
        }
        return $false
    }
    
    if ($Condition.not) {
        return -not (Test-PolicyCondition -Condition $Condition.not -Resource $Resource -PolicyParameters $PolicyParameters)
    }
    
    # Evalúa condición de campo
    if ($Condition.field) {
        $fieldValue = Get-ResourcePropertyByAlias -Resource $Resource -Alias $Condition.field
        
        # Resuelve parámetros si es necesario
        $compareValue = $null
        foreach ($prop in @('equals', 'notEquals', 'like', 'notLike', 'in', 'notIn', 'contains', 'notContains', 'greater', 'less', 'greaterOrEquals', 'lessOrEquals')) {
            if ($Condition.$prop) {
                $compareValue = $Condition.$prop
                # Resuelve referencias a parámetros
                if ($compareValue -is [string] -and $compareValue -match '^\[parameters\(''(.+)''\)\]$') {
                    $paramName = $Matches[1]
                    if ($PolicyParameters -and $PolicyParameters.$paramName) {
                        $compareValue = $PolicyParameters.$paramName.value
                    }
                }
                break
            }
        }
        
        # Evalúa operadores
        if ($null -ne $Condition.equals) {
            return $fieldValue -eq $compareValue
        }
        if ($null -ne $Condition.notEquals) {
            return $fieldValue -ne $compareValue
        }
        if ($null -ne $Condition.like) {
            return $fieldValue -like $compareValue
        }
        if ($null -ne $Condition.notLike) {
            return $fieldValue -notlike $compareValue
        }
        if ($null -ne $Condition.in) {
            return $compareValue -contains $fieldValue
        }
        if ($null -ne $Condition.notIn) {
            return $compareValue -notcontains $fieldValue
        }
        if ($null -ne $Condition.contains) {
            return $fieldValue -like "*$compareValue*"
        }
        if ($null -ne $Condition.notContains) {
            return $fieldValue -notlike "*$compareValue*"
        }
        if ($null -ne $Condition.greater) {
            return $fieldValue -gt $compareValue
        }
        if ($null -ne $Condition.less) {
            return $fieldValue -lt $compareValue
        }
        if ($null -ne $Condition.greaterOrEquals) {
            return $fieldValue -ge $compareValue
        }
        if ($null -ne $Condition.lessOrEquals) {
            return $fieldValue -le $compareValue
        }
        if ($null -ne $Condition.exists) {
            $exists = $null -ne $fieldValue
            return $exists -eq $Condition.exists
        }
    }
    
    # Si no se puede evaluar, asume que no cumple
    return $false
}

# Función para evaluar si un recurso INCUMPLE una política
function Test-ResourceViolatesPolicy {
    param(
        $PolicyDefinition,
        $Resource,
        $Assignment,
        $PolicyParameters = $null
    )
    
    if (-not $PolicyDefinition.Properties.PolicyRule) {
        return @{ Violates = $false; Effect = "Unknown" }
    }
    
    $policyRule = $PolicyDefinition.Properties.PolicyRule
    
    # Obtiene el efecto de la política
    $effect = $policyRule.then.effect
    $effectValue = $effect
    
    # Si el efecto es parametrizado, obtiene el valor real
    if ($effect -like "[parameters(*)]" -and $effect -match "parameters\('(.+)'\)") {
        $paramName = $Matches[1]
        
        # Primero intenta obtener el parámetro de los parámetros de iniciativa (PolicyParameters)
        if ($PolicyParameters -and $PolicyParameters.$paramName -and $PolicyParameters.$paramName.value) {
            $effectValue = $PolicyParameters.$paramName.value
        }
        # Si no, intenta obtenerlo de los parámetros de la asignación
        elseif ($Assignment.Properties.Parameters -and $Assignment.Properties.Parameters.$paramName -and $Assignment.Properties.Parameters.$paramName.value) {
            $effectValue = $Assignment.Properties.Parameters.$paramName.value
        }
    }
    
    # Evalúa la condición if de la política
    # Si la condición es TRUE, significa que el recurso está sujeto a esta política
    $assignmentParameters = $Assignment.Properties.Parameters
    $conditionResult = Test-PolicyCondition -Condition $policyRule.if -Resource $Resource -PolicyParameters $assignmentParameters
    
    return @{
        Violates = $conditionResult
        Effect = $effectValue
    }
}

# Analiza el impacto real evaluando cada recurso contra cada política
$resultados = @()
$policyDetails = @()
$processed = 0

foreach ($policyInfo in $allPolicies) {
    $assignment = $policyInfo.Assignment
    $policyName = $assignment.Properties.DisplayName
    $isInitiative = $policyInfo.IsInitiative
    
    Write-Host "Evaluando política: $policyName..." -ForegroundColor Gray
    
    if ($isInitiative) {
        # Para iniciativas, procesa cada política individual con sus parámetros
        foreach ($innerPolicyInfo in $policyInfo.Definition) {
            $innerPolicy = $innerPolicyInfo.Definition
            $innerParams = $innerPolicyInfo.Parameters
            $violatingResources = @()
            $compliantResources = @()
            
            foreach ($resource in $resources) {
                $processed++
                if ($processed % 5 -eq 0) {
                    Write-Progress -Activity "Evaluando recursos" -Status "Procesando $processed de $($resources.Count * $allPolicies.Count)" -PercentComplete (($processed / ($resources.Count * $allPolicies.Count)) * 100)
                }
                
                $result = Test-ResourceViolatesPolicy -PolicyDefinition $innerPolicy -Resource $resource -Assignment $assignment -PolicyParameters $innerParams
                
                if ($result.Violates) {
                    $violatingResources += $resource
                    
                    if ($Mode -eq "incumple" -or $Mode -eq "todos") {
                        $impacto = switch ($result.Effect) {
                            "Deny" { "❌ Sería BLOQUEADO" }
                            "Audit" { "⚠️  Sería marcado como NO CONFORME (solo auditoría)" }
                            "AuditIfNotExists" { "⚠️  Requiere recursos adicionales (auditoría)" }
                            "DeployIfNotExists" { "🔧 Se desplegarían recursos automáticamente" }
                            "Modify" { "🔧 Se modificaría automáticamente" }
                            default { "⚠️  Efecto: $($result.Effect)" }
                        }
                        
                        $resultados += [PSCustomObject]@{
                            ResourceName = $resource.Name
                            ResourceType = $resource.ResourceType
                            ResourceLocation = $resource.Location
                            ResourceId = $resource.ResourceId
                            PolicyOrInitiative = $policyName
                            PolicyName = $innerPolicy.Properties.DisplayName
                            PolicyScope = $assignment.Properties.Scope
                            Effect = $result.Effect
                            Estado = "❌ INCUMPLE"
                            Impacto = $impacto
                        }
                    }
                } else {
                    $compliantResources += $resource
                    
                    if ($Mode -eq "cumple" -or $Mode -eq "todos") {
                        $resultados += [PSCustomObject]@{
                            ResourceName = $resource.Name
                            ResourceType = $resource.ResourceType
                            ResourceLocation = $resource.Location
                            ResourceId = $resource.ResourceId
                            PolicyOrInitiative = $policyName
                            PolicyName = $innerPolicy.Properties.DisplayName
                            PolicyScope = $assignment.Properties.Scope
                            Effect = $result.Effect
                            Estado = "✓ CUMPLE"
                            Impacto = "Cumple con la política"
                        }
                    }
                }
            }
            
            if ($violatingResources.Count -gt 0 -or $compliantResources.Count -gt 0) {
                $policyDetails += [PSCustomObject]@{
                    PolicyAssignment = $policyName
                    PolicyDefinition = $innerPolicy.Properties.DisplayName
                    Effect = $result.Effect
                    ViolatingCount = $violatingResources.Count
                    CompliantCount = $compliantResources.Count
                    ViolatingTypes = if ($violatingResources.Count -gt 0) { ($violatingResources | Select-Object -ExpandProperty ResourceType -Unique) -join ", " } else { "Ninguno" }
                }
            }
        }
    } else {
        # Para política individual
        $policyDef = $policyInfo.Definition
        $violatingResources = @()
        $compliantResources = @()
        
        foreach ($resource in $resources) {
            $processed++
            if ($processed % 5 -eq 0) {
                Write-Progress -Activity "Evaluando recursos" -Status "Procesando $processed de $($resources.Count * $allPolicies.Count)" -PercentComplete (($processed / ($resources.Count * $allPolicies.Count)) * 100)
            }
            
            $result = Test-ResourceViolatesPolicy -PolicyDefinition $policyDef -Resource $resource -Assignment $assignment
            
            if ($result.Violates) {
                $violatingResources += $resource
                
                if ($Mode -eq "incumple" -or $Mode -eq "todos") {
                    $impacto = switch ($result.Effect) {
                        "Deny" { "❌ Sería BLOQUEADO" }
                        "Audit" { "⚠️  Sería marcado como NO CONFORME (solo auditoría)" }
                        "AuditIfNotExists" { "⚠️  Requiere recursos adicionales (auditoría)" }
                        "DeployIfNotExists" { "🔧 Se desplegarían recursos automáticamente" }
                        "Modify" { "🔧 Se modificaría automáticamente" }
                        default { "⚠️  Efecto: $($result.Effect)" }
                    }
                    
                    $resultados += [PSCustomObject]@{
                        ResourceName = $resource.Name
                        ResourceType = $resource.ResourceType
                        ResourceLocation = $resource.Location
                        ResourceId = $resource.ResourceId
                        PolicyOrInitiative = $policyName
                        PolicyName = $policyDef.Properties.DisplayName
                        PolicyScope = $assignment.Properties.Scope
                        Effect = $result.Effect
                        Estado = "❌ INCUMPLE"
                        Impacto = $impacto
                    }
                }
            } else {
                $compliantResources += $resource
                
                if ($Mode -eq "cumple" -or $Mode -eq "todos") {
                    $resultados += [PSCustomObject]@{
                        ResourceName = $resource.Name
                        ResourceType = $resource.ResourceType
                        ResourceLocation = $resource.Location
                        ResourceId = $resource.ResourceId
                        PolicyOrInitiative = $policyName
                        PolicyName = $policyDef.Properties.DisplayName
                        PolicyScope = $assignment.Properties.Scope
                        Effect = $result.Effect
                        Estado = "✓ CUMPLE"
                        Impacto = "Cumple con la política"
                    }
                }
            }
        }
        
        if ($violatingResources.Count -gt 0 -or $compliantResources.Count -gt 0) {
            $policyDetails += [PSCustomObject]@{
                PolicyAssignment = $policyName
                PolicyDefinition = $policyDef.Properties.DisplayName
                Effect = $result.Effect
                ViolatingCount = $violatingResources.Count
                CompliantCount = $compliantResources.Count
                ViolatingTypes = if ($violatingResources.Count -gt 0) { ($violatingResources | Select-Object -ExpandProperty ResourceType -Unique) -join ", " } else { "Ninguno" }
            }
        }
    }
}

Write-Progress -Activity "Evaluando recursos" -Completed

Write-Host "`n=== RESULTADOS DE LA EVALUACIÓN ===`n" -ForegroundColor Cyan

# Cuenta recursos que incumplen
$totalViolating = ($policyDetails | Measure-Object -Property ViolatingCount -Sum).Sum
$totalCompliant = ($policyDetails | Measure-Object -Property CompliantCount -Sum).Sum

if ($policyDetails.Count -eq 0) {
    Write-Host "✓ ÉXITO: No se encontraron políticas en el management group destino." -ForegroundColor Green
    Write-Host "  La migración al management group '$TargetMG' debería ser segura.`n" -ForegroundColor Green
} elseif ($totalViolating -eq 0) {
    Write-Host "✓ ÉXITO: Todos los recursos CUMPLEN con las políticas del destino." -ForegroundColor Green
    Write-Host "  La migración al management group '$TargetMG' debería ser segura.`n" -ForegroundColor Green
    Write-Host "📊 Resumen:" -ForegroundColor Cyan
    Write-Host "   - Políticas evaluadas: $($policyDetails.Count)" -ForegroundColor Gray
    Write-Host "   - Recursos que cumplen: $totalCompliant" -ForegroundColor Green
    Write-Host "   - Recursos que incumplen: $totalViolating`n" -ForegroundColor Green
} else {
    Write-Host "❌ ATENCIÓN: Se encontraron recursos que INCUMPLEN políticas`n" -ForegroundColor Red
    Write-Host "📊 Resumen:" -ForegroundColor Cyan
    Write-Host "   - Políticas evaluadas: $($policyDetails.Count)" -ForegroundColor Gray
    Write-Host "   - Recursos que INCUMPLEN: $totalViolating" -ForegroundColor Red
    Write-Host "   - Recursos que cumplen: $totalCompliant`n" -ForegroundColor Green
    
    # Resumen de políticas
    Write-Host "� DETALLE POR POLÍTICA:" -ForegroundColor Cyan
    Write-Host "=" * 120 -ForegroundColor Gray
    $policyDetails | Format-Table -Property PolicyAssignment, PolicyDefinition, ViolatingCount, CompliantCount, ViolatingTypes -AutoSize
    
    if ($resultados.Count -gt 0) {
        Write-Host "`n📋 DETALLE DE RECURSOS AFECTADOS:" -ForegroundColor Cyan
        Write-Host "=" * 100 -ForegroundColor Gray
        
        # Agrupa por política/iniciativa
        $groupedByPolicy = $resultados | Group-Object -Property PolicyOrInitiative
        
        foreach ($group in $groupedByPolicy) {
            Write-Host "`n� Política/Iniciativa: $($group.Name)" -ForegroundColor Yellow
            Write-Host "   Total de recursos afectados: $($group.Count)" -ForegroundColor Yellow
            
            # Agrupa por tipo de recurso dentro de cada política
            $byType = $group.Group | Group-Object -Property ResourceType
            foreach ($typeGroup in $byType) {
                Write-Host "`n   📦 Tipo: $($typeGroup.Name) ($($typeGroup.Count) recursos)" -ForegroundColor Cyan
                $typeGroup.Group | Select-Object ResourceName, ResourceLocation | Format-Table -AutoSize
            }
        }
    }
    
    Write-Host "`n⚠️  RECOMENDACIONES CRÍTICAS:" -ForegroundColor Red
    Write-Host "=" * 100 -ForegroundColor Gray
    Write-Host "1. 🔍 REVISAR: Analice cada política Deny para entender sus reglas específicas" -ForegroundColor Yellow
    Write-Host "   Comando: Get-AzPolicyDefinition -Id <policy-id> | Select-Object -ExpandProperty Properties" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. 📝 EVALUAR: Determine si los recursos cumplen con las reglas de las políticas" -ForegroundColor Yellow
    Write-Host "   - Las políticas Deny bloquean operaciones de creación/modificación no conformes" -ForegroundColor Gray
    Write-Host "   - Los recursos existentes NO son eliminados, pero pueden quedar en estado no conforme" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. ✅ CORREGIR: Ajuste los recursos para cumplir con las políticas antes de migrar" -ForegroundColor Yellow
    Write-Host "   - Modifique configuraciones de recursos que incumplen" -ForegroundColor Gray
    Write-Host "   - O solicite excepciones de política si es necesario" -ForegroundColor Gray
    Write-Host ""
    Write-Host "4. 🧪 PROBAR: Si es posible, pruebe la migración en un entorno de desarrollo primero" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "5. 📊 MONITOREAR: Después de migrar, revise el estado de cumplimiento" -ForegroundColor Yellow
    Write-Host "   Portal: Azure Policy > Compliance" -ForegroundColor Gray
    Write-Host "   Comando: Get-AzPolicyState -SubscriptionId $SubscriptionId -Filter 'ComplianceState eq ''NonCompliant'''" -ForegroundColor Gray
    Write-Host ""
}
