
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
    "todos": todos los recursos evaluados

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

# Filtra solo las policies con efecto Deny y construye información detallada
$denyPolicies = @()
$processedDefs = @{}

Write-Host "Analizando definiciones de políticas para identificar efecto Deny..." -ForegroundColor Cyan

foreach ($assignment in $policyAssignments) {
    $policyDefId = $assignment.Properties.PolicyDefinitionId
    
    # Evita procesar la misma definición múltiples veces
    if ($processedDefs.ContainsKey($policyDefId)) {
        if ($processedDefs[$policyDefId]) {
            $denyPolicies += @{
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
        if ($policyDef) {
            # Verifica si alguna de las políticas de la iniciativa tiene efecto Deny
            $denyPolicyDefs = @()
            foreach ($policyRef in $policyDef.Properties.PolicyDefinitions) {
                $innerPolicy = Get-AzPolicyDefinition -Id $policyRef.policyDefinitionId -ErrorAction SilentlyContinue
                if ($innerPolicy) {
                    $effect = $innerPolicy.Properties.PolicyRule.then.effect
                    # Verifica si el efecto es Deny directamente o si es parametrizado
                    if ($effect -eq "Deny" -or ($effect -like "[parameters(*)]" -and $policyRef.parameters.effect.value -eq "Deny")) {
                        $denyPolicyDefs += $innerPolicy
                    }
                }
            }
            
            if ($denyPolicyDefs.Count -gt 0) {
                $processedDefs[$policyDefId] = $denyPolicyDefs
                $denyPolicies += @{
                    Assignment = $assignment
                    Definition = $denyPolicyDefs
                    IsInitiative = $true
                }
            } else {
                $processedDefs[$policyDefId] = $null
            }
        }
    } else {
        # Es una política individual
        $policyDef = Get-AzPolicyDefinition -Id $policyDefId -ErrorAction SilentlyContinue
        if ($policyDef) {
            $effect = $policyDef.Properties.PolicyRule.then.effect
            # Verifica efecto Deny directo o parametrizado
            if ($effect -eq "Deny" -or ($effect -like "[parameters(*)]" -and $assignment.Properties.Parameters.effect.value -eq "Deny")) {
                $processedDefs[$policyDefId] = $policyDef
                $denyPolicies += @{
                    Assignment = $assignment
                    Definition = $policyDef
                    IsInitiative = $false
                }
            } else {
                $processedDefs[$policyDefId] = $null
            }
        }
    }
}

if ($denyPolicies.Count -eq 0) {
    Write-Host "No hay políticas/iniciativas con efecto Deny en el management group destino." -ForegroundColor Green
    exit 0
}

Write-Host "Políticas/iniciativas con efecto Deny encontradas: $($denyPolicies.Count)" -ForegroundColor Cyan

# Obtiene los recursos de la suscripción
Write-Host "Obteniendo recursos de la suscripción..." -ForegroundColor Cyan
$resources = Get-AzResource -SubscriptionId $SubscriptionId

if (-not $resources -or $resources.Count -eq 0) {
    Write-Host "No se encontraron recursos en la suscripción." -ForegroundColor Yellow
    exit 0
}

Write-Host "Recursos encontrados: $($resources.Count)" -ForegroundColor Cyan
Write-Host "`n=== SIMULACIÓN DE IMPACTO ===" -ForegroundColor Yellow
Write-Host "NOTA: Esta es una evaluación simulada basada en las políticas del MG destino." -ForegroundColor Yellow
Write-Host "      Los recursos listados PODRÍAN ser bloqueados o requerir corrección." -ForegroundColor Yellow
Write-Host "=================================`n" -ForegroundColor Yellow

# Simula el impacto: muestra todos los recursos y las políticas Deny que se les aplicarían
$resultados = @()

foreach ($resource in $resources) {
    foreach ($policyInfo in $denyPolicies) {
        $assignment = $policyInfo.Assignment
        $policyName = $assignment.Properties.DisplayName
        
        # Para simulación, mostramos todos los recursos que estarían sujetos a cada política Deny
        if ($Mode -eq "todos") {
            $resultados += [PSCustomObject]@{
                ResourceName = $resource.Name
                ResourceType = $resource.ResourceType
                ResourceLocation = $resource.Location
                PolicyOrInitiative = $policyName
                PolicyScope = $assignment.Properties.Scope
                ImpactoSimulado = "Estaría sujeto a esta política Deny"
            }
        } elseif ($Mode -eq "incumple") {
            # En modo incumple, mostramos recursos potencialmente en riesgo
            # (sin evaluación real, mostramos todos como posibles incumplimientos)
            $resultados += [PSCustomObject]@{
                ResourceName = $resource.Name
                ResourceType = $resource.ResourceType
                ResourceLocation = $resource.Location
                PolicyOrInitiative = $policyName
                PolicyScope = $assignment.Properties.Scope
                ImpactoSimulado = "⚠️  POSIBLE INCUMPLIMIENTO - Revisar manualmente"
            }
        }
    }
}

Write-Host "Análisis completado.`n" -ForegroundColor Cyan

if ($resultados.Count -eq 0) {
    Write-Host "✓ No hay políticas Deny en el management group destino que afecten a esta suscripción." -ForegroundColor Green
} else {
    Write-Host "⚠️  RECURSOS QUE SERÁN IMPACTADOS POR POLÍTICAS DENY:" -ForegroundColor Yellow
    Write-Host "   Total de combinaciones recurso-política: $($resultados.Count)`n" -ForegroundColor Yellow
    
    # Agrupa por política para mejor visualización
    $groupedByPolicy = $resultados | Group-Object -Property PolicyOrInitiative
    
    foreach ($group in $groupedByPolicy) {
        Write-Host "`n📋 Política: $($group.Name)" -ForegroundColor Cyan
        Write-Host "   Recursos afectados: $($group.Count)" -ForegroundColor Cyan
        $group.Group | Select-Object ResourceName, ResourceType, ResourceLocation | Format-Table -AutoSize
    }
    
    Write-Host "`n⚠️  RECOMENDACIONES:" -ForegroundColor Yellow
    Write-Host "   1. Revise manualmente cada recurso contra las reglas de política específicas" -ForegroundColor Yellow
    Write-Host "   2. Use 'Get-AzPolicyDefinition' para ver los detalles de cada política" -ForegroundColor Yellow
    Write-Host "   3. Considere crear excepciones si es necesario antes de mover la suscripción" -ForegroundColor Yellow
    Write-Host "   4. Pruebe en un entorno de desarrollo/test primero si es posible`n" -ForegroundColor Yellow
}
