
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

# Obtiene las asignaciones de políticas en el management group destino
$mgScope = "/providers/Microsoft.Management/managementGroups/$TargetMG"
$policyAssignments = Get-AzPolicyAssignment -Scope $mgScope

# Filtra solo las policies/iniciativas con efecto Deny
$denyAssignments = $policyAssignments | Where-Object {
    $_.PolicyDefinition -and (
        ($_.PolicyDefinition.Properties.Effect -eq "Deny") -or
        ($_.PolicyDefinition.Properties.Effects -contains "Deny")
    )
}

if (-not $denyAssignments) {
    Write-Host "No hay políticas/iniciativas con efecto Deny en el management group destino." -ForegroundColor Green
    exit 0
}

# Obtiene los recursos de la suscripción
$resources = Get-AzResource -SubscriptionId $SubscriptionId

# Evalúa el cumplimiento de cada recurso respecto a cada policy/iniciativa Deny
$resultados = @()
foreach ($resource in $resources) {
    foreach ($assignment in $denyAssignments) {
        $compliance = Get-AzPolicyState -SubscriptionId $SubscriptionId -PolicyAssignmentName $assignment.Name -ResourceId $resource.ResourceId
        if ($compliance) {
            $incumple = $compliance.ComplianceState -eq "NonCompliant"
            $cumple   = $compliance.ComplianceState -eq "Compliant"
            if (($Mode -eq "incumple" -and $incumple) -or
                ($Mode -eq "cumple"   -and $cumple)   -or
                ($Mode -eq "todos")) {
                $resultados += [PSCustomObject]@{
                    ResourceName = $resource.Name
                    ResourceType = $resource.ResourceType
                    PolicyOrInitiative = $assignment.DisplayName
                    ComplianceState = $compliance.ComplianceState
                }
            }
        }
    }
}

if ($resultados.Count -eq 0) {
    Write-Host "No se encontraron incumplimientos de políticas Deny para los recursos de la suscripción." -ForegroundColor Green
} else {
    $resultados | Format-Table -AutoSize
}
