<#
.SYNOPSIS
    Verifica incumplimientos de políticas Deny al mover una suscripción entre management groups en Azure.
.DESCRIPTION
    El script recibe por línea de comandos o de forma interactiva:
    - ID de suscripción
    - Management group origen
    - Management group destino
    - Modo de salida: incumplimientos, cumplimientos, o todos
    Devuelve los recursos de la suscripción que incumplen (o cumplen) las policies/iniciativas Deny del management group destino.
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
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId <id> -SourceMG <origen> -TargetMG <destino> -Mode incumple
#>

param(
    [string]$SubscriptionId,
    [string]$SourceMG,
    [string]$TargetMG,
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
$policyAssignments = Get-AzPolicyAssignment -ManagementGroupName $TargetMG

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
