
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

.PARAMETER ResourceTypeFilter
    Filtro opcional de tipo(s) de recurso. Permite evaluar solo tipos específicos de recursos.
    Ejemplos: "Microsoft.Network/publicIPAddresses", "Microsoft.Compute/virtualMachines"
    Se pueden especificar múltiples tipos separados por comas.

.PARAMETER Parallel
    Switch para habilitar el procesamiento paralelo de recursos. Mejora significativamente el rendimiento
    en suscripciones con muchos recursos. Requiere PowerShell 7.0 o superior.

.PARAMETER ThrottleLimit
    Número máximo de operaciones paralelas simultáneas (por defecto: número de procesadores lógicos).
    Solo se aplica cuando se usa el parámetro -Parallel. Un valor más alto puede mejorar el rendimiento
    pero consumirá más recursos del sistema. Si no se especifica, se usa automáticamente el número
    de procesadores lógicos disponibles.

.PARAMETER ExportResults
    Indica si se deben exportar los resultados a un archivo. Por defecto: $true.
    Use -ExportResults $false para deshabilitar la exportación.

.PARAMETER ExportFormat
    Formato de exportación de resultados: CSV o XLSX (Excel nativo).
    Por defecto: CSV. XLSX requiere el módulo ImportExcel (se instalará automáticamente si no está presente).

.PARAMETER PortalMode
    Modo portal: evalúa solo recursos que realmente violan la lógica de negocio.
    Para NICs, solo evaluará aquellas que tienen IP pública asignada (replicando el comportamiento del portal de Azure).
    Útil para obtener resultados consistentes con lo que se ve en Azure Policy Portal.

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Mode incumple

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Mode cumple

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Mode todos

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -ResourceTypeFilter "Microsoft.Network/publicIPAddresses"

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -ResourceTypeFilter "Microsoft.Compute/virtualMachines,Microsoft.Network/networkInterfaces"

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Parallel

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Parallel -ThrottleLimit 16

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -ResourceTypeFilter "Microsoft.Network/publicIPAddresses" -Parallel

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -ExportFormat XLSX

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -Parallel -ExportFormat XLSX

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -ExportResults $false

.EXAMPLE
    ./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SourceMG "MG-ORIGEN" -TargetMG "MG-DESTINO" -ResourceTypeFilter "Microsoft.Network/networkInterfaces" -PortalMode

.NOTES
    Si algún parámetro no se indica, el script lo solicitará de forma interactiva.
    Requiere permisos para consultar políticas y recursos en Azure.
    El procesamiento paralelo requiere PowerShell 7.0 o superior.
    La exportación a XLSX requiere el módulo ImportExcel (se instalará automáticamente si es necesario).

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
    [string]$Mode = "incumple",
    [Parameter(Mandatory=$false, HelpMessage="Filtro de tipo(s) de recurso. Ejemplos: 'Microsoft.Network/publicIPAddresses' o 'Microsoft.Compute/virtualMachines,Microsoft.Network/networkInterfaces'")]
    [string[]]$ResourceTypeFilter = @(),
    [Parameter(Mandatory=$false, HelpMessage="ID completo de un recurso para evaluar solo ese recurso (ej: /subscriptions/.../resourceGroups/.../providers/.../...)")]
    [string]$TestResourceId,
    [Parameter(Mandatory=$false, HelpMessage="Habilita el procesamiento paralelo de recursos (requiere PowerShell 7+)")]
    [switch]$Parallel,
    [Parameter(Mandatory=$false, HelpMessage="Número de threads paralelos (por defecto: número de procesadores lógicos)")]
    [int]$ThrottleLimit = 0,
    [Parameter(Mandatory=$false, HelpMessage="Exportar resultados a archivo. Por defecto: true")]
    [bool]$ExportResults = $true,
    [Parameter(Mandatory=$false, HelpMessage="Formato de exportación: CSV o XLSX")]
    [ValidateSet("CSV", "XLSX", "XLS")]
    [string]$ExportFormat = "CSV",
    [Parameter(Mandatory=$false, HelpMessage="Modo portal: evalúa solo recursos que realmente violan la lógica de negocio (ej: NICs que tienen IP pública)")]
    [switch]$PortalMode,
    [Parameter(Mandatory=$false, HelpMessage="Habilita información de debug detallada para troubleshooting")]
    [switch]$DebugMode
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

# Helper para obtener definiciones de política con retry, jitter y logging
# Maneja el error de JSON con claves duplicadas usando -AsHashtable
# Helper para obtener definiciones de política con API REST directamente
function Get-PolicyWithRetry {
    param(
        [Parameter(Mandatory=$true)] [string]$Id,
        [Parameter(Mandatory=$true)] [ValidateSet('Definition','SetDefinition')] [string]$Type,
        [int]$MaxRetries = 3
    )

    try {
        # Construir URI basado en el tipo y ID
        if ($Type -eq 'SetDefinition') {
            # Para iniciativas (Policy Set Definitions)
            if ($Id.StartsWith("/subscriptions/")) {
                $uri = "https://management.azure.com$Id"
            } elseif ($Id.StartsWith("/providers/Microsoft.Management/managementGroups/")) {
                $uri = "https://management.azure.com$Id"
            } elseif ($Id.StartsWith("/providers/Microsoft.Authorization/policySetDefinitions/")) {
                $uri = "https://management.azure.com$Id"
            } else {
                # ID de built-in, construir URI completo
                $uri = "https://management.azure.com/providers/Microsoft.Authorization/policySetDefinitions/$Id"
            }
        } else {
            # Para definiciones de política individuales
            if ($Id.StartsWith("/subscriptions/")) {
                $uri = "https://management.azure.com$Id"
            } elseif ($Id.StartsWith("/providers/Microsoft.Management/managementGroups/")) {
                $uri = "https://management.azure.com$Id"
            } elseif ($Id.StartsWith("/providers/Microsoft.Authorization/policyDefinitions/")) {
                $uri = "https://management.azure.com$Id"
            } else {
                # ID de built-in, construir URI completo
                $uri = "https://management.azure.com/providers/Microsoft.Authorization/policyDefinitions/$Id"
            }
        }
        
        if ($script:DebugMode) {
            Write-Host "      🔍 Obteniendo $Type via API REST: $Id" -ForegroundColor DarkGray
            Write-Host "      📡 URI construida: $uri" -ForegroundColor DarkGray
        }
        
        # NUEVO: Retry especial para políticas built-in problemáticas
        $response = $null
        $actualMaxRetries = $MaxRetries
        if ($Id -eq "6c112d4e-5bc7-47ae-a041-ea2d9dccd749") {
            $actualMaxRetries = 5  # Más reintentos para esta política específica
            Write-DebugMessage "      [DEBUG-DETAILED] 🔄 Política built-in conocida - usando $actualMaxRetries reintentos" -ForegroundColor Yellow
        }
        
        $response = Invoke-AzureRestApi -Uri $uri -MaxRetries $actualMaxRetries
        
        # NUEVO: Manejar casos donde la respuesta viene como String en lugar de PSCustomObject
        if ($response -is [string]) {
            Write-DebugMessage "      [DEBUG-DETAILED] WARN Response es String, convirtiendo a PSCustomObject usando -AsHashTable..." -ForegroundColor Yellow
            try {
                # Usar -AsHashTable para manejar claves duplicadas con diferentes casos
                $responseHashTable = $response | ConvertFrom-Json -AsHashTable
                # Convertir HashTable a PSCustomObject para mantener compatibilidad
                $response = [PSCustomObject]@{}
                foreach ($key in $responseHashTable.Keys) {
                    $response | Add-Member -MemberType NoteProperty -Name $key -Value $responseHashTable[$key] -Force
                }
                Write-DebugMessage "      [DEBUG-DETAILED] ✅ Conversión JSON con HashTable exitosa" -ForegroundColor Green
            } catch {
                Write-DebugMessage "      [DEBUG-DETAILED] ❌ Error en conversión JSON con HashTable: $($_.Exception.Message)" -ForegroundColor Red
                throw "Error convertiendo respuesta JSON: $($_.Exception.Message)"
            }
        }
        
        if ($response) {
            if ($script:DebugMode) {
                Write-DebugMessage "      [DEBUG-DETAILED] OK Respuesta API recibida para ${Type}: $Id" -ForegroundColor Cyan
            }
            
            # Debug: Verificar estructura de la respuesta  
            Write-DebugMessage "      [DEBUG-DETAILED] SEARCH Analizando response.properties..." -ForegroundColor Cyan
            Write-DebugMessage "      [DEBUG-DETAILED] SEARCH Type de response: $($response.GetType().Name)" -ForegroundColor Cyan
            Write-DebugMessage "      [DEBUG-DETAILED] SEARCH response.properties es null: $($response.properties -eq $null)" -ForegroundColor Cyan
            Write-DebugMessage "      [DEBUG-DETAILED] SEARCH response tiene propiedades: $(($response | Get-Member -MemberType Properties | Measure-Object).Count)" -ForegroundColor Cyan
            
            if ($response.properties) {
                Write-DebugMessage "      [DEBUG-DETAILED] OK response.properties existe" -ForegroundColor Cyan
                if ($Type -eq 'SetDefinition' -and $response.properties.policyDefinitions) {
                    Write-DebugMessage "      [DEBUG-DETAILED] OK policyDefinitions existe ($($response.properties.policyDefinitions.Count) policies)" -ForegroundColor Cyan
                } elseif ($Type -eq 'Definition' -and $response.properties.policyRule) {
                    Write-DebugMessage "      [DEBUG-DETAILED] OK policyRule existe" -ForegroundColor Cyan
                } elseif ($Type -eq 'Definition') {
                    # Verificar si tiene las propiedades básicas de una policy definition
                    $propNames = $response.properties | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                    Write-DebugMessage "      [DEBUG-DETAILED] WARN policyRule no encontrado, propiedades: $($propNames -join ', ')" -ForegroundColor Yellow
                    
                    # Si tiene displayName y policyType, probablemente sea válida
                    if ($response.properties.displayName -and $response.properties.policyType) {
                        Write-DebugMessage "      [DEBUG-DETAILED] OK Politica tiene propiedades basicas validas" -ForegroundColor Green
                    }
                } else {
                    Write-DebugMessage "      [DEBUG-DETAILED] WARN Estructura inesperada en response.properties" -ForegroundColor Yellow
                    $propNames = $response.properties | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                    Write-DebugMessage "      [DEBUG-DETAILED] Propiedades disponibles: $($propNames -join ', ')" -ForegroundColor Yellow
                }
            } else {
                Write-DebugMessage "      [DEBUG-DETAILED] ❌ response.properties NO existe" -ForegroundColor Red
                $responseProps = $response | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                Write-DebugMessage "      [DEBUG-DETAILED] Propiedades de response: $($responseProps -join ', ')" -ForegroundColor Red
                
                # NUEVO: Guardar respuesta completa para análisis
                if ($Id -like "*Santander-Policy-AKS-RBACEnabled*" -or $Id -like "*Santander-Policy-APP-AfaIpSecurityRestrictions*") {
                    Write-DebugMessage "      [DEBUG-DETAILED] 📋 RESPUESTA COMPLETA para análisis:" -ForegroundColor Yellow
                    Write-DebugMessage "      [DEBUG-DETAILED] $($response | ConvertTo-Json -Depth 10)" -ForegroundColor Yellow
                }
            }
            
            # Crear un objeto que simule la estructura de Get-AzPolicyDefinition/Get-AzPolicySetDefinition
            if ($Type -eq 'SetDefinition') {
                Write-DebugMessage "      [DEBUG-DETAILED] 🔨 Creando objeto SetDefinition..." -ForegroundColor Cyan
                try {
                    # Para iniciativas
                    $policyObject = [PSCustomObject]@{
                        PolicyDefinition = $response.properties.policyDefinitions
                        Properties = [PSCustomObject]@{
                            policyDefinitions = $response.properties.policyDefinitions
                            parameters = $response.properties.parameters
                            displayName = $response.properties.displayName
                            description = $response.properties.description
                            policyType = $response.properties.policyType
                            metadata = $response.properties.metadata
                            policyDefinitionGroups = $response.properties.policyDefinitionGroups
                        }
                        DisplayName = $response.properties.displayName
                        Description = $response.properties.description
                        PolicyType = $response.properties.policyType
                        Parameters = $response.properties.parameters
                        Metadata = $response.properties.metadata
                        Id = $response.id
                        Name = $response.name
                        Type = $response.type
                    }
                    Write-DebugMessage "      [DEBUG-DETAILED] ✓ Objeto SetDefinition creado exitosamente" -ForegroundColor Cyan
                } catch {
                    Write-DebugMessage "      [DEBUG-DETAILED] ❌ Error creando objeto SetDefinition: $($_.Exception.Message)" -ForegroundColor Red
                    throw $_
                }
            } else {
                Write-DebugMessage "      [DEBUG-DETAILED] HAMMER Creando objeto Definition..." -ForegroundColor Cyan
                try {
                    # Para políticas individuales
                    $policyObject = [PSCustomObject]@{
                        PolicyRule = $response.properties.policyRule
                        Properties = [PSCustomObject]@{
                            policyRule = $response.properties.policyRule
                            parameters = $response.properties.parameters
                            displayName = $response.properties.displayName
                            description = $response.properties.description
                            mode = $response.properties.mode
                            policyType = $response.properties.policyType
                            metadata = $response.properties.metadata
                        }
                        DisplayName = $response.properties.displayName
                        Description = $response.properties.description
                        Mode = $response.properties.mode
                        PolicyType = $response.properties.policyType
                        Parameters = $response.properties.parameters
                        Metadata = $response.properties.metadata
                        Id = $response.id
                        Name = $response.name
                        Type = $response.type
                    }
                    Write-DebugMessage "      [DEBUG-DETAILED] ✓ Objeto Definition creado exitosamente" -ForegroundColor Cyan
                } catch {
                    Write-DebugMessage "      [DEBUG-DETAILED] ❌ Error creando objeto Definition: $($_.Exception.Message)" -ForegroundColor Red
                    throw $_
                }
            }
            
            Write-Host "      ✓ $Type obtenida correctamente via API REST" -ForegroundColor Green
            return $policyObject
        } else {
            Write-DebugMessage "      [DEBUG-DETAILED] ❌ Respuesta API vacía o nula para ${Type}: $Id" -ForegroundColor Red
            Write-Host "      ❌ No se pudo obtener $Type via API REST: $Id" -ForegroundColor Red
            return $null
        }
        
    } catch {
        $errorMessage = $_.Exception.Message
        $errorDetails = $_.Exception | Format-List -Property * | Out-String
        Write-DebugMessage "      [DEBUG-DETAILED] ❌ EXCEPCIÓN CAPTURADA en Get-PolicyWithRetry:" -ForegroundColor Red
        Write-DebugMessage "      [DEBUG-DETAILED] Tipo: $Type, ID: $Id" -ForegroundColor Red
        Write-DebugMessage "      [DEBUG-DETAILED] Mensaje: $errorMessage" -ForegroundColor Red
        Write-DebugMessage "      [DEBUG-DETAILED] Línea de error: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
        Write-DebugMessage "      [DEBUG-DETAILED] En comando: $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
        
        # NUEVO: Verificación especial para políticas built-in conocidas que pueden fallar intermitentemente
        if ($Id -eq "6c112d4e-5bc7-47ae-a041-ea2d9dccd749") {
            Write-Host "      ⚠️ Política built-in 'Not allowed resource types' falló - verificando con CLI..." -ForegroundColor Yellow
            try {
                $azCliResult = az policy definition show --name $Id --output json 2>$null
                if ($azCliResult) {
                    Write-Host "      ✓ Política confirmada existente via Azure CLI - error API intermitente" -ForegroundColor Green
                } else {
                    Write-Host "      ❌ Política también falla en Azure CLI - posible problema de permisos" -ForegroundColor Red
                }
            } catch {
                Write-Host "      ❌ Azure CLI no disponible para verificación" -ForegroundColor Red
            }
        }
        
        Write-Host "      ❌ Error al obtener $Type via API REST: $errorMessage" -ForegroundColor Red
        Write-Host "      ⚠️ No se pudo obtener la definición de la política" -ForegroundColor Yellow
        return $null
    }
}

# Simple cache para evitar llamadas repetidas a Get-AzPolicyDefinition/SetDefinition
$script:policyCache = @{}

# Cache para Policy Exemptions para optimizar performance
$script:exemptionsCache = @{}

# Función helper para llamadas API REST con autenticación, retry y manejo de errores
function Invoke-AzureRestApi {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$false)][string]$Method = "GET",
        [Parameter(Mandatory=$false)][string]$ApiVersion = "2021-06-01",
        [Parameter(Mandatory=$false)][hashtable]$Body = $null,
        [Parameter(Mandatory=$false)][int]$MaxRetries = 3
    )
    
    # Obtener token de acceso usando el método que funciona
    $context = Get-AzContext
    if (-not $context) {
        throw "No hay contexto de Azure disponible. Ejecute Connect-AzAccount primero."
    }
    
    try {
        $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
        $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
        $accessToken = $token.AccessToken
    } catch {
        # Fallback para PowerShell 7+ con Az.Accounts modernos
        try {
            $accessToken = (Get-AzAccessToken).Token
        } catch {
            throw "No se pudo obtener el token de acceso: $_"
        }
    }
    
    # Construir URL completa
    if ($Uri -notmatch "api-version=") {
        $separator = if ($Uri -match "\?") { "&" } else { "?" }
        $fullUri = "$Uri${separator}api-version=$ApiVersion"
    } else {
        $fullUri = $Uri
    }
    
    $headers = @{
        'Authorization' = "Bearer $accessToken"
        'Content-Type' = 'application/json'
        'Accept' = 'application/json'
    }
    
    $attempt = 0
    $lastException = $null
    
    while ($attempt -lt $MaxRetries) {
        try {
            $requestParams = @{
                Uri = $fullUri
                Method = $Method
                Headers = $headers
                ErrorAction = 'Stop'
            }
            
            if ($Body) {
                $requestParams.Body = ($Body | ConvertTo-Json -Depth 10)
            }
            
            $response = Invoke-RestMethod @requestParams
            return $response
            
        } catch {
            $lastException = $_
            $errorMessage = $_.Exception.Message
            
            # Verificar códigos de estado específicos
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = $_.Exception.Response.StatusCode.value__
            }
            
            $attempt++
            
            # Si es el último intento, lanzar excepción
            if ($attempt -ge $MaxRetries) {
                Write-Host "      ❌ Error después de $MaxRetries intentos para $Method $fullUri" -ForegroundColor Red
                Write-Host "      Error: $errorMessage" -ForegroundColor Red
                if ($statusCode) {
                    Write-Host "      Código de estado: $statusCode" -ForegroundColor Red
                }
                throw $lastException
            }
            
            # Backoff exponencial con jitter
            $baseWait = [Math]::Pow(2, $attempt)
            $jitter = Get-Random -Minimum 0 -Maximum ([Math]::Min(5, $baseWait))
            $wait = [int]([math]::Max(1, $baseWait + $jitter))
            
            # Respetar Retry-After si está presente
            try {
                if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers["Retry-After"]) {
                    $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                    if ($retryAfter) { $wait = $retryAfter }
                }
            } catch { }
            
            Write-Host "      ⏳ Reintento $attempt/$MaxRetries para $Method $fullUri en $wait s - error: $errorMessage" -ForegroundColor Yellow
            Start-Sleep -Seconds $wait
        }
    }
    
    return $null
}

# Función helper para obtener información de Management Group via API REST
function Get-ManagementGroupViaRest {
    param(
        [Parameter(Mandatory=$true)][string]$GroupId,
        [Parameter(Mandatory=$false)][switch]$Expand
    )
    
    try {
        $uri = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$GroupId"
        if ($Expand) {
            $uri += "?`$expand=children&`$recurse=false"
        }
        
        $response = Invoke-AzureRestApi -Uri $uri -ApiVersion "2021-04-01"
        
        if ($response) {
            # Crear un objeto que simule la estructura de Get-AzManagementGroup
            $mgObject = [PSCustomObject]@{
                Id = $response.id
                Name = $response.name
                DisplayName = $response.properties.displayName
                ParentId = $response.properties.parentId
                ParentName = if ($response.properties.parentId) { 
                    ($response.properties.parentId -split '/')[-1] 
                } else { 
                    $null 
                }
                Children = if ($response.properties.children) { 
                    $response.properties.children 
                } else { 
                    @() 
                }
                Type = $response.type
                Properties = $response.properties
            }
            return $mgObject
        }
        return $null
        
    } catch {
        Write-Host "      ❌ Error al obtener Management Group $GroupId via API REST: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Función helper para obtener asignaciones de política via API REST
function Get-PolicyAssignmentViaRest {
    param(
        [Parameter(Mandatory=$true)][string]$Scope
    )
    
    try {
        # Usar filtro atScope() para obtener asignaciones en este scope y scopes superiores
        $filter = "atScope()"
        $uri = "https://management.azure.com$Scope/providers/Microsoft.Authorization/policyAssignments"
        
        # Agregar filtro como parámetro de query
        $uri += "?`$filter=$filter"
        
        $allAssignments = @()
        
        do {
            $response = Invoke-AzureRestApi -Uri $uri -ApiVersion "2021-06-01"
            
            if ($response -and $response.value) {
                foreach ($assignment in $response.value) {
                    # Crear un objeto que simule la estructura de Get-AzPolicyAssignment
                    $assignmentObject = [PSCustomObject]@{
                        Id = $assignment.id
                        Name = $assignment.name
                        DisplayName = $assignment.properties.displayName
                        PolicyDefinitionId = $assignment.properties.policyDefinitionId
                        Scope = $assignment.properties.scope
                        Properties = [PSCustomObject]@{
                            displayName = $assignment.properties.displayName
                            policyDefinitionId = $assignment.properties.policyDefinitionId
                            scope = $assignment.properties.scope
                            parameters = $assignment.properties.parameters
                            enforcementMode = $assignment.properties.enforcementMode
                            metadata = $assignment.properties.metadata
                            description = $assignment.properties.description
                        }
                        Parameter = $assignment.properties.parameters
                        Type = $assignment.type
                    }
                    $allAssignments += $assignmentObject
                }
            }
            
            # Manejar paginación
            $uri = $response.nextLink
        } while ($uri)
        
        return $allAssignments
        
    } catch {
        Write-Host "      ❌ Error al obtener Policy Assignments para scope $Scope via API REST: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-PolicyCached {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [Parameter(Mandatory=$true)][ValidateSet('Definition','SetDefinition')][string]$Type,
        [int]$MaxRetries = 3
    )
    if ($script:policyCache.ContainsKey($Id)) {
        return $script:policyCache[$Id]
    }
    
    Write-DebugMessage "      [DEBUG-CACHE] Intentando obtener ${Type}: $Id" -ForegroundColor Magenta
    
    try {
        Write-DebugMessage "      [DEBUG-CACHE] 🔄 Llamando a Get-PolicyWithRetry..." -ForegroundColor Magenta
        $res = Get-PolicyWithRetry -Id $Id -Type $Type -MaxRetries $MaxRetries
        
        Write-DebugMessage "      [DEBUG-CACHE] SEARCH Resultado de Get-PolicyWithRetry: $(if($res -ne $null){'NO-NULL'}else{'NULL'})" -ForegroundColor Magenta
        
        if ($res) { 
            Write-DebugMessage "      [DEBUG-CACHE] ✅ Resultado válido recibido, verificando propiedades..." -ForegroundColor Magenta
            
            # Verificar si el objeto tiene las propiedades esperadas
            if ($Type -eq 'SetDefinition') {
                $hasExpectedProps = ($res.PolicyDefinition -ne $null) -or ($res.Properties.policyDefinitions -ne $null)
                Write-DebugMessage "      [DEBUG-CACHE] 🔍 SetDefinition tiene propiedades esperadas: $hasExpectedProps" -ForegroundColor Magenta
                Write-DebugMessage "      [DEBUG-CACHE] 🔍 res.PolicyDefinition: $($res.PolicyDefinition -ne $null)" -ForegroundColor Magenta  
                Write-DebugMessage "      [DEBUG-CACHE] 🔍 res.Properties.policyDefinitions: $($res.Properties.policyDefinitions -ne $null)" -ForegroundColor Magenta
            } else {
                $hasExpectedProps = ($res.PolicyRule -ne $null) -or ($res.Properties.policyRule -ne $null)
                Write-DebugMessage "      [DEBUG-CACHE] 🔍 Definition tiene propiedades esperadas: $hasExpectedProps" -ForegroundColor Magenta
                Write-DebugMessage "      [DEBUG-CACHE] 🔍 res.PolicyRule: $($res.PolicyRule -ne $null)" -ForegroundColor Magenta
                Write-DebugMessage "      [DEBUG-CACHE] 🔍 res.Properties.policyRule: $($res.Properties.policyRule -ne $null)" -ForegroundColor Magenta
                Write-DebugMessage "      [DEBUG-CACHE] 🔍 res.Properties: $($res.Properties -ne $null)" -ForegroundColor Magenta
                if ($res.Properties) {
                    $propNames = $res.Properties | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                    Write-DebugMessage "      [DEBUG-CACHE] 🔍 Propiedades en res.Properties: $($propNames -join ', ')" -ForegroundColor Magenta
                }
            }
            
            $script:policyCache[$Id] = $res
            Write-DebugMessage "      [DEBUG-CACHE] ✓ Política cacheada exitosamente: $Id" -ForegroundColor Green
        } else {
            Write-DebugMessage "      [DEBUG-CACHE] ❌ Get-PolicyWithRetry retornó null para: $Id" -ForegroundColor Red
        }
        return $res
    } catch {
        Write-DebugMessage "      [DEBUG-CACHE] ❌ Excepción en Get-PolicyCached para $Id : $($_.Exception.Message)" -ForegroundColor Red
        Write-DebugMessage "      [DEBUG-CACHE] ❌ Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
        return $null
    }
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

# Validación de PowerShell 7+ si se usa -Parallel
if ($Parallel -and $PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "⚠️  El procesamiento paralelo requiere PowerShell 7 o superior." -ForegroundColor Yellow
    Write-Host "   Versión actual: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host "   Continuando en modo secuencial..." -ForegroundColor Yellow
    $Parallel = $false
}

# Configura ThrottleLimit por defecto si no se especificó
if ($Parallel -and $ThrottleLimit -eq 0) {
    $ThrottleLimit = [Environment]::ProcessorCount
    Write-Host "ℹ️  Usando $ThrottleLimit threads paralelos (procesadores detectados)" -ForegroundColor Cyan
}

$SubscriptionId = PromptIfMissing $SubscriptionId "Introduce el ID de la suscripción:"
$SourceMG      = PromptIfMissing $SourceMG      "Introduce el management group origen:"
$TargetMG      = PromptIfMissing $TargetMG      "Introduce el management group destino:"

# Configurar la variable global de debug
$script:DebugMode = $DebugMode.IsPresent

# Función helper para logging de debug
function Write-DebugMessage {
    param(
        [string]$Message,
        [string]$Color = "Gray"
    )
    if ($script:DebugMode) {
        Write-Host $Message -ForegroundColor $Color
    }
}

# Función para obtener todas las exemptions de un scope (incluye jerarquía)
function Get-PolicyExemptions {
    param(
        [Parameter(Mandatory=$true)][string]$Scope,
        [int]$MaxRetries = 3
    )

    # Verificar cache primero
    if ($script:exemptionsCache.ContainsKey($Scope)) {
        Write-DebugMessage "      [EXEMPTIONS-CACHE] ✓ Exemptions cacheadas para scope: $Scope" -ForegroundColor Green
        return $script:exemptionsCache[$Scope]
    }

    Write-DebugMessage "      [EXEMPTIONS] 🔍 Obteniendo exemptions para scope: $Scope" -ForegroundColor Cyan

    try {
        # Construir URI para obtener exemptions
        $uri = "https://management.azure.com$Scope/providers/Microsoft.Authorization/policyExemptions"
        
        # Para management groups, necesitamos añadir un filtro obligatorio
        if ($Scope -match "Microsoft\.Management/managementGroups") {
            # Usar atScope() para incluir exemptions heredadas del management group y ancestros
            $uri += "?`$filter=atScope()"
        }
        
        $response = Invoke-AzureRestApi -Uri $uri -ApiVersion "2022-07-01-preview" -MaxRetries $MaxRetries

        $exemptions = @()
        if ($response -and $response.value) {
            foreach ($exemption in $response.value) {
                $exemptionObject = [PSCustomObject]@{
                    Name = $exemption.name
                    Id = $exemption.id
                    Scope = if($exemption.properties.policyAssignmentScope){$exemption.properties.policyAssignmentScope}else{$Scope}
                    PolicyAssignmentId = $exemption.properties.policyAssignmentId
                    ExemptionCategory = $exemption.properties.exemptionCategory
                    Description = $exemption.properties.description
                    DisplayName = $exemption.properties.displayName
                    ExpiresOn = $exemption.properties.expiresOn
                    PolicyDefinitionReferenceIds = $exemption.properties.policyDefinitionReferenceIds
                }
                $exemptions += $exemptionObject
            }
            Write-DebugMessage "      [EXEMPTIONS] ✓ Encontradas $($exemptions.Count) exemptions en scope: $Scope" -ForegroundColor Green
        } else {
            Write-DebugMessage "      [EXEMPTIONS] ℹ️  No se encontraron exemptions en scope: $Scope" -ForegroundColor Yellow
        }

        # Cachear resultado
        $script:exemptionsCache[$Scope] = $exemptions
        return $exemptions

    } catch {
        $errorMessage = $_.Exception.Message
        $statusCode = $null
        
        # Intentar obtener el código de estado HTTP
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
        }
        
        # Manejo específico de errores 404 para exemptions
        if ($statusCode -eq 404) {
            Write-DebugMessage "      [EXEMPTIONS] ℹ️  No se encontraron exemptions en scope: $Scope (404 Not Found - esto es normal si no hay exemptions configuradas)" -ForegroundColor Yellow
        } else {
            Write-DebugMessage "      [EXEMPTIONS] ❌ Error obteniendo exemptions para $Scope (Código: $statusCode): $errorMessage" -ForegroundColor Red
            
            # Si falla el management group, intentar con API estable como fallback
            if ($statusCode -eq 400 -and $Scope -match "Microsoft\.Management/managementGroups") {
                Write-DebugMessage "      [EXEMPTIONS] 🔄 Intentando con API version estable como fallback..." -ForegroundColor Yellow
                try {
                    $fallbackUri = "https://management.azure.com$Scope/providers/Microsoft.Authorization/policyExemptions?`$filter=atScope()"
                    $response = Invoke-AzureRestApi -Uri $fallbackUri -ApiVersion "2020-07-01-preview" -MaxRetries 1
                    
                    $exemptions = @()
                    if ($response -and $response.value) {
                        foreach ($exemption in $response.value) {
                            $exemptionObject = [PSCustomObject]@{
                                Name = $exemption.name
                                Id = $exemption.id
                                Scope = if($exemption.properties.policyAssignmentScope){$exemption.properties.policyAssignmentScope}else{$Scope}
                                PolicyAssignmentId = $exemption.properties.policyAssignmentId
                                ExemptionCategory = $exemption.properties.exemptionCategory
                                Description = $exemption.properties.description
                                DisplayName = $exemption.properties.displayName
                                ExpiresOn = $exemption.properties.expiresOn
                                PolicyDefinitionReferenceIds = $exemption.properties.policyDefinitionReferenceIds
                            }
                            $exemptions += $exemptionObject
                        }
                        Write-DebugMessage "      [EXEMPTIONS] ✓ Fallback exitoso: encontradas $($exemptions.Count) exemptions" -ForegroundColor Green
                        $script:exemptionsCache[$Scope] = $exemptions
                        return $exemptions
                    }
                } catch {
                    Write-DebugMessage "      [EXEMPTIONS] ⚠️  Fallback también falló: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
        
        # Cachear resultado vacío para evitar reintentos
        $script:exemptionsCache[$Scope] = @()
        return @()
    }
}

# Función para verificar si un recurso/política tiene una exemption
function Test-ResourcePolicyExemption {
    param(
        [Parameter(Mandatory=$true)][string]$ResourceId,
        [Parameter(Mandatory=$true)][string]$PolicyAssignmentId,
        [Parameter(Mandatory=$false)][string]$PolicyDefinitionReferenceId,
        [Parameter(Mandatory=$true)][array]$AllExemptions
    )

    Write-DebugMessage "        [EXEMPTION-CHECK] 🔍 Verificando exemption para recurso: $ResourceId" -ForegroundColor DarkGray
    Write-DebugMessage "        [EXEMPTION-CHECK] 📋 Policy Assignment: $PolicyAssignmentId" -ForegroundColor DarkGray

    foreach ($exemption in $AllExemptions) {
        # 1. Verificar si la exemption aplica a esta policy assignment
        if ($exemption.PolicyAssignmentId -ne $PolicyAssignmentId) {
            continue
        }

        # 2. Si hay PolicyDefinitionReferenceIds específicos, verificar match
        if ($exemption.PolicyDefinitionReferenceIds -and $PolicyDefinitionReferenceId) {
            if ($exemption.PolicyDefinitionReferenceIds -notcontains $PolicyDefinitionReferenceId) {
                continue
            }
        }

        # 3. Verificar si el recurso está dentro del scope de la exemption
        if (Test-ResourceInScope -ResourceId $ResourceId -ExemptionScope $exemption.Scope) {
            Write-DebugMessage "        [EXEMPTION-CHECK] ✅ Exemption encontrada: $($exemption.Name)" -ForegroundColor Green
            return [PSCustomObject]@{
                HasExemption = $true
                ExemptionName = $exemption.Name
                ExemptionCategory = $exemption.ExemptionCategory
                Description = $exemption.Description
                ExpiresOn = $exemption.ExpiresOn
            }
        }
    }

    Write-DebugMessage "        [EXEMPTION-CHECK] ❌ No se encontró exemption aplicable" -ForegroundColor DarkGray
    return [PSCustomObject]@{
        HasExemption = $false
        ExemptionName = $null
        ExemptionCategory = $null
        Description = $null
        ExpiresOn = $null
    }
}

# Función helper para verificar si un recurso está dentro del scope de una exemption
function Test-ResourceInScope {
    param(
        [Parameter(Mandatory=$true)][string]$ResourceId,
        [Parameter(Mandatory=$true)][string]$ExemptionScope
    )

    # Normalizar IDs para comparación
    $resourcePath = $ResourceId.ToLower()
    $exemptionPath = $ExemptionScope.ToLower()

    # Si el scope de la exemption es igual o superior al recurso, aplica
    if ($resourcePath.StartsWith($exemptionPath)) {
        return $true
    }

    return $false
}

# Función para resolver parámetros anidados recursivamente
function Resolve-NestedParameters {
    param(
        [object]$ParameterValue,
        [hashtable]$ParameterSource,
        [int]$MaxDepth = 5,
        [int]$CurrentDepth = 0,
        [bool]$ShowDebug = $false
    )
    
    if ($CurrentDepth -ge $MaxDepth) {
        if ($ShowDebug) { Write-DebugMessage "            [DEBUG] ⚠️ Máxima profundidad alcanzada ($MaxDepth)" -ForegroundColor Yellow }
        return $ParameterValue
    }
    
    # Si el valor no es una string, devolver como está
    if ($ParameterValue -isnot [string]) {
        return $ParameterValue
    }
    
    # Buscar patron [parameters('nombreParam')]
    if ($ParameterValue -match '\[parameters\(.([^)]+).\)\]') {
        $referencedParam = $matches[1]
        if ($ShowDebug) { Write-DebugMessage "            [DEBUG] 🔍 Encontrado parámetro referenciado: $referencedParam" -ForegroundColor Cyan }
        
        if ($ParameterSource -and $ParameterSource.ContainsKey($referencedParam)) {
            $resolvedValue = $ParameterSource[$referencedParam]
            if ($ShowDebug) { Write-DebugMessage "            [DEBUG] ✓ Valor encontrado: $resolvedValue" -ForegroundColor Green }
            
            # Resolución recursiva en caso de que el valor resuelto también contenga parámetros
            return Resolve-NestedParameters -ParameterValue $resolvedValue -ParameterSource $ParameterSource -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -ShowDebug $ShowDebug
        } else {
            if ($ShowDebug) { Write-DebugMessage "            [DEBUG] WARN Parametro '$referencedParam' no encontrado en source" -ForegroundColor Yellow }
            return $ParameterValue  # Devolver sin resolver
        }
    }
    
    # Buscar patrón @{value=[parameters('nombreParam')]}
    if ($ParameterValue -match "@\{value=\[parameters\('([^']+)'\)\]\}") {
        $referencedParam = $matches[1]
        if ($ShowDebug) { Write-DebugMessage "            [DEBUG] 🔍 Encontrado parámetro @{value=...}: $referencedParam" -ForegroundColor Cyan }
        
        if ($ParameterSource -and $ParameterSource.ContainsKey($referencedParam)) {
            $resolvedValue = $ParameterSource[$referencedParam]
            if ($ShowDebug) { Write-DebugMessage "            [DEBUG] ✓ Valor @{value=...} encontrado: $resolvedValue" -ForegroundColor Green }
            
            # Resolución recursiva
            return Resolve-NestedParameters -ParameterValue $resolvedValue -ParameterSource $ParameterSource -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -ShowDebug $ShowDebug
        } else {
            if ($ShowDebug) { Write-DebugMessage "            [DEBUG] ⚠️ Parámetro @{value=...} '$referencedParam' no encontrado" -ForegroundColor Yellow }
            return $ParameterValue
        }
    }
    
    # Si no hay patrones de parámetros, devolver el valor tal como está
    return $ParameterValue
}

# Login if needed
if (-not (Get-AzContext)) {
    Write-Host "Autenticando en Azure..." -ForegroundColor Cyan
    Connect-AzAccount | Out-Null
}

# Selecciona la suscripción
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# Friendly startup banner
Write-Host "`n===============================================" -ForegroundColor Magenta
Write-Host " Check-SubscriptionPolicyCompliance v1 — Comprobación de políticas antes de migrar MG" -ForegroundColor Magenta
Write-Host " Soporta export formats: CSV, XLSX (Excel). También se acepta 'XLS' como alias." -ForegroundColor Magenta
Write-Host " Usa -ExportResults:$true para generar fichero; -ExportFormat XLSX para Excel nativo." -ForegroundColor Magenta
Write-Host "===============================================`n" -ForegroundColor Magenta

# Normalizar alias 'XLS' a 'XLSX' si se pasó
if ($ExportFormat -eq 'XLS') {
    Write-Host "ℹ️  Nota: 'XLS' es un alias antiguo; usando 'XLSX' internamente." -ForegroundColor Cyan
    $ExportFormat = 'XLSX'
}

# Obtiene las asignaciones de políticas que aplicarían a la suscripción desde el MG destino
Write-Host "`n=== FASE 1: OBTENIENDO ASIGNACIONES DE POLÍTICAS ===" -ForegroundColor Cyan
Write-Host "Simulando la suscripción bajo el management group destino..." -ForegroundColor Cyan

# Construimos la jerarquía del MG destino
Write-Host "`n  Construyendo jerarquía del management group destino..." -ForegroundColor Gray
$mgHierarchy = @()
$tempMG = $TargetMG

while ($tempMG) {
    # Obtiene info del MG y guarda el NOMBRE (no el ID) usando API REST
    $mgInfo = Get-ManagementGroupViaRest -GroupId $tempMG -Expand
    if ($mgInfo) {
        # Usa .Name en lugar de solo añadir $tempMG (que podría ser un ID)
        $mgHierarchy += $mgInfo.Name
        
        if ($mgInfo.ParentName) {
            $tempMG = $mgInfo.ParentName
        } else {
            $tempMG = $null
        }
    } else {
        Write-Host "  ⚠ No se pudo obtener información del MG: $tempMG" -ForegroundColor Yellow
        $tempMG = $null
    }
}

Write-Host "  Jerarquía del destino: $($mgHierarchy -join ' <- ')" -ForegroundColor Cyan

# Obtenemos asignaciones directamente desde cada nivel de la jerarquía del MG destino
Write-Host "`n  Obteniendo asignaciones desde la jerarquía destino..." -ForegroundColor Gray
$policyAssignments = @()
$uniqueIds = @{}

foreach ($mg in $mgHierarchy) {
    Write-Host "`n    Buscando asignaciones para MG: $mg" -ForegroundColor DarkGray
    
    # Usa el scope con el nombre del MG
    $mgScope = "/providers/Microsoft.Management/managementGroups/$mg"
    
    # Consulta directamente las asignaciones en este MG usando API REST
    $mgAssignments = @(Get-PolicyAssignmentViaRest -Scope $mgScope)
    
    if ($mgAssignments.Count -gt 0) {
        Write-Host "      ✓ Encontradas $($mgAssignments.Count) asignaciones" -ForegroundColor Green
        
        foreach ($assignment in $mgAssignments) {
            if ($assignment -and $assignment.Id -and -not $uniqueIds.ContainsKey($assignment.Id)) {
                $policyAssignments += $assignment
                $uniqueIds[$assignment.Id] = $true
                Write-Host "        + $($assignment.DisplayName)" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "      - No se encontraron asignaciones en este nivel" -ForegroundColor DarkGray
    }
}

Write-Host "`n✓ Total de asignaciones que aplicarían: $($policyAssignments.Count)" -ForegroundColor Green

if (-not $policyAssignments -or $policyAssignments.Count -eq 0) {
    Write-Host "No se encontraron asignaciones de políticas en el management group destino." -ForegroundColor Yellow
    exit 0
}

Write-Host "Asignaciones encontradas (incluyendo heredadas): $($policyAssignments.Count)" -ForegroundColor Cyan

# Procesa todas las políticas e iniciativas (cualquier efecto)
Write-Host "`n=== FASE 2: ANALIZANDO DEFINICIONES DE POLÍTICAS ===" -ForegroundColor Cyan
$allPolicies = @()
$processedDefs = @{}
$processedCount = 0

foreach ($assignment in $policyAssignments) {
    if (-not $assignment) {
        continue
    }
    
    $policyDefId = $assignment.PolicyDefinitionId
    
    # Valida que el ID no esté vacío
    if ([string]::IsNullOrWhiteSpace($policyDefId)) {
        continue
    }
    
    $assignmentName = $assignment.DisplayName
    if ([string]::IsNullOrWhiteSpace($assignmentName)) {
        $assignmentName = $assignment.Name
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
    
    $processedCount++
    Write-Host "  [$processedCount/$($policyAssignments.Count)] Procesando: $assignmentName" -ForegroundColor Gray
    
    # Obtiene la definición de la política o iniciativa
    if ($policyDefId -match "/policySetDefinitions/") {
        # Es una iniciativa
        Write-Host "      Tipo: Iniciativa" -ForegroundColor Cyan
        
        # Implementar retry para obtener la definición de la iniciativa
        $maxRetries = 3
        $retryCount = 0
        $policyDef = $null
        
    # Usar helper con retry/jitter y cache
    $policyDef = Get-PolicyCached -Id $policyDefId -Type 'SetDefinition' -MaxRetries $maxRetries
        
        if ($policyDef -and $policyDef.PolicyDefinition) {
            Write-Host "      Contiene $($policyDef.PolicyDefinition.Count) políticas" -ForegroundColor Gray
            
            # Obtiene todas las políticas de la iniciativa
            $innerPolicies = @()
            $innerCount = 0
            $failedPolicies = 0
            
            foreach ($policyRef in $policyDef.PolicyDefinition) {
                if (-not $policyRef.PolicyDefinitionId) {
                    continue
                }
                
                $innerCount++
                
                # Implementar retry para cada política individual dentro de la iniciativa
                $innerRetryCount = 0
                $innerPolicy = $null
                
                # Obtener política interna con helper retry y cache
                $innerPolicy = Get-PolicyCached -Id $policyRef.PolicyDefinitionId -Type 'Definition' -MaxRetries $maxRetries
                
                # Manejar diferencias de casing entre Get-AzPolicyDefinition y REST API
                $policyRule = if ($innerPolicy.PolicyRule) { $innerPolicy.PolicyRule } elseif ($innerPolicy.properties.policyRule) { $innerPolicy.properties.policyRule } else { $null }
                
                if ($innerPolicy -and $policyRule) {
                    # Intenta resolver el efecto si está parametrizado
                    $rawEffect = $policyRule.then.effect
                    $resolvedEffect = $rawEffect

                    if ($rawEffect -is [string] -and $rawEffect -match "\[parameters\('(?<p>[^']+)'\)\]") {
                        $paramName = $Matches['p']
                        $resolved = $null
                        $resolvedSource = "Direct"

                        # DEBUG: Solo para las primeras 3 políticas
                        $showDebug = ($innerCount -le 3)

                        # Flujo simplificado: Assignment → Initiative → Policy
                        
                        # 1) Buscar primero en parámetros de la asignación
                        if ($assignment.Properties -and $assignment.Properties.Parameters -and $assignment.Properties.Parameters.$paramName) {
                            $assignmentValue = $assignment.Properties.Parameters.$paramName
                            if ($assignmentValue -is [hashtable] -and $assignmentValue.value) {
                                $resolved = $assignmentValue.value
                            } else {
                                $resolved = $assignmentValue
                            }
                            $resolvedSource = "Assignment.Parameters"
                            if ($showDebug) { Write-DebugMessage "          [DEBUG] ✓ Desde Assignment.Parameters '$paramName': $resolved" -ForegroundColor Green }
                        }
                        
                        # 2) Si no se encontró en la asignación, buscar en policyRef.parameters (Initiative → Policy)
                        if (-not $resolved -and $policyRef.parameters -and $policyRef.parameters.$paramName) {
                            $paramValue = $policyRef.parameters.$paramName
                            
                            # Si es un objeto con .value, extraer el valor
                            if ($paramValue -is [hashtable] -and $paramValue.value) {
                                $resolved = $paramValue.value
                            } else {
                                $resolved = $paramValue
                            }
                            $resolvedSource = "Initiative.PolicyRef"
                            if ($showDebug) { Write-DebugMessage "          [DEBUG] ✓ Desde Initiative.PolicyRef '$paramName': $resolved" -ForegroundColor Green }
                        }

                        # 3) Revisar defaultValue en la definición de la política
                        try {
                            if (-not $resolved) {
                                $defParams = $null
                                if ($innerPolicy.Properties -and $innerPolicy.Properties.parameters) {
                                    $defParams = $innerPolicy.Properties.parameters
                                } elseif ($innerPolicy.properties -and $innerPolicy.properties.parameters) {
                                    $defParams = $innerPolicy.properties.parameters
                                } elseif ($innerPolicy.Parameters) {
                                    $defParams = $innerPolicy.Parameters
                                }
                                
                                if ($defParams -and $defParams.$paramName -and $defParams.$paramName.defaultValue) {
                                    $resolved = $defParams.$paramName.defaultValue
                                    $resolvedSource = "Policy.DefaultValue"
                                    if ($showDebug) { Write-DebugMessage "          [DEBUG] ✓ Resuelto desde defaultValue: $resolved" -ForegroundColor Green }
                                }
                            }
                        } catch { 
                            if ($showDebug) { Write-DebugMessage "          [DEBUG] ✗ Error al acceder defaultValue: $_" -ForegroundColor Yellow }
                        }

                        # 4) Crear mapa de parámetros para resolución recursiva
                        $parameterMap = @{}
                        
                        # Agregar parámetros de la asignación
                        if ($assignment.Properties -and $assignment.Properties.Parameters) {
                            foreach ($key in $assignment.Properties.Parameters.Keys) {
                                $val = $assignment.Properties.Parameters[$key]
                                if ($val -is [hashtable] -and $val.value) {
                                    $parameterMap[$key] = $val.value
                                } else {
                                    $parameterMap[$key] = $val
                                }
                            }
                        }
                        
                        # Agregar parámetros de la iniciativa (defaults)
                        if ($policyDef.Properties -and $policyDef.Properties.parameters) {
                            foreach ($key in $policyDef.Properties.parameters.Keys) {
                                if (-not $parameterMap.ContainsKey($key) -and $policyDef.Properties.parameters[$key].defaultValue) {
                                    $parameterMap[$key] = $policyDef.Properties.parameters[$key].defaultValue
                                }
                            }
                        }

                        # 5) Aplicar resolución recursiva al valor resuelto
                        if ($resolved) {
                            if ($showDebug) { Write-DebugMessage "          [DEBUG] 🔄 Aplicando resolución recursiva a: $resolved" -ForegroundColor Cyan }
                            $finalResolved = Resolve-NestedParameters -ParameterValue $resolved -ParameterSource $parameterMap -ShowDebug $showDebug
                            if ($finalResolved -ne $resolved) {
                                if ($showDebug) { Write-DebugMessage "          [DEBUG] 🎯 Resolución recursiva completada: $resolved → $finalResolved" -ForegroundColor Magenta }
                            }
                            $resolvedEffect = $finalResolved
                        } else {
                            $resolvedEffect = "Parametrizado-NoResuelto"
                            $resolvedSource = "Parameter '$paramName' not found"
                            if ($showDebug) { Write-DebugMessage "          [DEBUG] ⚠ Parámetro '$paramName' no se pudo resolver" -ForegroundColor Yellow }
                        }
                    }

                    if ($innerCount -le 3) {
                        if ($rawEffect -ne $resolvedEffect) {
                            Write-Host "        ├─ $($innerPolicy.DisplayName) (Efecto: $rawEffect → $resolvedEffect)" -ForegroundColor DarkGray
                        } else {
                            Write-Host "        ├─ $($innerPolicy.DisplayName) (Efecto: $resolvedEffect)" -ForegroundColor DarkGray
                        }
                    }

                    # Aplicar EnforcementMode si está configurado como DoNotEnforce
                    $finalEffect = $resolvedEffect
                    if ($assignment.Properties.EnforcementMode -eq "DoNotEnforce") {
                        # Mapeo de efectos cuando está en modo DoNotEnforce
                        $finalEffect = switch ($resolvedEffect) {
                            "Deny" { "Audit" }
                            "DenyAction" { "Audit" }
                            "DeployIfNotExists" { "AuditIfNotExists" }
                            "Modify" { "AuditIfNotExists" }
                            default { $resolvedEffect }  # Mantener efectos como Audit, AuditIfNotExists, Disabled, etc.
                        }
                        if ($finalEffect -ne $resolvedEffect) {
                            if ($showDebug) { Write-DebugMessage "          [DEBUG] 🔄 EnforcementMode DoNotEnforce: $resolvedEffect → $finalEffect" -ForegroundColor Cyan }
                        }
                    }

                    # Agrega la política con sus parámetros de la iniciativa y efecto resuelto
                    $innerPolicies += @{
                        Definition = $innerPolicy
                        Parameters = $policyRef.parameters
                        ResolvedEffect = $finalEffect
                        OriginalEffect = $rawEffect
                        EffectSource = if ($rawEffect -ne $finalEffect) { "Resolved" } else { "Direct" }
                        EnforcementMode = $assignment.Properties.EnforcementMode
                    }
                } else {
                    $failedPolicies++
                    if ($innerCount -le 3) {
                        Write-Host "        ├─ ⚠️ No se pudo cargar política después de $maxRetries intentos" -ForegroundColor DarkYellow
                    }
                }
            }
            
            if ($innerCount -gt 3) {
                Write-Host "        └─ ... y $(($innerCount - 3)) más" -ForegroundColor DarkGray
            }
            
            if ($failedPolicies -gt 0) {
                Write-Host "      ⚠️  $failedPolicies de $innerCount políticas no se pudieron cargar" -ForegroundColor Yellow
            }

            if ($innerPolicies.Count -gt 0) {
                $processedDefs[$policyDefId] = $innerPolicies
                $allPolicies += @{
                    Assignment = $assignment
                    Definition = $innerPolicies
                    IsInitiative = $true
                }
                Write-Host "      ✓ Iniciativa procesada correctamente ($($innerPolicies.Count)/$innerCount políticas cargadas)" -ForegroundColor Green
            } else {
                $processedDefs[$policyDefId] = $null
                Write-Host "      ❌ No se pudieron cargar las políticas de la iniciativa después de $maxRetries intentos" -ForegroundColor Red
            }
        } else {
            $processedDefs[$policyDefId] = $null
            Write-Host "      ❌ No se pudo obtener la definición de la iniciativa después de $maxRetries intentos" -ForegroundColor Red
        }
    } else {
        # Es una política individual
        Write-Host "      Tipo: Política individual" -ForegroundColor Cyan
    $policyDef = Get-PolicyCached -Id $policyDefId -Type 'Definition' -MaxRetries $maxRetries
    if ($policyDef -and $policyDef.PolicyRule) {
            $rawEffect = $policyDef.PolicyRule.then.effect
            $resolvedEffect = $rawEffect
            $effectSource = "Direct"

            if ($rawEffect -is [string] -and $rawEffect -match "\[parameters\('(?<p>[^']+)'\)\]") {
                $paramName = $Matches['p']
                $resolved = $null
                $effectSource = "Direct"
                
                try {
                    if ($assignment.Properties -and $assignment.Properties.Parameters -and $assignment.Properties.Parameters.$paramName) {
                        $paramValue = $assignment.Properties.Parameters.$paramName
                        if ($paramValue -is [hashtable] -and $paramValue.value) {
                            $resolved = $paramValue.value
                        } elseif ($paramValue -is [hashtable] -and $paramValue.ContainsKey('value')) {
                            $resolved = $paramValue['value']
                        } else {
                            $resolved = $paramValue
                        }
                        $effectSource = "Assignment.Properties.Parameters"
                    }
                } catch { }
                
                try {
                    if (-not $resolved -and $assignment.Parameter -and $assignment.Parameter.$paramName) {
                        $paramValue = $assignment.Parameter.$paramName
                        if ($paramValue -is [hashtable] -and $paramValue.value) {
                            $resolved = $paramValue.value
                            $effectSource = "Assignment.Parameter.value"
                        } elseif ($paramValue -is [hashtable] -and $paramValue.ContainsKey('value')) {
                            $resolved = $paramValue['value']
                            $effectSource = "Assignment.Parameter.value"
                        } else {
                            $resolved = $paramValue
                            $effectSource = "Assignment.Parameter"
                        }
                    }
                } catch { }
                
                try {
                    if (-not $resolved) {
                        # Intentar primero con Properties.parameters
                        $defParams = $null
                        if ($policyDef.Properties -and $policyDef.Properties.parameters) {
                            $defParams = $policyDef.Properties.parameters
                        }
                        # Si no está disponible, intentar con Parameters directamente
                        elseif ($policyDef.Parameters) {
                            $defParams = $policyDef.Parameters
                        }
                        
                        if ($defParams -and $defParams.$paramName -and $defParams.$paramName.defaultValue) {
                            $resolved = $defParams.$paramName.defaultValue
                            $effectSource = "Policy.DefaultValue"
                        }
                    }
                } catch { }

                # Crear mapa de parámetros para resolución recursiva
                $parameterMap = @{}
                
                # Agregar parámetros de la asignación
                if ($assignment.Properties -and $assignment.Properties.Parameters) {
                    foreach ($key in $assignment.Properties.Parameters.Keys) {
                        $val = $assignment.Properties.Parameters[$key]
                        if ($val -is [hashtable] -and $val.value) {
                            $parameterMap[$key] = $val.value
                        } else {
                            $parameterMap[$key] = $val
                        }
                    }
                }
                
                # Agregar parámetros de la asignación (Parameter)
                if ($assignment.Parameter) {
                    foreach ($key in $assignment.Parameter.Keys) {
                        if (-not $parameterMap.ContainsKey($key)) {
                            $val = $assignment.Parameter[$key]
                            if ($val -is [hashtable] -and $val.value) {
                                $parameterMap[$key] = $val.value
                            } else {
                                $parameterMap[$key] = $val
                            }
                        }
                    }
                }
                
                # Agregar defaults de la política
                if ($policyDef.Properties -and $policyDef.Properties.parameters) {
                    foreach ($key in $policyDef.Properties.parameters.Keys) {
                        if (-not $parameterMap.ContainsKey($key) -and $policyDef.Properties.parameters[$key].defaultValue) {
                            $parameterMap[$key] = $policyDef.Properties.parameters[$key].defaultValue
                        }
                    }
                } elseif ($policyDef.Parameters) {
                    foreach ($key in $policyDef.Parameters.Keys) {
                        if (-not $parameterMap.ContainsKey($key) -and $policyDef.Parameters[$key].defaultValue) {
                            $parameterMap[$key] = $policyDef.Parameters[$key].defaultValue
                        }
                    }
                }

                # Aplicar resolución recursiva
                if ($resolved) {
                    Write-Host "      🔄 Aplicando resolución recursiva a: $resolved" -ForegroundColor Cyan
                    $finalResolved = Resolve-NestedParameters -ParameterValue $resolved -ParameterSource $parameterMap -ShowDebug $true
                    if ($finalResolved -ne $resolved) {
                        Write-Host "      🎯 Resolución recursiva completada: $resolved → $finalResolved" -ForegroundColor Magenta
                        $effectSource = "$effectSource (recursively resolved)"
                    }
                    $resolved = $finalResolved
                }

                if ($resolved) { 
                    $resolvedEffect = $resolved 
                    Write-Host "      Efecto: $resolvedEffect (resuelto desde: $effectSource)" -ForegroundColor Gray
                } else { 
                    $resolvedEffect = "Parametrizado-NoResuelto"
                    $effectSource = "Parameter '$paramName' not found"
                    Write-Host "      Efecto: $rawEffect → No resuelto (parámetro '$paramName' no encontrado)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "      Efecto: $resolvedEffect" -ForegroundColor Gray
            }
            
            # Aplicar EnforcementMode si está configurado como DoNotEnforce
            $finalEffect = $resolvedEffect
            if ($assignment.Properties.EnforcementMode -eq "DoNotEnforce") {
                # Mapeo de efectos cuando está en modo DoNotEnforce
                $finalEffect = switch ($resolvedEffect) {
                    "Deny" { "Audit" }
                    "DenyAction" { "Audit" }
                    "DeployIfNotExists" { "AuditIfNotExists" }
                    "Modify" { "AuditIfNotExists" }
                    default { $resolvedEffect }  # Mantener efectos como Audit, AuditIfNotExists, Disabled, etc.
                }
                if ($finalEffect -ne $resolvedEffect) {
                    Write-Host "      🔄 EnforcementMode DoNotEnforce: $resolvedEffect → $finalEffect" -ForegroundColor Cyan
                }
            }
            
            $processedDefs[$policyDefId] = $policyDef
            $allPolicies += @{
                Assignment = $assignment
                Definition = $policyDef
                IsInitiative = $false
                ResolvedEffect = $finalEffect
                OriginalEffect = $rawEffect
                EffectSource = $effectSource
                EnforcementMode = $assignment.Properties.EnforcementMode
            }
            Write-Host "      ✓ Política procesada correctamente" -ForegroundColor Green
        } else {
            $processedDefs[$policyDefId] = $null
            Write-Host "      ⚠ No se pudo obtener la definición de la política" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n📊 Resumen de procesamiento:" -ForegroundColor Cyan
Write-Host "   - Asignaciones procesadas: $processedCount" -ForegroundColor Gray
Write-Host "   - Políticas/iniciativas válidas: $($allPolicies.Count)" -ForegroundColor Gray

if ($allPolicies.Count -eq 0) {
    Write-Host "`n❌ No hay políticas/iniciativas en el management group destino." -ForegroundColor Red
    Write-Host "   Esto puede indicar que:" -ForegroundColor Yellow
    Write-Host "   - El management group no tiene políticas asignadas" -ForegroundColor Yellow
    Write-Host "   - No tienes permisos para leer las definiciones de políticas" -ForegroundColor Yellow
    Write-Host "   - Hubo un error al obtener las definiciones`n" -ForegroundColor Yellow
    exit 0
}

Write-Host "`n=== FASE 3: OBTENIENDO EXEMPTIONS DE POLÍTICAS ===" -ForegroundColor Cyan

# Obtener exemptions del management group destino y jerarquía
Write-Host "Obteniendo exemptions de políticas del management group destino..." -ForegroundColor Cyan
Write-Host "   ℹ️  Nota: Los errores 404 (Not Found) son normales si no hay exemptions configuradas en el scope" -ForegroundColor Gray
$targetMgPath = "/providers/Microsoft.Management/managementGroups/$TargetMG"

# Obtener exemptions de todos los niveles relevantes
$allExemptions = @()

# 1. Exemptions del Management Group destino
$mgExemptions = Get-PolicyExemptions -Scope $targetMgPath
if ($mgExemptions.Count -gt 0) {
    Write-Host "  ✓ Encontradas $($mgExemptions.Count) exemptions en el management group destino" -ForegroundColor Green
    $allExemptions += $mgExemptions
}

# 2. Exemptions de la suscripción
$subscriptionPath = "/subscriptions/$SubscriptionId"
$subExemptions = Get-PolicyExemptions -Scope $subscriptionPath
if ($subExemptions.Count -gt 0) {
    Write-Host "  ✓ Encontradas $($subExemptions.Count) exemptions en la suscripción" -ForegroundColor Green
    $allExemptions += $subExemptions
}

Write-Host "📋 Total de exemptions aplicables: $($allExemptions.Count)" -ForegroundColor Yellow

Write-Host "`n=== FASE 4: OBTENIENDO RECURSOS ===" -ForegroundColor Cyan

# Obtiene los recursos de la suscripción
Write-Host "Obteniendo recursos de la suscripción $SubscriptionId..." -ForegroundColor Cyan
$resources = Get-AzResource

# Si se especifica TestResourceId, evaluar solo ese recurso
if ($TestResourceId) {
    Write-Host "ℹ️  Evaluando recurso único: $TestResourceId" -ForegroundColor Cyan
    $single = @(Get-AzResource -ResourceId $TestResourceId -ErrorAction SilentlyContinue)
    if (-not $single -or $single.Count -eq 0) {
        Write-Host "❌ No se pudo obtener el recurso especificado: $TestResourceId" -ForegroundColor Red
        exit 1
    }
    $resources = $single
}

if (-not $resources -or $resources.Count -eq 0) {
    Write-Host "❌ No se encontraron recursos en la suscripción." -ForegroundColor Red
    exit 0
}

Write-Host "✓ Recursos encontrados (antes de filtrar): $($resources.Count)" -ForegroundColor Green

# Aplica filtro de tipo de recurso si se especificó
if ($ResourceTypeFilter -and $ResourceTypeFilter.Count -gt 0) {
    Write-Host "`n🔍 Aplicando filtro de tipo de recurso..." -ForegroundColor Cyan
    $filteredResources = @()
    foreach ($filter in $ResourceTypeFilter) {
        $matchingResources = $resources | Where-Object { $_.ResourceType -eq $filter }
        if ($matchingResources) {
            $filteredResources += $matchingResources
            Write-Host "   - $filter`: $($matchingResources.Count) recursos" -ForegroundColor Gray
        } else {
            Write-Host "   - $filter`: 0 recursos (no se encontraron)" -ForegroundColor DarkGray
        }
    }
    
    $resources = $filteredResources
    
    if ($resources.Count -eq 0) {
        Write-Host "`n❌ No se encontraron recursos que coincidan con el filtro especificado." -ForegroundColor Red
        exit 0
    }
    
    Write-Host "`n✓ Recursos después de filtrar: $($resources.Count)" -ForegroundColor Green
}

# Aplica filtro del modo portal si está activado
if ($PortalMode) {
    Write-Host "`n🎯 Modo Portal activado: filtrando recursos que realmente violan la lógica de negocio..." -ForegroundColor Cyan
    $portalFilteredResources = @()
    
    foreach ($resource in $resources) {
        $includeResource = $false
        
        # Para NICs: solo incluir las que tienen IP pública asignada
        if ($resource.ResourceType -eq "Microsoft.Network/networkInterfaces") {
            try {
                $nic = Get-AzNetworkInterface -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -ErrorAction SilentlyContinue
                if ($nic -and $nic.IpConfigurations -and $nic.IpConfigurations.PublicIpAddress) {
                    $hasPublicIP = $nic.IpConfigurations | Where-Object { $_.PublicIpAddress -ne $null }
                    if ($hasPublicIP) {
                        $includeResource = $true
                        Write-Host "   - ✓ NIC con IP pública: $($resource.Name)" -ForegroundColor Green
                    }
                }
            }
            catch {
                Write-Warning "No se pudo verificar IP pública para NIC: $($resource.Name)"
            }
        }
        else {
            # Para otros tipos de recursos, incluir todos (lógica futura extensible)
            $includeResource = $true
        }
        
        if ($includeResource) {
            $portalFilteredResources += $resource
        }
    }
    
    $resources = $portalFilteredResources
    
    if ($resources.Count -eq 0) {
        Write-Host "`n❌ No se encontraron recursos que violen realmente la lógica de negocio." -ForegroundColor Red
        exit 0
    }
    
    Write-Host "`n✓ Recursos en modo portal: $($resources.Count)" -ForegroundColor Green
}

# Muestra resumen de tipos de recursos
$resourceTypes = $resources | Group-Object -Property ResourceType | Sort-Object Count -Descending | Select-Object -First 5
Write-Host "`n📦 Tipos de recursos a evaluar:" -ForegroundColor Cyan
foreach ($type in $resourceTypes) {
    Write-Host "   - $($type.Name): $($type.Count) recursos" -ForegroundColor Gray
}
if ($resourceTypes.Count -lt ($resources | Group-Object -Property ResourceType).Count) {
    $remaining = ($resources | Group-Object -Property ResourceType).Count - $resourceTypes.Count
    Write-Host "   - ... y $remaining tipos más" -ForegroundColor DarkGray
}

Write-Host "`n=== FASE 5: EVALUANDO CUMPLIMIENTO ===" -ForegroundColor Cyan
Write-Host "Analizando cumplimiento de recursos contra políticas del MG destino..." -ForegroundColor Cyan
Write-Host "Este proceso puede tardar varios minutos...`n" -ForegroundColor Yellow

# Inicializar caché global de recursos para mejorar el rendimiento
Write-Host "Inicializando caché de recursos..." -ForegroundColor Cyan
$global:resourceCache = @{}
Write-Host "✓ Caché inicializada" -ForegroundColor Green

# Función para obtener el valor de una propiedad usando alias de Azure Policy
function Get-ResourcePropertyByAlias {
    param(
        $Resource,
        [string]$Alias
    )
    
    # Usa caché para evitar llamadas repetidas a Get-AzResource
    if (-not $global:resourceCache) {
        $global:resourceCache = @{}
    }
    
    # Busca en caché primero
    if (-not $global:resourceCache.ContainsKey($Resource.ResourceId)) {
        # Si no está en caché, obtiene las propiedades completas del recurso
        $fullResource = Get-AzResource -ResourceId $Resource.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
        
        if ($fullResource) {
            # Guarda en caché para futuras consultas
            $global:resourceCache[$Resource.ResourceId] = $fullResource
        }
    } else {
        # Usa el recurso desde la caché
        $fullResource = $global:resourceCache[$Resource.ResourceId]
    }
    
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
        if ($fullResource.Tags) {
            return $fullResource.Tags[$tagName]
        }
        return $null
    }
    
    # CORRECCIÓN ESPECÍFICA PARA INTERFACES DE RED usando aliases oficiales de Azure Policy
    # Get-AzResource no incluye publicIPAddress en Properties, necesitamos usar Get-AzNetworkInterface
    if ($fullResource.ResourceType -eq "Microsoft.Network/networkInterfaces") {
        # Caché específico para NICs con información detallada
        $nicCacheKey = "$($Resource.ResourceId)_detailed"
        if (-not $global:resourceCache.ContainsKey($nicCacheKey)) {
            try {
                # Obtener información detallada de la NIC usando Get-AzNetworkInterface
                $nic = Get-AzNetworkInterface -ResourceId $Resource.ResourceId -ErrorAction SilentlyContinue
                if ($nic) {
                    $global:resourceCache[$nicCacheKey] = $nic
                }
            } catch {
                # Si falla, usar datos básicos
                $global:resourceCache[$nicCacheKey] = $null
            }
        }
        
        $detailedNic = $global:resourceCache[$nicCacheKey]
        
        # Maneja aliases oficiales de Azure Policy para publicIPAddress en NICs
        if ($detailedNic) {
            # Alias oficial: Microsoft.Network/networkInterfaces/ipConfigurations[*].publicIPAddress
            if ($Alias -eq "Microsoft.Network/networkInterfaces/ipConfigurations[*].publicIPAddress") {
                $publicIPs = @()
                foreach ($ipConfig in $detailedNic.IpConfigurations) {
                    if ($ipConfig.PublicIpAddress) {
                        $publicIPs += $ipConfig.PublicIpAddress
                    }
                }
                if ($publicIPs.Count -gt 0) { 
                    return $publicIPs 
                } else { 
                    return $null 
                }
            }
            
            # Alias oficial: Microsoft.Network/networkInterfaces/ipconfigurations[*].publicIpAddress.id
            if ($Alias -eq "Microsoft.Network/networkInterfaces/ipconfigurations[*].publicIpAddress.id") {
                $publicIPIds = @()
                foreach ($ipConfig in $detailedNic.IpConfigurations) {
                    if ($ipConfig.PublicIpAddress) {
                        $publicIPIds += $ipConfig.PublicIpAddress.Id
                    }
                }
                if ($publicIPIds.Count -gt 0) { 
                    return $publicIPIds 
                } else { 
                    return $null 
                }
            }
            
            # Para compatibilidad con posibles aliases específicos de índice [0]
            if ($Alias -match "ipConfigurations\[0\]\.publicIPAddress") {
                if ($detailedNic.IpConfigurations.Count -gt 0) {
                    $publicIP = $detailedNic.IpConfigurations[0].PublicIpAddress
                    if ($Alias -match "\.id$") {
                        if ($publicIP) { 
                            return $publicIP.Id 
                        } else { 
                            return $null 
                        }
                    } else {
                        return $publicIP
                    }
                }
                return $null
            }
            
            # Alias adicionales que pueden usar las políticas personalizadas
            if ($Alias -eq "Microsoft.Network/networkInterfaces/ipConfigurations[0].publicIPAddress.id" -or
                $Alias -eq "Microsoft.Network/networkInterfaces/ipconfigurations[0].publicIpAddress.id") {
                if ($detailedNic.IpConfigurations.Count -gt 0) {
                    $publicIP = $detailedNic.IpConfigurations[0].PublicIpAddress
                    return if($publicIP){$publicIP.Id}else{$null}
                }
                return $null
            }
            
            # Alias para obtener solo la existencia de IP pública (común en políticas Deny)
            if ($Alias -eq "Microsoft.Network/networkInterfaces/ipConfigurations[0].publicIPAddress" -or
                $Alias -eq "Microsoft.Network/networkInterfaces/ipconfigurations[0].publicIpAddress") {
                if ($detailedNic.IpConfigurations.Count -gt 0) {
                    return $detailedNic.IpConfigurations[0].PublicIpAddress
                }
                return $null
            }
        }
    }
    
    # Para otros aliases, intenta mapear a propiedades usando el método tradicional
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
        $PolicyParameters,
        [switch]$DebugMode
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
        $PolicyParameters = $null,
        $ResolvedEffect = $null
    )
    
    if (-not $PolicyDefinition.PolicyRule) {
        return @{ 
            Violates = $false; 
            Effect = "Unknown";
            OriginalEffect = "Unknown";
            EffectSource = "Unknown"
        }
    }
    
    $policyRule = $PolicyDefinition.PolicyRule
    
    # Si se proporciona un efecto ya resuelto, usarlo pero aplicar resolución recursiva si es necesario
    if ($ResolvedEffect) {
        $effectValue = $ResolvedEffect
        $originalEffect = $policyRule.then.effect
        $effectSource = "PreResolved"
        
        # Aplicar resolución recursiva si el efecto aún contiene referencias a parámetros
        if ($effectValue -is [string] -and ($effectValue -match "\[parameters\('([^']+)'\)\]" -or $effectValue -match "@\{value=\[parameters\('([^']+)'\)\]\}")) {
            # Crear mapa de parámetros para resolución recursiva
            $parameterMap = @{}
            
            # Agregar parámetros de la asignación
            if ($Assignment.Properties -and $Assignment.Properties.Parameters) {
                foreach ($key in $Assignment.Properties.Parameters.Keys) {
                    $val = $Assignment.Properties.Parameters[$key]
                    if ($val -is [hashtable] -and $val.value) {
                        $parameterMap[$key] = $val.value
                    } else {
                        $parameterMap[$key] = $val
                    }
                }
            }
            
            # Agregar parámetros de la iniciativa (PolicyParameters)
            if ($PolicyParameters) {
                foreach ($key in $PolicyParameters.Keys) {
                    if (-not $parameterMap.ContainsKey($key)) {
                        $val = $PolicyParameters[$key]
                        if ($val -is [hashtable] -and $val.value) {
                            $parameterMap[$key] = $val.value
                        } else {
                            $parameterMap[$key] = $val
                        }
                    }
                }
            }
            
            # Agregar parámetros de la asignación (Parameter)
            if ($Assignment.Parameter) {
                foreach ($key in $Assignment.Parameter.Keys) {
                    if (-not $parameterMap.ContainsKey($key)) {
                        $val = $Assignment.Parameter[$key]
                        if ($val -is [hashtable] -and $val.value) {
                            $parameterMap[$key] = $val.value
                        } else {
                            $parameterMap[$key] = $val
                        }
                    }
                }
            }
            
            # Agregar defaults de la política
            if ($PolicyDefinition.Properties -and $PolicyDefinition.Properties.parameters) {
                foreach ($key in $PolicyDefinition.Properties.parameters.Keys) {
                    if (-not $parameterMap.ContainsKey($key) -and $PolicyDefinition.Properties.parameters[$key].defaultValue) {
                        $parameterMap[$key] = $PolicyDefinition.Properties.parameters[$key].defaultValue
                    }
                }
            } elseif ($PolicyDefinition.Parameters) {
                foreach ($key in $PolicyDefinition.Parameters.Keys) {
                    if (-not $parameterMap.ContainsKey($key) -and $PolicyDefinition.Parameters[$key].defaultValue) {
                        $parameterMap[$key] = $PolicyDefinition.Parameters[$key].defaultValue
                    }
                }
            }
            
            # Aplicar resolución recursiva
            $finalResolvedEffect = Resolve-NestedParameters -ParameterValue $effectValue -ParameterSource $parameterMap -ShowDebug $false
            if ($finalResolvedEffect -ne $effectValue) {
                $effectValue = $finalResolvedEffect
                $effectSource = "PreResolved(Recursively)"
            }
        }
    } else {
        # Obtiene el efecto de la política (lógica original)
        $effect = $policyRule.then.effect
        $effectValue = $effect
        $originalEffect = $effect
        $effectSource = "Direct"
    
        # Si el efecto es parametrizado, obtiene el valor real siguiendo el patrón oficial de Azure Policy
        if ($effect -like "[parameters(*)]" -and $effect -match "parameters\('(.+)'\)") {
        $paramName = $Matches[1]
        $resolved = $null
        $resolvedSource = $null

        # 1. Buscar en los parámetros de la asignación
        if ($Assignment.Properties -and $Assignment.Properties.Parameters -and $Assignment.Properties.Parameters.$paramName) {
            $paramValue = $Assignment.Properties.Parameters.$paramName
            if ($paramValue -is [hashtable] -and $paramValue.value) {
                $resolved = $paramValue.value
            } elseif ($paramValue -is [hashtable] -and $paramValue.ContainsKey('value')) {
                $resolved = $paramValue['value']
            } else {
                $resolved = $paramValue
            }
            $resolvedSource = "Assignment.Properties.Parameters"
        }
        # 2. Buscar en los parámetros de la iniciativa (PolicyParameters)
        elseif ($PolicyParameters -and $PolicyParameters.$paramName) {
            $paramValue = $PolicyParameters.$paramName
            if ($paramValue -is [hashtable] -and $paramValue.value) {
                $resolved = $paramValue.value
                $resolvedSource = "Initiative.Parameters.value"
            } elseif ($paramValue -is [hashtable] -and $paramValue.ContainsKey('value')) {
                $resolved = $paramValue['value']
                $resolvedSource = "Initiative.Parameters.value"
            } else {
                $resolved = $paramValue
                $resolvedSource = "Initiative.Parameters"
            }
        }
        # 3. Buscar en Assignment.Parameter (sin Properties)
        elseif ($Assignment.Parameter -and $Assignment.Parameter.$paramName) {
            $paramValue = $Assignment.Parameter.$paramName
            if ($paramValue -is [hashtable] -and $paramValue.value) {
                $resolved = $paramValue.value
                $resolvedSource = "Assignment.Parameter.value"
            } elseif ($paramValue -is [hashtable] -and $paramValue.ContainsKey('value')) {
                $resolved = $paramValue['value']
                $resolvedSource = "Assignment.Parameter.value"
            } else {
                $resolved = $paramValue
                $resolvedSource = "Assignment.Parameter"
            }
        }
        # 4. Buscar en la definición de la política (defaultValue)
        else {
            $defParams = $null
            if ($PolicyDefinition.Properties -and $PolicyDefinition.Properties.parameters) {
                $defParams = $PolicyDefinition.Properties.parameters
            } elseif ($PolicyDefinition.Parameters) {
                $defParams = $PolicyDefinition.Parameters
            }
            if ($defParams -and $defParams.$paramName -and $defParams.$paramName.defaultValue) {
                $resolved = $defParams.$paramName.defaultValue
                $resolvedSource = "Policy.DefaultValue"
            }
        }
        
        # Si el valor resuelto es aún una referencia a parámetro, intentar resolverlo una vez más
        if ($resolved -and $resolved -is [string] -and $resolved -match "\[parameters\('(.+)'\)\]") {
            $nestedParamName = $Matches[1]
            $nestedResolved = $null
            
            # Buscar el parámetro anidado en las mismas fuentes
            if ($Assignment.Properties -and $Assignment.Properties.Parameters -and $Assignment.Properties.Parameters.$nestedParamName) {
                $nestedParamValue = $Assignment.Properties.Parameters.$nestedParamName
                if ($nestedParamValue -is [hashtable] -and $nestedParamValue.value) {
                    $nestedResolved = $nestedParamValue.value
                } elseif ($nestedParamValue -is [hashtable] -and $nestedParamValue.ContainsKey('value')) {
                    $nestedResolved = $nestedParamValue['value']
                } else {
                    $nestedResolved = $nestedParamValue
                }
            }
            elseif ($PolicyParameters -and $PolicyParameters.$nestedParamName) {
                $nestedParamValue = $PolicyParameters.$nestedParamName
                if ($nestedParamValue -is [hashtable] -and $nestedParamValue.value) {
                    $nestedResolved = $nestedParamValue.value
                } elseif ($nestedParamValue -is [hashtable] -and $nestedParamValue.ContainsKey('value')) {
                    $nestedResolved = $nestedParamValue['value']
                } else {
                    $nestedResolved = $nestedParamValue
                }
            }
            
            if ($nestedResolved) {
                $resolved = $nestedResolved
                $resolvedSource = "$resolvedSource (nested:$nestedParamName)"
            }
        }
        
        if ($resolved) { 
            # Aplicar resolución recursiva antes de usar el valor final
            $parameterMap = @{}
            
            # Agregar parámetros de la asignación
            if ($Assignment.Properties -and $Assignment.Properties.Parameters) {
                foreach ($key in $Assignment.Properties.Parameters.Keys) {
                    $val = $Assignment.Properties.Parameters[$key]
                    if ($val -is [hashtable] -and $val.value) {
                        $parameterMap[$key] = $val.value
                    } else {
                        $parameterMap[$key] = $val
                    }
                }
            }
            
            # Agregar parámetros de la iniciativa (PolicyParameters)
            if ($PolicyParameters) {
                foreach ($key in $PolicyParameters.Keys) {
                    if (-not $parameterMap.ContainsKey($key)) {
                        $val = $PolicyParameters[$key]
                        if ($val -is [hashtable] -and $val.value) {
                            $parameterMap[$key] = $val.value
                        } else {
                            $parameterMap[$key] = $val
                        }
                    }
                }
            }
            
            # Agregar parámetros de la asignación (Parameter)
            if ($Assignment.Parameter) {
                foreach ($key in $Assignment.Parameter.Keys) {
                    if (-not $parameterMap.ContainsKey($key)) {
                        $val = $Assignment.Parameter[$key]
                        if ($val -is [hashtable] -and $val.value) {
                            $parameterMap[$key] = $val.value
                        } else {
                            $parameterMap[$key] = $val
                        }
                    }
                }
            }
            
            # Agregar defaults de la política
            if ($PolicyDefinition.Properties -and $PolicyDefinition.Properties.parameters) {
                foreach ($key in $PolicyDefinition.Properties.parameters.Keys) {
                    if (-not $parameterMap.ContainsKey($key) -and $PolicyDefinition.Properties.parameters[$key].defaultValue) {
                        $parameterMap[$key] = $PolicyDefinition.Properties.parameters[$key].defaultValue
                    }
                }
            } elseif ($PolicyDefinition.Parameters) {
                foreach ($key in $PolicyDefinition.Parameters.Keys) {
                    if (-not $parameterMap.ContainsKey($key) -and $PolicyDefinition.Parameters[$key].defaultValue) {
                        $parameterMap[$key] = $PolicyDefinition.Parameters[$key].defaultValue
                    }
                }
            }
            
            # Aplicar resolución recursiva
            $finalResolvedEffect = Resolve-NestedParameters -ParameterValue $resolved -ParameterSource $parameterMap -ShowDebug $false
            if ($finalResolvedEffect -ne $resolved) {
                $effectValue = $finalResolvedEffect
                $effectSource = "$resolvedSource (Recursively)"
            } else {
                $effectValue = $resolved 
                $effectSource = $resolvedSource
            }
        } else {
            $effectValue = "Parametrizado-NoResuelto"
            $effectSource = "Parameter '$paramName' not found"
        }
        }
    }
    
    # Evalúa la condición if de la política
    # Si la condición es TRUE, significa que el recurso está sujeto a esta política
    $assignmentParameters = $Assignment.Parameter
    $conditionResult = Test-PolicyCondition -Condition $policyRule.if -Resource $Resource -PolicyParameters $assignmentParameters
    
    # LÓGICA MEJORADA: Para políticas Deny, solo marcamos violación si la condición se cumple
    # Esto significa que el recurso actual violaría la política si fuera a ser creado/modificado
    $violates = $false
    
    if ($effectValue -eq "Deny" -or $effectValue -eq "deny") {
        # Para efectos Deny: el recurso viola la política solo si cumple la condición IF
        # (porque Deny bloquea recursos que cumplen la condición IF)
        $violates = $conditionResult
    }
    elseif ($effectValue -eq "Audit" -or $effectValue -eq "audit") {
        # Para efectos Audit: el recurso viola la política si cumple la condición IF
        # (porque Audit marca como no conforme los recursos que cumplen la condición IF)
        $violates = $conditionResult
    }
    elseif ($effectValue -eq "AuditIfNotExists" -or $effectValue -eq "auditIfNotExists") {
        # Para AuditIfNotExists: evaluación más compleja, por ahora usar condición simple
        $violates = $conditionResult
    }
    elseif ($effectValue -eq "DeployIfNotExists" -or $effectValue -eq "deployIfNotExists") {
        # Para DeployIfNotExists: evaluación más compleja, por ahora usar condición simple
        $violates = $conditionResult
    }
    elseif ($effectValue -eq "Modify" -or $effectValue -eq "modify") {
        # Para Modify: el recurso sería modificado si cumple la condición IF
        $violates = $conditionResult
    }
    else {
        # Para otros efectos o efectos desconocidos, usar evaluación básica
        $violates = $conditionResult
    }
    
    return @{
        Violates = $violates
        Effect = $effectValue
        OriginalEffect = $originalEffect
        EffectSource = $effectSource
    }
}

# Analiza el impacto real evaluando cada recurso contra cada política
$resultados = @()
$policyDetails = @()
$processed = 0

$policyIndex = 0
foreach ($policyInfo in $allPolicies) {
    $policyIndex++
    $assignment = $policyInfo.Assignment
    $policyName = $assignment.DisplayName
    $isInitiative = $policyInfo.IsInitiative
    
    $policyType = if ($isInitiative) { "Iniciativa" } else { "Política" }
    Write-Host "[$policyIndex/$($allPolicies.Count)] Evaluando $policyType`: $policyName" -ForegroundColor Cyan
    
    if ($isInitiative) {
        # Para iniciativas, procesa cada política individual con sus parámetros
        $innerPolicyCount = 0
        $totalInnerPolicies = $policyInfo.Definition.Count
        foreach ($innerPolicyInfo in $policyInfo.Definition) {
            $innerPolicyCount++
            $innerPolicy = $innerPolicyInfo.Definition
            $innerParams = $innerPolicyInfo.Parameters
            $innerResolvedEffect = $innerPolicyInfo.ResolvedEffect  # ← USAR el efecto ya resuelto
            $innerPolicyDisplayName = if ($innerPolicy.DisplayName) { $innerPolicy.DisplayName } else { "Sin nombre" }
            $violatingResources = @()
            $compliantResources = @()
            
            Write-Host "  ↳ [$innerPolicyCount/$totalInnerPolicies] $innerPolicyDisplayName" -ForegroundColor DarkCyan
            
            if ($Parallel) {
                # Procesamiento paralelo
                Write-Host "    Evaluando $($resources.Count) recursos en paralelo..." -ForegroundColor Gray
                # Obtener el código de las funciones como texto
                $testFunctionDef = (Get-Command Test-ResourceViolatesPolicy).Definition
                $testConditionFunctionDef = (Get-Command Test-PolicyCondition).Definition
                $getPropertyFunctionDef = (Get-Command Get-ResourcePropertyByAlias).Definition
                
                $evalResults = $resources | ForEach-Object -Parallel {
                    $resource = $_
                    $innerPolicy = $using:innerPolicy
                    $assignment = $using:assignment
                    $innerParams = $using:innerParams
                    $innerResolvedEffect = $using:innerResolvedEffect
                    $Mode = $using:Mode
                    $policyName = $using:policyName
                    
                    # Recrear las funciones desde las definiciones de texto
                    $testFunctionDef = $using:testFunctionDef
                    $testConditionFunctionDef = $using:testConditionFunctionDef
                    $getPropertyFunctionDef = $using:getPropertyFunctionDef
                    
                    Invoke-Expression "function Get-ResourcePropertyByAlias { $getPropertyFunctionDef }"
                    Invoke-Expression "function Test-PolicyCondition { $testConditionFunctionDef }"
                    Invoke-Expression "function Test-ResourceViolatesPolicy { $testFunctionDef }"
                    
                    $result = Test-ResourceViolatesPolicy -PolicyDefinition $innerPolicy -Resource $resource -Assignment $assignment -PolicyParameters $innerParams -ResolvedEffect $innerResolvedEffect
                    
                    [PSCustomObject]@{
                        Resource = $resource
                        Result = $result
                    }
                } -ThrottleLimit $ThrottleLimit
                
                # Procesa los resultados
                foreach ($evalResult in $evalResults) {
                    $resource = $evalResult.Resource
                    $result = $evalResult.Result
                    $processed++
                    
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

                            # Verificar si existe una exemption para este incumplimiento
                            $exemptionCheck = Test-ResourcePolicyExemption -ResourceId $resource.ResourceId -PolicyAssignmentId $assignment.Id -PolicyDefinitionReferenceId $innerPolicy.ReferenceId -AllExemptions $allExemptions
                            
                            $waiverStatus = if ($exemptionCheck.HasExemption) { "Existente" } else { "Revisar" }
                            $waiverName = $exemptionCheck.ExemptionName
                            $waiverReason = $exemptionCheck.Description
                            $waiverExpiry = if ($exemptionCheck.ExpiresOn) { 
                                $exemptionCheck.ExpiresOn 
                            } else { 
                                "" 
                            }
                            
                            $resultados += [PSCustomObject]@{
                                SubscriptionId = $SubscriptionId
                                ResourceName = $resource.Name
                                ResourceType = $resource.ResourceType
                                ResourceLocation = $resource.Location
                                ResourceId = $resource.ResourceId
                                SourceMG = $SourceMG
                                TargetMG = $TargetMG
                                PolicyOrInitiative = $policyName
                                PolicyName = $innerPolicy.DisplayName
                                PolicyScope = $assignment.Scope
                                Effect = if ($innerResolvedEffect) { $innerResolvedEffect } else { $result.Effect }
                                OriginalEffect = $result.OriginalEffect
                                EffectSource = $result.EffectSource
                                ResolvedEffect = $innerResolvedEffect
                                InitiativeParameters = if ($innerParams) { ($innerParams | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                PolicyParameters = if ($innerPolicy.Properties.parameters) { ($innerPolicy.Properties.parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($innerPolicy.parameters) { ($innerPolicy.parameters | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                AssignmentParameters = if ($assignment.Properties.Parameters) { ($assignment.Properties.Parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($assignment.Parameter) { ($assignment.Parameter | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                Estado = "❌ INCUMPLE"
                                Impacto = $impacto
                                WaiverStatus = $waiverStatus
                                WaiverName = $waiverName
                                WaiverReason = $waiverReason
                                WaiverExpiry = $waiverExpiry
                            }
                        }
                    } else {
                        $compliantResources += $resource
                        
                        if ($Mode -eq "cumple" -or $Mode -eq "todos") {
                            $resultados += [PSCustomObject]@{
                                SubscriptionId = $SubscriptionId
                                ResourceName = $resource.Name
                                ResourceType = $resource.ResourceType
                                ResourceLocation = $resource.Location
                                ResourceId = $resource.ResourceId
                                SourceMG = $SourceMG
                                TargetMG = $TargetMG
                                PolicyOrInitiative = $policyName
                                PolicyName = $innerPolicy.DisplayName
                                PolicyScope = $assignment.Scope
                                Effect = if ($innerResolvedEffect) { $innerResolvedEffect } else { $result.Effect }
                                OriginalEffect = $result.OriginalEffect
                                EffectSource = $result.EffectSource
                                ResolvedEffect = $innerResolvedEffect
                                InitiativeParameters = if ($innerParams) { ($innerParams | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                PolicyParameters = if ($innerPolicy.Properties.parameters) { ($innerPolicy.Properties.parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($innerPolicy.parameters) { ($innerPolicy.parameters | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                AssignmentParameters = if ($assignment.Properties.Parameters) { ($assignment.Properties.Parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($assignment.Parameter) { ($assignment.Parameter | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                Estado = "✓ CUMPLE"
                                Impacto = "Cumple con la política"
                            }
                        }
                    }
                }
            } else {
                # Procesamiento secuencial
                foreach ($resource in $resources) {
                    $processed++
                    if ($processed % 5 -eq 0) {
                        # Calcular PercentComplete de forma segura (evitar >100 y división por cero)
                        $denom = ($resources.Count * $allPolicies.Count)
                        if (-not $denom -or $denom -eq 0) { $pct = 0 } else { $pct = [math]::Round((($processed / $denom) * 100), 0) }
                        $pct = [int]([math]::Max(0, [math]::Min(100, $pct)))
                        Write-Progress -Activity "Evaluando recursos" -Status "Procesando $processed de $denom" -PercentComplete $pct
                    }
                    
                    $result = Test-ResourceViolatesPolicy -PolicyDefinition $innerPolicy -Resource $resource -Assignment $assignment -PolicyParameters $innerParams -ResolvedEffect $innerResolvedEffect
                
                    if ($result.Violates) {
                        $violatingResources += $resource
                        
                        if ($Mode -eq "incumple" -or $Mode -eq "todos") {
                            $impacto = switch ($innerResolvedEffect) {
                                "Deny" { "❌ Sería BLOQUEADO" }
                                "Audit" { "⚠️  Sería marcado como NO CONFORME (solo auditoría)" }
                                "AuditIfNotExists" { "⚠️  Requiere recursos adicionales (auditoría)" }
                                "DeployIfNotExists" { "🔧 Se desplegarían recursos automáticamente" }
                                "Modify" { "🔧 Se modificaría automáticamente" }
                                default { "⚠️  Efecto: $innerResolvedEffect" }
                            }
                            
                            # Check for waiver (exemption) for this specific resource and policy
                            $exemption = Test-ResourcePolicyExemption -ResourceId $resource.ResourceId -PolicyAssignmentId $assignment.Id -PolicyDefinitionReferenceId $innerPolicy.ReferenceId -AllExemptions $allExemptions
                            
                            $resultados += [PSCustomObject]@{
                                SubscriptionId = $SubscriptionId
                                ResourceName = $resource.Name
                                ResourceType = $resource.ResourceType
                                ResourceLocation = $resource.Location
                                ResourceId = $resource.ResourceId
                                SourceMG = $SourceMG
                                TargetMG = $TargetMG
                                PolicyOrInitiative = $policyName
                                PolicyName = $innerPolicy.DisplayName
                                PolicyScope = $assignment.Scope
                                Effect = if ($innerResolvedEffect) { $innerResolvedEffect } else { $result.Effect }
                                OriginalEffect = $result.OriginalEffect
                                EffectSource = $result.EffectSource
                                ResolvedEffect = $innerResolvedEffect
                                InitiativeParameters = if ($innerParams) { ($innerParams | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                PolicyParameters = if ($innerPolicy.Properties.parameters) { ($innerPolicy.Properties.parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($innerPolicy.parameters) { ($innerPolicy.parameters | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                AssignmentParameters = if ($assignment.Properties.Parameters) { ($assignment.Properties.Parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($assignment.Parameter) { ($assignment.Parameter | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                Estado = "❌ INCUMPLE"
                                Impacto = $impacto
                                WaiverStatus = if ($exemption) { "Existente" } else { "Revisar" }
                                WaiverName = if ($exemption) { $exemption.Name } else { "" }
                                WaiverReason = if ($exemption) { $exemption.Reason } else { "" }
                                WaiverExpiry = if ($exemption -and $exemption.ExpiresOn) { $exemption.ExpiresOn.ToString("yyyy-MM-dd") } else { "" }
                            }
                        }
                    } else {
                        $compliantResources += $resource
                        
                        if ($Mode -eq "cumple" -or $Mode -eq "todos") {
                            $resultados += [PSCustomObject]@{
                                    SubscriptionId = $SubscriptionId
                                ResourceName = $resource.Name
                                ResourceType = $resource.ResourceType
                                ResourceLocation = $resource.Location
                                ResourceId = $resource.ResourceId
                                    SourceMG = $SourceMG
                                    TargetMG = $TargetMG
                                PolicyOrInitiative = $policyName
                                PolicyName = $innerPolicy.DisplayName
                                PolicyScope = $assignment.Scope
                                Effect = if ($innerResolvedEffect) { $innerResolvedEffect } else { $result.Effect }
                                OriginalEffect = $result.OriginalEffect
                                EffectSource = $result.EffectSource
                                ResolvedEffect = $innerResolvedEffect
                                InitiativeParameters = if ($innerParams) { ($innerParams | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                PolicyParameters = if ($innerPolicy.Properties.parameters) { ($innerPolicy.Properties.parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($innerPolicy.parameters) { ($innerPolicy.parameters | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                AssignmentParameters = if ($assignment.Properties.Parameters) { ($assignment.Properties.Parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($assignment.Parameter) { ($assignment.Parameter | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                                Estado = "✓ CUMPLE"
                                Impacto = "Cumple con la política"
                            }
                        }
                    }
                }
            }
            
            if ($violatingResources.Count -gt 0 -or $compliantResources.Count -gt 0) {
                $policyDetails += [PSCustomObject]@{
                    PolicyAssignment = $policyName
                    PolicyDefinition = $innerPolicy.DisplayName
                    Effect = if ($innerResolvedEffect) { $innerResolvedEffect } else { "Unknown" }
                    ViolatingCount = $violatingResources.Count
                    CompliantCount = $compliantResources.Count
                    ViolatingTypes = if ($violatingResources.Count -gt 0) { ($violatingResources | Select-Object -ExpandProperty ResourceType -Unique) -join ", " } else { "Ninguno" }
                }
            }
        }
    } else {
        # Para política individual
        $policyDef = $policyInfo.Definition
        $resolvedEffect = $policyInfo.ResolvedEffect  # Efecto ya resuelto con EnforcementMode aplicado
        $violatingResources = @()
        $compliantResources = @()
        
        if ($Parallel) {
            # Procesamiento paralelo para política individual
            Write-Host "  Evaluando $($resources.Count) recursos en paralelo..." -ForegroundColor Gray
            # Obtener el código de las funciones como texto
            $testFunctionDef = (Get-Command Test-ResourceViolatesPolicy).Definition
            $testConditionFunctionDef = (Get-Command Test-PolicyCondition).Definition
            $getPropertyFunctionDef = (Get-Command Get-ResourcePropertyByAlias).Definition
            
            $parallelResults = $resources | ForEach-Object -Parallel {
                # Recrear las funciones desde las definiciones de texto
                $testFunctionDef = $using:testFunctionDef
                $testConditionFunctionDef = $using:testConditionFunctionDef
                $getPropertyFunctionDef = $using:getPropertyFunctionDef
                
                Invoke-Expression "function Get-ResourcePropertyByAlias { $getPropertyFunctionDef }"
                Invoke-Expression "function Test-PolicyCondition { $testConditionFunctionDef }"
                Invoke-Expression "function Test-ResourceViolatesPolicy { $testFunctionDef }"
                
                $resource = $_
                $policyDef = $using:policyDef
                $assignment = $using:assignment
                $resolvedEffect = $using:resolvedEffect
                $Mode = $using:Mode
                $policyName = $using:policyName
                
                $result = Test-ResourceViolatesPolicy -PolicyDefinition $policyDef -Resource $resource -Assignment $assignment -ResolvedEffect $resolvedEffect
                
                if ($result.Violates) {
                    if ($Mode -eq "incumple" -or $Mode -eq "todos") {
                        $impacto = switch ($result.Effect) {
                            "Deny" { "❌ Sería BLOQUEADO" }
                            "Audit" { "⚠️  Sería marcado como NO CONFORME (solo auditoría)" }
                            "AuditIfNotExists" { "⚠️  Requiere recursos adicionales (auditoría)" }
                            "DeployIfNotExists" { "🔧 Se desplegarían recursos automáticamente" }
                            "Modify" { "🔧 Se modificaría automáticamente" }
                            default { "⚠️  Efecto: $($result.Effect)" }
                        }
                        
                        # Check for waiver (exemption) for this specific resource and policy
                        $exemption = Test-ResourcePolicyExemption -ResourceId $resource.ResourceId -PolicyAssignmentId $assignment.Id -AllExemptions $allExemptions
                        
                        [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            ResourceName = $resource.Name
                            ResourceType = $resource.ResourceType
                            ResourceLocation = $resource.Location
                            ResourceId = $resource.ResourceId
                            SourceMG = $SourceMG
                            TargetMG = $TargetMG
                            PolicyOrInitiative = $policyName
                            PolicyName = $policyDef.Properties.DisplayName
                            PolicyScope = $assignment.Properties.Scope
                            Effect = if ($result.Effect -and $result.Effect -notmatch "\[parameters\('([^']+)'\)\]" -and $result.Effect -notmatch "@\{value=") { $result.Effect } else { $resolvedEffect }
                            OriginalEffect = $result.OriginalEffect
                            EffectSource = $result.EffectSource
                            ResolvedEffect = if ($result.Effect -and $result.Effect -notmatch "\[parameters\('([^']+)'\)\]" -and $result.Effect -notmatch "@\{value=") { $result.Effect } else { $resolvedEffect }
                            InitiativeParameters = $null
                            PolicyParameters = if ($policyDef.Properties.parameters) { ($policyDef.Properties.parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($policyDef.parameters) { ($policyDef.parameters | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                            AssignmentParameters = if ($assignment.Properties.Parameters) { ($assignment.Properties.Parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($assignment.Parameter) { ($assignment.Parameter | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                            Estado = "❌ INCUMPLE"
                            Impacto = $impacto
                            Type = "Violation"
                            WaiverStatus = if ($exemption) { "Existente" } else { "Revisar" }
                            WaiverName = if ($exemption) { $exemption.Name } else { "" }
                            WaiverReason = if ($exemption) { $exemption.Reason } else { "" }
                            WaiverExpiry = if ($exemption -and $exemption.ExpiresOn) { $exemption.ExpiresOn.ToString("yyyy-MM-dd") } else { "" }
                        }
                    }
                } else {
                    if ($Mode -eq "cumple" -or $Mode -eq "todos") {
                        [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            ResourceName = $resource.Name
                            ResourceType = $resource.ResourceType
                            ResourceLocation = $resource.Location
                            ResourceId = $resource.ResourceId
                            SourceMG = $SourceMG
                            TargetMG = $TargetMG
                            PolicyOrInitiative = $policyName
                            PolicyName = $policyDef.Properties.DisplayName
                            PolicyScope = $assignment.Properties.Scope
                            Effect = if ($result.Effect -and $result.Effect -notmatch "\[parameters\('([^']+)'\)\]" -and $result.Effect -notmatch "@\{value=") { $result.Effect } else { $resolvedEffect }
                            OriginalEffect = $result.OriginalEffect
                            EffectSource = $result.EffectSource
                            ResolvedEffect = if ($result.Effect -and $result.Effect -notmatch "\[parameters\('([^']+)'\)\]" -and $result.Effect -notmatch "@\{value=") { $result.Effect } else { $resolvedEffect }
                            InitiativeParameters = $null
                            PolicyParameters = if ($policyDef.Properties.parameters) { ($policyDef.Properties.parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($policyDef.parameters) { ($policyDef.parameters | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                            AssignmentParameters = if ($assignment.Properties.Parameters) { ($assignment.Properties.Parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($assignment.Parameter) { ($assignment.Parameter | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                            Estado = "✓ CUMPLE"
                            Impacto = "Cumple con la política"
                            Type = "Compliant"
                        }
                    }
                }
            } -ThrottleLimit $ThrottleLimit
            
            # Procesar resultados paralelos
            foreach ($result in $parallelResults) {
                if ($result) {
                    $resultados += $result
                    if ($result.Type -eq "Violation") {
                        $violatingResources += $result.ResourceId
                    } else {
                        $compliantResources += $result.ResourceId
                    }
                }
            }
        } else {
            # Procesamiento secuencial (original)
            foreach ($resource in $resources) {
                $processed++
                if ($processed % 5 -eq 0) {
                    # Calcular PercentComplete de forma segura (evitar >100 y división por cero)
                    $denom = ($resources.Count * $allPolicies.Count)
                    if (-not $denom -or $denom -eq 0) { $pct = 0 } else { $pct = [math]::Round((($processed / $denom) * 100), 0) }
                    $pct = [int]([math]::Max(0, [math]::Min(100, $pct)))
                    Write-Progress -Activity "Evaluando recursos" -Status "Procesando $processed de $denom" -PercentComplete $pct
                }
                
                $result = Test-ResourceViolatesPolicy -PolicyDefinition $policyDef -Resource $resource -Assignment $assignment -ResolvedEffect $resolvedEffect
                
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

                        # Verificar si existe una exemption para este incumplimiento (política individual)
                        $exemptionCheck = Test-ResourcePolicyExemption -ResourceId $resource.ResourceId -PolicyAssignmentId $assignment.Id -AllExemptions $allExemptions
                        
                        $waiverStatus = if ($exemptionCheck.HasExemption) { "Existente" } else { "Revisar" }
                        $waiverName = $exemptionCheck.ExemptionName
                        $waiverReason = $exemptionCheck.Description
                        $waiverExpiry = if ($exemptionCheck.ExpiresOn) { 
                            $exemptionCheck.ExpiresOn 
                        } else { 
                            "" 
                        }
                        
                        $resultados += [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            ResourceName = $resource.Name
                            ResourceType = $resource.ResourceType
                            ResourceLocation = $resource.Location
                            ResourceId = $resource.ResourceId
                            SourceMG = $SourceMG
                            TargetMG = $TargetMG
                            PolicyOrInitiative = $policyName
                            PolicyName = $policyDef.Properties.DisplayName
                            PolicyScope = $assignment.Properties.Scope
                            Effect = if ($result.Effect -and $result.Effect -notmatch "\[parameters\('([^']+)'\)\]" -and $result.Effect -notmatch "@\{value=") { $result.Effect } else { $resolvedEffect }
                            OriginalEffect = $result.OriginalEffect
                            EffectSource = $result.EffectSource
                            ResolvedEffect = if ($result.Effect -and $result.Effect -notmatch "\[parameters\('([^']+)'\)\]" -and $result.Effect -notmatch "@\{value=") { $result.Effect } else { $resolvedEffect }
                            InitiativeParameters = $null
                            PolicyParameters = if ($policyDef.Properties.parameters) { ($policyDef.Properties.parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($policyDef.parameters) { ($policyDef.parameters | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                            AssignmentParameters = if ($assignment.Properties.Parameters) { ($assignment.Properties.Parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($assignment.Parameter) { ($assignment.Parameter | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                            Estado = "❌ INCUMPLE"
                            Impacto = $impacto
                            WaiverStatus = $waiverStatus
                            WaiverName = $waiverName
                            WaiverReason = $waiverReason
                            WaiverExpiry = $waiverExpiry
                        }
                    }
                } else {
                    $compliantResources += $resource
                    
                    if ($Mode -eq "cumple" -or $Mode -eq "todos") {
                        $resultados += [PSCustomObject]@{
                            SubscriptionId = $SubscriptionId
                            ResourceName = $resource.Name
                            ResourceType = $resource.ResourceType
                            ResourceLocation = $resource.Location
                            ResourceId = $resource.ResourceId
                            SourceMG = $SourceMG
                            TargetMG = $TargetMG
                            PolicyOrInitiative = $policyName
                            PolicyName = $policyDef.Properties.DisplayName
                            PolicyScope = $assignment.Properties.Scope
                            Effect = if ($result.Effect -and $result.Effect -notmatch "\[parameters\('([^']+)'\)\]" -and $result.Effect -notmatch "@\{value=") { $result.Effect } else { $resolvedEffect }
                            OriginalEffect = $result.OriginalEffect
                            EffectSource = $result.EffectSource
                            ResolvedEffect = if ($result.Effect -and $result.Effect -notmatch "\[parameters\('([^']+)'\)\]" -and $result.Effect -notmatch "@\{value=") { $result.Effect } else { $resolvedEffect }
                            InitiativeParameters = $null
                            PolicyParameters = if ($policyDef.Properties.parameters) { ($policyDef.Properties.parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($policyDef.parameters) { ($policyDef.parameters | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                            AssignmentParameters = if ($assignment.Properties.Parameters) { ($assignment.Properties.Parameters | ConvertTo-Json -Depth 10 -Compress) } elseif ($assignment.Parameter) { ($assignment.Parameter | ConvertTo-Json -Depth 10 -Compress) } else { $null }
                            Estado = "✓ CUMPLE"
                            Impacto = "Cumple con la política"
                        }
                    }
                }
            }
        }
        
        if ($violatingResources.Count -gt 0 -or $compliantResources.Count -gt 0) {
            $policyDetails += [PSCustomObject]@{
                PolicyAssignment = $policyName
                PolicyDefinition = $policyDef.Properties.DisplayName
                Effect = $resolvedEffect
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
    
    # Mostrar estadísticas de caché
    if ($global:resourceCache) {
        Write-Host "`n📊 ESTADÍSTICAS DE RENDIMIENTO:" -ForegroundColor Cyan
        Write-Host "=" * 100 -ForegroundColor Gray
        Write-Host "Recursos cargados en caché: $($global:resourceCache.Count)" -ForegroundColor Green
        Write-Host "Esto evitó múltiples llamadas API repetidas, mejorando significativamente el rendimiento" -ForegroundColor Gray
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

# Exportar resultados a archivo (CSV o XLSX)
if ($ExportResults -and $resultados.Count -gt 0) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportData = $resultados | Select-Object SubscriptionId, SourceMG, TargetMG, ResourceName, ResourceType, ResourceLocation, ResourceId, PolicyOrInitiative, PolicyName, PolicyScope, Effect, OriginalEffect, EffectSource, ResolvedEffect, InitiativeParameters, PolicyParameters, AssignmentParameters, Estado, Impacto, WaiverStatus, WaiverName, WaiverReason, WaiverExpiry
    
    Write-Host "`n📄 EXPORTANDO RESULTADOS..." -ForegroundColor Cyan
    Write-Host "=" * 100 -ForegroundColor Gray
    
    try {
        if ($ExportFormat -eq "XLSX") {
            # Exportar a Excel (XLSX) usando ImportExcel module
            $xlsxPath = Join-Path $PSScriptRoot "PolicyCompliance_${SubscriptionId}_${timestamp}.xlsx"
            
            # Verificar si el módulo ImportExcel está disponible
            if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
                Write-Host "⚠️  El módulo ImportExcel no está instalado." -ForegroundColor Yellow
                Write-Host "   Instalando ImportExcel..." -ForegroundColor Cyan
                try {
                    Install-Module -Name ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
                    Write-Host "   ✓ Módulo ImportExcel instalado correctamente" -ForegroundColor Green
                } catch {
                    Write-Host "   ❌ No se pudo instalar ImportExcel. Exportando a CSV en su lugar..." -ForegroundColor Yellow
                    $ExportFormat = "CSV"
                }
            }
            
            if ($ExportFormat -eq "XLSX") {
                Import-Module ImportExcel -ErrorAction Stop
                
                $exportData | Export-Excel -Path $xlsxPath `
                    -AutoSize `
                    -TableName "PolicyCompliance" `
                    -TableStyle Medium2 `
                    -FreezeTopRow `
                    -BoldTopRow `
                    -WorksheetName "Compliance Report"
                
                Write-Host "✓ Resultados exportados a: $xlsxPath" -ForegroundColor Green
                Write-Host "  Formato: Excel (XLSX)" -ForegroundColor Gray
                Write-Host "  Total de registros: $($resultados.Count)" -ForegroundColor Gray
                Write-Host "  El archivo incluye formato de tabla y está listo para análisis" -ForegroundColor Gray
                Write-Host ""
            }
        }
        
        if ($ExportFormat -eq "CSV") {
            # Exportar a CSV
            $csvPath = Join-Path $PSScriptRoot "PolicyCompliance_${SubscriptionId}_${timestamp}.csv"
            $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            
            Write-Host "✓ Resultados exportados a: $csvPath" -ForegroundColor Green
            Write-Host "  Formato: CSV (compatible con Excel)" -ForegroundColor Gray
            Write-Host "  Total de registros: $($resultados.Count)" -ForegroundColor Gray
            Write-Host "  Puede abrir este archivo en Excel para análisis adicional" -ForegroundColor Gray
            Write-Host ""
        }
    } catch {
        Write-Host "❌ Error al exportar resultados: $_" -ForegroundColor Red
        Write-Host "   Intentando exportar a CSV como respaldo..." -ForegroundColor Yellow
        try {
            $csvPath = Join-Path $PSScriptRoot "PolicyCompliance_${SubscriptionId}_${timestamp}.csv"
            $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "   ✓ Exportado a CSV correctamente: $csvPath" -ForegroundColor Green
        } catch {
            Write-Host "   ❌ No se pudo exportar el archivo: $_" -ForegroundColor Red
        }
    }
} elseif (-not $ExportResults) {
    Write-Host "`nℹ️  Exportación de resultados deshabilitada (use -ExportResults `$true para habilitar)" -ForegroundColor Cyan
}

