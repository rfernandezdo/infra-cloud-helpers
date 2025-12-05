# Check-SubscriptionPolicyCompliance.ps1

Este script de PowerShell permite verificar el cumplimiento de las políticas (o iniciativas) con efecto **Deny** que se aplicarán a los recursos de una suscripción al moverla de un management group de Azure a otro.

## 🚀 Características Principales
- **Evaluación de políticas**: Recibe los parámetros por línea de comandos o los solicita de forma interactiva si faltan:
  - ID de la suscripción
  - Management group origen
  - Management group destino
  - Modo de salida: incumple, cumple, todos
- **Análisis de cumplimiento**: Evalúa los recursos de la suscripción frente a las políticas/iniciativas Deny del management group destino.
- **Gestión de waivers**: 🆕 **NUEVA FUNCIONALIDAD** - Detecta automáticamente policy exemptions (waivers) existentes en el management group destino y proporciona información detallada para la toma de decisiones.
- **Exportación completa**: Genera archivos CSV con análisis detallado incluyendo estado de waivers para facilitar la migración.
- **Modo de prueba**: Permite evaluar recursos específicos para testing y validación.
- **Optimización de rendimiento**: Sistema de caché para evitar llamadas API repetidas.

## 💡 Uso

### Ejemplos Básicos
```powsh
# Ejemplo básico (solo incumplimientos)
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId <id> -SourceMG <origen> -TargetMG <destino>

# Mostrar solo los recursos que cumplen
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId <id> -SourceMG <origen> -TargetMG <destino> -Mode cumple

# Mostrar todos los recursos evaluados
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId <id> -SourceMG <origen> -TargetMG <destino> -Mode todos

# Evaluar un recurso específico para pruebas
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId <id> -SourceMG <origen> -TargetMG <destino> -Mode incumple -TestResourceId "/subscriptions/.../resourceGroups/.../providers/Microsoft.Network/networkInterfaces/mi-nic"
```

### Ejemplo Completo con Análisis de Waivers
```powsh
# Análisis completo con detección de waivers para migración
./Check-SubscriptionPolicyCompliance.ps1 `
    -SubscriptionId "049843f8-8df4-4e76-9575-06355059595e" `
    -SourceMG "mg-origen" `
    -TargetMG "mg-destino" `
    -Mode "incumple" `
    -ExportFormat "CSV"
```

Si algún parámetro no se indica, el script lo solicitará de forma interactiva.

## 📋 Parámetros

| Parámetro | Tipo | Obligatorio | Descripción |
|-----------|------|-------------|-------------|
| `SubscriptionId` | String | Sí | ID de la suscripción a evaluar para migración |
| `SourceMG` | String | Sí | Management group origen actual |
| `TargetMG` | String | Sí | Management group destino donde se migrará |
| `Mode` | String | No | **"incumple"** (default), "cumple", "todos" |
| `ExportFormat` | String | No | **"CSV"** (default), "XLSX" - Formato de exportación |
| `TestResourceId` | String | No | ID específico de recurso para evaluación de prueba |
| `Parallel` | Switch | No | Habilita procesamiento paralelo para mejor rendimiento |
| `MaxRetries` | Int | No | Número máximo de reintentos para llamadas API (default: 3) |

### 🆕 Funcionalidad de Waivers
El script detecta automáticamente **Policy Exemptions** (waivers) existentes en el management group destino y proporciona información crucial para la toma de decisiones de migración:

- **Detección automática**: Busca exemptions en management group y subscription de destino
- **Matching inteligente**: Correlaciona incumplimientos con waivers existentes por policy assignment y scope
- **Análisis de vigencia**: Verifica fechas de expiración de waivers existentes
- **Información completa**: Incluye nombre, razón y fecha de expiración de cada waiver

## ⚙️ Requisitos
- **PowerShell**: 5.1 o superior (se recomienda 7.0+ para mejor rendimiento)
- **Módulo Az**: `Install-Module -Name Az -Scope CurrentUser`
- **Módulo ImportExcel** (opcional): `Install-Module -Name ImportExcel -Scope CurrentUser` para exportación XLSX
- **Permisos de Azure**:
  - `Policy Reader` en management groups origen y destino
  - `Reader` en la suscripción a evaluar
  - `Policy Reader` para acceder a Policy Exemptions

## 🔧 Casos de Uso

### 1. Migración de Suscripción
```powsh
# Análisis previo a migración con detección de waivers
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxx" -SourceMG "mg-dev" -TargetMG "mg-prod" -Mode "incumple"
```

### 2. Auditoría de Cumplimiento
```powsh
# Revisión completa de todos los recursos
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxx" -SourceMG "mg-current" -TargetMG "mg-target" -Mode "todos" -Parallel
```

### 3. Testing de Recursos Específicos
```powsh
# Validación de recurso específico
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId "xxx" -SourceMG "mg-dev" -TargetMG "mg-prod" -TestResourceId "/subscriptions/.../providers/Microsoft.Network/networkInterfaces/test-nic"
```

## 🚀 Flujo de Trabajo Recomendado

1. **Análisis inicial**: Ejecutar script en modo "incumple" para identificar problemas
2. **Revisión de waivers**: Analizar columnas `WaiverStatus` en CSV exportado
3. **Planificación**: Para cada "Revisar", decidir entre:
   - Corregir el recurso para cumplir la política
   - Solicitar waiver/exemption en management group destino
4. **Validación**: Re-ejecutar script para confirmar resolución de incumplimientos
5. **Migración**: Proceder con migración una vez resueltos los problemas críticos

## 🎯 Beneficios de la Funcionalidad de Waivers

- **Decisiones informadas**: Saber qué incumplimientos ya tienen waivers aprobados
- **Reducción de riesgo**: Evitar migraciones que causen bloqueos por políticas Deny
- **Eficiencia operativa**: Identificar rápidamente qué waivers necesitan crearse
- **Cumplimiento**: Mantener trazabilidad de exemptions durante migraciones
- **Planificación**: Calcular tiempo y esfuerzo necesario para migración segura

## 📊 Salida y Exportación

### Consola
- **Resumen ejecutivo**: Estadísticas de cumplimiento y recursos afectados
- **Detalles por política**: Lista de políticas/iniciativas que generan incumplimientos
- **Recursos afectados**: Agrupación por tipo de recurso con nombres y ubicaciones
- **Recomendaciones**: Guías específicas para resolver cada incumplimiento

### Archivo CSV (Nuevo formato extendido)
El script genera automáticamente un archivo CSV con análisis completo:

```
PolicyCompliance_{SubscriptionId}_{YYYYMMDD}_{HHMMSS}.csv
```

#### 🆕 Columnas de Waivers
| Columna | Descripción | Valores |
|---------|-------------|---------|
| `WaiverStatus` | Estado del waiver para el incumplimiento | **"Existente"** = Ya existe waiver aplicable<br/>**"Revisar"** = Necesita crear/solicitar waiver<br/>*(Vacío)* = No aplica evaluación |
| `WaiverName` | Nombre del waiver existente | Nombre del Policy Exemption que aplica |
| `WaiverReason` | Razón del waiver | Categoría: "Waiver", "Mitigated", etc. |
| `WaiverExpiry` | Fecha de expiración | Fecha ISO 8601 o vacío si es permanente |

#### Columnas Completas del CSV
```csv
SubscriptionId,SourceMG,TargetMG,ResourceName,ResourceType,ResourceLocation,ResourceId,
PolicyOrInitiative,PolicyName,PolicyScope,Effect,OriginalEffect,EffectSource,
ResolvedEffect,InitiativeParameters,PolicyParameters,AssignmentParameters,
Estado,Impacto,WaiverStatus,WaiverName,WaiverReason,WaiverExpiry
```

### 💡 Interpretación de Resultados de Waivers

| Escenario | WaiverStatus | Acción Recomendada |
|-----------|--------------|-------------------|
| Incumplimiento con waiver existente | **"Existente"** | ✅ **Migración segura** - El waiver cubre este incumplimiento |
| Incumplimiento sin waiver | **"Revisar"** | ⚠️ **Acción requerida** - Crear waiver o corregir recurso |
| Cumplimiento | *(Vacío)* | ✅ **Sin acción** - Recurso cumple políticas |

## 📚 Ejemplos de Salida

### Ejemplo de CSV con Waivers
```csv
SubscriptionId,SourceMG,TargetMG,ResourceName,ResourceType,PolicyName,Estado,WaiverStatus,WaiverName,WaiverReason,WaiverExpiry
049843f8-...,mg-dev,mg-prod,mi-storage,Microsoft.Storage/storageAccounts,RequirePrivateLink,❌ INCUMPLE,Existente,Storage-Migration-Waiver,Waiver,2025-12-31T23:59:59Z
049843f8-...,mg-dev,mg-prod,mi-vm,Microsoft.Compute/virtualMachines,RequireEncryption,❌ INCUMPLE,Revisar,,,
049843f8-...,mg-dev,mg-prod,mi-keyvault,Microsoft.KeyVault/vaults,RequireRBAC,✅ CUMPLE,,,,
```

### Interpretación:
- **mi-storage**: ✅ Tiene waiver existente, migración segura
- **mi-vm**: ⚠️ Necesita waiver o corrección antes de migrar  
- **mi-keyvault**: ✅ Cumple políticas, sin acción requerida

## 🔍 Troubleshooting

### Error 404 en Policy Exemptions
```
❌ Error después de 3 intentos para GET .../policyExemptions
Error: Response status code does not indicate success: 404 (Not Found).
```
**Solución**: Esto es normal cuando no existen exemptions en el management group. El script continúa correctamente.

### Sin permisos para Policy Exemptions
```
Error: Insufficient privileges to complete the operation.
```
**Solución**: Solicitar rol `Policy Reader` en el management group destino.

### Recursos no encontrados
```
⚠️ Recursos encontrados (antes de filtrar): 0
```
**Solución**: Verificar que la suscripción contenga recursos y que se tengan permisos `Reader`.

## 🆕 Changelog - Funcionalidad de Waivers

### Versión 2.0 (Noviembre 2025)
- ✅ **Nueva funcionalidad**: Detección automática de Policy Exemptions (waivers)
- ✅ **Columnas CSV extendidas**: WaiverStatus, WaiverName, WaiverReason, WaiverExpiry
- ✅ **Optimización**: Sistema de caché para exemptions y mejor rendimiento
- ✅ **Análisis inteligente**: Matching de incumplimientos con waivers por scope y assignment
- ✅ **Experiencia mejorada**: Recomendaciones específicas basadas en estado de waivers

## 👨‍💻 Autor
**rfernandezdo**

---
*Script desarrollado para facilitar migraciones seguras de suscripciones entre management groups con análisis completo de políticas y waivers.*
