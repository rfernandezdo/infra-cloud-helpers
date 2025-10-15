# Check-SubscriptionPolicyCompliance.ps1

Este script de PowerShell permite verificar el cumplimiento de las políticas (o iniciativas) con efecto **Deny** que se aplicarán a los recursos de una suscripción al moverla de un management group de Azure a otro.

## Características
- Recibe los parámetros por línea de comandos o los solicita de forma interactiva si faltan:
  - ID de la suscripción
  - Management group origen
  - Management group destino
  - Modo de salida: incumple, cumple, todos
- Evalúa los recursos de la suscripción frente a las políticas/iniciativas Deny del management group destino.
- Devuelve los recursos y las policies/iniciativas que incumplen, cumplen, o todos según el modo elegido.
- Si no hay incumplimientos, lo refleja en la salida.

## Uso
```pwsh
# Ejemplo básico (solo incumplimientos)
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId <id> -SourceMG <origen> -TargetMG <destino>

# Mostrar solo los recursos que cumplen
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId <id> -SourceMG <origen> -TargetMG <destino> -Mode cumple

# Mostrar todos los recursos evaluados
./Check-SubscriptionPolicyCompliance.ps1 -SubscriptionId <id> -SourceMG <origen> -TargetMG <destino> -Mode todos
```
Si algún parámetro no se indica, el script lo solicitará de forma interactiva.

## Parámetros
- `SubscriptionId`: ID de la suscripción a mover.
- `SourceMG`: Management group origen.
- `TargetMG`: Management group destino.
- `Mode`: "incumple" (default), "cumple", "todos".

## Requisitos
- Módulo Az instalado (`Install-Module -Name Az -Scope CurrentUser`)
- Permisos para consultar políticas y recursos en Azure

## Salida
- Tabla con los recursos, tipo, policy/iniciativa y estado de cumplimiento.
- Mensaje si no hay incumplimientos.

## Autor
rfernandezdo
