# Check if JAz.PIM module is installed, if not, install it
if (-not (Get-module -ListAvailable -Name JAz.PIM)) {
    Install-Module -Name Az.PIM -Force -Scope CurrentUser
}
# Import JAz.PIM module if not already imported
if ( -not (Get-module -Name JAz.PIM)) {
    Import-module JAz.PIM
}
# Check if logged in to Azure,
if (-not (Get-AzContext)) {
    Connect-AzAccount
}
if (-not (Get-AzContext)) {
    Connect-AzAccount
}
# Change default to 8 hours
$PSDefaultParameterValues['Enable-JAz*Role:Hours'] = 8
# Enable all
Get-JAzRole | Enable-JAzRole -Justification "Administrative task"
