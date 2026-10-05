# Fail on every diagnostic in the shipping module and manifest. Intentional legacy
# API exceptions are documented as narrowly scoped attributes on those functions.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Import-Module PSScriptAnalyzer -RequiredVersion 1.24.0 -ErrorAction Stop
$root = Split-Path $PSScriptRoot -Parent
# Resolve result types consistently even when analysis is run before the tests.
$assembly = 'lib/WinSCPnet.dll'
if ($PSEdition -eq 'Core') { $assembly = 'lib/netstandard2.0/WinSCPnet.dll' }
Add-Type -Path (Join-Path $root $assembly) -ErrorAction Stop
$results = @(foreach ($file in @('PowerScp.psm1','PowerScp.psd1')) {
    Invoke-ScriptAnalyzer -Path (Join-Path $root $file)
})
if ($results.Count) {
    $results | Format-Table RuleName,Severity,Line,Message -Wrap
    throw "Static analysis found $($results.Count) diagnostic(s)."
}
Write-Output 'Static analysis passed with no unsuppressed diagnostics.'
