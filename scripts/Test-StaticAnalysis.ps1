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
$files = @(
    Get-Item -LiteralPath (Join-Path $root 'PowerScp.psm1'), (Join-Path $root 'PowerScp.psd1')

    foreach ($folder in @('Private', 'Public'))
    {
        Get-ChildItem -LiteralPath (Join-Path $root $folder) -Filter '*.ps1' -File
    }
)

$results = @(
    foreach ($file in $files)
    {
        Invoke-ScriptAnalyzer -Path $file.FullName
    }
)
if ($results.Count) {
    $results | Format-Table RuleName,Severity,Line,Message -Wrap
    throw "Static analysis found $($results.Count) diagnostic(s)."
}
Write-Output 'Static analysis passed with no unsuppressed diagnostics.'
