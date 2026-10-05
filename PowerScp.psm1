# Load the build appropriate to the PowerShell runtime before resolving WinSCP types.
$assemblyPath = Join-Path $PSScriptRoot 'lib/WinSCPnet.dll'

if ($PSEdition -eq 'Core')
{
    $assemblyPath = Join-Path $PSScriptRoot 'lib/netstandard2.0/WinSCPnet.dll'
}

if (!(Test-Path -LiteralPath $assemblyPath))
{
    throw "Missing WinSCP assembly: $assemblyPath. See README.md for dependency setup."
}

Add-Type -Path $assemblyPath -ErrorAction Stop

# Function files have their own PSScriptRoot; retain the module root for bundled binaries.
$script:ModuleRoot = $PSScriptRoot

$script:ScpSessions = @{} # Tracks open sessions for this module instance.

# Release resources when Remove-Module or Import-Module -Force unloads this instance.
$ExecutionContext.SessionState.Module.OnRemove =
{
    foreach ($session in @($script:ScpSessions.Values))
    {
        try
        {
            $session.Dispose()
        }
        catch
        {
            Write-Warning "Could not dispose a tracked WinSCP session: $_"
        }
    }

    $script:ScpSessions.Clear()
}

# Load helpers before the public commands. The manifest controls command exports.
foreach ($folder in @('Private', 'Public'))
{
    $functionPath = Join-Path $PSScriptRoot $folder

    foreach ($file in @(Get-ChildItem -LiteralPath $functionPath -Filter '*.ps1' -File | Sort-Object Name))
    {
        . $file.FullName
    }
}
