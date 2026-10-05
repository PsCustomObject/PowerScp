function New-ScpSessionObject
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Constructs an in-memory options or unopened session object; public mutations implement ShouldProcess.')]
    [CmdletBinding()]
    param
    (
        [string]
        $SessionLogPath,

        [string]
        $DebugLogPath,

        [int]
        $DebugLevel = 0,

        [timespan]
        $ReconnectTime = [timespan]::FromSeconds(120)
    )

    Assert-ScpPlatform

    $session = New-Object WinSCP.Session

    $session.ExecutablePath = Join-Path $script:ModuleRoot 'bin/WinSCP.exe'
    $session.ReconnectTime = $ReconnectTime
    $session.DebugLogLevel = $DebugLevel

    if ($SessionLogPath)
    {
        $session.SessionLogPath = $SessionLogPath
    }

    if ($DebugLogPath)
    {
        $session.DebugLogPath = $DebugLogPath
    }

    $session
}
