function Start-WinScpConsole
{
    <#
        .SYNOPSIS
            Launch the bundled WinSCP console and wait for it to exit.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param()

    Assert-ScpPlatform
    $path = Join-Path $script:ModuleRoot 'bin/WinSCP.exe'

    if ($PSCmdlet.ShouldProcess($path, 'Start console'))
    {
        Start-Process -FilePath $path -ArgumentList '/console' -Wait
    }
}
