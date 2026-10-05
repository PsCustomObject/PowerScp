function Remove-ScpSession
{
    <#
        .SYNOPSIS
            Dispose a session; disposed sessions cannot be reused.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session
    )

    process
    {
        if ($PSCmdlet.ShouldProcess('WinSCP session', 'Dispose'))
        {
            $Session.Dispose()

            # Snapshot keys before removing entries; match the object rather than its assigned name.
            foreach ($key in @($script:ScpSessions.Keys))
            {
                if ([object]::ReferenceEquals($script:ScpSessions[$key], $Session))
                {
                    $script:ScpSessions.Remove($key)
                }
            }

            $true
        }
    }
}
