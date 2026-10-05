function Close-ScpSession
{
    <#
        .SYNOPSIS
            Close a connection without disposing its Session object.

        .DESCRIPTION
            The returned object can be reopened through its Open method. Remove-ScpSession
            disposes it permanently and removes it from the module's session list.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session
    )

    process
    {
        if ($PSCmdlet.ShouldProcess('WinSCP session', 'Close connection'))
        {
            $Session.Close()
        }
    }
}
