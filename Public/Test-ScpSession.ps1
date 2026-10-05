function Test-ScpSession
{
    <#
        .SYNOPSIS
            Return whether a WinSCP session is open.
    #>

    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [WinSCP.Session]
        $Session
    )

    process
    {
        $null -ne $Session -and $Session.Opened
    }
}
