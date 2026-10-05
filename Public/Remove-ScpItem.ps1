function Remove-ScpItem
{
    <#
        .SYNOPSIS
            Remove remote files or directories. Paths are literal unless UseFileMask is set.
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([WinSCP.RemovalOperationResult])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath,

        [Parameter(Mandatory)]
        [WinSCP.Session]
        $Session,

        [switch]
        $UseFileMask
    )

    process
    {
        Assert-ScpSession $Session

        foreach ($path in $RemotePath)
        {
            $path = Format-StringPath $path
            $mask = $path

            if (!$UseFileMask)
            {
                $mask = [WinSCP.RemotePath]::EscapeFileMask($path)
            }

            if ($PSCmdlet.ShouldProcess($path, 'Remove remote item'))
            {
                $result = $Session.RemoveFiles($mask)

                $result.Check()
                $result
            }
        }
    }
}
