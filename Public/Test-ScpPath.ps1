function Test-ScpPath
{
    <#
        .SYNOPSIS
            Test existence of a literal remote file or directory.
    #>

    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSCP.Session]
        $Session,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $RemotePath
    )

    process
    {
        Assert-ScpSession $Session

        foreach ($path in $RemotePath)
        {
            $Session.FileExists((Format-StringPath $path))
        }
    }
}
